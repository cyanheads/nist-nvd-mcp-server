/**
 * @fileoverview Tool for finding CVEs affecting a specific product and version by CPE.
 * @module src/mcp-server/tools/definitions/nvd-audit-cpe
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { escapeMarkdownInline, markdownLink } from '@cyanheads/mcp-ts-core/utils';
import {
  dateWindowEcho,
  dateWindowEnrichment,
  dateWindowInput,
  renderDatesClamped,
  renderFiltersApplied,
  resolveDateWindows,
  windowReexpandedNotice,
  windowReplayClause,
} from '@/mcp-server/tools/date-windows.js';
import { flattenCpeMatches, summarizeCpeNodes } from '@/mcp-server/tools/formatting/cpe-match.js';
import {
  formatAffectedProducts,
  formatCvssScore,
  formatRecordSource,
} from '@/mcp-server/tools/formatting/full-record.js';
import { formatSsvc } from '@/mcp-server/tools/formatting/ssvc.js';
import {
  applyReadLimit,
  readLimitEnrichment,
  readLimitSchema,
} from '@/mcp-server/tools/read-limit.js';
import { CveRecordSchema } from '@/mcp-server/tools/schemas/full-cve.js';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

const CPE_V23_REGEX = /^cpe:2\.3:/i;

export const nvdAuditCpe = tool('nvd_audit_cpe', {
  title: 'Audit CPE for Vulnerabilities',
  description:
    "Find all CVEs affecting a specific product and version using CPE (Common Platform Enumeration). Requires either an exact CPE name (cpeName) or a partial match string (virtualMatchString) with optional version range bounds. With cpeName, NVD scopes results to configurations where the product is directly vulnerable, not merely referenced as a dependency. Use nvd_search_cpes first to resolve the correct CPE string for a product. Narrow the audit server-side with kevOnly, an exact severity band, or publication, last-modified, or KEV-addition date windows; pubDays, lastModDays, and kevDays expand to date pairs ending at call time, values over 120 days are clamped and reported, and a shorthand re-expands on every call, so page with the dates echoed in filtersApplied. Returns full CVE records including current SSVC assessments, each score's supplier, and the affected products the CNA and any ADP state themselves.",
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    cpeName: z
      .string()
      .optional()
      .describe(
        'Full CPEv2.3 name (e.g., "cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*"). ' +
          'NVD adds isVulnerable automatically. Mutually exclusive with virtualMatchString.',
      ),
    virtualMatchString: z
      .string()
      .optional()
      .describe(
        'Partial CPE match pattern (e.g., "cpe:2.3:a:apache:http_server:*"). ' +
          'Use with versionStart/versionEnd for version range audits. Mutually exclusive with cpeName.',
      ),
    versionStart: z
      .string()
      .optional()
      .describe('Lower version bound. Requires virtualMatchString.'),
    versionStartType: z
      .enum(['including', 'excluding'])
      .default('including')
      .describe('Whether the lower version bound is inclusive or exclusive.'),
    versionEnd: z.string().optional().describe('Upper version bound. Requires virtualMatchString.'),
    versionEndType: z
      .enum(['including', 'excluding'])
      .default('including')
      .describe('Whether the upper version bound is inclusive or exclusive.'),
    kevOnly: z
      .boolean()
      .default(false)
      .describe(
        'When true, limits the audit to CVEs in the CISA Known Exploited Vulnerabilities catalog, whenever CISA added them. A KEV window (kevDays or kevStartDate/kevEndDate) already returns only catalog members.',
      ),
    severity: z
      .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
      .optional()
      .describe(
        'Server-side filter to CVEs in exactly this CVSS severity band at severityVersion — NVD matches the one band, not a floor, so totalCount and paging count that band alone. Covering several bands (e.g. HIGH and CRITICAL) takes one call per band. Combines with severityMin, which then filters the fetched page across every CVSS version.',
      ),
    severityVersion: z
      .enum(['v2', 'v3', 'v4'])
      .default('v3')
      .describe(
        'CVSS version to use for the severity filter. Default: v3 (maps to cvssV3Severity).',
      ),
    ...dateWindowInput,
    severityMin: z
      .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
      .optional()
      .describe(
        'Keep CVEs whose highest severity band across all CVSS versions meets this threshold, which can exceed the row headline severity. Applied after NVD returns the page, so only CVEs within limit are evaluated and totalCount is unchanged; for a server-side band that totalCount and paging count, use severity.',
      ),
    includeConfigurations: z
      .boolean()
      .default(true)
      .describe('When false, omits configurationNodes from each record and its rendered text.'),
    includeAffected: z
      .boolean()
      .default(true)
      .describe('When false, omits affectedProducts from each record and its rendered text.'),
    includeReferences: z
      .boolean()
      .default(true)
      .describe('When false, omits references from each record and its rendered text.'),
    allLanguages: z
      .boolean()
      .default(false)
      .describe(
        'When true, keeps every localized description NVD supplies on each record. Default keeps English only.',
      ),
    limit: readLimitSchema(2000, 20).describe(
      'Maximum number of CVEs to return (default 20; values above 2000 are clamped unless NVD_CLAMP_LIMITS is false).',
    ),
    offset: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe(
        'Zero-based page offset for pagination. Page through totalCount with a modest limit ' +
          'rather than raising limit — this tool returns full CVE records, so a large limit is a large response.',
      ),
  }),

  output: z.object({
    cves: z
      .array(
        CveRecordSchema.partial({ configurationNodes: true, affectedProducts: true }).describe(
          'CVE record for one vulnerability affecting the product; configurations, affected products, and references can be omitted by caller selectors.',
        ),
      )
      .describe('Full CVE records for CVEs affecting the specified product.'),
  }),

  enrichment: {
    ...readLimitEnrichment,
    totalCount: z.number().describe('Total CVEs matched before pagination.'),
    returned: z.number().describe('Number of CVE records returned.'),
    offset: z.number().describe('Page offset used in this query.'),
    auditTarget: z.string().describe('The CPE name or virtual match string used for this audit.'),
    severityMin: z
      .string()
      .optional()
      .describe('The client-side minimum severity filter applied. Absent when none was set.'),
    filteredCount: z
      .number()
      .optional()
      .describe(
        'CVEs below severityMin on every CVSS band, or with no scores, on the page NVD returned. Present whenever severityMin is set; 0 means none were dropped. Bands across all versions are evaluated independently of the row headline; CVEs beyond limit were not evaluated.',
      ),
    ...dateWindowEnrichment,
    filtersApplied: z
      .object({
        severity: z
          .string()
          .optional()
          .describe(
            'The exact CVSS severity band that was applied — results are limited to this band alone, so higher bands are not included.',
          ),
        severityVersion: z
          .string()
          .optional()
          .describe(
            'The CVSS version the severity filter matched on. Present only alongside severity.',
          ),
        ...dateWindowEcho,
        kevOnly: z
          .boolean()
          .optional()
          .describe('Present as true when results were limited to the CISA KEV catalog.'),
      })
      .optional()
      .describe(
        'The server-side filters this audit applied beyond its target — the ones totalCount counts within, and that can account for an empty or unexpectedly narrow result. Absent when none was set. severityMin is reported on its own field because it filters the fetched page, not the NVD query.',
      ),
    notice: z
      .string()
      .optional()
      .describe(
        "Guidance on the shape of this page. When no CVEs came back it distinguishes a target NVD holds no CVEs for from a target with none matching the server-side filters, from a severityMin filter that dropped everything on the page, from an offset past the result set, from an empty page NVD returned inside a range it says has matches. A page severityMin emptied names the offset of the next page while CVEs remain past it, or says the target is exhausted at that threshold once none do. On a partial page it names the offset that reaches the next one. On the first page of a window a shorthand set, any next-page offset it names comes with the filtersApplied dates to send in its place; past offset 0 it flags a shorthand window re-expanded for this call and points to the first page's dates instead. Also reports blank date filters it ignored.",
      ),
  },

  enrichmentTrailer: {
    returned: { label: 'Returned' },
    offset: { label: 'Offset' },
    auditTarget: { label: 'Audit Target' },
    severityMin: { label: 'Severity Filter' },
    filteredCount: { label: 'Dropped by Severity Filter' },
    datesClamped: { render: renderDatesClamped },
    filtersApplied: { render: renderFiltersApplied },
  },

  errors: [
    {
      reason: 'nvd_invalid_response',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'NVD returned an invalid response.',
      thrownBy: 'service',
      retryable: false,
      recovery: 'Retry later; report a persistent invalid NVD response.',
    },
    {
      reason: 'nvd_request_blocked',
      code: JsonRpcErrorCode.Forbidden,
      when: 'NVD blocked the request.',
      thrownBy: 'service',
      retryable: false,
      recovery: 'Rephrase query text; otherwise try later or use another network.',
    },
    {
      reason: 'missing_cpe_input',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Neither cpeName nor virtualMatchString was provided.',
      recovery:
        'Provide either cpeName (exact CPEv2.3 string) or virtualMatchString (partial match pattern) — use nvd_search_cpes to find the correct CPE.',
    },
    {
      reason: 'conflicting_cpe_inputs',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Both cpeName and virtualMatchString were provided simultaneously.',
      recovery: 'Provide only one of cpeName or virtualMatchString per call, not both.',
    },
    {
      reason: 'version_range_without_match_string',
      code: JsonRpcErrorCode.ValidationError,
      when: 'versionStart or versionEnd was provided without virtualMatchString.',
      recovery:
        'Version range parameters require virtualMatchString; provide that parameter or use cpeName for exact-version queries.',
    },
    {
      reason: 'invalid_cpe_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'cpeName or virtualMatchString does not start with "cpe:2.3:", or NVD rejected it as a malformed CPE parameter — cpeName rejects anything short of a complete CPEv2.3 name, virtualMatchString only genuinely malformed characters.',
      recovery:
        'Provide a valid CPEv2.3 string starting with "cpe:2.3:". Use nvd_search_cpes to find the correct CPE name.',
    },
    {
      reason: 'nvd_request_rejected',
      code: JsonRpcErrorCode.ValidationError,
      when: 'NVD rejected a request parameter other than the CPE — a date it cannot parse, or a range it measures past 120 days — or rejected the request without naming a parameter.',
      retryable: false,
      thrownBy: 'service',
      recovery:
        'Fix the parameter NVD names in the message: send date fields as YYYY-MM-DDThh:mm[:ss[.fraction]] with an optional Z or ±hh:mm offset, e.g. 2024-01-01T00:00:00.000Z. If NVD names none, confirm the CPE with nvd_search_cpes.',
    },
    // The five date reasons below are raised by the shared resolver in date-windows.ts.
    {
      reason: 'mutually_exclusive_params',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A date shorthand was sent with its explicit range: pubDays with pubStartDate/pubEndDate, lastModDays with lastModStartDate/lastModEndDate, or kevDays with kevStartDate/kevEndDate.',
      thrownBy: 'service',
      recovery:
        'Use either the convenience shorthand (pubDays, lastModDays, or kevDays) or its explicit date range (start + end date), not both.',
    },
    {
      reason: 'missing_date_pair',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Only one end of a date range was provided (pubStartDate/pubEndDate, lastModStartDate/lastModEndDate, or kevStartDate/kevEndDate) — NVD requires both.',
      thrownBy: 'service',
      recovery:
        'Provide both the start and end date, or use pubDays, lastModDays, or kevDays instead of an explicit date range.',
    },
    {
      reason: 'date_range_inverted',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The end date of a date range is before its start date.',
      thrownBy: 'service',
      recovery: 'Ensure the end date is after the start date.',
    },
    {
      reason: 'date_range_exceeds_max',
      code: JsonRpcErrorCode.ValidationError,
      when: 'An explicit date range (pubStartDate/pubEndDate, lastModStartDate/lastModEndDate, or kevStartDate/kevEndDate) spans more than 120 days.',
      thrownBy: 'service',
      recovery:
        'Narrow the date range to 120 days or fewer, or split it into consecutive windows of at most 120 days and query each.',
    },
    {
      reason: 'invalid_date_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A date field (pubStartDate, pubEndDate, lastModStartDate, lastModEndDate, kevStartDate, or kevEndDate) is not a date and time in the form NVD accepts.',
      thrownBy: 'service',
      recovery:
        'Send YYYY-MM-DDThh:mm[:ss[.fraction]] with an optional Z or ±hh:mm offset, e.g. 2024-01-01T00:00:00.000Z; a value without an offset is read as UTC.',
    },
    {
      reason: 'invalid_severity_for_version',
      code: JsonRpcErrorCode.ValidationError,
      when: 'severity="CRITICAL" was specified with severityVersion="v2" — CVSS v2 has no CRITICAL tier.',
      recovery: 'Use LOW, MEDIUM, or HIGH when severityVersion is "v2". Use v3 or v4 for CRITICAL.',
    },
    {
      reason: 'rate_limited',
      code: JsonRpcErrorCode.RateLimited,
      when: 'NVD explicitly reported that the rate limit was exceeded.',
      retryable: true,
      /** Raised by the HTTP client on NVD's 403, below this handler. */
      thrownBy: 'service',
      recovery:
        'Wait for the NVD rate window to reset, then retry; a server operator can set NVD_API_KEY for higher limits.',
    },
    {
      reason: 'nvd_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'NVD answered with HTTP 5xx, or the request or its response failed on the network, after the client retried.',
      retryable: true,
      /** Raised by the HTTP client, below this handler. */
      thrownBy: 'service',
      recovery: 'NVD is failing or unreachable; wait a minute and retry the call.',
    },
    {
      reason: 'nvd_timeout',
      code: JsonRpcErrorCode.Timeout,
      when: 'An NVD request outlived its timeout, or the call ran out of its 55-second deadline.',
      retryable: true,
      /** Raised by the HTTP client, below this handler. */
      thrownBy: 'service',
      recovery:
        'NVD did not answer in time; retry in a minute. A server operator can raise NVD_REQUEST_TIMEOUT_MS.',
    },
    {
      reason: 'nvd_invalid_api_key',
      code: JsonRpcErrorCode.ConfigurationError,
      when: "NVD refused the server's configured NVD_API_KEY.",
      retryable: false,
      /** Raised by the HTTP client, below this handler, carrying this same hint. */
      thrownBy: 'service',
      recovery:
        "NVD refused this server's NVD_API_KEY, so no NVD call can succeed until a server operator fixes it: verify the key, request a replacement at https://nvd.nist.gov/developers/request-an-api-key, or unset NVD_API_KEY to run keyless at 5 req/30s.",
    },
  ],

  async handler(input, ctx) {
    // A blank date field from a form client is unset, as on nvd_search_cves; the resolver needs it gone.
    input = { ...input };
    const ignoredFilters: string[] = [];
    for (const field of [
      'pubStartDate',
      'pubEndDate',
      'lastModStartDate',
      'lastModEndDate',
      'kevStartDate',
      'kevEndDate',
    ] as const) {
      const value = input[field];
      if (value === undefined) continue;
      const trimmed = value.trim();
      if (trimmed) input[field] = trimmed;
      else {
        delete input[field];
        ignoredFilters.push(field);
      }
    }

    // Validate inputs
    if (!input.cpeName && !input.virtualMatchString) {
      throw ctx.fail('missing_cpe_input', 'Either cpeName or virtualMatchString is required.');
    }
    if (input.cpeName && input.virtualMatchString) {
      throw ctx.fail(
        'conflicting_cpe_inputs',
        'Provide only one of cpeName or virtualMatchString, not both.',
      );
    }
    if ((input.versionStart || input.versionEnd) && !input.virtualMatchString) {
      throw ctx.fail(
        'version_range_without_match_string',
        'versionStart/versionEnd require virtualMatchString.',
      );
    }

    if (input.cpeName && !CPE_V23_REGEX.test(input.cpeName)) {
      throw ctx.fail(
        'invalid_cpe_format',
        `Invalid CPE name: "${input.cpeName}". CPEv2.3 names must start with "cpe:2.3:".`,
      );
    }
    if (input.virtualMatchString && !CPE_V23_REGEX.test(input.virtualMatchString)) {
      throw ctx.fail(
        'invalid_cpe_format',
        `Invalid CPE string: "${input.virtualMatchString}". CPEv2.3 strings must start with "cpe:2.3:".`,
      );
    }

    const windows = resolveDateWindows(input, Date.now());

    // CVSS v2 has no CRITICAL tier, so NVD could only answer the band with nothing.
    if (input.severity === 'CRITICAL' && input.severityVersion === 'v2') {
      throw ctx.fail(
        'invalid_severity_for_version',
        'CVSS v2 has no CRITICAL severity tier. Valid values for severityVersion="v2" are LOW, MEDIUM, HIGH.',
      );
    }

    ctx.log.info('Auditing CPE for vulnerabilities', {
      cpeName: input.cpeName,
      virtualMatchString: input.virtualMatchString,
      severity: input.severity,
      kevOnly: input.kevOnly,
      limit: input.limit,
      offset: input.offset,
    });

    const service = getNvdCveService();
    const clamped = applyReadLimit(input.limit, 2000, 'nvd_audit_cpe', ctx);
    const notices: string[] = [];
    if (ignoredFilters.length > 0) notices.push(`Ignored empty ${ignoredFilters.join(', ')}.`);
    if (clamped.notice) notices.push(clamped.notice);
    const result = await service.auditCpe(
      {
        ...(input.cpeName && { cpeName: input.cpeName }),
        ...(input.virtualMatchString && { virtualMatchString: input.virtualMatchString }),
        ...(input.versionStart && { versionStart: input.versionStart }),
        versionStartType: input.versionStartType,
        ...(input.versionEnd && { versionEnd: input.versionEnd }),
        versionEndType: input.versionEndType,
        kevOnly: input.kevOnly,
        ...(input.severity && { severity: input.severity, severityVersion: input.severityVersion }),
        ...windows.dates,
        ...(input.severityMin && { severityMin: input.severityMin }),
        allLanguages: input.allLanguages,
        limit: clamped.limit,
        offset: input.offset,
      },
      ctx,
    );

    /**
     * Echo only what the caller narrowed the NVD query by: severityVersion carries a default, so it
     * rides only beside a band. severityMin keeps its own field — it filters the fetched page, not
     * the query totalCount counts.
     */
    const filtersApplied = {
      ...(input.severity && { severity: input.severity, severityVersion: input.severityVersion }),
      ...windows.dates,
      ...(input.kevOnly && { kevOnly: true }),
    };
    const filtered = Object.keys(filtersApplied).length > 0;

    const auditTarget = result.cpeName ?? result.virtualMatchString ?? 'unknown CPE';
    ctx.enrich({
      returned: result.returned,
      offset: result.offset,
      auditTarget,
      ...(input.severityMin && {
        severityMin: input.severityMin,
        filteredCount: result.filteredCount,
      }),
      ...(windows.datesClamped.length > 0 && { datesClamped: windows.datesClamped }),
      ...(filtered && { filtersApplied }),
    });
    ctx.enrich.total(result.totalResults);
    if (result.cves.length === 0) {
      /**
       * Five ways a page comes back empty, narrowest first. An offset at or past totalCount means
       * the product has CVEs and this page merely sits past them. filteredCount > 0 means NVD did
       * return CVEs and severityMin cut them. A valid offset inside a non-zero totalCount means
       * NVD contradicted its own count, so neither the offset nor the target is at fault. A zero
       * count under a server-side filter says only that nothing matched the filters — the target
       * may hold other CVEs — so it is never reported as a clean audit. Only an unfiltered zero
       * leaves the CPE string itself unconfirmed, and even then the finding leads — every branch
       * exists to keep the caller from being sent after a mistake they did not make.
       */
      if (result.totalResults > 0 && input.offset >= result.totalResults) {
        notices.push(
          `Offset ${input.offset} is past the end of the result set (${result.totalResults} total). Use a lower offset to page through results.`,
        );
      } else if (input.severityMin && result.filteredCount > 0) {
        /**
         * NVD spent an index position on every row the threshold dropped, so the next page starts
         * at `offset + filteredCount`, as on a partly filtered page. Once that reaches totalCount
         * nothing is left to fetch, and raising limit would fetch nothing new.
         */
        const next = result.offset + result.filteredCount;
        const dropped = `All ${result.filteredCount} CVE(s) on the fetched page scored below ${input.severityMin}`;
        if (next < result.totalResults) {
          const replay = windowReplayClause(windows.shorthands, input.offset);
          notices.push(
            `${dropped}. To continue at this threshold, set offset to ${next} for the next page${replay ? ` and ${replay}` : ''}. Lower severityMin or raise limit to widen the page NVD returns.`,
          );
        } else {
          notices.push(
            `${dropped}, and that page reached the end of the ${result.totalResults} CVE(s) matching this audit target: the target is exhausted at this threshold. Lower severityMin to see the CVEs it dropped.`,
          );
        }
      } else if (result.totalResults > 0) {
        notices.push(
          `NVD reported ${result.totalResults} CVE(s) for this audit target but returned none at offset ${input.offset}, which is inside that range. Retry the query; neither the offset nor the audit target is the problem.`,
        );
      } else if (filtered) {
        notices.push(
          'No CVEs for this audit target match the applied filters (see filtersApplied) — this is not a clean audit. Widen or drop a filter; an unfiltered audit shows whether NVD holds any CVEs for the target.',
        );
      } else {
        notices.push(
          'No CVEs in NVD for this audit target — a clean audit, not a failed one. ' +
            'If that is unexpected, confirm the CPE string with nvd_search_cpes: it is the one input this audit cannot verify on its own.',
        );
      }
    } else if (result.totalResults > result.offset + result.returned + result.filteredCount) {
      /**
       * Advance by what NVD's page consumed, not by what survived it: `returned` counts the rows
       * left after the client-side severityMin filter, so paging on `offset + returned` alone
       * would re-serve every row that filter dropped. `returned + filteredCount` is the span NVD
       * actually spent index positions on, and collapses to `returned` when no filter is set. A
       * shorthand window would move by the next call, so the notice also names the echoed dates
       * that hold it still.
       */
      const consumed = result.returned + result.filteredCount;
      const replay = windowReplayClause(windows.shorthands, input.offset);
      notices.push(
        `Results truncated — ${result.totalResults} CVEs match this audit target; set offset to ${result.offset + consumed} for the next page${replay ? ` and ${replay}` : ''}.`,
      );
    }
    const reexpanded = windowReexpandedNotice(windows.shorthands, input.offset);
    if (reexpanded) notices.push(reexpanded);

    if (notices.length > 0) ctx.enrich.notice(notices.join(' '));
    // Each unselected section is dropped by removal alone, so the fields left keep their order.
    const cves = result.cves.map((cve) => {
      const { configurationNodes: _configurationNodes, ...withoutConfigurations } = cve;
      const configured = input.includeConfigurations ? cve : withoutConfigurations;
      const { affectedProducts: _affectedProducts, ...withoutAffected } = configured;
      const selected = input.includeAffected ? configured : withoutAffected;
      if (input.includeReferences) return selected;
      const { references: _references, ...withoutReferences } = selected;
      return withoutReferences;
    });
    return { cves };
  },

  format: (result) => {
    const lines: string[] = [];

    if (result.cves.length === 0) {
      return [{ type: 'text', text: 'No CVEs returned for this product.' }];
    }

    for (const cve of result.cves) {
      lines.push(`## ${escapeMarkdownInline(cve.cveId)}`);
      lines.push(
        `**Status:** ${escapeMarkdownInline(cve.vulnStatus)} | **Published:** ${escapeMarkdownInline(cve.published)} | **Last Modified:** ${escapeMarkdownInline(cve.lastModified)}${formatRecordSource(cve)}`,
      );

      if (cve.severity) {
        lines.push(
          `**Severity:** ${escapeMarkdownInline(cve.severity.label)} (${cve.severity.score}) from CVSS ${escapeMarkdownInline(cve.severity.fromVersion)}`,
        );
      } else {
        lines.push('**Severity:** Not available (no CVSS scores)');
      }

      if (cve.cvssScores && cve.cvssScores.length > 0) {
        lines.push('**CVSS Scores:**');
        for (const s of cve.cvssScores) lines.push(`  - ${formatCvssScore(s)}`);
      }

      if (cve.weaknesses && cve.weaknesses.length > 0) {
        lines.push('**Weaknesses:**');
        for (const w of cve.weaknesses) {
          if (w.cweIds.length > 0) {
            lines.push(
              `  - ${escapeMarkdownInline(w.source)}: ${w.cweIds.map(escapeMarkdownInline).join(', ')}`,
            );
          }
        }
      }

      if (cve.ssvc) lines.push(...formatSsvc(cve.ssvc));

      // Descriptions — render lang and value for all entries to satisfy format-parity
      for (const desc of cve.descriptions) {
        lines.push(`\n[${escapeMarkdownInline(desc.lang)}] ${escapeMarkdownInline(desc.value)}`);
      }

      if (cve.cisaKev) {
        lines.push(`\n**CISA KEV:** ${escapeMarkdownInline(cve.cisaKev.vulnerabilityName)}`);
        lines.push(`  - Added: ${escapeMarkdownInline(cve.cisaKev.exploitAddDate)}`);
        lines.push(`  - Action Due: ${escapeMarkdownInline(cve.cisaKev.actionDueDate)}`);
        lines.push(`  - Required Action: ${escapeMarkdownInline(cve.cisaKev.requiredAction)}`);
      }

      if (cve.configurationNodes && cve.configurationNodes.length > 0) {
        const matches = flattenCpeMatches(cve.configurationNodes);
        lines.push(`**Configurations:** ${summarizeCpeNodes(cve.configurationNodes)}`);
        for (const match of matches) lines.push(`  - ${match}`);
      }

      if (cve.affectedProducts) lines.push(...formatAffectedProducts(cve.affectedProducts));

      if (cve.references && cve.references.length > 0) {
        lines.push(`**References (${cve.references.length}):**`);
        for (const ref of cve.references) {
          const sourcePart = ref.source ? ` [${escapeMarkdownInline(ref.source)}]` : '';
          const tagPart = ref.tags?.length
            ? ` (${ref.tags.map(escapeMarkdownInline).join(', ')})`
            : '';
          lines.push(`  - ${markdownLink(ref.url, ref.url)}${sourcePart}${tagPart}`);
        }
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
