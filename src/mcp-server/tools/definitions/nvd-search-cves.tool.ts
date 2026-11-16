/**
 * @fileoverview Tool for searching CVEs by keyword, severity, CWE, publication, last-modified, or
 * KEV-addition date window, or KEV status.
 * @module src/mcp-server/tools/definitions/nvd-search-cves
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
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
import {
  applyReadLimit,
  readLimitEnrichment,
  readLimitSchema,
} from '@/mcp-server/tools/read-limit.js';
import { BriefCveRecordSchema } from '@/mcp-server/tools/schemas/brief-cve.js';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

export const nvdSearchCves = tool('nvd_search_cves', {
  title: 'Search CVEs',
  description:
    'Search CVEs by keyword, severity, CWE, publication or last-modified date, CISA KEV status, or the date CISA added a CVE to KEV. The primary discovery tool for vulnerability surveillance and triage workflows. pubDays, lastModDays, and kevDays expand to date pairs ending at call time; values over 120 days are clamped to the NVD maximum and reported in the response enrichment. A shorthand re-expands on every call, so page with the dates echoed in filtersApplied. Returns brief summaries — call nvd_get_cve for full detail on specific IDs. At least one filter is recommended; omitting all filters returns CVEs in default NVD index order (oldest first by CVE ID). Blank string filters are omitted with a notice; nonblank strings are trimmed.',
  annotations: { readOnlyHint: true, openWorldHint: false },

  input: z.object({
    keyword: z
      .string()
      .optional()
      .describe('Full-text search across CVE descriptions (AND-semantics across words).'),
    exactPhrase: z
      .boolean()
      .default(false)
      .describe(
        'When true, keyword matches as an exact phrase rather than ANDing its words independently. Requires keyword.',
      ),
    severity: z
      .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
      .optional()
      .describe(
        'Filter to CVEs in exactly this CVSS severity band — NVD matches the one band, not a floor. ' +
          'Covering several bands (e.g. HIGH and CRITICAL) takes one call per band.',
      ),
    severityVersion: z
      .enum(['v2', 'v3', 'v4'])
      .default('v3')
      .describe(
        'CVSS version to use for the severity filter. Default: v3 (maps to cvssV3Severity).',
      ),
    cweId: z
      .string()
      .optional()
      .describe('Filter by CWE weakness ID (e.g., "CWE-79", "NVD-CWE-Other").'),
    ...dateWindowInput,
    kevOnly: z
      .boolean()
      .default(false)
      .describe(
        'When true, filters results to CVEs in the CISA Known Exploited Vulnerabilities catalog, whenever CISA added them. A KEV window (kevDays or kevStartDate/kevEndDate) already returns only catalog members.',
      ),
    noRejected: z
      .boolean()
      .default(true)
      .describe('When true (default), excludes CVEs with REJECT/Rejected status.'),
    limit: readLimitSchema(2000, 20).describe(
      'Maximum number of results to return (default 20; values above 2000 are clamped unless NVD_CLAMP_LIMITS is false).',
    ),
    offset: z.number().int().min(0).default(0).describe('Zero-based page offset for pagination.'),
  }),

  output: z.object({
    cves: z
      .array(BriefCveRecordSchema.describe('Brief summary for one matching CVE.'))
      .describe('Matching CVE summaries. Call nvd_get_cve for full detail on specific IDs.'),
  }),

  enrichment: {
    ...readLimitEnrichment,
    totalCount: z.number().describe('Total matching CVEs in NVD before pagination.'),
    returned: z.number().describe('Number of CVEs returned in this response.'),
    offset: z.number().describe('Page offset used in this query.'),
    ...dateWindowEnrichment,
    filtersApplied: z
      .object({
        keyword: z.string().optional().describe('The keyword filter that was applied.'),
        exactPhrase: z
          .boolean()
          .optional()
          .describe(
            'Present as true when the keyword was matched as an exact phrase rather than word-by-word.',
          ),
        severity: z
          .string()
          .optional()
          .describe(
            'The exact CVSS severity band that was applied — results are limited to this band alone, ' +
              'so higher bands are not included.',
          ),
        severityVersion: z
          .string()
          .optional()
          .describe(
            'The CVSS version the severity filter matched on. Present only alongside severity.',
          ),
        cweId: z.string().optional().describe('The CWE weakness filter that was applied.'),
        ...dateWindowEcho,
        kevOnly: z
          .boolean()
          .optional()
          .describe('Present as true when results were limited to the CISA KEV catalog.'),
        noRejected: z
          .boolean()
          .optional()
          .describe('Present as false when rejected CVEs were left in the results.'),
      })
      .optional()
      .describe(
        'The non-default filters this query actually applied — the ones that can account for an empty or unexpectedly narrow result set. Absent when the query ran unfiltered, which is itself the answer when a result set is unexpectedly broad.',
      ),
    notice: z
      .string()
      .optional()
      .describe(
        "Ignored blank filters and paging guidance: distinguishes no matches, an exhausted offset, and an inconsistent empty upstream page; on a partial page, names the next offset and, on the first page of a window a shorthand set, the filtersApplied dates to send in its place; past offset 0, flags a shorthand window re-expanded for this call and points to the first page's dates instead.",
      ),
  },

  enrichmentTrailer: {
    notice: { render: (notice) => (notice ? `> ${escapeMarkdownInline(notice)}` : '') },
    returned: { label: 'Returned' },
    offset: { label: 'Offset' },
    datesClamped: { render: renderDatesClamped },
    filtersApplied: { render: renderFiltersApplied },
  },

  errors: [
    {
      reason: 'nvd_invalid_response',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'NVD returned an unusable response.',
      retryable: false,
      thrownBy: 'service',
      recovery: 'Try again later; if the failure persists, report the failing tool call.',
    },
    {
      reason: 'nvd_request_blocked',
      code: JsonRpcErrorCode.Forbidden,
      when: 'The NVD security layer blocked the request.',
      retryable: false,
      thrownBy: 'service',
      recovery: 'Rephrase query text, or try again later or from another network.',
    },
    {
      reason: 'nvd_request_rejected',
      code: JsonRpcErrorCode.ValidationError,
      when: 'NVD rejected a search parameter.',
      retryable: false,
      thrownBy: 'service',
      recovery:
        'Use case-sensitive CWE-<number>, NVD-CWE-Other, or NVD-CWE-noinfo for cweId, and YYYY-MM-DDThh:mm[:ss[.fraction]] with an optional Z or ±hh:mm offset, such as 2024-01-01T00:00:00.000Z, for date fields. Check the rejected parameter named in the message.',
    },
    {
      reason: 'exact_phrase_without_keyword',
      code: JsonRpcErrorCode.ValidationError,
      when: 'exactPhrase was set without a keyword. It selects how keyword matches and has nothing to modify on its own; NVD rejects the underlying flag on the same grounds.',
      recovery:
        'Supply the phrase in keyword alongside exactPhrase, or drop exactPhrase and search on the other filters.',
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
    input = { ...input };
    const ignoredFilters: string[] = [];
    for (const field of [
      'keyword',
      'cweId',
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
    const notices: string[] = [];
    if (ignoredFilters.length > 0) notices.push(`Ignored empty ${ignoredFilters.join(', ')}.`);

    ctx.log.info('Searching CVEs', {
      keyword: input.keyword,
      severity: input.severity,
      kevOnly: input.kevOnly,
      limit: input.limit,
    });

    /**
     * A filter the server accepts and then drops returns a broader result set than the caller
     * asked for, with nothing in the response to say so — reject instead, as every other
     * companion-parameter rule on this surface does.
     */
    if (input.exactPhrase && !input.keyword) {
      throw ctx.fail(
        'exact_phrase_without_keyword',
        'exactPhrase selects how keyword is matched and cannot be used without one.',
      );
    }

    const windows = resolveDateWindows(input, Date.now());

    // Validate severity cross-field constraint: CVSS v2 has no CRITICAL tier.
    if (input.severity === 'CRITICAL' && input.severityVersion === 'v2') {
      throw ctx.fail(
        'invalid_severity_for_version',
        'CVSS v2 has no CRITICAL severity tier. Valid values for severityVersion="v2" are LOW, MEDIUM, HIGH.',
      );
    }

    const service = getNvdCveService();
    const clamped = applyReadLimit(input.limit, 2000, 'nvd_search_cves', ctx);
    if (clamped.notice) notices.push(clamped.notice);
    const result = await service.searchCves(
      {
        ...(input.keyword && { keyword: input.keyword }),
        exactPhrase: input.exactPhrase,
        ...(input.severity && { severityParam: input.severity }),
        severityVersion: input.severityVersion,
        ...(input.cweId && { cweId: input.cweId }),
        ...windows.dates,
        kevOnly: input.kevOnly,
        noRejected: input.noRejected,
        limit: clamped.limit,
        offset: input.offset,
      },
      ctx,
    );

    /**
     * Echo only what the caller actually narrowed by: severityVersion and noRejected carry
     * defaults, so reporting them unconditionally would name filters the caller never chose.
     */
    const filtersApplied = {
      ...(input.keyword && { keyword: input.keyword }),
      ...(input.exactPhrase && { exactPhrase: true }),
      ...(input.severity && { severity: input.severity, severityVersion: input.severityVersion }),
      ...(input.cweId && { cweId: input.cweId }),
      ...windows.dates,
      ...(input.kevOnly && { kevOnly: true }),
      ...(input.noRejected === false && { noRejected: false }),
    };

    ctx.enrich({
      returned: result.returned,
      offset: result.offset,
      ...(windows.datesClamped.length > 0 && { datesClamped: windows.datesClamped }),
      ...(Object.keys(filtersApplied).length > 0 && { filtersApplied }),
    });
    ctx.enrich.total(result.totalResults);
    if (result.cves.length === 0) {
      /**
       * An empty page only proves the offset overran when the offset is at or past totalCount.
       * Inside that range NVD contradicted its own count, and neither "lower the offset" nor
       * "nothing matched" is true — say so rather than sending the caller after a mistake they
       * did not make.
       */
      if (result.totalResults > 0 && input.offset >= result.totalResults) {
        notices.push(
          `Offset ${input.offset} is past the end of the result set (${result.totalResults} total). Use a lower offset to page through results.`,
        );
      } else if (result.totalResults > 0) {
        notices.push(
          `NVD reported ${result.totalResults} match(es) but returned no CVEs at offset ${input.offset}, which is inside that range. Retry the query; the offset is not the problem.`,
        );
      } else {
        notices.push(
          'No CVEs matched the search criteria. Try broadening the keyword or date range.',
        );
      }
    } else if (result.totalResults > result.offset + result.returned) {
      /**
       * Offset is zero-based, so `offset + returned` is the index of the first record this page
       * did not carry — the next page's own offset, not one past it. Naming anything higher skips
       * a record. A shorthand window would move by the next call, so the first page's notice also
       * names the echoed dates that hold it still.
       */
      const replay = windowReplayClause(windows.shorthands, input.offset);
      notices.push(
        `Results truncated — ${result.totalResults} CVEs match; set offset to ${result.offset + result.returned} for the next page${replay ? ` and ${replay}` : ''}.`,
      );
    }
    const reexpanded = windowReexpandedNotice(windows.shorthands, input.offset);
    if (reexpanded) notices.push(reexpanded);

    if (notices.length > 0) ctx.enrich.notice(notices.join(' '));
    return { cves: result.cves };
  },

  format: (result) => {
    const lines: string[] = [];

    if (result.cves.length === 0) {
      return [{ type: 'text', text: 'No CVEs returned.' }];
    }

    for (const cve of result.cves) {
      lines.push(`### ${escapeMarkdownInline(cve.cveId)}`);
      lines.push(
        `**Status:** ${escapeMarkdownInline(cve.vulnStatus)} | **Published:** ${escapeMarkdownInline(cve.published)}`,
      );

      if (cve.severity) {
        lines.push(
          `**Severity:** ${escapeMarkdownInline(cve.severity.label)} (${cve.severity.score}) from CVSS ${escapeMarkdownInline(cve.severity.fromVersion)}`,
        );
      } else {
        lines.push('**Severity:** Not available');
      }

      if (cve.filteredSeverity) {
        lines.push(
          `**Severity at the filtered CVSS version:** ${escapeMarkdownInline(cve.filteredSeverity.label)} (${cve.filteredSeverity.score}) from CVSS ${escapeMarkdownInline(cve.filteredSeverity.fromVersion)} — this is the score the severity filter matched on.`,
        );
      }

      if (cve.cisaVulnerabilityName) {
        lines.push(`**CISA KEV:** ${escapeMarkdownInline(cve.cisaVulnerabilityName)}`);
      }

      if (cve.description) {
        lines.push(escapeMarkdownInline(cve.description));
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
