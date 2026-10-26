/**
 * @fileoverview Tool for fetching one or more CVEs by ID from the NIST NVD API.
 * @module src/mcp-server/tools/definitions/nvd-get-cve
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { escapeMarkdownInline, markdownLink } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';
import { flattenCpeMatches, summarizeCpeNodes } from '@/mcp-server/tools/formatting/cpe-match.js';
import { formatSsvc } from '@/mcp-server/tools/formatting/ssvc.js';
import { applyReadLimit, readLimitEnrichment } from '@/mcp-server/tools/read-limit.js';
import { UnfilteredBriefCveRecordSchema } from '@/mcp-server/tools/schemas/brief-cve.js';
import {
  CONDITIONAL_FULL_CVE_FIELDS,
  CveRecordSchema,
} from '@/mcp-server/tools/schemas/full-cve.js';
import { getNvdCveService, toBriefCve } from '@/services/nvd-cve/nvd-cve-service.js';
import { validateCveId } from '@/services/nvd-cve/validate-cve-id.js';

/**
 * One item schema spanning both modes. `brief` is an input flag, not an output discriminator the
 * schema can branch on — a tool's `output` must be a flat object — so every field either mode adds
 * beyond the three both always carry is declared optional. Optional is not cosmetic here: the
 * framework parses each success return against this schema, and a full-record field marked
 * required would reject every `brief: true` call.
 */
const CveItemSchema = CveRecordSchema.partial(CONDITIONAL_FULL_CVE_FIELDS)
  .extend(
    UnfilteredBriefCveRecordSchema.pick({ description: true, cisaVulnerabilityName: true }).shape,
  )
  .loose();

const CveIdsSchema = z.array(z.string().describe('One CVE ID.')).min(1);

export const nvdGetCve = tool('nvd_get_cve', {
  title: 'Get CVE Details',
  description:
    'Fetch one or more CVEs by ID from the NIST National Vulnerability Database. ' +
    'Returns CVSS scores across all available versions (v2.0, v3.0, v3.1, v4.0), CWE weakness classifications, ' +
    'affected CPE configurations, CISA KEV fields, current SSVC assessments, and references. ' +
    'Up to 100 CVE IDs per call. For bulk lookups of more than 10 IDs, use brief: true — ' +
    'full records for 100 CVEs can exceed 1MB and exhaust context budgets.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    cveIds: z
      .union([
        z.string().describe('A single CVE ID (e.g., "CVE-2021-44228").'),
        (getServerConfig().clampLimits ? CveIdsSchema : CveIdsSchema.max(100)).describe(
          'An array of CVE IDs — at least 1. The first 100 are processed; excess IDs are reported unless NVD_CLAMP_LIMITS is false, which rejects them.',
        ),
      ])
      .describe('One CVE ID or an array of CVE IDs; at most 100 are fetched per call.'),
    brief: z
      .boolean()
      .default(false)
      .describe(
        'When true, returns trimmed records (ID, status, top CVSS score, KEV name, published date, ' +
          'and a truncated description) instead of full detail. Recommended for batches of more than 10 IDs.',
      ),
    includeReferences: z
      .boolean()
      .default(true)
      .describe('When false, omits the references array to reduce response size.'),
    includeConfigurations: z
      .boolean()
      .default(true)
      .describe('When false, omits configurationNodes from full records and their rendered text.'),
    allLanguages: z
      .boolean()
      .default(false)
      .describe(
        'When true, keeps every localized description NVD supplies on each record, and full records ' +
          'render all of them. Default keeps English only, falling back to whatever exists if a record ' +
          'has no English entry. Brief records always carry a single truncated description.',
      ),
  }),

  output: z.object({
    brief: z.boolean().describe('Whether brief or full records were returned.'),
    cves: z
      .array(
        CveItemSchema.describe(
          'One CVE record. Every field beyond cveId, vulnStatus, and published depends on the mode: ' +
            'full mode (the default) carries all of them except description and cisaVulnerabilityName, ' +
            'which are the brief-mode substitutes for descriptions and cisaKev.',
        ),
      )
      .describe('CVE records — full detail by default, trimmed rows when brief is true.'),
  }),

  enrichment: {
    ...readLimitEnrichment,
    requested: z.number().describe('Number of CVE IDs processed in this call.'),
    returned: z.number().describe('Number of CVE records returned.'),
    missingIds: z
      .array(z.string().describe('A CVE ID not found in NVD.'))
      .optional()
      .describe('CVE IDs requested but not found in NVD. Absent when all IDs matched.'),
    unprocessedIds: z
      .array(z.string().describe('Normalized CVE ID not attempted.'))
      .optional()
      .describe(
        'IDs beyond the processed prefix, deduplicated in request order and excluding IDs already attempted.',
      ),
    notice: z.string().optional().describe('Explains when the requested ID count was clamped.'),
  },

  enrichmentTrailer: {
    requested: { label: 'Requested' },
    returned: { label: 'Returned' },
    missingIds: {
      render: (ids) => `**Not found in NVD:** ${ids?.map(escapeMarkdownInline).join(', ')}`,
    },
    unprocessedIds: {
      render: (ids) => `**Not attempted:** ${ids?.map(escapeMarkdownInline).join(', ')}`,
    },
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
      reason: 'invalid_cve_id_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'One or more CVE IDs fail format validation (NVD returns HTTP 404 for malformed IDs).',
      /** Raised by the CVE service during ID validation, below this handler. */
      thrownBy: 'service',
      recovery: 'Use the format CVE-YYYY-NNNNN (e.g., CVE-2021-44228) and verify each ID.',
    },
    {
      reason: 'cve_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'A valid-format CVE ID returns no results — the ID is well-formed but does not exist in NVD.',
      /** Raised by the CVE service when NVD returns no records, below this handler. */
      thrownBy: 'service',
      recovery: 'Verify the CVE ID is correct; use nvd_search_cves to search by keyword or date.',
    },
    {
      reason: 'rate_limited',
      code: JsonRpcErrorCode.RateLimited,
      when: 'NVD explicitly reported that the rate limit was exceeded.',
      retryable: true,
      /** Raised by the HTTP client on NVD's 403, below this handler. */
      thrownBy: 'service',
      recovery:
        'Wait for the NVD rate window to reset or set the NVD_API_KEY environment variable for higher limits.',
    },
  ],

  async handler(input, ctx) {
    const ids = (Array.isArray(input.cveIds) ? input.cveIds : [input.cveIds]).map(validateCveId);
    const clamped = applyReadLimit(ids.length, 100, 'nvd_get_cve', ctx);
    const selectedIds = ids.slice(0, clamped.limit);
    if (clamped.notice) {
      const attempted = new Set(selectedIds);
      const unprocessedIds = [
        ...new Set(ids.slice(clamped.limit).filter((id) => !attempted.has(id))),
      ];
      ctx.enrich({ unprocessedIds });
      ctx.enrich.notice(clamped.notice);
    }
    ctx.log.info('Fetching CVEs', { count: ids.length, brief: input.brief });

    const service = getNvdCveService();
    const result = await service.fetchById(
      selectedIds,
      {
        includeReferences: input.includeReferences,
        allLanguages: input.allLanguages,
        // Brief rows carry no `source` field, so resolving contributor names for them emits nothing.
        resolveSources: !input.brief,
      },
      ctx,
    );

    ctx.enrich({
      requested: result.requested,
      returned: result.returned,
      ...(result.missingIds.length > 0 && { missingIds: result.missingIds }),
    });

    if (input.brief) {
      /**
       * No severity filter exists on this tool, so `toBriefCve` is called without a filter version
       * and the rows never carry `filteredSeverity` — matching the schema declared above.
       */
      return { brief: true, cves: result.cves.map((cve) => toBriefCve(cve)) };
    }

    const cves = input.includeConfigurations
      ? result.cves
      : result.cves.map(({ configurationNodes: _configurationNodes, ...cve }) => cve);
    return { brief: false, cves };
  },

  /**
   * One pass over both modes, testing each field for presence rather than branching on `brief`:
   * the flag describes the call, and the record itself says which fields it carries. A
   * mode-branched formatter would also leave the other branch's fields unrendered for any
   * consumer that walks the declared schema rather than a live response.
   */
  format: (result) => {
    const lines: string[] = [];
    lines.push(`**Mode:** ${result.brief ? 'Brief' : 'Full'}\n`);

    for (const cve of result.cves) {
      lines.push(`## ${escapeMarkdownInline(cve.cveId)}`);
      lines.push(
        `**Status:** ${escapeMarkdownInline(cve.vulnStatus)} | **Published:** ${escapeMarkdownInline(cve.published)}` +
          (cve.lastModified
            ? ` | **Last Modified:** ${escapeMarkdownInline(cve.lastModified)}`
            : ''),
      );

      if (cve.severity) {
        lines.push(
          `**Severity:** ${escapeMarkdownInline(cve.severity.label)} (${cve.severity.score}) from CVSS ${escapeMarkdownInline(cve.severity.fromVersion)}`,
        );
      } else {
        lines.push('**Severity:** Not available (no CVSS scores)');
      }

      // The brief row's KEV name, in place of the full block below. Sits with the rest of the
      // row's metadata rather than after its prose — a KEV listing is the line a triage read
      // scans for, and trailing the description would fold it into that paragraph.
      if (cve.cisaVulnerabilityName)
        lines.push(`**CISA KEV:** ${escapeMarkdownInline(cve.cisaVulnerabilityName)}`);

      if (cve.cvssScores && cve.cvssScores.length > 0) {
        lines.push('\n**CVSS Scores:**');
        for (const s of cve.cvssScores) {
          lines.push(
            `- v${escapeMarkdownInline(s.version)} (${escapeMarkdownInline(s.sourceType)}): ${s.baseScore} ${escapeMarkdownInline(s.severity)}${s.vectorString ? ` — ${escapeMarkdownInline(s.vectorString)}` : ''}`,
          );
        }
      }

      // The brief row's single truncated snippet, in place of the per-language array below.
      if (cve.ssvc) lines.push(...formatSsvc(cve.ssvc));

      if (cve.description) lines.push(`\n${escapeMarkdownInline(cve.description)}`);

      /**
       * Render every description the record carries. The service already applied the language
       * policy — English-only by default (falling back when a record has no English entry),
       * every language when `allLanguages` is set — so picking one here would make that input
       * inert for clients that read `content[]` instead of `structuredContent`.
       */
      for (const desc of cve.descriptions ?? []) {
        lines.push(`\n[${escapeMarkdownInline(desc.lang)}] ${escapeMarkdownInline(desc.value)}`);
      }

      if (cve.weaknesses && cve.weaknesses.length > 0) {
        lines.push('**Weaknesses:**');
        for (const w of cve.weaknesses) {
          if (w.cweIds.length > 0)
            lines.push(
              `- ${escapeMarkdownInline(w.source)}: ${w.cweIds.map(escapeMarkdownInline).join(', ')}`,
            );
        }
      }

      if (cve.configurationNodes && cve.configurationNodes.length > 0) {
        const matches = flattenCpeMatches(cve.configurationNodes);
        lines.push(`**Configurations:** ${summarizeCpeNodes(cve.configurationNodes)}`);
        for (const match of matches) lines.push(`  - ${match}`);
      }

      if (cve.cisaKev) {
        lines.push(`\n**CISA KEV Details:**`);
        lines.push(`- Name: ${escapeMarkdownInline(cve.cisaKev.vulnerabilityName)}`);
        lines.push(`- Added: ${escapeMarkdownInline(cve.cisaKev.exploitAddDate)}`);
        lines.push(`- Action Due: ${escapeMarkdownInline(cve.cisaKev.actionDueDate)}`);
        lines.push(`- Required Action: ${escapeMarkdownInline(cve.cisaKev.requiredAction)}`);
      }

      if (cve.references && cve.references.length > 0) {
        lines.push(`\n**References (${cve.references.length}):**`);
        for (const ref of cve.references) {
          const source = ref.source ? ` [${escapeMarkdownInline(ref.source)}]` : '';
          const tags = ref.tags?.length
            ? ` (${ref.tags.map(escapeMarkdownInline).join(', ')})`
            : '';
          lines.push(`- ${markdownLink(ref.url, ref.url)}${source}${tags}`);
        }
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
