/**
 * @fileoverview Tool for fetching one or more CVEs by ID from the NIST NVD API.
 * @module src/mcp-server/tools/definitions/nvd-get-cve
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { CPE_MATCH_CAP, flattenCpeMatches } from '@/mcp-server/tools/formatting/cpe-match.js';
import { UnfilteredBriefCveRecordSchema } from '@/mcp-server/tools/schemas/brief-cve.js';
import {
  CONDITIONAL_FULL_CVE_FIELDS,
  CveRecordSchema,
} from '@/mcp-server/tools/schemas/full-cve.js';
import { getNvdCveService, toBriefCve } from '@/services/nvd-cve/nvd-cve-service.js';

/**
 * References rendered per CVE. A dense record runs to ~100 references at roughly 140 bytes a line
 * once the URL, its contributing source, and its tags are on it (CVE-2021-44228 carries 103,
 * ~14.4KB rendered in full). 15 covers the advisory/patch/exploit cluster a triage decision turns
 * on for ~2.3KB per record, and the trailer discloses the remainder that `structuredContent`
 * still carries in full.
 */
export const REFERENCE_CAP = 15;

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

export const nvdGetCve = tool('nvd_get_cve', {
  title: 'Get CVE Details',
  description:
    'Fetch one or more CVEs by ID from the NIST National Vulnerability Database. ' +
    'Returns CVSS scores across all available versions (v2.0, v3.0, v3.1, v4.0), CWE weakness classifications, ' +
    'affected CPE configurations, CISA KEV fields, and references. ' +
    'Up to 100 CVE IDs per call. For bulk lookups of more than 10 IDs, use brief: true — ' +
    'full records for 100 CVEs can exceed 1MB and exhaust context budgets.',
  annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },

  input: z.object({
    cveIds: z
      .union([
        z.string().describe('A single CVE ID (e.g., "CVE-2021-44228").'),
        z
          .array(z.string())
          .min(1)
          .max(100)
          .describe('An array of CVE IDs — at least 1, up to 100 per call.'),
      ])
      .describe('One CVE ID or an array of up to 100 CVE IDs to fetch.'),
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
    requested: z.number().describe('Number of CVE IDs requested.'),
    returned: z.number().describe('Number of CVE records returned.'),
    missingIds: z
      .array(z.string().describe('A CVE ID not found in NVD.'))
      .optional()
      .describe('CVE IDs requested but not found in NVD. Absent when all IDs matched.'),
  },

  enrichmentTrailer: {
    requested: { label: 'Requested' },
    returned: { label: 'Returned' },
    missingIds: {
      render: (ids) => `**Not found in NVD:** ${ids?.join(', ')}`,
    },
  },

  errors: [
    {
      reason: 'invalid_cve_id_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'One or more CVE IDs fail format validation (NVD returns HTTP 404 for malformed IDs).',
      recovery: 'Use the format CVE-YYYY-NNNNN (e.g., CVE-2021-44228) and verify each ID.',
    },
    {
      reason: 'cve_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'A valid-format CVE ID returns no results — the ID is well-formed but does not exist in NVD.',
      recovery: 'Verify the CVE ID is correct; use nvd_search_cves to search by keyword or date.',
    },
    {
      reason: 'rate_limited',
      code: JsonRpcErrorCode.RateLimited,
      when: 'NVD returned HTTP 403 indicating the rate limit was exceeded.',
      retryable: true,
      recovery:
        'Wait for the NVD rate window to reset or set the NVD_API_KEY environment variable for higher limits.',
    },
  ],

  async handler(input, ctx) {
    const ids = Array.isArray(input.cveIds) ? input.cveIds : [input.cveIds];
    ctx.log.info('Fetching CVEs', { count: ids.length, brief: input.brief });

    const service = getNvdCveService();
    const result = await service.fetchById(
      ids,
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

    return { brief: false, cves: result.cves };
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
      lines.push(`## ${cve.cveId}`);
      lines.push(
        `**Status:** ${cve.vulnStatus} | **Published:** ${cve.published}` +
          (cve.lastModified ? ` | **Last Modified:** ${cve.lastModified}` : ''),
      );

      if (cve.severity) {
        lines.push(
          `**Severity:** ${cve.severity.label} (${cve.severity.score}) from CVSS ${cve.severity.fromVersion}`,
        );
      } else {
        lines.push('**Severity:** Not available (no CVSS scores)');
      }

      // The brief row's KEV name, in place of the full block below. Sits with the rest of the
      // row's metadata rather than after its prose — a KEV listing is the line a triage read
      // scans for, and trailing the description would fold it into that paragraph.
      if (cve.cisaVulnerabilityName) lines.push(`**CISA KEV:** ${cve.cisaVulnerabilityName}`);

      if (cve.cvssScores && cve.cvssScores.length > 0) {
        lines.push('\n**CVSS Scores:**');
        for (const s of cve.cvssScores) {
          lines.push(
            `- v${s.version} (${s.sourceType}): ${s.baseScore} ${s.severity}${s.vectorString ? ` — ${s.vectorString}` : ''}`,
          );
        }
      }

      // The brief row's single truncated snippet, in place of the per-language array below.
      if (cve.description) lines.push(`\n${cve.description}`);

      /**
       * Render every description the record carries. The service already applied the language
       * policy — English-only by default (falling back when a record has no English entry),
       * every language when `allLanguages` is set — so picking one here would make that input
       * inert for clients that read `content[]` instead of `structuredContent`.
       */
      for (const desc of cve.descriptions ?? []) {
        lines.push(`\n[${desc.lang}] ${desc.value}`);
      }

      if (cve.weaknesses && cve.weaknesses.length > 0) {
        lines.push('**Weaknesses:**');
        for (const w of cve.weaknesses) {
          if (w.cweIds.length > 0) lines.push(`- ${w.source}: ${w.cweIds.join(', ')}`);
        }
      }

      if (cve.configurations && cve.configurations.length > 0) {
        const matches = flattenCpeMatches(cve.configurations);
        lines.push(
          `**Configurations:** ${cve.configurations.length} node group(s), ${matches.length} CPE match(es)`,
        );
        for (const match of matches.slice(0, CPE_MATCH_CAP)) lines.push(`  - ${match}`);
        if (matches.length > CPE_MATCH_CAP) {
          lines.push(
            `  - … ${matches.length - CPE_MATCH_CAP} more — call nvd_audit_cpe with a specific cpeName to test whether a product version is affected.`,
          );
        }
      }

      if (cve.cisaKev) {
        lines.push(`\n**CISA KEV Details:**`);
        lines.push(`- Name: ${cve.cisaKev.vulnerabilityName}`);
        lines.push(`- Added: ${cve.cisaKev.exploitAddDate}`);
        lines.push(`- Action Due: ${cve.cisaKev.actionDueDate}`);
        lines.push(`- Required Action: ${cve.cisaKev.requiredAction}`);
      }

      if (cve.references && cve.references.length > 0) {
        lines.push(`\n**References (${cve.references.length}):**`);
        for (const ref of cve.references.slice(0, REFERENCE_CAP)) {
          const source = ref.source ? ` [${ref.source}]` : '';
          const tags = ref.tags?.length ? ` (${ref.tags.join(', ')})` : '';
          lines.push(`- ${ref.url}${source}${tags}`);
        }
        if (cve.references.length > REFERENCE_CAP) {
          lines.push(`- … ${cve.references.length - REFERENCE_CAP} more references`);
        }
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
