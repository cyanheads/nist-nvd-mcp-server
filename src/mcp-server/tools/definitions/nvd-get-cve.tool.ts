/**
 * @fileoverview Tool for fetching one or more CVEs by ID from the NIST NVD API.
 * @module src/mcp-server/tools/definitions/nvd-get-cve
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { BriefCveRecord, CveRecord } from '@/services/nvd-cve/types.js';

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
        'When true, returns trimmed records (ID, status, top CVSS score, KEV name, published date) ' +
          'instead of full detail. Recommended for batches of more than 10 IDs.',
      ),
    includeReferences: z
      .boolean()
      .default(true)
      .describe('When false, omits the references array to reduce response size.'),
  }),

  // Use passthrough to avoid aspirational over-typing of the upstream CVE schema.
  // structuredContent will carry the full typed data; format() renders what matters.
  output: z.object({
    brief: z.boolean().describe('Whether brief or full records were returned.'),
    cves: z
      .array(
        z
          .object({})
          .passthrough()
          .describe(
            'One CVE record. Full mode includes CVSS scores, configurations, weaknesses, and references. ' +
              'Brief mode includes ID, status, top severity, and CISA KEV name.',
          ),
      )
      .describe(
        'CVE records. In full mode: complete records with CVSS scores, configurations, weaknesses, and references. ' +
          'In brief mode: trimmed records with ID, status, top severity, and CISA KEV name.',
      ),
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
      code: JsonRpcErrorCode.ServiceUnavailable,
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
    const result = await service.fetchById(ids, input.includeReferences, ctx);

    ctx.enrich({
      requested: result.requested,
      returned: result.returned,
      ...(result.missingIds.length > 0 && { missingIds: result.missingIds }),
    });

    if (input.brief) {
      return {
        brief: true,
        cves: result.cves.map((cve) => ({
          cveId: cve.cveId,
          vulnStatus: cve.vulnStatus,
          published: cve.published,
          ...(cve.severity && { severity: cve.severity }),
          ...(cve.cisaKev && { cisaVulnerabilityName: cve.cisaKev.vulnerabilityName }),
        })) as Record<string, unknown>[],
      };
    }

    return {
      brief: false,
      cves: result.cves as unknown as Record<string, unknown>[],
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(`**Mode:** ${result.brief ? 'Brief' : 'Full'}\n`);

    for (const rawCve of result.cves) {
      if (result.brief) {
        const cve = rawCve as unknown as BriefCveRecord & { cisaVulnerabilityName?: string };
        lines.push(`## ${cve.cveId}`);
        lines.push(`**Status:** ${cve.vulnStatus} | **Published:** ${cve.published}`);
        if (cve.severity) {
          lines.push(
            `**Severity:** ${cve.severity.label} (${cve.severity.score}) from CVSS ${cve.severity.fromVersion}`,
          );
        } else {
          lines.push('**Severity:** Not available (no CVSS scores)');
        }
        if (cve.cisaVulnerabilityName) {
          lines.push(`**CISA KEV:** ${cve.cisaVulnerabilityName}`);
        }
      } else {
        const cve = rawCve as unknown as CveRecord;
        lines.push(`## ${cve.cveId}`);
        lines.push(
          `**Status:** ${cve.vulnStatus} | **Published:** ${cve.published} | **Last Modified:** ${cve.lastModified}`,
        );

        if (cve.severity) {
          lines.push(
            `**Severity:** ${cve.severity.label} (${cve.severity.score}) from CVSS ${cve.severity.fromVersion}`,
          );
        } else {
          lines.push('**Severity:** Not available (no CVSS scores)');
        }

        if (cve.cvssScores && cve.cvssScores.length > 0) {
          lines.push('\n**CVSS Scores:**');
          for (const s of cve.cvssScores) {
            lines.push(
              `- v${s.version} (${s.sourceType}): ${s.baseScore} ${s.severity}${s.vectorString ? ` — ${s.vectorString}` : ''}`,
            );
          }
        }

        if (cve.descriptions && cve.descriptions.length > 0) {
          const en = cve.descriptions.find((d) => d.lang === 'en');
          if (en) lines.push(`\n${en.value}`);
        }

        if (cve.weaknesses && cve.weaknesses.length > 0) {
          const allCwes = cve.weaknesses.flatMap((w) => w.cweIds).filter(Boolean);
          if (allCwes.length > 0) lines.push(`**Weaknesses:** ${allCwes.join(', ')}`);
        }

        if (cve.configurations && cve.configurations.length > 0) {
          lines.push(`**Configurations:** ${cve.configurations.length} node group(s)`);
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
          for (const ref of cve.references.slice(0, 5)) {
            lines.push(`- ${ref.url}${ref.tags?.length ? ` [${ref.tags.join(', ')}]` : ''}`);
          }
          if (cve.references.length > 5) {
            lines.push(`- … ${cve.references.length - 5} more references`);
          }
        }
      }
      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
