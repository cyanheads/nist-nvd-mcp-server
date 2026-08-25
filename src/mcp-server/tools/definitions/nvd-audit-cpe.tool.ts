/**
 * @fileoverview Tool for finding CVEs affecting a specific product and version by CPE.
 * @module src/mcp-server/tools/definitions/nvd-audit-cpe
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import {
  CPE_MATCH_CAP,
  flattenCpeMatches,
  summarizeCpeNodes,
} from '@/mcp-server/tools/formatting/cpe-match.js';
import { CveRecordSchema } from '@/mcp-server/tools/schemas/full-cve.js';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

const CPE_V23_REGEX = /^cpe:2\.3:/i;

/** References rendered per CVE — this tool returns full records for many CVEs at once. */
const REFERENCE_CAP = 5;

export const nvdAuditCpe = tool('nvd_audit_cpe', {
  title: 'Audit CPE for Vulnerabilities',
  description:
    'Find all CVEs affecting a specific product and version using CPE (Common Platform Enumeration). ' +
    'Requires either an exact CPE name (cpeName) or a partial match string (virtualMatchString) with optional version range bounds. ' +
    'With cpeName, NVD scopes results to configurations where the product is directly vulnerable, not merely referenced as a dependency. ' +
    'Use nvd_search_cpes first to resolve the correct CPE string for a product. ' +
    'Returns full CVE records.',
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
    severityMin: z
      .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
      .optional()
      .describe(
        'Filter out CVEs below this severity level. Applied after NVD returns the page, so it can only drop CVEs within limit — raise limit to widen what it sees.',
      ),
    allLanguages: z
      .boolean()
      .default(false)
      .describe(
        'When true, keeps every localized description NVD supplies on each record. Default keeps English only.',
      ),
    limit: z
      .number()
      .int()
      .min(1)
      .max(2000)
      .default(20)
      .describe('Maximum number of CVEs to return (default 20, max 2000).'),
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
        CveRecordSchema.describe('Full CVE record for one vulnerability affecting the product.'),
      )
      .describe('Full CVE records for CVEs affecting the specified product.'),
  }),

  enrichment: {
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
        'CVEs dropped by the severityMin filter from the page NVD returned. Present whenever severityMin is set; 0 means the filter dropped nothing, so a narrow result reflects totalCount and limit instead. This is not totalCount minus returned — CVEs beyond limit were never fetched and so were never evaluated against the filter.',
      ),
    notice: z
      .string()
      .optional()
      .describe(
        'Guidance on the shape of this page. When no CVEs came back it distinguishes a target NVD holds no CVEs for from a severityMin filter that dropped everything on the page, from an offset past the result set, from an empty page NVD returned inside a range it says has matches. On a partial page it names the offset that reaches the next one.',
      ),
  },

  enrichmentTrailer: {
    returned: { label: 'Returned' },
    offset: { label: 'Offset' },
    auditTarget: { label: 'Audit Target' },
    severityMin: { label: 'Severity Filter' },
    filteredCount: { label: 'Dropped by Severity Filter' },
  },

  errors: [
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
      reason: 'rate_limited',
      code: JsonRpcErrorCode.RateLimited,
      when: 'NVD returned HTTP 403 indicating the rate limit was exceeded.',
      retryable: true,
      recovery:
        'Wait for the NVD rate window to reset or set the NVD_API_KEY environment variable for higher limits.',
    },
  ],

  async handler(input, ctx) {
    // Validate inputs
    if (!input.cpeName && !input.virtualMatchString) {
      throw ctx.fail(
        'missing_cpe_input',
        'Either cpeName or virtualMatchString is required.',
        ctx.recoveryFor('missing_cpe_input'),
      );
    }
    if (input.cpeName && input.virtualMatchString) {
      throw ctx.fail(
        'conflicting_cpe_inputs',
        'Provide only one of cpeName or virtualMatchString, not both.',
        ctx.recoveryFor('conflicting_cpe_inputs'),
      );
    }
    if ((input.versionStart || input.versionEnd) && !input.virtualMatchString) {
      throw ctx.fail(
        'version_range_without_match_string',
        'versionStart/versionEnd require virtualMatchString.',
        ctx.recoveryFor('version_range_without_match_string'),
      );
    }

    if (input.cpeName && !CPE_V23_REGEX.test(input.cpeName)) {
      throw ctx.fail(
        'invalid_cpe_format',
        `Invalid CPE name: "${input.cpeName}". CPEv2.3 names must start with "cpe:2.3:".`,
        ctx.recoveryFor('invalid_cpe_format'),
      );
    }
    if (input.virtualMatchString && !CPE_V23_REGEX.test(input.virtualMatchString)) {
      throw ctx.fail(
        'invalid_cpe_format',
        `Invalid CPE string: "${input.virtualMatchString}". CPEv2.3 strings must start with "cpe:2.3:".`,
        ctx.recoveryFor('invalid_cpe_format'),
      );
    }

    ctx.log.info('Auditing CPE for vulnerabilities', {
      cpeName: input.cpeName,
      virtualMatchString: input.virtualMatchString,
      limit: input.limit,
      offset: input.offset,
    });

    const service = getNvdCveService();
    const result = await service.auditCpe(
      {
        ...(input.cpeName && { cpeName: input.cpeName }),
        ...(input.virtualMatchString && { virtualMatchString: input.virtualMatchString }),
        ...(input.versionStart && { versionStart: input.versionStart }),
        versionStartType: input.versionStartType,
        ...(input.versionEnd && { versionEnd: input.versionEnd }),
        versionEndType: input.versionEndType,
        ...(input.severityMin && { severityMin: input.severityMin }),
        allLanguages: input.allLanguages,
        limit: input.limit,
        offset: input.offset,
      },
      ctx,
    );

    const auditTarget = result.cpeName ?? result.virtualMatchString ?? 'unknown CPE';
    ctx.enrich({
      returned: result.returned,
      offset: result.offset,
      auditTarget,
      ...(input.severityMin && {
        severityMin: input.severityMin,
        filteredCount: result.filteredCount,
      }),
    });
    ctx.enrich.total(result.totalResults);
    if (result.cves.length === 0) {
      /**
       * Four ways a page comes back empty, narrowest first. An offset at or past totalCount means
       * the product has CVEs and this page merely sits past them. filteredCount > 0 means NVD did
       * return CVEs and severityMin cut them. A valid offset inside a non-zero totalCount means
       * NVD contradicted its own count, so neither the offset nor the target is at fault. Only a
       * zero count leaves the CPE string itself unconfirmed, and even then the finding leads —
       * every branch exists to keep the caller from being sent after a mistake they did not make.
       */
      if (result.totalResults > 0 && input.offset >= result.totalResults) {
        ctx.enrich.notice(
          `Offset ${input.offset} is past the end of the result set (${result.totalResults} total). Use a lower offset to page through results.`,
        );
      } else if (input.severityMin && result.filteredCount > 0) {
        ctx.enrich.notice(
          `All ${result.filteredCount} CVE(s) on the fetched page scored below ${input.severityMin}. ` +
            'Lower severityMin or raise limit to widen the page NVD returns.',
        );
      } else if (result.totalResults > 0) {
        ctx.enrich.notice(
          `NVD reported ${result.totalResults} CVE(s) for this audit target but returned none at offset ${input.offset}, which is inside that range. Retry the query; neither the offset nor the audit target is the problem.`,
        );
      } else {
        ctx.enrich.notice(
          'No CVEs in NVD for this audit target — a clean audit, not a failed one. ' +
            'If that is unexpected, confirm the CPE string with nvd_search_cpes: it is the one input this audit cannot verify on its own.',
        );
      }
    } else if (result.totalResults > result.offset + result.returned + result.filteredCount) {
      /**
       * Advance by what NVD's page consumed, not by what survived it: `returned` counts the rows
       * left after the client-side severityMin filter, so paging on `offset + returned` alone
       * would re-serve every row that filter dropped. `returned + filteredCount` is the span NVD
       * actually spent index positions on, and collapses to `returned` when no filter is set.
       */
      const consumed = result.returned + result.filteredCount;
      ctx.enrich.notice(
        `Results truncated — ${result.totalResults} CVEs match this audit target; set offset to ${result.offset + consumed} for the next page.`,
      );
    }

    return { cves: result.cves };
  },

  format: (result) => {
    const lines: string[] = [];

    if (result.cves.length === 0) {
      return [{ type: 'text', text: 'No CVEs returned for this product.' }];
    }

    for (const cve of result.cves) {
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
        lines.push('**CVSS Scores:**');
        for (const s of cve.cvssScores) {
          lines.push(
            `  - v${s.version} (${s.sourceType}): ${s.baseScore} ${s.severity}` +
              (s.vectorString ? ` — ${s.vectorString}` : ''),
          );
        }
      }

      if (cve.weaknesses && cve.weaknesses.length > 0) {
        lines.push('**Weaknesses:**');
        for (const w of cve.weaknesses) {
          if (w.cweIds.length > 0) {
            lines.push(`  - ${w.source}: ${w.cweIds.join(', ')}`);
          }
        }
      }

      // Descriptions — render lang and value for all entries to satisfy format-parity
      for (const desc of cve.descriptions) {
        const truncated = desc.value.length > 300 ? `${desc.value.slice(0, 300)}…` : desc.value;
        lines.push(`\n[${desc.lang}] ${truncated}`);
      }

      if (cve.cisaKev) {
        lines.push(`\n**CISA KEV:** ${cve.cisaKev.vulnerabilityName}`);
        lines.push(`  - Added: ${cve.cisaKev.exploitAddDate}`);
        lines.push(`  - Action Due: ${cve.cisaKev.actionDueDate}`);
        lines.push(`  - Required Action: ${cve.cisaKev.requiredAction}`);
      }

      if (cve.configurationNodes && cve.configurationNodes.length > 0) {
        const matches = flattenCpeMatches(cve.configurationNodes);
        lines.push(`**Configurations:** ${summarizeCpeNodes(cve.configurationNodes)}`);
        for (const match of matches.slice(0, CPE_MATCH_CAP)) lines.push(`  - ${match}`);
        if (matches.length > CPE_MATCH_CAP) {
          lines.push(`  - … ${matches.length - CPE_MATCH_CAP} more`);
        }
      }

      if (cve.references && cve.references.length > 0) {
        lines.push(`**References (${cve.references.length}):**`);
        for (const ref of cve.references.slice(0, REFERENCE_CAP)) {
          const sourcePart = ref.source ? ` [${ref.source}]` : '';
          const tagPart = ref.tags?.length ? ` (${ref.tags.join(', ')})` : '';
          lines.push(`  - ${ref.url}${sourcePart}${tagPart}`);
        }
        if (cve.references.length > REFERENCE_CAP) {
          lines.push(`  - … ${cve.references.length - REFERENCE_CAP} more`);
        }
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
