/**
 * @fileoverview Tool for finding CVEs affecting a specific product and version by CPE.
 * @module src/mcp-server/tools/definitions/nvd-audit-cpe
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

const CPE_V23_REGEX = /^cpe:2\.3:/i;

const CvssScoreSchema = z.object({
  version: z.string().describe('CVSS version (e.g., "2.0", "3.1", "4.0").'),
  sourceType: z.string().describe('Score source: "Primary" = NVD, "Secondary" = CNA.'),
  baseScore: z.number().describe('Base score (0.0–10.0).'),
  severity: z.string().describe('Severity label: CRITICAL, HIGH, MEDIUM, or LOW.'),
  vectorString: z.string().optional().describe('CVSS vector string.'),
});

const TopSeveritySchema = z.object({
  label: z.string().describe('Highest severity label across all CVSS versions.'),
  score: z.number().describe('Highest base score (0.0–10.0).'),
  fromVersion: z.string().describe('Which CVSS version this top score came from.'),
});

const CveRecordSchema = z.object({
  cveId: z.string().describe('CVE identifier (e.g., "CVE-2021-44228").'),
  vulnStatus: z.string().describe('NVD analysis status.'),
  published: z.string().describe('ISO 8601 publication datetime.'),
  lastModified: z.string().describe('ISO 8601 last-modified datetime.'),
  descriptions: z
    .array(
      z
        .object({
          lang: z.string().describe('Language code.'),
          value: z.string().describe('CVE description.'),
        })
        .describe('One localized CVE description.'),
    )
    .describe('CVE descriptions by language.'),
  cvssScores: z
    .array(CvssScoreSchema.describe('One CVSS score entry.'))
    .describe('All available CVSS scores across versions.'),
  severity: TopSeveritySchema.optional().describe(
    'Top severity. Absent if no CVSS scores present.',
  ),
  weaknesses: z
    .array(
      z
        .object({
          source: z.string().describe('Weakness source (NVD or CNA).'),
          cweIds: z
            .array(z.string().describe('One CWE identifier.'))
            .describe('CWE identifiers for this source.'),
        })
        .describe('One weakness classification entry.'),
    )
    .describe('CWE weakness classifications.'),
  configurations: z
    .array(
      z
        .object({
          nodes: z
            .array(
              z
                .object({
                  operator: z.string().optional().describe('Logical operator (AND/OR).'),
                  cpeMatch: z
                    .array(
                      z
                        .object({
                          vulnerable: z
                            .boolean()
                            .describe('Whether this CPE is the vulnerable component.'),
                          criteria: z.string().describe('CPEv2.3 match criteria string.'),
                          versionStartIncluding: z
                            .string()
                            .optional()
                            .describe('Inclusive lower version bound.'),
                          versionStartExcluding: z
                            .string()
                            .optional()
                            .describe('Exclusive lower version bound.'),
                          versionEndIncluding: z
                            .string()
                            .optional()
                            .describe('Inclusive upper version bound.'),
                          versionEndExcluding: z
                            .string()
                            .optional()
                            .describe('Exclusive upper version bound.'),
                        })
                        .describe('One CPE match criterion.'),
                    )
                    .describe('CPE match criteria for this node.'),
                })
                .describe('One configuration node with its CPE match criteria.'),
            )
            .describe('Configuration nodes.'),
        })
        .describe('One affected product configuration group.'),
    )
    .describe('Affected product configurations.'),
  references: z
    .array(
      z
        .object({
          url: z.string().describe('Reference URL.'),
          source: z.string().optional().describe('Reference source.'),
          tags: z
            .array(z.string().describe('One classification tag.'))
            .optional()
            .describe('Classification tags.'),
        })
        .describe('One external reference.'),
    )
    .optional()
    .describe('External references.'),
  cisaKev: z
    .object({
      exploitAddDate: z.string().describe('Date added to CISA KEV catalog.'),
      actionDueDate: z.string().describe('Federal agency remediation deadline.'),
      requiredAction: z.string().describe('Required remediation steps.'),
      vulnerabilityName: z.string().describe("CISA's vulnerability name."),
    })
    .optional()
    .describe('CISA KEV fields. Present only when CVE is in the KEV catalog.'),
});

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
      .describe('Filter out CVEs below this severity level.'),
    limit: z
      .number()
      .int()
      .min(1)
      .max(2000)
      .default(20)
      .describe('Maximum number of CVEs to return (default 20, max 2000).'),
  }),

  output: z.object({
    cves: z
      .array(
        CveRecordSchema.describe('Full CVE record for one vulnerability affecting the product.'),
      )
      .describe('Full CVE records for CVEs affecting the specified product.'),
  }),

  enrichment: {
    totalResults: z.number().describe('Total CVEs matched before pagination.'),
    returned: z.number().describe('Number of CVE records returned.'),
    auditTarget: z.string().describe('The CPE name or virtual match string used for this audit.'),
    notice: z
      .string()
      .optional()
      .describe('Guidance when no CVEs were found — suggests verifying the CPE name.'),
  },

  enrichmentTrailer: {
    totalResults: { label: 'Total CVEs' },
    returned: { label: 'Returned' },
    auditTarget: { label: 'Audit Target' },
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
      when: 'cpeName or virtualMatchString does not start with "cpe:2.3:" — not a valid CPEv2.3 string.',
      recovery:
        'Provide a valid CPEv2.3 string starting with "cpe:2.3:". Use nvd_search_cpes to find the correct CPE name.',
    },
    {
      reason: 'cpe_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'NVD itself returned zero results (totalResults === 0) for the given cpeName — the CPE is likely misspelled or absent from NVD.',
      recovery:
        'Use nvd_search_cpes to verify the exact CPE name exists in the NVD dictionary before auditing.',
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
        limit: input.limit,
      },
      ctx,
    );

    const auditTarget = result.cpeName ?? result.virtualMatchString ?? 'unknown CPE';
    ctx.enrich({
      totalResults: result.totalResults,
      returned: result.returned,
      auditTarget,
    });
    if (result.cves.length === 0) {
      ctx.enrich.notice(
        'No CVEs found for this product. Verify the CPE name with nvd_search_cpes.',
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

      if (cve.configurations && cve.configurations.length > 0) {
        lines.push(`**Configurations:** ${cve.configurations.length} node group(s)`);
        for (const cfg of cve.configurations) {
          for (const node of cfg.nodes) {
            if (node.operator) lines.push(`  - Operator: ${node.operator}`);
          }
        }
      }

      if (cve.references && cve.references.length > 0) {
        lines.push(`**References (${cve.references.length}):**`);
        for (const ref of cve.references.slice(0, 5)) {
          const sourcePart = ref.source ? ` [${ref.source}]` : '';
          const tagPart = ref.tags?.length ? ` (${ref.tags.join(', ')})` : '';
          lines.push(`  - ${ref.url}${sourcePart}${tagPart}`);
        }
        if (cve.references.length > 5) lines.push(`  - … ${cve.references.length - 5} more`);
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
