/**
 * @fileoverview Zod mirror of the `CveRecord` domain shape produced by `normalizeCve()`.
 * Shared by every tool that emits full CVE records so one definition describes them all —
 * the full-record counterpart to `brief-cve.ts`.
 *
 * Optionality here is load-bearing, not cosmetic: the framework parses every success return
 * against the declared output schema, so a field is required only when the normalizer assigns
 * it unconditionally. `descriptions`, `cvssScores`, `weaknesses`, and `configurations` always
 * default to `[]`; `references`, `severity`, and `cisaKev` are spread-gated upstream and stay
 * optional.
 * @module src/mcp-server/tools/schemas/full-cve
 */

import { z } from '@cyanheads/mcp-ts-core';

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

const CpeMatchSchema = z.object({
  vulnerable: z
    .boolean()
    .describe('Whether this CPE is the vulnerable component or only the context it runs in.'),
  criteria: z.string().describe('CPEv2.3 match criteria string.'),
  versionStartIncluding: z.string().optional().describe('Inclusive lower version bound.'),
  versionStartExcluding: z.string().optional().describe('Exclusive lower version bound.'),
  versionEndIncluding: z.string().optional().describe('Inclusive upper version bound.'),
  versionEndExcluding: z.string().optional().describe('Exclusive upper version bound.'),
});

export const CveRecordSchema = z.object({
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
          operator: z
            .string()
            .optional()
            .describe(
              'Logical operator (AND/OR) combining this group\'s sibling nodes. An "AND" means every node must match for the CVE to apply — e.g. a firmware node and the hardware it runs on. Absent when the group has nothing to combine.',
            ),
          nodes: z
            .array(
              z
                .object({
                  operator: z
                    .string()
                    .optional()
                    .describe("Logical operator (AND/OR) combining this node's own CPE matches."),
                  cpeMatch: z
                    .array(CpeMatchSchema.describe('One CPE match criterion.'))
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

/**
 * Full-record fields a surface cannot promise on every row — `nvd_get_cve` returns brief rows
 * under `brief: true`, which carry none of them. Declaring them required there would fail the
 * framework's output parse on every brief call.
 */
export const CONDITIONAL_FULL_CVE_FIELDS = {
  lastModified: true,
  descriptions: true,
  cvssScores: true,
  weaknesses: true,
  configurations: true,
} as const;
