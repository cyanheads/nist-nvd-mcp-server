/**
 * @fileoverview Zod mirror of the `CveRecord` domain shape produced by `normalizeCve()`.
 * Shared by every tool that emits full CVE records so one definition describes them all —
 * the full-record counterpart to `brief-cve.ts`.
 *
 * Optionality here is load-bearing, not cosmetic: the framework parses every success return
 * against the declared output schema, so a field is required only when the normalizer assigns
 * it unconditionally. `descriptions`, `cvssScores`, `weaknesses`, `configurationNodes`, and
 * `affectedProducts` always default to `[]`; `references`, `severity`, `cisaKev`,
 * `sourceIdentifier`, and `cveTags` are spread-gated upstream and stay optional.
 * @module src/mcp-server/tools/schemas/full-cve
 */

import { z } from '@cyanheads/mcp-ts-core';

const CvssScoreSchema = z.object({
  version: z.string().describe('CVSS version (e.g., "2.0", "3.1", "4.0").'),
  sourceType: z
    .string()
    .describe(
      'NVD\'s label for this score, "Primary" or "Secondary". It does not say who scored it — a CNA\'s score can be Primary and an ADP\'s Secondary; source names the scorer.',
    ),
  baseScore: z.number().describe('Base score (0.0–10.0).'),
  severity: z.string().describe('Severity label: CRITICAL, HIGH, MEDIUM, or LOW.'),
  vectorString: z.string().optional().describe('CVSS vector string.'),
  source: z
    .string()
    .optional()
    .describe(
      'Who supplied the score, as the contributor name NVD publishes for it (e.g. "CISA-ADP"). Contributors NVD identifies by email address keep that address (e.g. "nvd@nist.gov"); an identifier absent from NVD\'s contributor dictionary passes through as its raw value. Absent when NVD names no source.',
    ),
});

const AffectedProductSchema = z.object({
  source: z
    .string()
    .optional()
    .describe(
      'Who made this statement — the CNA or an ADP — as the contributor name NVD publishes for it (e.g. "CISA-ADP"). Contributors NVD identifies by email address keep that address (e.g. "security@apache.org"); an identifier absent from NVD\'s contributor dictionary passes through as its raw value.',
    ),
  vendor: z.string().optional().describe('Vendor, project, or maintainer of the product.'),
  product: z.string().optional().describe('Product name.'),
  collectionURL: z
    .string()
    .optional()
    .describe('Package collection that gives packageName its meaning (e.g. a registry URL).'),
  packageName: z.string().optional().describe('Package name within collectionURL.'),
  packageURL: z.string().optional().describe('Package URL (purl) for the package.'),
  repo: z.string().optional().describe('Source code repository URL.'),
  defaultStatus: z
    .string()
    .optional()
    .describe(
      'Status of every version the versions list does not cover: affected, unaffected, or unknown. Absent when the contributor stated none, which the CVE schema reads as unknown.',
    ),
  cpes: z
    .array(z.string().describe('One CPE name.'))
    .optional()
    .describe('CPE names the contributor attached to this product.'),
  modules: z
    .array(z.string().describe('One module or component.'))
    .optional()
    .describe('Affected modules, components, or features.'),
  programFiles: z
    .array(z.string().describe('One source file path.'))
    .optional()
    .describe('Affected source code files.'),
  programRoutines: z
    .array(
      z
        .object({ name: z.string().describe('Function, method, or routine name.') })
        .describe('One affected routine.'),
    )
    .optional()
    .describe('Affected functions, methods, or routines.'),
  platforms: z
    .array(z.string().describe('One platform.'))
    .optional()
    .describe('Platforms the statement is limited to. Absent means every relevant platform.'),
  versions: z
    .array(
      z
        .object({
          version: z
            .string()
            .optional()
            .describe('A single version, or the inclusive lower bound of a range.'),
          status: z
            .string()
            .optional()
            .describe('Status of this version or range: affected, unaffected, or unknown.'),
          versionType: z
            .string()
            .optional()
            .describe(
              'Version scheme a range is compared under (e.g. "semver", "git", "custom"). Absent on a single version.',
            ),
          lessThan: z.string().optional().describe('Exclusive upper bound of the range.'),
          lessThanOrEqual: z.string().optional().describe('Inclusive upper bound of the range.'),
        })
        .describe('One version or version range.'),
    )
    .optional()
    .describe(
      'Versions and ranges with their status, in the order the contributor listed them. A range can change status partway through; versionChanges carries those points.',
    ),
  versionChanges: z
    .array(
      z
        .object({
          versionIndex: z
            .number()
            .describe('Zero-based index of the versions entry whose range this change is inside.'),
          at: z.string().describe('Version at which the status changes.'),
          status: z
            .string()
            .describe('Status from this version on, until the next change or the range end.'),
        })
        .describe('One status change inside a version range.'),
    )
    .optional()
    .describe(
      'Status changes inside version ranges, moved out of their range so each stays addressable; versionIndex names the range. Within one range, sort by version under its versionType before applying them.',
    ),
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
  ssvc: z
    .array(
      z
        .object({
          source: z.string().describe('Contributor name or original source identifier.'),
          role: z.string().describe('Assessment role.'),
          version: z.string().describe('SSVC decision-tree version.'),
          timestamp: z.string().optional().describe('Assessment timestamp when provided.'),
          decisionPoints: z
            .array(
              z
                .record(
                  z.string().describe('Decision-point name.'),
                  z
                    .union([
                      z.string().describe('Decision-point value.'),
                      z
                        .array(z.string().describe('One decision-point value.'))
                        .describe('Decision-point values.'),
                    ])
                    .describe('One string or ordered list of strings.'),
                )
                .describe('Decision-point names and values.'),
            )
            .describe('Ordered option objects; repeated keys remain separate.'),
        })
        .describe('One current SSVC assessment.'),
    )
    .optional()
    .describe('Current SSVC assessments in upstream order.'),
  weaknesses: z
    .array(
      z
        .object({
          source: z
            .string()
            .describe(
              'Who classified the weakness, as the contributor name NVD publishes for it (e.g. "CVE", "CISA-ADP"). Contributors NVD identifies by email address keep that address (e.g. "nvd@nist.gov"); an identifier absent from NVD\'s contributor dictionary passes through as its raw value.',
            ),
          cweIds: z
            .array(z.string().describe('One CWE identifier.'))
            .describe('CWE identifiers for this source.'),
        })
        .describe('One weakness classification entry.'),
    )
    .describe('CWE weakness classifications.'),
  configurationNodes: z
    .array(
      z
        .object({
          groupIndex: z
            .number()
            .describe(
              'Zero-based index of the NVD configuration group this node belongs to. Nodes sharing a groupIndex were siblings in one group, combined by groupOperator.',
            ),
          groupOperator: z
            .string()
            .optional()
            .describe(
              'Logical operator (AND/OR) combining this node with its sibling nodes in the same group. An "AND" means every node in the group must match for the CVE to apply — e.g. a firmware node and the hardware it runs on. Absent when the group has nothing to combine.',
            ),
          nodeOperator: z
            .string()
            .optional()
            .describe(
              "Logical operator (AND/OR) combining this node's own criteria below. Absent when the node has nothing to combine.",
            ),
          cpeMatch: z
            .array(CpeMatchSchema.describe('One CPE match criterion.'))
            .describe("This node's CPE match criteria, in the order NVD lists them."),
        })
        .describe('One affected product configuration node, tagged with the group it came from.'),
    )
    .describe(
      "Affected product configuration nodes. NVD nests these under configuration groups; the groups are represented by groupIndex so each node's own criteria stay together.",
    ),
  references: z
    .array(
      z
        .object({
          url: z.string().describe('Reference URL.'),
          source: z
            .string()
            .optional()
            .describe(
              'Who contributed the reference, as the contributor name NVD publishes for it (e.g. "CVE", "CISA-ADP"). Contributors NVD identifies by email address keep that address (e.g. "security@apache.org"); an identifier absent from NVD\'s contributor dictionary passes through as its raw value.',
            ),
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
  sourceIdentifier: z
    .string()
    .optional()
    .describe(
      'The contributor NVD lists as the record\'s source — the CNA that submitted it — as the contributor name NVD publishes for it (e.g. "CPANSec"). Contributors NVD identifies by email address keep that address (e.g. "cve@mitre.org"); an identifier absent from NVD\'s contributor dictionary passes through as its raw value.',
    ),
  cveTags: z
    .array(
      z
        .object({
          source: z
            .string()
            .optional()
            .describe(
              'Who attached the tags, as the contributor name NVD publishes for it; email-form identifiers keep their address.',
            ),
          tags: z
            .array(z.string().describe('One tag.'))
            .describe(
              'Tags: "disputed", "unsupported-when-assigned", or "exclusively-hosted-service".',
            ),
        })
        .describe("One contributor's tags."),
    )
    .optional()
    .describe('Tags contributors attached to the CVE. Absent when none did.'),
  affectedProducts: z
    .array(AffectedProductSchema.describe('One product statement.'))
    .describe(
      'Affected products as the CNA and any ADP state them, one entry per product — their own statement, not NVD analysis, and often the only product and version evidence on a record NVD has not analyzed. Read versions with versionChanges and defaultStatus. Empty when no contributor sent any.',
    ),
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
  configurationNodes: true,
  affectedProducts: true,
} as const;
