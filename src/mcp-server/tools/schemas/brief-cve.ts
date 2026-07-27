/**
 * @fileoverview Zod mirror of the `BriefCveRecord` domain shape produced by `toBriefCve()`.
 * Shared by every tool that emits brief rows so one definition describes them all.
 * @module src/mcp-server/tools/schemas/brief-cve
 */

import { z } from '@cyanheads/mcp-ts-core';

export const BriefCveRecordSchema = z.object({
  cveId: z.string().describe('CVE identifier (e.g., "CVE-2021-44228").'),
  vulnStatus: z.string().describe('NVD analysis status.'),
  published: z.string().describe('ISO 8601 publication datetime.'),
  description: z
    .string()
    .optional()
    .describe(
      'Opening 200 characters of the English CVE description, truncated with an ellipsis when longer. ' +
        'Enough to tell one result from another; call nvd_get_cve for the full text. ' +
        'Absent when NVD carries no description for the record.',
    ),
  severity: z
    .object({
      label: z.string().describe('Highest severity label across all CVSS versions.'),
      score: z.number().describe('Highest base score (0.0–10.0).'),
      fromVersion: z.string().describe('CVSS version this score came from.'),
    })
    .optional()
    .describe('Top severity. Absent if no CVSS scores are present.'),
  filteredSeverity: z
    .object({
      label: z.string().describe('Severity label at the CVSS version the severity filter used.'),
      score: z.number().describe('Base score at that CVSS version (0.0–10.0).'),
      fromVersion: z.string().describe('The CVSS version the severity filter matched on.'),
    })
    .optional()
    .describe(
      'Severity at the CVSS version the severity filter matched this CVE on. Present only when a severity filter was supplied and that version disagrees with the cross-version top severity above — e.g. a CVE scored v2 10.0 (HIGH) and v3.1 9.8 (CRITICAL) headlines as HIGH but matched a CRITICAL v3 query on the 9.8.',
    ),
  cisaVulnerabilityName: z
    .string()
    .optional()
    .describe('CISA KEV vulnerability name. Present only when in the KEV catalog.'),
});

/**
 * Brief row without `filteredSeverity`, for surfaces that never apply a severity filter and so can
 * never diverge from the cross-version headline — advertising the field there would name something
 * the tool cannot emit.
 */
export const UnfilteredBriefCveRecordSchema = BriefCveRecordSchema.omit({
  filteredSeverity: true,
});
