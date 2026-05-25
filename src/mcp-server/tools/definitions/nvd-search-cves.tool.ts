/**
 * @fileoverview Tool for searching CVEs by keyword, severity, CWE, date range, or KEV status.
 * @module src/mcp-server/tools/definitions/nvd-search-cves
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

const MAX_DATE_RANGE_DAYS = 120;

/** Returns the date N days ago from now as ISO 8601 string (milliseconds zeroed, UTC). */
function daysAgo(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

/** Returns the current datetime as ISO 8601 string (milliseconds zeroed, UTC). */
function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

const BriefCveRecordSchema = z.object({
  cveId: z.string().describe('CVE identifier (e.g., "CVE-2021-44228").'),
  vulnStatus: z.string().describe('NVD analysis status.'),
  published: z.string().describe('ISO 8601 publication datetime.'),
  severity: z
    .object({
      label: z.string().describe('Highest severity label across all CVSS versions.'),
      score: z.number().describe('Highest base score (0.0–10.0).'),
      fromVersion: z.string().describe('CVSS version this score came from.'),
    })
    .optional()
    .describe('Top severity. Absent if no CVSS scores are present.'),
  cisaVulnerabilityName: z
    .string()
    .optional()
    .describe('CISA KEV vulnerability name. Present only when in the KEV catalog.'),
});

export const nvdSearchCves = tool('nvd_search_cves', {
  title: 'Search CVEs',
  description:
    'Search CVEs by keyword, severity, CWE, date range, or CISA KEV status. ' +
    'The primary discovery tool for vulnerability surveillance and triage workflows. ' +
    'pubDays and lastModDays are convenience shorthands that expand to date pairs; values over 120 days are clamped to the NVD maximum and reported in queryMeta. ' +
    'Returns brief summaries — call nvd_get_cve for full detail on specific IDs. ' +
    'At least one filter is recommended; omitting all filters returns CVEs in default NVD index order (oldest first by CVE ID).',
  annotations: { readOnlyHint: true, openWorldHint: false },

  input: z.object({
    keyword: z
      .string()
      .optional()
      .describe('Full-text search across CVE descriptions (AND-semantics across words).'),
    severity: z
      .enum(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
      .optional()
      .describe('Filter to CVEs at this CVSS severity level or above.'),
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
    pubDays: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        'CVEs published in the last N days (max 120; values over 120 are clamped). ' +
          'Mutually exclusive with pubStartDate/pubEndDate.',
      ),
    lastModDays: z
      .number()
      .int()
      .positive()
      .optional()
      .describe(
        'CVEs last modified in the last N days (max 120; values over 120 are clamped). ' +
          'Mutually exclusive with lastModStartDate/lastModEndDate.',
      ),
    pubStartDate: z
      .string()
      .optional()
      .describe(
        'ISO 8601 datetime for publication range start. Both pubStartDate and pubEndDate required together. ' +
          'Mutually exclusive with pubDays.',
      ),
    pubEndDate: z
      .string()
      .optional()
      .describe(
        'ISO 8601 datetime for publication range end. Both pubStartDate and pubEndDate required together.',
      ),
    lastModStartDate: z
      .string()
      .optional()
      .describe(
        'ISO 8601 datetime for last-modified range start. Both required together. Mutually exclusive with lastModDays.',
      ),
    lastModEndDate: z
      .string()
      .optional()
      .describe('ISO 8601 datetime for last-modified range end. Both required together.'),
    kevOnly: z
      .boolean()
      .default(false)
      .describe(
        'When true, filters results to CVEs in the CISA Known Exploited Vulnerabilities catalog.',
      ),
    noRejected: z
      .boolean()
      .default(true)
      .describe('When true (default), excludes CVEs with REJECT/Rejected status.'),
    limit: z
      .number()
      .int()
      .min(1)
      .max(2000)
      .default(20)
      .describe('Maximum number of results to return (default 20, max 2000).'),
    offset: z.number().int().min(0).default(0).describe('Zero-based page offset for pagination.'),
  }),

  output: z.object({
    cves: z
      .array(BriefCveRecordSchema.describe('Brief summary for one matching CVE.'))
      .describe('Matching CVE summaries. Call nvd_get_cve for full detail on specific IDs.'),
    queryMeta: z
      .object({
        totalResults: z.number().describe('Total matching CVEs in NVD before pagination.'),
        returned: z.number().describe('Number of CVEs returned in this response.'),
        offset: z.number().describe('Page offset used in this query.'),
        datesClamped: z
          .array(
            z
              .object({
                param: z
                  .string()
                  .describe('The parameter that was clamped (pubDays or lastModDays).'),
                original: z.number().describe('The original value supplied.'),
                clamped: z.number().describe('The clamped value used (max 120).'),
              })
              .describe('A single clamping event for one convenience date parameter.'),
          )
          .optional()
          .describe(
            'Entries for any pubDays/lastModDays values that exceeded 120 and were auto-clamped. ' +
              'Absent when no clamping occurred.',
          ),
      })
      .describe('Query execution metadata including total count and any date clamping applied.'),
  }),

  errors: [
    {
      reason: 'mutually_exclusive_params',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Both pubDays and pubStartDate/pubEndDate provided, or both lastModDays and lastModStartDate/lastModEndDate.',
      recovery:
        'Use either the convenience shorthand (pubDays) or the explicit date range (pubStartDate + pubEndDate), not both.',
    },
    {
      reason: 'missing_date_pair',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Only one of pubStartDate/pubEndDate (or lastModStartDate/lastModEndDate) was provided — NVD requires both.',
      recovery:
        'Provide both the start and end date, or use pubDays/lastModDays instead of an explicit date range.',
    },
    {
      reason: 'date_range_inverted',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'The end date is before the start date.',
      recovery: 'Ensure the end date is after the start date.',
    },
    {
      reason: 'date_range_exceeds_max',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Explicit pubStartDate/pubEndDate or lastModStartDate/lastModEndDate span more than 120 days.',
      recovery: 'Narrow the date range to 120 days or fewer, or use multiple paginated queries.',
    },
    {
      reason: 'invalid_date_format',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'A date string provided for pubStartDate, pubEndDate, lastModStartDate, or lastModEndDate is not a valid ISO 8601 datetime.',
      recovery: 'Use ISO 8601 format, e.g. 2024-01-01T00:00:00.000Z.',
    },
    {
      reason: 'invalid_severity_for_version',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'severity="CRITICAL" was specified with severityVersion="v2" — CVSS v2 has no CRITICAL tier.',
      recovery: 'Use LOW, MEDIUM, or HIGH when severityVersion is "v2". Use v3 or v4 for CRITICAL.',
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
    ctx.log.info('Searching CVEs', {
      keyword: input.keyword,
      severity: input.severity,
      kevOnly: input.kevOnly,
      limit: input.limit,
    });

    // Validate mutual exclusivity
    if (input.pubDays !== undefined && (input.pubStartDate || input.pubEndDate)) {
      throw ctx.fail(
        'mutually_exclusive_params',
        'pubDays and pubStartDate/pubEndDate are mutually exclusive.',
        ctx.recoveryFor('mutually_exclusive_params'),
      );
    }
    if (input.lastModDays !== undefined && (input.lastModStartDate || input.lastModEndDate)) {
      throw ctx.fail(
        'mutually_exclusive_params',
        'lastModDays and lastModStartDate/lastModEndDate are mutually exclusive.',
        {
          recovery: {
            hint: 'Use either the convenience shorthand (lastModDays) or the explicit date range (lastModStartDate + lastModEndDate), not both.',
          },
        },
      );
    }

    // Validate co-requirement: start and end must be provided together.
    if (input.pubStartDate && !input.pubEndDate) {
      throw ctx.fail(
        'missing_date_pair',
        'pubStartDate requires pubEndDate.',
        ctx.recoveryFor('missing_date_pair'),
      );
    }
    if (input.pubEndDate && !input.pubStartDate) {
      throw ctx.fail(
        'missing_date_pair',
        'pubEndDate requires pubStartDate.',
        ctx.recoveryFor('missing_date_pair'),
      );
    }
    if (input.lastModStartDate && !input.lastModEndDate) {
      throw ctx.fail(
        'missing_date_pair',
        'lastModStartDate requires lastModEndDate.',
        ctx.recoveryFor('missing_date_pair'),
      );
    }
    if (input.lastModEndDate && !input.lastModStartDate) {
      throw ctx.fail(
        'missing_date_pair',
        'lastModEndDate requires lastModStartDate.',
        ctx.recoveryFor('missing_date_pair'),
      );
    }

    const datesClamped: Array<{ param: string; original: number; clamped: number }> = [];
    let pubStartDate: string | undefined = input.pubStartDate;
    let pubEndDate: string | undefined = input.pubEndDate;
    let lastModStartDate: string | undefined = input.lastModStartDate;
    let lastModEndDate: string | undefined = input.lastModEndDate;
    // Track whether dates came from convenience params — those are always within range.
    let pubDatesFromConvenience = false;
    let lastModDatesFromConvenience = false;

    // Expand pubDays convenience param
    if (input.pubDays !== undefined) {
      let days = input.pubDays;
      if (days > MAX_DATE_RANGE_DAYS) {
        datesClamped.push({ param: 'pubDays', original: days, clamped: MAX_DATE_RANGE_DAYS });
        days = MAX_DATE_RANGE_DAYS;
      }
      pubStartDate = daysAgo(days);
      pubEndDate = nowIso();
      pubDatesFromConvenience = true;
    }

    // Expand lastModDays convenience param
    if (input.lastModDays !== undefined) {
      let days = input.lastModDays;
      if (days > MAX_DATE_RANGE_DAYS) {
        datesClamped.push({ param: 'lastModDays', original: days, clamped: MAX_DATE_RANGE_DAYS });
        days = MAX_DATE_RANGE_DAYS;
      }
      lastModStartDate = daysAgo(days);
      lastModEndDate = nowIso();
      lastModDatesFromConvenience = true;
    }

    // Validate severity cross-field constraint: CVSS v2 has no CRITICAL tier.
    if (input.severity === 'CRITICAL' && input.severityVersion === 'v2') {
      throw ctx.fail(
        'invalid_severity_for_version',
        'CVSS v2 has no CRITICAL severity tier. Valid values for severityVersion="v2" are LOW, MEDIUM, HIGH.',
        ctx.recoveryFor('invalid_severity_for_version'),
      );
    }

    // Validate explicit date range spans — skip when dates came from convenience params
    // (those are always within the max range after clamping).
    if (!pubDatesFromConvenience && pubStartDate && pubEndDate) {
      const start = new Date(pubStartDate);
      const end = new Date(pubEndDate);
      if (Number.isNaN(start.getTime())) {
        throw ctx.fail(
          'invalid_date_format',
          `Invalid date for pubStartDate: "${pubStartDate}". Expected ISO 8601 format.`,
          ctx.recoveryFor('invalid_date_format'),
        );
      }
      if (Number.isNaN(end.getTime())) {
        throw ctx.fail(
          'invalid_date_format',
          `Invalid date for pubEndDate: "${pubEndDate}". Expected ISO 8601 format.`,
          ctx.recoveryFor('invalid_date_format'),
        );
      }
      const days = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24);
      if (days < 0) {
        throw ctx.fail(
          'date_range_inverted',
          'pubEndDate is before pubStartDate — the date range is inverted.',
          ctx.recoveryFor('date_range_inverted'),
        );
      }
      if (days > MAX_DATE_RANGE_DAYS) {
        throw ctx.fail(
          'date_range_exceeds_max',
          `Publication date range spans ${Math.ceil(days)} days; maximum is 120.`,
          ctx.recoveryFor('date_range_exceeds_max'),
        );
      }
    }

    if (!lastModDatesFromConvenience && lastModStartDate && lastModEndDate) {
      const start = new Date(lastModStartDate);
      const end = new Date(lastModEndDate);
      if (Number.isNaN(start.getTime())) {
        throw ctx.fail(
          'invalid_date_format',
          `Invalid date for lastModStartDate: "${lastModStartDate}". Expected ISO 8601 format.`,
          ctx.recoveryFor('invalid_date_format'),
        );
      }
      if (Number.isNaN(end.getTime())) {
        throw ctx.fail(
          'invalid_date_format',
          `Invalid date for lastModEndDate: "${lastModEndDate}". Expected ISO 8601 format.`,
          ctx.recoveryFor('invalid_date_format'),
        );
      }
      const days = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24);
      if (days < 0) {
        throw ctx.fail(
          'date_range_inverted',
          'lastModEndDate is before lastModStartDate — the date range is inverted.',
          ctx.recoveryFor('date_range_inverted'),
        );
      }
      if (days > MAX_DATE_RANGE_DAYS) {
        throw ctx.fail(
          'date_range_exceeds_max',
          `Last-modified date range spans ${Math.ceil(days)} days; maximum is 120.`,
          ctx.recoveryFor('date_range_exceeds_max'),
        );
      }
    }

    const service = getNvdCveService();
    const result = await service.searchCves(
      {
        ...(input.keyword && { keyword: input.keyword }),
        ...(input.severity && { severityParam: input.severity }),
        severityVersion: input.severityVersion,
        ...(input.cweId && { cweId: input.cweId }),
        ...(pubStartDate && { pubStartDate }),
        ...(pubEndDate && { pubEndDate }),
        ...(lastModStartDate && { lastModStartDate }),
        ...(lastModEndDate && { lastModEndDate }),
        kevOnly: input.kevOnly,
        noRejected: input.noRejected,
        limit: input.limit,
        offset: input.offset,
      },
      ctx,
    );

    return {
      cves: result.cves,
      queryMeta: {
        totalResults: result.totalResults,
        returned: result.returned,
        offset: result.offset,
        ...(datesClamped.length > 0 && { datesClamped }),
      },
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(
      `**Total:** ${result.queryMeta.totalResults} matching CVEs | ` +
        `**Showing:** ${result.queryMeta.returned} (offset ${result.queryMeta.offset})`,
    );

    if (result.queryMeta.datesClamped && result.queryMeta.datesClamped.length > 0) {
      for (const c of result.queryMeta.datesClamped) {
        lines.push(
          `> **Note:** ${c.param} value ${c.original} exceeded the 120-day maximum and was clamped to ${c.clamped}.`,
        );
      }
    }

    if (result.cves.length === 0) {
      if (result.queryMeta.totalResults > 0) {
        lines.push(
          `\nOffset ${result.queryMeta.offset} is past the end of the result set ` +
            `(${result.queryMeta.totalResults} total). Use a lower offset to page through results.`,
        );
      } else {
        lines.push(
          '\nNo CVEs matched the search criteria. Try broadening the keyword or date range.',
        );
      }
      return [{ type: 'text', text: lines.join('\n') }];
    }

    lines.push('');

    for (const cve of result.cves) {
      lines.push(`### ${cve.cveId}`);
      lines.push(`**Status:** ${cve.vulnStatus} | **Published:** ${cve.published}`);

      if (cve.severity) {
        lines.push(
          `**Severity:** ${cve.severity.label} (${cve.severity.score}) from CVSS ${cve.severity.fromVersion}`,
        );
      } else {
        lines.push('**Severity:** Not available');
      }

      if (cve.cisaVulnerabilityName) {
        lines.push(`**CISA KEV:** ${cve.cisaVulnerabilityName}`);
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
