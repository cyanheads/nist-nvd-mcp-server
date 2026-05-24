/**
 * @fileoverview Tool for searching CVEs by keyword, severity, CWE, date range, or KEV status.
 * @module mcp-server/tools/definitions/nvd-search-cves
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

const MAX_DATE_RANGE_DAYS = 120;

/** Parse a date string and return a Date, or throw a descriptive error. */
function parseDate(dateStr: string, fieldName: string): Date {
  const d = new Date(dateStr);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`Invalid date for ${fieldName}: "${dateStr}". Expected ISO 8601 format.`);
  }
  return d;
}

/** Returns the date N days ago from now as ISO 8601 string. */
function daysAgo(days: number): string {
  const d = new Date();
  d.setDate(d.getDate() - days);
  return d.toISOString().replace(/\.\d{3}Z$/, '000 UTC+00:00');
}

/** Returns now as ISO 8601 string. */
function nowIso(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, '000 UTC+00:00');
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
    'pubDays and lastModDays are convenience shorthands — the tool converts them to API date pairs ' +
    'and clamps values over 120 days (the NVD API maximum), reporting the clamped range in queryMeta. ' +
    'Search results are always brief; call nvd_get_cve for full detail on specific IDs. ' +
    'At least one filter is recommended — omitting all filters returns the most recently modified CVEs.',
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
      reason: 'date_range_exceeds_max',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Explicit pubStartDate/pubEndDate or lastModStartDate/lastModEndDate span more than 120 days.',
      recovery: 'Narrow the date range to 120 days or fewer, or use multiple paginated queries.',
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
        {
          ...ctx.recoveryFor('mutually_exclusive_params'),
        },
      );
    }
    if (input.lastModDays !== undefined && (input.lastModStartDate || input.lastModEndDate)) {
      throw ctx.fail(
        'mutually_exclusive_params',
        'lastModDays and lastModStartDate/lastModEndDate are mutually exclusive.',
        {
          ...ctx.recoveryFor('mutually_exclusive_params'),
        },
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

    // Validate explicit date range spans — skip when dates came from convenience params
    // (those are always within the max range after clamping).
    if (!pubDatesFromConvenience && pubStartDate && pubEndDate) {
      const start = parseDate(pubStartDate, 'pubStartDate');
      const end = parseDate(pubEndDate, 'pubEndDate');
      const days = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24);
      if (days > MAX_DATE_RANGE_DAYS) {
        throw ctx.fail(
          'date_range_exceeds_max',
          `Publication date range spans ${Math.ceil(days)} days; maximum is 120.`,
          {
            ...ctx.recoveryFor('date_range_exceeds_max'),
          },
        );
      }
    }

    if (!lastModDatesFromConvenience && lastModStartDate && lastModEndDate) {
      const start = parseDate(lastModStartDate, 'lastModStartDate');
      const end = parseDate(lastModEndDate, 'lastModEndDate');
      const days = (end.getTime() - start.getTime()) / (1000 * 60 * 60 * 24);
      if (days > MAX_DATE_RANGE_DAYS) {
        throw ctx.fail(
          'date_range_exceeds_max',
          `Last-modified date range spans ${Math.ceil(days)} days; maximum is 120.`,
          {
            ...ctx.recoveryFor('date_range_exceeds_max'),
          },
        );
      }
    }

    const service = getNvdCveService();
    const searchParams: Parameters<typeof service.searchCves>[0] = {
      severityVersion: input.severityVersion,
      kevOnly: input.kevOnly,
      noRejected: input.noRejected,
      limit: input.limit,
      offset: input.offset,
    };
    if (input.keyword) searchParams.keyword = input.keyword;
    if (input.severity) searchParams.severityParam = input.severity;
    if (input.cweId) searchParams.cweId = input.cweId;
    if (pubStartDate) searchParams.pubStartDate = pubStartDate;
    if (pubEndDate) searchParams.pubEndDate = pubEndDate;
    if (lastModStartDate) searchParams.lastModStartDate = lastModStartDate;
    if (lastModEndDate) searchParams.lastModEndDate = lastModEndDate;
    const result = await service.searchCves(searchParams, ctx);

    return {
      cves: result.cves.map((cve) => ({
        cveId: cve.cveId,
        vulnStatus: cve.vulnStatus,
        published: cve.published,
        ...(cve.severity ? { severity: cve.severity } : {}),
        ...(cve.cisaVulnerabilityName ? { cisaVulnerabilityName: cve.cisaVulnerabilityName } : {}),
      })),
      queryMeta: {
        totalResults: result.totalResults,
        returned: result.returned,
        offset: result.offset,
        ...(datesClamped.length > 0 ? { datesClamped } : {}),
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
      lines.push(
        '\nNo CVEs matched the search criteria. Try broadening the keyword or date range.',
      );
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
