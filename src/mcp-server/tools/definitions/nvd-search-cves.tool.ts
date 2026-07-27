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

export const nvdSearchCves = tool('nvd_search_cves', {
  title: 'Search CVEs',
  description:
    'Search CVEs by keyword, severity, CWE, date range, or CISA KEV status. ' +
    'The primary discovery tool for vulnerability surveillance and triage workflows. ' +
    'pubDays and lastModDays are convenience shorthands that expand to date pairs; values over 120 days are clamped to the NVD maximum and reported in the response enrichment. ' +
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
      .describe(
        'Filter to CVEs in exactly this CVSS severity band — NVD matches the one band, not a floor. ' +
          'Covering several bands (e.g. HIGH and CRITICAL) takes one call per band.',
      ),
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
  }),

  enrichment: {
    totalCount: z.number().describe('Total matching CVEs in NVD before pagination.'),
    returned: z.number().describe('Number of CVEs returned in this response.'),
    offset: z.number().describe('Page offset used in this query.'),
    datesClamped: z
      .array(
        z
          .object({
            param: z.string().describe('The parameter that was clamped (pubDays or lastModDays).'),
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
    filtersApplied: z
      .object({
        keyword: z.string().optional().describe('The keyword filter that was applied.'),
        severity: z
          .string()
          .optional()
          .describe(
            'The exact CVSS severity band that was applied — results are limited to this band alone, ' +
              'so higher bands are not included.',
          ),
        severityVersion: z
          .string()
          .optional()
          .describe(
            'The CVSS version the severity filter matched on. Present only alongside severity.',
          ),
        cweId: z.string().optional().describe('The CWE weakness filter that was applied.'),
        kevOnly: z
          .boolean()
          .optional()
          .describe('Present as true when results were limited to the CISA KEV catalog.'),
        noRejected: z
          .boolean()
          .optional()
          .describe('Present as false when rejected CVEs were left in the results.'),
      })
      .optional()
      .describe(
        'The non-default filters this query actually applied — the ones that can account for an empty or unexpectedly narrow result set. Absent when the query ran unfiltered, which is itself the answer when a result set is unexpectedly broad.',
      ),
    notice: z
      .string()
      .optional()
      .describe('Guidance when no CVEs matched or the page offset is past the result set.'),
  },

  enrichmentTrailer: {
    returned: { label: 'Returned' },
    offset: { label: 'Offset' },
    datesClamped: {
      render: (clamped) =>
        clamped
          ?.map(
            (c) =>
              `> **Note:** ${c.param} value ${c.original} exceeded the 120-day maximum and was clamped to ${c.clamped}.`,
          )
          .join('\n') ?? '',
    },
    filtersApplied: {
      render: (filters) =>
        filters
          ? `**Filters applied:** ${Object.entries(filters)
              .map(([key, value]) => `${key}=${value}`)
              .join(', ')}`
          : '',
    },
  },

  errors: [
    {
      reason: 'mutually_exclusive_params',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Both pubDays and pubStartDate/pubEndDate provided, or both lastModDays and lastModStartDate/lastModEndDate.',
      recovery:
        'Use either the convenience shorthand (pubDays) or the explicit date range (pubStartDate + pubEndDate), not both.',
    },
    {
      reason: 'missing_date_pair',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Only one of pubStartDate/pubEndDate (or lastModStartDate/lastModEndDate) was provided — NVD requires both.',
      recovery:
        'Provide both the start and end date, or use pubDays/lastModDays instead of an explicit date range.',
    },
    {
      reason: 'date_range_inverted',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The end date is before the start date.',
      recovery: 'Ensure the end date is after the start date.',
    },
    {
      reason: 'date_range_exceeds_max',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Explicit pubStartDate/pubEndDate or lastModStartDate/lastModEndDate span more than 120 days.',
      recovery: 'Narrow the date range to 120 days or fewer, or use multiple paginated queries.',
    },
    {
      reason: 'invalid_date_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'A date string provided for pubStartDate, pubEndDate, lastModStartDate, or lastModEndDate is not a valid ISO 8601 datetime.',
      recovery: 'Use ISO 8601 format, e.g. 2024-01-01T00:00:00.000Z.',
    },
    {
      reason: 'invalid_severity_for_version',
      code: JsonRpcErrorCode.ValidationError,
      when: 'severity="CRITICAL" was specified with severityVersion="v2" — CVSS v2 has no CRITICAL tier.',
      recovery: 'Use LOW, MEDIUM, or HIGH when severityVersion is "v2". Use v3 or v4 for CRITICAL.',
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

    /**
     * Echo only what the caller actually narrowed by: severityVersion and noRejected carry
     * defaults, so reporting them unconditionally would name filters the caller never chose.
     */
    const filtersApplied = {
      ...(input.keyword && { keyword: input.keyword }),
      ...(input.severity && { severity: input.severity, severityVersion: input.severityVersion }),
      ...(input.cweId && { cweId: input.cweId }),
      ...(input.kevOnly && { kevOnly: true }),
      ...(input.noRejected === false && { noRejected: false }),
    };

    ctx.enrich({
      returned: result.returned,
      offset: result.offset,
      ...(datesClamped.length > 0 && { datesClamped }),
      ...(Object.keys(filtersApplied).length > 0 && { filtersApplied }),
    });
    ctx.enrich.total(result.totalResults);
    if (result.cves.length === 0) {
      if (result.totalResults > 0) {
        ctx.enrich.notice(
          `Offset ${result.offset} is past the end of the result set (${result.totalResults} total). Use a lower offset to page through results.`,
        );
      } else {
        ctx.enrich.notice(
          'No CVEs matched the search criteria. Try broadening the keyword or date range.',
        );
      }
    }

    return { cves: result.cves };
  },

  format: (result) => {
    const lines: string[] = [];

    if (result.cves.length === 0) {
      return [{ type: 'text', text: 'No CVEs returned.' }];
    }

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

      if (cve.filteredSeverity) {
        lines.push(
          `**Severity at the filtered CVSS version:** ${cve.filteredSeverity.label} (${cve.filteredSeverity.score}) from CVSS ${cve.filteredSeverity.fromVersion} — this is the score the severity filter matched on.`,
        );
      }

      if (cve.cisaVulnerabilityName) {
        lines.push(`**CISA KEV:** ${cve.cisaVulnerabilityName}`);
      }

      if (cve.description) {
        lines.push(cve.description);
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
