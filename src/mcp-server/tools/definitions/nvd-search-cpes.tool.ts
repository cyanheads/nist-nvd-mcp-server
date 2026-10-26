/**
 * @fileoverview Tool for searching the NVD CPE dictionary by keyword or match string.
 * @module src/mcp-server/tools/definitions/nvd-search-cpes
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';
import {
  applyReadLimit,
  readLimitEnrichment,
  readLimitSchema,
} from '@/mcp-server/tools/read-limit.js';
import { getNvdCpeService } from '@/services/nvd-cpe/nvd-cpe-service.js';

const CPE_PREFIX_REGEX = /^cpe:2\.3:/i;

export const nvdSearchCpes = tool('nvd_search_cpes', {
  title: 'Search CPE Dictionary',
  description:
    'Search the NVD CPE (Common Platform Enumeration) dictionary by product keyword or partial match string. ' +
    'Returns CPE names, human-readable titles, and deprecation status. ' +
    'Use before nvd_audit_cpe to resolve the correct CPE name for a product — CPE strings are precise identifiers ' +
    '(e.g., cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*) and must match exactly to audit the right product.',
  annotations: { readOnlyHint: true, openWorldHint: false },

  input: z.object({
    keyword: z
      .string()
      .optional()
      .describe(
        'Product name or vendor keyword (e.g., "apache http server", "openssl", "nginx"). ' +
          'At least one of keyword or cpeMatchString is required.',
      ),
    cpeMatchString: z
      .string()
      .optional()
      .describe(
        'Partial CPEv2.3 pattern (e.g., "cpe:2.3:a:apache:http_server"). ' +
          'At least one of keyword or cpeMatchString is required.',
      ),
    limit: readLimitSchema(10000, 20).describe(
      'Maximum number of CPE entries to return (default 20; values above 10000 are clamped unless NVD_CLAMP_LIMITS is false).',
    ),
    offset: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe(
        'Zero-based page offset for pagination. When totalCount exceeds offset + returned, ' +
          'raise offset to reach the rest — a vendor-level keyword has nothing left to narrow toward.',
      ),
  }),

  output: z.object({
    cpes: z
      .array(
        z
          .object({
            cpeName: z
              .string()
              .describe('Full CPEv2.3 name (use this as the cpeName in nvd_audit_cpe).'),
            title: z
              .string()
              .optional()
              .describe('Human-readable product title. Absent when NVD has no English title.'),
            deprecated: z
              .boolean()
              .describe('Whether this CPE has been deprecated in the NVD dictionary.'),
            deprecatedBy: z
              .array(z.string().describe('Superseding CPE name.'))
              .optional()
              .describe('CPE names that supersede this deprecated entry.'),
            lastModified: z
              .string()
              .optional()
              .describe('ISO 8601 datetime when this CPE was last modified.'),
          })
          .describe('One CPE dictionary entry.'),
      )
      .describe('Matching CPE dictionary entries.'),
  }),

  enrichment: {
    ...readLimitEnrichment,
    totalCount: z.number().describe('Total matching CPE entries before the limit was applied.'),
    returned: z.number().describe('Number of entries returned in this response.'),
    offset: z.number().describe('Page offset used in this query.'),
    notice: z
      .string()
      .optional()
      .describe(
        'Guidance when no CPEs matched, the offset ran past the result set, NVD returned an empty page inside a range it says has matches, or entries remain beyond this page.',
      ),
  },

  enrichmentTrailer: {
    returned: { label: 'Returned' },
    offset: { label: 'Offset' },
  },

  errors: [
    {
      reason: 'nvd_invalid_response',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'NVD returned an unusable response.',
      retryable: false,
      thrownBy: 'service',
      recovery: 'Try again later; if the failure persists, report the failing tool call.',
    },
    {
      reason: 'nvd_request_blocked',
      code: JsonRpcErrorCode.Forbidden,
      when: 'The NVD security layer blocked the request.',
      retryable: false,
      thrownBy: 'service',
      recovery: 'Rephrase query text, or try again later or from another network.',
    },
    {
      reason: 'missing_search_input',
      code: JsonRpcErrorCode.ValidationError,
      when: 'Neither keyword nor cpeMatchString was provided.',
      recovery:
        'Provide at least one of keyword (e.g., "apache http server") or cpeMatchString (partial CPEv2.3 pattern).',
    },
    {
      reason: 'invalid_cpe_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The cpeMatchString does not start with "cpe:2.3:", or NVD rejected it as a malformed CPE parameter. A merely truncated prefix is a legitimate partial match and returns an empty page instead.',
      recovery:
        'Provide a valid CPEv2.3 string starting with "cpe:2.3:", or use keyword search to find the correct CPE name.',
    },
    {
      reason: 'rate_limited',
      code: JsonRpcErrorCode.RateLimited,
      when: 'NVD explicitly reported that the rate limit was exceeded.',
      retryable: true,
      /** Raised by the HTTP client on NVD's 403, below this handler. */
      thrownBy: 'service',
      recovery:
        'Wait for the NVD rate window to reset or set the NVD_API_KEY environment variable for higher limits.',
    },
  ],

  async handler(input, ctx) {
    if (!input.keyword && !input.cpeMatchString) {
      throw ctx.fail(
        'missing_search_input',
        'At least one of keyword or cpeMatchString is required.',
      );
    }

    if (input.cpeMatchString && !CPE_PREFIX_REGEX.test(input.cpeMatchString)) {
      throw ctx.fail(
        'invalid_cpe_format',
        `Invalid CPE string: "${input.cpeMatchString}". CPEv2.3 strings must start with "cpe:2.3:".`,
      );
    }

    ctx.log.info('Searching CPE dictionary', {
      keyword: input.keyword,
      cpeMatchString: input.cpeMatchString,
      limit: input.limit,
      offset: input.offset,
    });

    const service = getNvdCpeService();
    const clamped = applyReadLimit(input.limit, 10000, 'nvd_search_cpes', ctx);
    const notices: string[] = clamped.notice ? [clamped.notice] : [];
    const result = await service.searchCpes(
      {
        limit: clamped.limit,
        offset: input.offset,
        ...(input.keyword && { keyword: input.keyword }),
        ...(input.cpeMatchString && { cpeMatchString: input.cpeMatchString }),
      },
      ctx,
    );

    ctx.enrich({ returned: result.returned, offset: result.offset });
    ctx.enrich.total(result.totalResults);
    if (result.cpes.length === 0) {
      /**
       * An empty page only proves the offset overran once the offset reaches totalCount. Inside
       * that range NVD contradicted its own count, and neither "lower the offset" nor "nothing
       * matched" is true — say so rather than sending the caller after a mistake they did not make.
       */
      if (result.totalResults > 0 && input.offset >= result.totalResults) {
        notices.push(
          `Offset ${input.offset} is past the end of the result set (${result.totalResults} total). Use a lower offset to page through results.`,
        );
      } else if (result.totalResults > 0) {
        notices.push(
          `NVD reported ${result.totalResults} match(es) but returned no entries at offset ${input.offset}, which is inside that range. Retry the query; the offset is not the problem.`,
        );
      } else {
        notices.push('No CPEs matched. Try a broader keyword or different spelling.');
      }
    } else if (result.totalResults > result.offset + result.returned) {
      /**
       * A vendor-level keyword is already as specific as the vendor gets, so "narrow the keyword"
       * has no move behind it — point at the offset that actually reaches the remainder.
       */
      notices.push(
        `Results truncated — ${result.totalResults} entries match; set offset to ${result.offset + result.returned} for the next page.`,
      );
    }

    if (notices.length > 0) ctx.enrich.notice(notices.join(' '));
    return { cpes: result.cpes };
  },

  format: (result) => {
    const lines: string[] = [];

    if (result.cpes.length === 0) {
      return [{ type: 'text', text: 'No CPEs returned.' }];
    }

    for (const cpe of result.cpes) {
      const depFlag = cpe.deprecated ? ' *(deprecated)*' : '';
      lines.push(`### ${escapeMarkdownInline(cpe.title ?? cpe.cpeName)}${depFlag}`);
      lines.push(`**CPE Name:** ${escapeMarkdownInline(cpe.cpeName)}`);

      if (cpe.deprecated && cpe.deprecatedBy && cpe.deprecatedBy.length > 0) {
        lines.push(`**Deprecated By:** ${cpe.deprecatedBy.map(escapeMarkdownInline).join(', ')}`);
      }

      if (cpe.lastModified) {
        lines.push(`**Last Modified:** ${escapeMarkdownInline(cpe.lastModified)}`);
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
