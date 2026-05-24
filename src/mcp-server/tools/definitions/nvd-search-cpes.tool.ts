/**
 * @fileoverview Tool for searching the NVD CPE dictionary by keyword or match string.
 * @module mcp-server/tools/definitions/nvd-search-cpes
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getNvdCpeService } from '@/services/nvd-cpe/nvd-cpe-service.js';

export const nvdSearchCpes = tool('nvd_search_cpes', {
  title: 'Search CPE Dictionary',
  description:
    'Search the NVD CPE (Common Platform Enumeration) dictionary by product keyword or partial match string. ' +
    'Returns CPE names, human-readable titles, and deprecation status. ' +
    'Use this tool to find the correct cpeName before calling nvd_audit_cpe — ' +
    'when multiple CPEs match a product name, review the results and select the right one ' +
    'rather than guessing. CPE names are arcane strings like cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:* — ' +
    'a wrong guess audits the wrong product.',
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
    limit: z
      .number()
      .int()
      .min(1)
      .max(10_000)
      .default(20)
      .describe(
        'Maximum number of CPE entries to return (default 20, max 10000). ' +
          'If totalResults > returned, narrow the keyword for a more specific result.',
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
    queryMeta: z
      .object({
        totalResults: z
          .number()
          .describe('Total matching CPE entries before the limit was applied.'),
        returned: z.number().describe('Number of entries returned in this response.'),
      })
      .describe(
        'Query metadata. When totalResults > returned, narrow the keyword for more specific results.',
      ),
  }),

  errors: [
    {
      reason: 'missing_search_input',
      code: JsonRpcErrorCode.InvalidParams,
      when: 'Neither keyword nor cpeMatchString was provided.',
      recovery:
        'Provide at least one of keyword (e.g., "apache http server") or cpeMatchString (partial CPEv2.3 pattern).',
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
    if (!input.keyword && !input.cpeMatchString) {
      throw ctx.fail(
        'missing_search_input',
        'At least one of keyword or cpeMatchString is required.',
        {
          ...ctx.recoveryFor('missing_search_input'),
        },
      );
    }

    ctx.log.info('Searching CPE dictionary', {
      keyword: input.keyword,
      cpeMatchString: input.cpeMatchString,
      limit: input.limit,
    });

    const service = getNvdCpeService();
    const searchParams: Parameters<typeof service.searchCpes>[0] = { limit: input.limit };
    if (input.keyword) searchParams.keyword = input.keyword;
    if (input.cpeMatchString) searchParams.cpeMatchString = input.cpeMatchString;
    const result = await service.searchCpes(searchParams, ctx);

    return {
      cpes: result.cpes.map((cpe) => ({
        cpeName: cpe.cpeName,
        ...(cpe.title ? { title: cpe.title } : {}),
        deprecated: cpe.deprecated,
        ...(cpe.deprecatedBy ? { deprecatedBy: cpe.deprecatedBy } : {}),
        ...(cpe.lastModified ? { lastModified: cpe.lastModified } : {}),
      })),
      queryMeta: {
        totalResults: result.totalResults,
        returned: result.returned,
      },
    };
  },

  format: (result) => {
    const lines: string[] = [];
    lines.push(
      `**Total:** ${result.queryMeta.totalResults} matching CPEs | **Returned:** ${result.queryMeta.returned}`,
    );

    if (result.queryMeta.totalResults > result.queryMeta.returned) {
      lines.push(`> Results truncated — narrow the keyword for more specific results.`);
    }

    if (result.cpes.length === 0) {
      lines.push('\nNo CPEs matched. Try a broader keyword or different spelling.');
      return [{ type: 'text', text: lines.join('\n') }];
    }

    lines.push('');

    for (const cpe of result.cpes) {
      const depFlag = cpe.deprecated ? ' *(deprecated)*' : '';
      lines.push(`### ${cpe.title ?? cpe.cpeName}${depFlag}`);
      lines.push(`**CPE Name:** \`${cpe.cpeName}\``);

      if (cpe.deprecated && cpe.deprecatedBy && cpe.deprecatedBy.length > 0) {
        lines.push(`**Deprecated By:** ${cpe.deprecatedBy.join(', ')}`);
      }

      if (cpe.lastModified) {
        lines.push(`**Last Modified:** ${cpe.lastModified}`);
      }

      lines.push('');
    }

    return [{ type: 'text', text: lines.join('\n') }];
  },
});
