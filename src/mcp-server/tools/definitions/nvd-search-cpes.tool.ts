/**
 * @fileoverview Tool for searching the NVD CPE dictionary by keyword or match string.
 * @module src/mcp-server/tools/definitions/nvd-search-cpes
 */

import { tool, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
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
      code: JsonRpcErrorCode.ValidationError,
      when: 'Neither keyword nor cpeMatchString was provided.',
      recovery:
        'Provide at least one of keyword (e.g., "apache http server") or cpeMatchString (partial CPEv2.3 pattern).',
    },
    {
      reason: 'invalid_cpe_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The cpeMatchString does not start with "cpe:2.3:" — it is clearly not a valid CPEv2.3 string.',
      recovery:
        'Provide a valid CPEv2.3 string starting with "cpe:2.3:", or use keyword search to find the correct CPE name.',
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
        ctx.recoveryFor('missing_search_input'),
      );
    }

    if (input.cpeMatchString && !CPE_PREFIX_REGEX.test(input.cpeMatchString)) {
      throw ctx.fail(
        'invalid_cpe_format',
        `Invalid CPE string: "${input.cpeMatchString}". CPEv2.3 strings must start with "cpe:2.3:".`,
        ctx.recoveryFor('invalid_cpe_format'),
      );
    }

    ctx.log.info('Searching CPE dictionary', {
      keyword: input.keyword,
      cpeMatchString: input.cpeMatchString,
      limit: input.limit,
    });

    const service = getNvdCpeService();
    const result = await service.searchCpes(
      {
        limit: input.limit,
        ...(input.keyword && { keyword: input.keyword }),
        ...(input.cpeMatchString && { cpeMatchString: input.cpeMatchString }),
      },
      ctx,
    );

    return {
      cpes: result.cpes,
      queryMeta: { totalResults: result.totalResults, returned: result.returned },
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
