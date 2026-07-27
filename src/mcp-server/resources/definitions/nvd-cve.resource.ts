/**
 * @fileoverview Resource exposing a single CVE record by ID via a stable URI.
 * @module src/mcp-server/resources/definitions/nvd-cve
 */

import { resource, z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { getNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';

const CVE_ID_REGEX = /^CVE-\d{4}-\d{4,}$/i;

export const nvdCveResource = resource('nvd://cve/{cveId}', {
  name: 'NVD CVE Record',
  description:
    'Fetch a single CVE record by ID from the NIST NVD via a stable URI. ' +
    'Returns the same full data as nvd_get_cve for a single ID: CVSS scores, CWE weaknesses, ' +
    'CPE configurations, CISA KEV fields, and references.',
  mimeType: 'application/json',

  params: z.object({
    cveId: z
      .string()
      .describe('CVE identifier (e.g., "CVE-2021-44228"). Must match the format CVE-YYYY-NNNNN.'),
  }),

  errors: [
    {
      reason: 'invalid_cve_id_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The cveId segment of the URI fails format validation.',
      recovery:
        'Use a URI of the form nvd://cve/CVE-YYYY-NNNNN, for example nvd://cve/CVE-2021-44228.',
    },
    {
      reason: 'cve_not_found',
      code: JsonRpcErrorCode.NotFound,
      when: 'The CVE ID is well-formed but NVD holds no record for it.',
      recovery:
        'Verify the CVE ID is correct, or use nvd_search_cves to find it by keyword or date range.',
    },
  ],

  async handler(params, ctx) {
    const { cveId } = params;
    if (!CVE_ID_REGEX.test(cveId)) {
      throw ctx.fail(
        'invalid_cve_id_format',
        `Invalid CVE ID format: "${cveId}". Expected format: CVE-YYYY-NNNNN.`,
        { cveId, ...ctx.recoveryFor('invalid_cve_id_format') },
      );
    }

    ctx.log.debug('Fetching CVE resource', { cveId });
    const service = getNvdCveService();

    const result = await service.fetchById(
      [cveId.toUpperCase()],
      { includeReferences: true, allLanguages: false },
      ctx,
    );

    if (result.cves.length === 0) {
      throw ctx.fail('cve_not_found', `CVE ${cveId} not found in the NVD database.`, {
        cveId,
        ...ctx.recoveryFor('cve_not_found'),
      });
    }

    return result.cves[0];
  },
});
