/**
 * @fileoverview Resource exposing a single CVE record by ID via a stable URI.
 * @module src/mcp-server/resources/definitions/nvd-cve
 */

import { resource, z } from '@cyanheads/mcp-ts-core';
import { notFound, validationError } from '@cyanheads/mcp-ts-core/errors';
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

  async handler(params, ctx) {
    const { cveId } = params;
    if (!CVE_ID_REGEX.test(cveId)) {
      throw validationError(`Invalid CVE ID format: "${cveId}". Expected format: CVE-YYYY-NNNNN.`, {
        cveId,
      });
    }

    ctx.log.debug('Fetching CVE resource', { cveId });
    const service = getNvdCveService();

    const result = await service.fetchById(
      [cveId.toUpperCase()],
      { includeReferences: true, allLanguages: false },
      ctx,
    );

    if (result.cves.length === 0) {
      throw notFound(`CVE ${cveId} not found in the NVD database.`, { cveId });
    }

    return result.cves[0];
  },
});
