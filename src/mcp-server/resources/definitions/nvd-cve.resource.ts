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
    "Fetch a single CVE record by ID from the NIST NVD via a stable URI. Returns the same full data as nvd_get_cve for a single ID: CVSS scores with who supplied each, CWE weaknesses, CPE configurations from NVD analysis, the affected products the CNA and any ADP state themselves, the record's source and tags, CISA KEV fields, current SSVC assessments, and references.",
  mimeType: 'application/json',

  params: z.object({
    cveId: z
      .string()
      .describe('CVE identifier (e.g., "CVE-2021-44228"). Must match the format CVE-YYYY-NNNNN.'),
  }),

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
      reason: 'rate_limited',
      code: JsonRpcErrorCode.RateLimited,
      when: 'NVD explicitly reported that the rate limit was exceeded.',
      retryable: true,
      thrownBy: 'service',
      recovery:
        'Wait for the NVD rate window to reset, then retry; a server operator can set NVD_API_KEY for higher limits.',
    },
    {
      reason: 'nvd_unavailable',
      code: JsonRpcErrorCode.ServiceUnavailable,
      when: 'NVD answered with HTTP 5xx, or the request or its response failed on the network, after the client retried.',
      retryable: true,
      thrownBy: 'service',
      recovery: 'NVD is failing or unreachable; wait a minute and retry the call.',
    },
    {
      reason: 'nvd_timeout',
      code: JsonRpcErrorCode.Timeout,
      when: 'An NVD request outlived its timeout, or the call ran out of its 55-second deadline.',
      retryable: true,
      thrownBy: 'service',
      recovery:
        'NVD did not answer in time; retry in a minute. A server operator can raise NVD_REQUEST_TIMEOUT_MS.',
    },
    {
      reason: 'nvd_invalid_api_key',
      code: JsonRpcErrorCode.ConfigurationError,
      when: "NVD refused the server's configured NVD_API_KEY.",
      retryable: false,
      thrownBy: 'service',
      recovery:
        "NVD refused this server's NVD_API_KEY, so no NVD call can succeed until a server operator fixes it: verify the key, request a replacement at https://nvd.nist.gov/developers/request-an-api-key, or unset NVD_API_KEY to run keyless at 5 req/30s.",
    },
    {
      reason: 'invalid_cve_id_format',
      code: JsonRpcErrorCode.ValidationError,
      when: 'The cveId segment of the URI fails format validation.',
      recovery:
        'Use a URI of the form nvd://cve/CVE-YYYY-NNNNN, for example nvd://cve/CVE-2021-44228.',
    },
    {
      /**
       * Thrown by the service, not this handler: a single-ID fetch that NVD answers with no
       * records raises `cve_not_found` there. The entry stays declared here so the framework
       * fills this recovery text onto the wire when that throw reaches the resource boundary.
       */
      reason: 'cve_not_found',
      code: JsonRpcErrorCode.NotFound,
      thrownBy: 'service',
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
        { cveId },
      );
    }

    ctx.log.debug('Fetching CVE resource', { cveId });
    const service = getNvdCveService();

    // A single-ID miss throws `cve_not_found` inside fetchById, so this always has a record.
    const result = await service.fetchById(
      [cveId.toUpperCase()],
      { includeReferences: true, allLanguages: false },
      ctx,
    );

    return result.cves[0];
  },
});
