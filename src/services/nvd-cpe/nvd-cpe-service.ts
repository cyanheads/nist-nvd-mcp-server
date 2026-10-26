/**
 * @fileoverview Service for the NIST NVD CPE API 2.0.
 * Provides CPE dictionary search by keyword and match string.
 * @module services/nvd-cpe/nvd-cpe-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import type { StorageService } from '@cyanheads/mcp-ts-core/storage';
import { getNvdHttpClient, isNvdRequestRejected } from '../nvd-http/nvd-http-client.js';
import { parseNvdResponse } from '../nvd-http/parse-nvd-response.js';
import type { CpeRecord, RawCpeItem, RawCpeResponse } from './types.js';
import { rawCpeResponseSchema } from './types.js';

/** Normalize a raw CPE item to a CpeRecord. */
function normalizeCpe(raw: RawCpeItem): CpeRecord {
  const title = raw.titles?.find((entry) => entry.lang === 'en' && entry.title)?.title;

  const deprecatedBy = (raw.deprecatedBy ?? []).flatMap((entry) =>
    entry.cpeName ? [entry.cpeName] : [],
  );

  return {
    cpeName: raw.cpeName ?? '',
    ...(title && { title }),
    deprecated: raw.deprecated ?? false,
    ...(deprecatedBy.length > 0 && { deprecatedBy }),
    ...(raw.lastModified && { lastModified: raw.lastModified }),
  };
}

export class NvdCpeService {
  // biome-ignore lint/complexity/noUselessConstructor: preserves framework init-pattern signature
  constructor(_config: AppConfig, _storage: StorageService) {}

  /**
   * Search CPEs by keyword or partial match string.
   */
  async searchCpes(
    params: {
      keyword?: string;
      cpeMatchString?: string;
      limit?: number;
      /** Zero-based index of the first entry to return — maps to NVD's `startIndex`. */
      offset?: number;
    },
    ctx: Context,
  ): Promise<{ cpes: CpeRecord[]; totalResults: number; returned: number; offset: number }> {
    const client = getNvdHttpClient();

    // `cpes/2.0` caps `resultsPerPage` at 10,000; `startIndex` pages independently of that cap.
    const apiParams: Record<string, string | number | boolean | undefined> = {
      resultsPerPage: Math.min(params.limit ?? 20, 10_000),
      startIndex: params.offset ?? 0,
    };

    if (params.keyword) apiParams.keywordSearch = params.keyword;
    if (params.cpeMatchString) apiParams.cpeMatchString = params.cpeMatchString;

    let response: RawCpeResponse;
    try {
      response = parseNvdResponse(
        rawCpeResponseSchema,
        await client.get('cpes/2.0', apiParams, ctx),
        'cpes/2.0',
      );
    } catch (err) {
      /**
       * The tool's prefix check clears any string starting `cpe:2.3:`, but NVD rejects a pattern
       * carrying genuinely malformed characters with a 404. A merely truncated prefix is a
       * legitimate partial match here and comes back as an empty HTTP 200, so only the rejection
       * means the string itself is at fault.
       */
      if (params.cpeMatchString && isNvdRequestRejected(err)) {
        throw validationError(
          `Invalid CPE string "${params.cpeMatchString}". ${err.message}`,
          { reason: 'invalid_cpe_format', cpe: params.cpeMatchString },
          { cause: err },
        );
      }
      throw err;
    }

    const items = response.products.map((p) => p.cpe).filter((c): c is RawCpeItem => !!c);

    const cpes = items.map(normalizeCpe);
    const totalResults = response.totalResults;

    ctx.log.info('CPE search completed', { totalResults, returned: cpes.length });

    return { cpes, totalResults, returned: cpes.length, offset: params.offset ?? 0 };
  }
}

// --- Init/accessor pattern ---

let _service: NvdCpeService | undefined;

export function initNvdCpeService(config: AppConfig, storage: StorageService): void {
  _service = new NvdCpeService(config, storage);
}

export function getNvdCpeService(): NvdCpeService {
  if (!_service) {
    throw new Error('NvdCpeService not initialized — call initNvdCpeService() in setup()');
  }
  return _service;
}
