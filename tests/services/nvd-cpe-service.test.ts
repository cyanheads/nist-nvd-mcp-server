/**
 * @fileoverview Tests for NvdCpeService — CPE normalization logic that cannot be
 * exercised through tool-level tests (which mock the service itself).
 * @module tests/services/nvd-cpe-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdSearchCpes } from '@/mcp-server/tools/definitions/nvd-search-cpes.tool.js';
import { NvdCpeService } from '@/services/nvd-cpe/nvd-cpe-service.js';
import type { RawCpeResponse } from '@/services/nvd-cpe/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';
import { at } from '../support/at.js';

function makeRawCpeResponse(overrides: Partial<RawCpeResponse> = {}): RawCpeResponse {
  return {
    totalResults: 1,
    products: [
      {
        cpe: {
          cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*',
          deprecated: false,
          titles: [{ lang: 'en', title: 'Apache HTTP Server 2.4.51' }],
          lastModified: '2023-01-01T00:00:00.000',
        },
      },
    ],
    ...overrides,
  };
}

describe('NvdCpeService — CPE normalization', () => {
  const mockClient = {
    get: vi.fn(async (_endpoint: string, _params?: Record<string, unknown>) => ({})),
  };

  beforeEach(() => {
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      mockClient as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    mockClient.get.mockReset();
  });

  const service = new NvdCpeService({} as never, {} as never);

  it('normalizes a full CPE item with title and lastModified', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse());
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'apache' }, ctx);

    expect(result.cpes).toHaveLength(1);
    const cpe = at(result.cpes);
    expect(cpe.cpeName).toBe('cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*');
    expect(cpe.title).toBe('Apache HTTP Server 2.4.51');
    expect(cpe.deprecated).toBe(false);
    expect(cpe.lastModified).toBe('2023-01-01T00:00:00.000');
    expect(cpe.deprecatedBy).toBeUndefined();
  });

  it('picks only the English title when multiple language titles present', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 1,
      products: [
        {
          cpe: {
            cpeName: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
            deprecated: false,
            titles: [
              { lang: 'fr', title: 'Produit Fournisseur 1.0' },
              { lang: 'en', title: 'Vendor Product 1.0' },
            ],
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'vendor' }, ctx);

    expect(at(result.cpes).title).toBe('Vendor Product 1.0');
  });

  it('omits title when no English title exists', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 1,
      products: [
        {
          cpe: {
            cpeName: 'cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*',
            deprecated: false,
            titles: [{ lang: 'de', title: 'Hersteller Produkt 2.0' }],
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'vendor' }, ctx);

    expect(at(result.cpes).title).toBeUndefined();
  });

  it('normalizes a deprecated CPE with deprecatedBy list', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 1,
      products: [
        {
          cpe: {
            cpeName: 'cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*',
            deprecated: true,
            deprecatedBy: [
              { cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*' },
              { cpeName: 'cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*' },
            ],
            titles: [{ lang: 'en', title: 'Apache HTTP Server 2.4.0' }],
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'apache' }, ctx);

    const cpe = at(result.cpes);
    expect(cpe.deprecated).toBe(true);
    expect(cpe.deprecatedBy).toHaveLength(2);
    expect(cpe.deprecatedBy).toContain('cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*');
  });

  it('ignores deprecatedBy entries without cpeName', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 1,
      products: [
        {
          cpe: {
            cpeName: 'cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*',
            deprecated: true,
            deprecatedBy: [
              { cpeNameId: 'some-id-only' }, // no cpeName
              { cpeName: 'cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*' },
            ],
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'vendor' }, ctx);

    expect(at(result.cpes).deprecatedBy).toHaveLength(1);
    expect(at(at(result.cpes).deprecatedBy)).toBe('cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*');
  });

  it('handles a CPE with no titles array at all', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 1,
      products: [
        {
          cpe: {
            cpeName: 'cpe:2.3:a:some_vendor:some_product:1.0:*:*:*:*:*:*:*',
            deprecated: false,
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'some_vendor' }, ctx);

    expect(at(result.cpes).title).toBeUndefined();
    expect(at(result.cpes).lastModified).toBeUndefined();
    expect(at(result.cpes).deprecatedBy).toBeUndefined();
  });

  it('handles empty products array from API', async () => {
    mockClient.get.mockResolvedValue({ totalResults: 0, products: [] });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'nonexistent' }, ctx);

    expect(result.cpes).toHaveLength(0);
    expect(result.totalResults).toBe(0);
    expect(result.returned).toBe(0);
  });

  it('handles products array with null cpe entries', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 0,
      products: [{ cpe: undefined }, { cpe: undefined }],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'test' }, ctx);

    expect(result.cpes).toHaveLength(0);
  });

  it('returns correct totalResults and returned counts', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 150,
      products: [
        {
          cpe: {
            cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*',
            deprecated: false,
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'apache', limit: 1 }, ctx);

    expect(result.totalResults).toBe(150);
    expect(result.returned).toBe(1);
    expect(result.cpes).toHaveLength(1);
  });

  it('applies limit cap at 10000 (does not pass values over the max to NVD)', async () => {
    mockClient.get.mockResolvedValue({ totalResults: 0, products: [] });
    const ctx = createMockContext();
    await service.searchCpes({ keyword: 'test', limit: 99_999 }, ctx);

    const call = at(mockClient.get.mock.calls)[1] ?? {};
    expect(Number(call.resultsPerPage)).toBeLessThanOrEqual(10_000);
  });

  it('propagates service errors from the HTTP client', async () => {
    mockClient.get.mockRejectedValue(new Error('NVD rate limit exceeded'));
    const ctx = createMockContext();
    await expect(service.searchCpes({ keyword: 'apache' }, ctx)).rejects.toThrow(
      'NVD rate limit exceeded',
    );
  });

  it('handles missing cpeName in raw item by falling back to empty string', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 1,
      products: [
        {
          cpe: {
            // cpeName intentionally absent
            deprecated: false,
            titles: [{ lang: 'en', title: 'Unknown Product' }],
          },
        },
      ],
    });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'unknown' }, ctx);

    // Falls back to empty string — caller/tool layer validates CPE format
    expect(at(result.cpes).cpeName).toBe('');
    expect(at(result.cpes).title).toBe('Unknown Product');
  });

  // Issue #31: startIndex was hardcoded to 0, so nothing past the first page was reachable.
  it('maps offset to startIndex and echoes it back', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse({ totalResults: 21_178 }));
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'apache', limit: 3, offset: 60 }, ctx);

    expect(mockClient.get).toHaveBeenCalledWith(
      'cpes/2.0',
      expect.objectContaining({ resultsPerPage: 3, startIndex: 60 }),
      ctx,
    );
    expect(result.offset).toBe(60);
  });

  it('defaults startIndex to 0 when no offset is supplied', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse());
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'apache' }, ctx);

    expect(mockClient.get).toHaveBeenCalledWith(
      'cpes/2.0',
      expect.objectContaining({ startIndex: 0 }),
      ctx,
    );
    expect(result.offset).toBe(0);
  });

  // cpes/2.0 caps resultsPerPage at 10,000; startIndex pages independently of that cap.
  it('keeps a large offset intact while capping resultsPerPage at 10000', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse({ totalResults: 21_178 }));
    const ctx = createMockContext();
    await service.searchCpes({ keyword: 'apache', limit: 99_999, offset: 15_000 }, ctx);

    expect(mockClient.get).toHaveBeenCalledWith(
      'cpes/2.0',
      expect.objectContaining({ resultsPerPage: 10_000, startIndex: 15_000 }),
      ctx,
    );
  });

  it('returns an empty page without error when offset runs past totalResults', async () => {
    mockClient.get.mockResolvedValue({ totalResults: 12, products: [] });
    const ctx = createMockContext();
    const result = await service.searchCpes({ keyword: 'apache', offset: 500 }, ctx);

    expect(result.cpes).toHaveLength(0);
    expect(result.totalResults).toBe(12);
    expect(result.offset).toBe(500);
  });

  it('passes cpeMatchString to API params when provided', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse());
    const ctx = createMockContext();
    await service.searchCpes({ cpeMatchString: 'cpe:2.3:a:apache:http_server' }, ctx);

    const call = at(mockClient.get.mock.calls)[1] ?? {};
    expect(call.cpeMatchString).toBe('cpe:2.3:a:apache:http_server');
    expect(call.keywordSearch).toBeUndefined();
  });

  it('passes both keyword and cpeMatchString when both provided', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse());
    const ctx = createMockContext();
    await service.searchCpes(
      { keyword: 'apache', cpeMatchString: 'cpe:2.3:a:apache:http_server' },
      ctx,
    );

    const call = at(mockClient.get.mock.calls)[1] ?? {};
    expect(call.keywordSearch).toBe('apache');
    expect(call.cpeMatchString).toBe('cpe:2.3:a:apache:http_server');
  });
});

/**
 * Issue #45: `cpeMatchString` is a partial-match parameter — a truncated prefix is a legitimate
 * pattern NVD answers HTTP 200 with zero results for (verified live against
 * `cpe:2.3:a:zzznotavendor`). It rejects only genuinely malformed characters, answering 404
 * `Invalid cpeMatchstring parameter, see documentation.`, which reached the caller as an
 * undeclared `nvd_request_rejected` with no recovery hint.
 */
describe('NvdCpeService.searchCpes — NVD CPE parameter rejection (issue #45)', () => {
  const mockClient = {
    get: vi.fn(async (_endpoint: string, _params?: Record<string, unknown>) => ({})),
  };

  beforeEach(() => {
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      mockClient as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    mockClient.get.mockReset();
  });

  const service = new NvdCpeService({} as never, {} as never);

  it('translates a rejected cpeMatchString into invalid_cpe_format with a recovery hint', async () => {
    mockClient.get.mockRejectedValue(
      nvdHttpClientModule.nvdRequestRejected(
        'cpes/2.0',
        'Invalid cpeMatchstring parameter, see documentation.',
      ),
    );
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });

    await expect(
      service.searchCpes({ cpeMatchString: 'cpe:2.3:a:zzz notavendor:%%%:' }, ctx),
    ).rejects.toMatchObject({
      data: {
        reason: 'invalid_cpe_format',
        cpe: 'cpe:2.3:a:zzz notavendor:%%%:',
        recovery: { hint: expect.stringContaining('cpe:2.3:') },
      },
    });
  });

  it("keeps NVD's own diagnosis in the translated message", async () => {
    mockClient.get.mockRejectedValue(
      nvdHttpClientModule.nvdRequestRejected(
        'cpes/2.0',
        'Invalid cpeMatchstring parameter, see documentation.',
      ),
    );
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });

    await expect(
      service.searchCpes({ cpeMatchString: 'cpe:2.3:a:zzz notavendor:%%%:' }, ctx),
    ).rejects.toThrow(/Invalid CPE string ".*"\..*Invalid cpeMatchstring parameter/);
  });

  it('leaves a zero-result cpeMatchString an empty success rather than a format error', async () => {
    mockClient.get.mockResolvedValue({ totalResults: 0, products: [] });
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const result = await service.searchCpes({ cpeMatchString: 'cpe:2.3:a:zzznotavendor' }, ctx);

    expect(result.cpes).toEqual([]);
    expect(result.totalResults).toBe(0);
  });

  /** No CPE string to blame — a keyword-only search must surface the rejection as it arrived. */
  it('rethrows a rejection untranslated when the query carried no cpeMatchString', async () => {
    mockClient.get.mockRejectedValue(
      nvdHttpClientModule.nvdRequestRejected('cpes/2.0', 'Invalid parameter.'),
    );
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });

    await expect(service.searchCpes({ keyword: 'apache' }, ctx)).rejects.toMatchObject({
      data: { reason: 'nvd_request_rejected' },
    });
  });
});
