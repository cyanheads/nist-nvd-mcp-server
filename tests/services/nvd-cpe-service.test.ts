/**
 * @fileoverview Tests for NvdCpeService — CPE normalization logic that cannot be
 * exercised through tool-level tests (which mock the service itself).
 * @module tests/services/nvd-cpe-service.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NvdCpeService } from '@/services/nvd-cpe/nvd-cpe-service.js';
import type { RawCpeResponse } from '@/services/nvd-cpe/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';

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
  const mockClient = { get: vi.fn() };

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
    const cpe = result.cpes[0];
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

    expect(result.cpes[0].title).toBe('Vendor Product 1.0');
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

    expect(result.cpes[0].title).toBeUndefined();
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

    const cpe = result.cpes[0];
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

    expect(result.cpes[0].deprecatedBy).toHaveLength(1);
    expect(result.cpes[0].deprecatedBy![0]).toBe('cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*');
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

    expect(result.cpes[0].title).toBeUndefined();
    expect(result.cpes[0].lastModified).toBeUndefined();
    expect(result.cpes[0].deprecatedBy).toBeUndefined();
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

    const call = mockClient.get.mock.calls[0][1] as Record<string, unknown>;
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
    expect(result.cpes[0].cpeName).toBe('');
    expect(result.cpes[0].title).toBe('Unknown Product');
  });

  it('passes cpeMatchString to API params when provided', async () => {
    mockClient.get.mockResolvedValue(makeRawCpeResponse());
    const ctx = createMockContext();
    await service.searchCpes({ cpeMatchString: 'cpe:2.3:a:apache:http_server' }, ctx);

    const call = mockClient.get.mock.calls[0][1] as Record<string, unknown>;
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

    const call = mockClient.get.mock.calls[0][1] as Record<string, unknown>;
    expect(call.keywordSearch).toBe('apache');
    expect(call.cpeMatchString).toBe('cpe:2.3:a:apache:http_server');
  });
});
