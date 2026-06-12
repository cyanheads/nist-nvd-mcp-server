/**
 * @fileoverview Tests for nvd_search_cpes tool.
 * @module tests/tools/nvd-search-cpes.tool.test
 */

import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdSearchCpes } from '@/mcp-server/tools/definitions/nvd-search-cpes.tool.js';
import * as nvdCpeServiceModule from '@/services/nvd-cpe/nvd-cpe-service.js';
import type { CpeRecord } from '@/services/nvd-cpe/types.js';

const CPE_APACHE: CpeRecord = {
  cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*',
  title: 'Apache HTTP Server 2.4.51',
  deprecated: false,
  lastModified: '2023-01-01T00:00:00.000',
};

const CPE_DEPRECATED: CpeRecord = {
  cpeName: 'cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*:*',
  title: 'Apache HTTP Server 2.4.0',
  deprecated: true,
  deprecatedBy: ['cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*'],
  lastModified: '2022-01-01T00:00:00.000',
};

const CPE_NO_TITLE: CpeRecord = {
  cpeName: 'cpe:2.3:a:some_vendor:some_product:1.0:*:*:*:*:*:*:*',
  deprecated: false,
};

function makeSearchResult(cpes: CpeRecord[] = [CPE_APACHE], total = 1) {
  return { cpes, totalResults: total, returned: cpes.length };
}

describe('nvdSearchCpes', () => {
  const mockService = { searchCpes: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCpeServiceModule.getNvdCpeService>,
    );
    mockService.searchCpes.mockReset();
  });

  it('returns CPE entries and enrichment for a keyword search', async () => {
    mockService.searchCpes.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'apache http server' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes).toHaveLength(1);
    expect(result.cpes[0].cpeName).toBe('cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*');
    expect(result.cpes[0].deprecated).toBe(false);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(1);
    expect(enrichment.returned).toBe(1);
  });

  it('returns CPE entries for a cpeMatchString search', async () => {
    mockService.searchCpes.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ cpeMatchString: 'cpe:2.3:a:apache:http_server' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes).toHaveLength(1);
    expect(result.cpes[0].cpeName).toContain('apache:http_server');
  });

  it('throws missing_search_input when neither keyword nor cpeMatchString provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const input = nvdSearchCpes.input.parse({});
    await expect(nvdSearchCpes.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'missing_search_input' },
    });
  });

  it('handles deprecated CPE with deprecatedBy list', async () => {
    mockService.searchCpes.mockResolvedValue(makeSearchResult([CPE_DEPRECATED], 1));
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'apache' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes[0].deprecated).toBe(true);
    expect(result.cpes[0].deprecatedBy).toContain(
      'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*',
    );
  });

  it('handles CPE without title (sparse upstream payload)', async () => {
    mockService.searchCpes.mockResolvedValue(makeSearchResult([CPE_NO_TITLE], 1));
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'some_vendor' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes[0].title).toBeUndefined();
    expect(result.cpes[0].cpeName).toBe('cpe:2.3:a:some_vendor:some_product:1.0:*:*:*:*:*:*:*');
  });

  it('handles empty search results with enriched notice', async () => {
    mockService.searchCpes.mockResolvedValue({ cpes: [], totalResults: 0, returned: 0 });
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'nonexistent_product_xyz' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes).toHaveLength(0);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(0);
    expect(enrichment.notice).toContain('No CPEs matched');
  });

  it('formats CPE results with name and title', () => {
    const output = {
      cpes: [{ cpeName: CPE_APACHE.cpeName, title: CPE_APACHE.title, deprecated: false }],
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Apache HTTP Server 2.4.51');
    expect(text).toContain('cpe:2.3:a:apache:http_server:2.4.51');
  });

  it('formats deprecated CPE with deprecation marker', () => {
    const output = {
      cpes: [
        {
          cpeName: CPE_DEPRECATED.cpeName,
          title: CPE_DEPRECATED.title,
          deprecated: true,
          deprecatedBy: CPE_DEPRECATED.deprecatedBy,
        },
      ],
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('deprecated');
    expect(text).toContain('Deprecated By');
  });

  it('formats empty results with placeholder', () => {
    const output = { cpes: [] };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    // format() renders domain payload; notices reach content[] via enrichment trailer
    expect(text).toBeTruthy();
  });

  it('formats CPE without title using cpeName as heading', () => {
    const output = {
      cpes: [{ cpeName: CPE_NO_TITLE.cpeName, deprecated: false }],
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('cpe:2.3:a:some_vendor:some_product:1.0');
  });

  it('enriches truncation notice when totalResults exceeds returned', async () => {
    mockService.searchCpes.mockResolvedValue({
      cpes: [CPE_APACHE],
      totalResults: 100,
      returned: 1,
    });
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'apache' });
    await nvdSearchCpes.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('truncated');
  });

  // Issue #10: malformed CPE strings should fail locally before hitting NVD
  it('throws invalid_cpe_format when cpeMatchString does not start with cpe:2.3:', async () => {
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const input = nvdSearchCpes.input.parse({ cpeMatchString: 'not-a-valid-cpe' });
    await expect(nvdSearchCpes.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('throws invalid_cpe_format for garbage cpeMatchString', async () => {
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const input = nvdSearchCpes.input.parse({ cpeMatchString: 'garbage' });
    await expect(nvdSearchCpes.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('accepts a valid cpe:2.3: cpeMatchString', async () => {
    mockService.searchCpes.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const input = nvdSearchCpes.input.parse({ cpeMatchString: 'cpe:2.3:a:apache:http_server' });
    const result = await nvdSearchCpes.handler(input, ctx);
    expect(result.cpes).toHaveLength(1);
  });
});
