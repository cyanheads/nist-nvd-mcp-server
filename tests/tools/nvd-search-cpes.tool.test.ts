/**
 * @fileoverview Tests for nvd_search_cpes tool.
 * @module tests/tools/nvd-search-cpes.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
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

  it('returns CPE entries for a keyword search', async () => {
    mockService.searchCpes.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'apache http server' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes).toHaveLength(1);
    expect(result.cpes[0].cpeName).toBe('cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*');
    expect(result.cpes[0].deprecated).toBe(false);
    expect(result.queryMeta.totalResults).toBe(1);
    expect(result.queryMeta.returned).toBe(1);
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

  it('handles empty search results', async () => {
    mockService.searchCpes.mockResolvedValue({ cpes: [], totalResults: 0, returned: 0 });
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'nonexistent_product_xyz' });
    const result = await nvdSearchCpes.handler(input, ctx);

    expect(result.cpes).toHaveLength(0);
    expect(result.queryMeta.totalResults).toBe(0);
  });

  it('formats CPE results with name and title', () => {
    const output = {
      cpes: [{ cpeName: CPE_APACHE.cpeName, title: CPE_APACHE.title, deprecated: false }],
      queryMeta: { totalResults: 1, returned: 1 },
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Apache HTTP Server 2.4.51');
    expect(text).toContain('cpe:2.3:a:apache:http_server:2.4.51');
    expect(text).toContain('**Total:** 1');
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
      queryMeta: { totalResults: 1, returned: 1 },
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('deprecated');
    expect(text).toContain('Deprecated By');
  });

  it('formats empty results with no-match message', () => {
    const output = {
      cpes: [],
      queryMeta: { totalResults: 0, returned: 0 },
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('No CPEs matched');
  });

  it('formats CPE without title using cpeName as heading', () => {
    const output = {
      cpes: [{ cpeName: CPE_NO_TITLE.cpeName, deprecated: false }],
      queryMeta: { totalResults: 1, returned: 1 },
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('cpe:2.3:a:some_vendor:some_product:1.0');
  });

  it('formats truncation notice when totalResults exceeds returned', () => {
    const output = {
      cpes: [{ cpeName: CPE_APACHE.cpeName, title: CPE_APACHE.title, deprecated: false }],
      queryMeta: { totalResults: 100, returned: 1 },
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('truncated');
  });
});
