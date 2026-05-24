/**
 * @fileoverview Tests for nvd_search_cves tool.
 * @module tests/tools/nvd-search-cves.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import type { BriefCveRecord } from '@/services/nvd-cve/types.js';

const BRIEF_CVE: BriefCveRecord = {
  cveId: 'CVE-2021-44228',
  vulnStatus: 'Analyzed',
  published: '2021-12-10T10:15:00.000',
  severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
};

const BRIEF_CVE_NO_SEVERITY: BriefCveRecord = {
  cveId: 'CVE-2022-00001',
  vulnStatus: 'Awaiting Analysis',
  published: '2022-01-01T00:00:00.000',
};

function makeSearchResult(cves: BriefCveRecord[] = [BRIEF_CVE], total = 1) {
  return { cves, totalResults: total, returned: cves.length, offset: 0 };
}

describe('nvdSearchCves', () => {
  const mockService = { searchCves: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.searchCves.mockReset();
  });

  it('returns CVE summaries with metadata for a keyword search', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'log4j' });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves).toHaveLength(1);
    expect(result.cves[0].cveId).toBe('CVE-2021-44228');
    expect(result.queryMeta.totalResults).toBe(1);
    expect(result.queryMeta.returned).toBe(1);
    expect(result.queryMeta.offset).toBe(0);
    expect(result.queryMeta.datesClamped).toBeUndefined();
  });

  it('applies defaults when no filters are provided', async () => {
    mockService.searchCves.mockResolvedValue({ cves: [], totalResults: 0, returned: 0, offset: 0 });
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({});
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves).toHaveLength(0);
    expect(result.queryMeta.totalResults).toBe(0);
  });

  it('clamps pubDays over 120 and reports clamping in queryMeta', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ pubDays: 200 });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.queryMeta.datesClamped).toHaveLength(1);
    expect(result.queryMeta.datesClamped![0].param).toBe('pubDays');
    expect(result.queryMeta.datesClamped![0].original).toBe(200);
    expect(result.queryMeta.datesClamped![0].clamped).toBe(120);
  });

  it('clamps lastModDays over 120 and reports clamping', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ lastModDays: 150 });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.queryMeta.datesClamped).toHaveLength(1);
    expect(result.queryMeta.datesClamped![0].param).toBe('lastModDays');
    expect(result.queryMeta.datesClamped![0].original).toBe(150);
  });

  it('throws mutually_exclusive_params when pubDays and pubStartDate are both provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubDays: 30,
      pubStartDate: '2024-01-01T00:00:00.000',
      pubEndDate: '2024-01-30T00:00:00.000',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mutually_exclusive_params' },
    });
  });

  it('throws mutually_exclusive_params when lastModDays and lastModStartDate are both provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      lastModDays: 30,
      lastModStartDate: '2024-01-01T00:00:00.000',
      lastModEndDate: '2024-01-30T00:00:00.000',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mutually_exclusive_params' },
    });
  });

  it('throws date_range_exceeds_max when explicit pub date range spans more than 120 days', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubStartDate: '2024-01-01T00:00:00.000',
      pubEndDate: '2024-06-01T00:00:00.000',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'date_range_exceeds_max' },
    });
  });

  it('preserves CVEs without severity in output (sparse upstream payload)', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult([BRIEF_CVE_NO_SEVERITY], 1));
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({});
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves[0].severity).toBeUndefined();
    expect(result.cves[0].cveId).toBe('CVE-2022-00001');
  });

  it('formats output with CVE IDs and severity present', () => {
    const output = {
      cves: [BRIEF_CVE],
      queryMeta: { totalResults: 1, returned: 1, offset: 0 },
    };
    const blocks = nvdSearchCves.format!(output);
    expect(blocks[0].type).toBe('text');
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('10');
  });

  it('formats output with clamping notice', () => {
    const output = {
      cves: [BRIEF_CVE],
      queryMeta: {
        totalResults: 1,
        returned: 1,
        offset: 0,
        datesClamped: [{ param: 'pubDays', original: 200, clamped: 120 }],
      },
    };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('clamped to 120');
    expect(text).toContain('pubDays');
  });

  it('formats empty result with no-match message', () => {
    const output = {
      cves: [],
      queryMeta: { totalResults: 0, returned: 0, offset: 0 },
    };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('No CVEs matched');
  });

  it('formats CVE without severity using "Not available"', () => {
    const output = {
      cves: [BRIEF_CVE_NO_SEVERITY],
      queryMeta: { totalResults: 1, returned: 1, offset: 0 },
    };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
    expect(text).not.toMatch(/Severity:.*undefined/);
  });
});
