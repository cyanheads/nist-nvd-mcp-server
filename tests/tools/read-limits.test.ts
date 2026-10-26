/** @fileoverview Read-limit clamping at the tool boundary, including batch ID accounting. */
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdGetCve } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
import { nvdGetCveHistory } from '@/mcp-server/tools/definitions/nvd-get-cve-history.tool.js';
import { nvdSearchCpes } from '@/mcp-server/tools/definitions/nvd-search-cpes.tool.js';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as cpeModule from '@/services/nvd-cpe/nvd-cpe-service.js';
import * as cveModule from '@/services/nvd-cve/nvd-cve-service.js';

const cpeName = 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*';
const cveId = 'CVE-2021-44228';
const page = {
  cves: [],
  cpes: [],
  changes: [],
  cveId,
  cpeName,
  totalResults: 0,
  returned: 0,
  offset: 0,
  filteredCount: 0,
  order: 'newest',
};
const service = {
  searchCves: vi.fn(),
  auditCpe: vi.fn(),
  getCveHistory: vi.fn(),
  searchCpes: vi.fn(),
  fetchById: vi.fn(),
};
function text(result: Awaited<ReturnType<typeof runToolContract>>) {
  return result.content.flatMap((block) => (block.type === 'text' ? [block.text] : [])).join('\n');
}

describe('read limits', () => {
  beforeEach(() => {
    for (const fn of Object.values(service)) fn.mockReset().mockResolvedValue(page);
    vi.spyOn(cveModule, 'getNvdCveService').mockReturnValue(service as never);
    vi.spyOn(cpeModule, 'getNvdCpeService').mockReturnValue(service as never);
  });

  const cases = [
    [nvdSearchCves, { keyword: 'log4j' }, 2000, service.searchCves],
    [nvdAuditCpe, { cpeName }, 2000, service.auditCpe],
    [nvdGetCveHistory, { cveId }, 2000, service.getCveHistory],
    [nvdSearchCpes, { keyword: 'apache' }, 10000, service.searchCpes],
  ] as const;
  for (const [tool, valid, maximum, fn] of cases) {
    it(`${tool.name} preserves at-cap behavior without clamp fields`, async () => {
      const result = await runToolContract(tool, { ...valid, limit: maximum } as never);
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).not.toHaveProperty('requestedLimit');
      expect(fn.mock.calls[0]?.[0]).toMatchObject({ limit: maximum });
    });
    it(`${tool.name} clamps over-cap calls and preserves empty-result guidance`, async () => {
      const result = await runToolContract(tool, { ...valid, limit: maximum + 1 } as never);
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toMatchObject({
        requestedLimit: maximum + 1,
        effectiveLimit: maximum,
        notice: expect.stringContaining('clamped'),
      });
      expect(text(result)).toContain(String(maximum + 1));
      expect(text(result)).toContain(String(maximum));
      expect(fn.mock.calls[0]?.[0]).toMatchObject({ limit: maximum });
    });
    it.each([0, -1, 1.5])(`${tool.name} still rejects invalid limit %s`, async (limit) => {
      const result = await runToolContract(tool, { ...valid, limit } as never);
      expect(result.isError).toBe(true);
      expect(fn).not.toHaveBeenCalled();
    });
    it(`${tool.name} keeps the next offset alongside its clamp notice`, async () => {
      fn.mockResolvedValue({
        ...page,
        totalResults: 4,
        returned: 1,
        offset: 1,
        cves: [
          {
            cveId,
            vulnStatus: 'Analyzed',
            published: '2021-12-10',
            lastModified: '2024-01-01',
            descriptions: [],
            cvssScores: [],
            weaknesses: [],
            configurationNodes: [],
          },
        ],
        cpes: [{ cpeName, deprecated: false }],
        changes: [{ changeDate: '2024-01-01', details: [] }],
      });
      const result = await runToolContract(tool, {
        ...valid,
        limit: maximum + 1,
        offset: 1,
      } as never);
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toHaveProperty('notice', expect.stringContaining('clamped'));
      expect(result.structuredContent).toHaveProperty(
        'notice',
        expect.stringContaining('set offset to 2'),
      );
      expect(text(result)).toContain('set offset to 2');
    });
    it(`${tool.name} keeps past-end guidance alongside its clamp notice`, async () => {
      fn.mockResolvedValue({ ...page, totalResults: 1, offset: 2 });
      const result = await runToolContract(tool, {
        ...valid,
        limit: maximum + 1,
        offset: 2,
      } as never);
      expect(result.isError).not.toBe(true);
      expect(result.structuredContent).toHaveProperty('notice', expect.stringContaining('clamped'));
      expect(text(result)).toContain('past the end');
    });
  }
  it('separates unattempted IDs from missing IDs across duplicates and case variants', async () => {
    const prefix = Array.from({ length: 100 }, (_, i) => `CVE-2021-${10000 + i}`);
    service.fetchById.mockResolvedValue({
      cves: [],
      requested: 100,
      returned: 0,
      missingIds: ['CVE-2021-10000'],
    });
    const result = await runToolContract(nvdGetCve, {
      cveIds: [...prefix, 'cve-2021-10000', 'cve-2021-20000', 'CVE-2021-20000', 'CVE-2021-20001'],
    });
    expect(result.isError).not.toBe(true);
    expect(service.fetchById.mock.calls[0]?.[0]).toEqual(prefix);
    expect(result.structuredContent).toMatchObject({
      requested: 100,
      requestedLimit: 104,
      effectiveLimit: 100,
      missingIds: ['CVE-2021-10000'],
      unprocessedIds: ['CVE-2021-20000', 'CVE-2021-20001'],
    });
    expect(text(result)).toContain('CVE-2021-20000');
    expect(text(result)).toContain('CVE-2021-20001');
  });
  it('validates the tail before spending any request', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: [...Array.from({ length: 100 }, () => cveId), 'not-a-cve'],
    });
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cve_id_format' } },
    });
    expect(service.fetchById).not.toHaveBeenCalled();
  });
});
