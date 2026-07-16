/**
 * @fileoverview Tests for nvd://cve/{cveId} resource.
 * @module tests/resources/nvd-cve.resource.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdCveResource } from '@/mcp-server/resources/definitions/nvd-cve.resource.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import type { CveRecord } from '@/services/nvd-cve/types.js';

const FULL_CVE: CveRecord = {
  cveId: 'CVE-2021-44228',
  vulnStatus: 'Analyzed',
  published: '2021-12-10T10:15:00.000',
  lastModified: '2023-11-06T03:18:00.000',
  descriptions: [{ lang: 'en', value: 'Apache Log4j2 JNDI vulnerability.' }],
  cvssScores: [
    {
      version: '3.1',
      sourceType: 'Primary',
      baseScore: 10.0,
      severity: 'CRITICAL',
    },
  ],
  severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
  weaknesses: [{ source: 'NVD', cweIds: ['CWE-20'] }],
  configurations: [],
};

describe('nvdCveResource', () => {
  const mockService = { fetchById: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.fetchById.mockReset();
  });

  it('returns a CVE record for a valid ID', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
    });
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'CVE-2021-44228' });
    const result = await nvdCveResource.handler(params, ctx);

    expect(result).toBeDefined();
    const cve = result as CveRecord;
    expect(cve.cveId).toBe('CVE-2021-44228');
    expect(cve.vulnStatus).toBe('Analyzed');
  });

  it('normalizes CVE ID to uppercase before fetching', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
    });
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'cve-2021-44228' });
    await nvdCveResource.handler(params, ctx);

    expect(mockService.fetchById).toHaveBeenCalledWith(
      ['CVE-2021-44228'],
      { includeReferences: true, allLanguages: false },
      ctx,
    );
  });

  it('throws validationError for an invalid CVE ID format', async () => {
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'INVALID-ID' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
  });

  it('throws validationError for a malformed CVE ID (no year)', async () => {
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'CVE-12345' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
  });

  it('throws notFound when NVD returns no records for a valid ID', async () => {
    mockService.fetchById.mockResolvedValue({ cves: [], returned: 0, requested: 1 });
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'CVE-9999-99999' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/not found/i);
  });

  it('propagates service errors (e.g. rate_limited)', async () => {
    mockService.fetchById.mockRejectedValue(new Error('NVD rate limit exceeded'));
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'CVE-2021-44228' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow('NVD rate limit exceeded');
  });

  it('handles a sparse CVE record (missing optional fields)', async () => {
    const sparseCve: CveRecord = {
      cveId: 'CVE-2022-00001',
      vulnStatus: 'Awaiting Analysis',
      published: '2022-01-01T00:00:00.000',
      lastModified: '2022-01-02T00:00:00.000',
      descriptions: [],
      cvssScores: [],
      weaknesses: [],
      configurations: [],
    };
    mockService.fetchById.mockResolvedValue({ cves: [sparseCve], returned: 1, requested: 1 });
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'CVE-2022-00001' });
    const result = await nvdCveResource.handler(params, ctx);

    const cve = result as CveRecord;
    expect(cve.cveId).toBe('CVE-2022-00001');
    expect(cve.severity).toBeUndefined();
    expect(cve.cisaKev).toBeUndefined();
  });
});
