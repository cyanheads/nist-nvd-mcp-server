/**
 * @fileoverview Tests for nvd_get_cve tool.
 * @module tests/tools/nvd-get-cve.tool.test
 */

import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdGetCve } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
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
      vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    },
  ],
  severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
  weaknesses: [{ source: 'NVD', cweIds: ['CWE-20'] }],
  configurations: [
    {
      nodes: [
        {
          operator: 'OR',
          cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*' }],
        },
      ],
    },
  ],
  references: [
    { url: 'https://logging.apache.org/log4j/2.x/security.html', tags: ['Vendor Advisory'] },
  ],
  cisaKev: {
    exploitAddDate: '2021-12-10',
    actionDueDate: '2021-12-24',
    requiredAction: 'Apply updates per vendor instructions.',
    vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
  },
};

const SPARSE_CVE: CveRecord = {
  cveId: 'CVE-2022-00001',
  vulnStatus: 'Awaiting Analysis',
  published: '2022-01-01T00:00:00.000',
  lastModified: '2022-01-02T00:00:00.000',
  descriptions: [],
  cvssScores: [],
  weaknesses: [],
  configurations: [],
};

describe('nvdGetCve', () => {
  const mockService = { fetchById: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.fetchById.mockReset();
  });

  it('returns full records and enrichment for a single CVE ID (string)', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228' });
    const result = await nvdGetCve.handler(input, ctx);

    expect(result.brief).toBe(false);
    expect(result.cves).toHaveLength(1);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.requested).toBe(1);
    expect(enrichment.returned).toBe(1);
    expect(enrichment.missingIds).toBeUndefined();
  });

  it('returns brief records when brief: true', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: ['CVE-2021-44228'], brief: true });
    const result = await nvdGetCve.handler(input, ctx);

    expect(result.brief).toBe(true);
    const cve = result.cves[0] as {
      cveId: string;
      severity?: unknown;
      cisaVulnerabilityName?: string;
    };
    expect(cve.cveId).toBe('CVE-2021-44228');
    expect(cve.cisaVulnerabilityName).toBe('Apache Log4j2 Remote Code Execution Vulnerability');
  });

  it('handles an array of CVE IDs and enriches counts', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE, SPARSE_CVE],
      returned: 2,
      requested: 2,
      missingIds: [],
    });
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: ['CVE-2021-44228', 'CVE-2022-00001'] });
    const result = await nvdGetCve.handler(input, ctx);

    expect(result.cves).toHaveLength(2);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.requested).toBe(2);
    expect(enrichment.returned).toBe(2);
  });

  it('propagates service errors (e.g. cve_not_found)', async () => {
    mockService.fetchById.mockRejectedValue(
      Object.assign(new Error('CVE-9999-99999 not found'), {
        data: { reason: 'cve_not_found' },
      }),
    );
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-9999-99999' });
    await expect(nvdGetCve.handler(input, ctx)).rejects.toThrow('CVE-9999-99999 not found');
  });

  it('handles sparse upstream CVE without severity or references', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [SPARSE_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2022-00001', brief: true });
    const result = await nvdGetCve.handler(input, ctx);

    const cve = result.cves[0] as { severity?: unknown };
    expect(cve.severity).toBeUndefined();
  });

  it('exposes missingIds in enrichment for partial batch results', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 2,
      missingIds: ['CVE-2099-99999'],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({
      cveIds: ['CVE-2021-44228', 'CVE-2099-99999'],
      brief: true,
    });
    await nvdGetCve.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.missingIds).toEqual(['CVE-2099-99999']);
    expect(enrichment.returned).toBe(1);
    expect(enrichment.requested).toBe(2);
  });

  it('rejects empty cveIds array at schema parse', () => {
    expect(() => nvdGetCve.input.parse({ cveIds: [] })).toThrow();
  });

  it('formats full CVE output with key fields', () => {
    const output = {
      brief: false,
      cves: [FULL_CVE as unknown as Record<string, unknown>],
    };
    const blocks = nvdGetCve.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('10');
    expect(text).toContain('CWE-20');
    expect(text).toContain('Apache Log4j2 Remote Code Execution Vulnerability');
    expect(text).toContain('Analyzed');
  });

  it('formats brief CVE output', () => {
    const output = {
      brief: true,
      cves: [
        {
          cveId: 'CVE-2021-44228',
          vulnStatus: 'Analyzed',
          published: '2021-12-10T10:15:00.000',
          severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
          cisaVulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
        } as Record<string, unknown>,
      ],
    };
    const blocks = nvdGetCve.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('Brief');
  });

  it('formats CVE without severity using "Not available" (sparse)', () => {
    const output = {
      brief: true,
      cves: [
        {
          cveId: 'CVE-2022-00001',
          vulnStatus: 'Awaiting Analysis',
          published: '2022-01-01T00:00:00.000',
        } as Record<string, unknown>,
      ],
    };
    const blocks = nvdGetCve.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
    expect(text).not.toMatch(/Severity:.*undefined/);
  });
});
