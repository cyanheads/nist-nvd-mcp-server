/**
 * @fileoverview Tests for nvd_audit_cpe tool.
 * @module tests/tools/nvd-audit-cpe.tool.test
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
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
          cpeMatch: [
            {
              vulnerable: true,
              criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*',
              versionStartIncluding: '2.0',
              versionEndExcluding: '2.15.0',
            },
          ],
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
  cveId: 'CVE-2022-11111',
  vulnStatus: 'Awaiting Analysis',
  published: '2022-06-01T00:00:00.000',
  lastModified: '2022-06-02T00:00:00.000',
  descriptions: [],
  cvssScores: [],
  weaknesses: [],
  configurations: [],
};

function makeAuditResult(
  cves: CveRecord[] = [FULL_CVE],
  extra: Record<string, unknown> = { cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*' },
) {
  return {
    cves,
    totalResults: cves.length,
    returned: cves.length,
    ...extra,
  };
}

describe('nvdAuditCpe', () => {
  const mockService = { auditCpe: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.auditCpe.mockReset();
  });

  it('returns CVEs for a valid cpeName', async () => {
    mockService.auditCpe.mockResolvedValue(makeAuditResult());
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(result.cves).toHaveLength(1);
    expect(result.cves[0].cveId).toBe('CVE-2021-44228');
    expect(result.queryMeta.totalResults).toBe(1);
    expect(result.queryMeta.cpeName).toBe('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*');
  });

  it('returns CVEs for a virtualMatchString', async () => {
    mockService.auditCpe.mockResolvedValue(
      makeAuditResult([FULL_CVE], {
        virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
      }),
    );
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(result.queryMeta.virtualMatchString).toBe('cpe:2.3:a:apache:log4j:*');
    expect(result.queryMeta.cpeName).toBeUndefined();
  });

  it('throws missing_cpe_input when neither cpeName nor virtualMatchString provided', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({});
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'missing_cpe_input' },
    });
  });

  it('throws conflicting_cpe_inputs when both cpeName and virtualMatchString provided', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'conflicting_cpe_inputs' },
    });
  });

  it('throws version_range_without_match_string when versionStart provided without virtualMatchString', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
      versionStart: '2.0',
    });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'version_range_without_match_string' },
    });
  });

  it('throws version_range_without_match_string when versionEnd provided without virtualMatchString', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
      versionEnd: '2.15.0',
    });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'version_range_without_match_string' },
    });
  });

  it('propagates cpe_not_found from service', async () => {
    mockService.auditCpe.mockRejectedValue(
      Object.assign(new Error('No CVEs found for CPE'), {
        data: { reason: 'cpe_not_found' },
      }),
    );
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:nonexistent:product:9.9:*:*:*:*:*:*:*',
    });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toThrow('No CVEs found for CPE');
  });

  it('handles sparse CVE without severity or references', async () => {
    mockService.auditCpe.mockResolvedValue(
      makeAuditResult([SPARSE_CVE], {
        virtualMatchString: 'cpe:2.3:a:some_vendor:product:*',
      }),
    );
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:some_vendor:product:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(result.cves[0].severity).toBeUndefined();
    expect(result.cves[0].references).toBeUndefined();
  });

  it('formats audit results with CVE IDs and severity', () => {
    const output = {
      cves: [FULL_CVE],
      queryMeta: {
        totalResults: 1,
        returned: 1,
        cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
      },
    };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('10');
    expect(text).toContain('cpe:2.3:a:apache:log4j:2.14.1');
    expect(text).toContain('CWE-20');
    expect(text).toContain('Apache Log4j2 JNDI vulnerability');
    expect(text).toContain('Apache Log4j2 Remote Code Execution Vulnerability');
  });

  it('formats sparse CVE without severity using "Not available"', () => {
    const output = {
      cves: [SPARSE_CVE],
      queryMeta: {
        totalResults: 1,
        returned: 1,
        virtualMatchString: 'cpe:2.3:a:some_vendor:product:*',
      },
    };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
    expect(text).not.toMatch(/Severity:.*undefined/);
  });

  it('formats empty audit result with no-CVE message', () => {
    const output = {
      cves: [],
      queryMeta: {
        totalResults: 0,
        returned: 0,
        cpeName: 'cpe:2.3:a:fake:product:1.0:*:*:*:*:*:*:*',
      },
    };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('No CVEs found');
    expect(text).toContain('nvd_search_cpes');
  });

  // Issue #10: malformed CPE strings should fail locally before hitting NVD
  it('throws invalid_cpe_format when cpeName does not start with cpe:2.3:', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ cpeName: 'not-a-valid-cpe' });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('throws invalid_cpe_format when virtualMatchString does not start with cpe:2.3:', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ virtualMatchString: 'garbage' });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('accepts a valid cpe:2.3: cpeName', async () => {
    mockService.auditCpe.mockResolvedValue(makeAuditResult());
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);
    expect(result.cves).toHaveLength(1);
  });
});
