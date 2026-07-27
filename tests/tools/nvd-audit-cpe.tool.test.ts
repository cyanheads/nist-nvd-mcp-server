/**
 * @fileoverview Tests for nvd_audit_cpe tool.
 * @module tests/tools/nvd-audit-cpe.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
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

/**
 * Shape NVD uses when a group AND-combines its nodes: a vulnerable firmware node plus the
 * hardware it runs on, which must both match. Mirrors CVE-2022-1292's NetApp groups.
 */
const AND_GROUP_CVE: CveRecord = {
  cveId: 'CVE-2022-1292',
  vulnStatus: 'Analyzed',
  published: '2022-05-03T00:00:00.000',
  lastModified: '2023-01-01T00:00:00.000',
  descriptions: [{ lang: 'en', value: 'c_rehash script command injection.' }],
  cvssScores: [],
  weaknesses: [],
  configurations: [
    {
      operator: 'AND',
      nodes: [
        {
          operator: 'OR',
          cpeMatch: [
            { vulnerable: true, criteria: 'cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*' },
          ],
        },
        {
          operator: 'OR',
          cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*' }],
        },
      ],
    },
  ],
};

/** Eight CPE matches in one node — two past the five-per-CVE render cap. */
const MANY_MATCH_CVE: CveRecord = {
  cveId: 'CVE-2021-44224',
  vulnStatus: 'Analyzed',
  published: '2021-12-20T00:00:00.000',
  lastModified: '2023-01-01T00:00:00.000',
  descriptions: [],
  cvssScores: [],
  weaknesses: [],
  configurations: [
    {
      nodes: [
        {
          operator: 'OR',
          cpeMatch: Array.from({ length: 8 }, (_, i) => ({
            vulnerable: true,
            criteria: `cpe:2.3:o:fedoraproject:fedora:${30 + i}:*:*:*:*:*:*:*`,
          })),
        },
      ],
    },
  ],
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
    offset: 0,
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

  it('returns CVEs and enrichment for a valid cpeName', async () => {
    mockService.auditCpe.mockResolvedValue(makeAuditResult());
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(result.cves).toHaveLength(1);
    expect(result.cves[0].cveId).toBe('CVE-2021-44228');

    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(1);
    expect(enrichment.auditTarget).toBe('cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*');
  });

  it('returns CVEs and enrichment for a virtualMatchString', async () => {
    mockService.auditCpe.mockResolvedValue(
      makeAuditResult([FULL_CVE], {
        virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
      }),
    );
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    await nvdAuditCpe.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.auditTarget).toBe('cpe:2.3:a:apache:log4j:*');
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
    const output = { cves: [FULL_CVE] };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('10');
    expect(text).toContain('CWE-20');
    expect(text).toContain('Apache Log4j2 JNDI vulnerability');
    expect(text).toContain('Apache Log4j2 Remote Code Execution Vulnerability');
  });

  // Issue #22: the Configurations block rendered bare operator lines and no CPE data.
  it('renders CPE match criteria and version bounds instead of bare operator lines', () => {
    const blocks = nvdAuditCpe.format!({ cves: [FULL_CVE] });
    const text = (blocks[0] as { text: string }).text;

    expect(text).toContain('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*');
    expect(text).toContain('>= 2.0');
    expect(text).toContain('< 2.15.0');
    expect(text).toContain('1 node group(s), 1 CPE match(es)');
    // The operator now qualifies a real criteria line rather than standing alone.
    expect(text).not.toMatch(/^\s*-\s*Operator:/m);
  });

  it('renders the group-level operator and flags non-vulnerable context matches', () => {
    const blocks = nvdAuditCpe.format!({ cves: [AND_GROUP_CVE] });
    const text = (blocks[0] as { text: string }).text;

    expect(text).toContain('cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*');
    // The AND is what marks the two nodes as jointly required rather than alternatives.
    expect(text).toContain('AND with sibling nodes');
    expect(text).toContain('not the vulnerable component');
  });

  it('caps CPE matches at five per CVE and trails with the omitted count', () => {
    const blocks = nvdAuditCpe.format!({ cves: [MANY_MATCH_CVE] });
    const text = (blocks[0] as { text: string }).text;

    expect(text).toContain('1 node group(s), 8 CPE match(es)');
    expect(text).toContain('… 3 more');
    expect(text.match(/cpe:2\.3:o:fedoraproject/g)).toHaveLength(5);
    // The trailer names what was dropped — the last three are not silently missing.
    expect(text).not.toContain('fedora:37');
  });

  it('formats sparse CVE without severity using "Not available"', () => {
    const output = { cves: [SPARSE_CVE] };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
    expect(text).not.toMatch(/Severity:.*undefined/);
  });

  it('formats empty audit result with no-CVE message', () => {
    const output = { cves: [] };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('No CVEs returned');
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

  it('enriches empty-result notice when no CVEs found', async () => {
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults: 0,
      returned: 0,
      offset: 0,
      cpeName: 'cpe:2.3:a:fake:product:1.0:*:*:*:*:*:*:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:fake:product:1.0:*:*:*:*:*:*:*',
    });
    await nvdAuditCpe.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('nvd_search_cpes');
  });

  it('returns structured empty success when severityMin filters out all NVD results (issues #17, #19)', async () => {
    // cves=[] with totalResults=3 and filteredCount=3: NVD had results, the severity filter
    // removed them all. Empty success, not an error — and the notice names the severity drop.
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults: 3,
      returned: 0,
      offset: 0,
      filteredCount: 3,
      cpeName: 'cpe:2.3:a:some:product:1.0:*:*:*:*:*:*:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:some:product:1.0:*:*:*:*:*:*:*',
      severityMin: 'CRITICAL',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(result.cves).toHaveLength(0);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(3);
    expect(enrichment.returned).toBe(0);
    expect(enrichment.severityMin).toBe('CRITICAL');
    expect(enrichment.filteredCount).toBe(3);
    // #19: the notice distinguishes a severity drop from an unknown CPE — it must NOT send the
    // agent to re-check the CPE spelling when the CPE was fine and the threshold did the cutting.
    expect(enrichment.notice).toContain('CRITICAL');
    expect(enrichment.notice).not.toContain('nvd_search_cpes');
  });

  it('surfaces severityMin and filteredCount enrichment when results pass the filter (issue #19)', async () => {
    mockService.auditCpe.mockResolvedValue({
      cves: [FULL_CVE],
      totalResults: 5,
      returned: 1,
      offset: 0,
      filteredCount: 2,
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
      severityMin: 'HIGH',
    });
    await nvdAuditCpe.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.severityMin).toBe('HIGH');
    expect(enrichment.filteredCount).toBe(2);
  });

  it('keeps the unknown-CPE notice when severityMin dropped nothing on an empty page (issue #19)', async () => {
    // virtualMatchString with an empty page: filteredCount 0 means the filter cut nothing, so the
    // right guidance is to verify the CPE, not to blame the severity threshold.
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults: 0,
      returned: 0,
      offset: 0,
      filteredCount: 0,
      virtualMatchString: 'cpe:2.3:a:nonexistent:product:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:nonexistent:product:*',
      severityMin: 'HIGH',
    });
    await nvdAuditCpe.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('nvd_search_cpes');
  });

  it('omits severityMin and filteredCount enrichment when no severityMin was set', async () => {
    mockService.auditCpe.mockResolvedValue(makeAuditResult());
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    await nvdAuditCpe.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.severityMin).toBeUndefined();
    expect(enrichment.filteredCount).toBeUndefined();
  });

  // Issue #23: allLanguages must reach the service, not sit as a dead input.
  it('threads allLanguages through to the service when set', async () => {
    mockService.auditCpe.mockResolvedValue(makeAuditResult());
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
      allLanguages: true,
    });
    await nvdAuditCpe.handler(input, ctx);

    const params = mockService.auditCpe.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(params.allLanguages).toBe(true);
  });

  // Issue #25: the advertised rate_limited code must match the client's thrown RateLimited.
  it('declares rate_limited with the RateLimited error code', () => {
    const entry = nvdAuditCpe.errors?.find((e) => e.reason === 'rate_limited');
    expect(entry?.code).toBe(JsonRpcErrorCode.RateLimited);
  });

  // Issue #31: without offset, results past the first page were unreachable at any limit.
  it('threads offset through to the service and echoes it in enrichment', async () => {
    mockService.auditCpe.mockResolvedValue(
      makeAuditResult([FULL_CVE], {
        virtualMatchString: 'cpe:2.3:a:apache:http_server:*',
        totalResults: 351,
        offset: 300,
      }),
    );
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:apache:http_server:*',
      limit: 2,
      offset: 300,
    });
    await nvdAuditCpe.handler(input, ctx);

    const params = mockService.auditCpe.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(params.offset).toBe(300);
    expect(params.limit).toBe(2);
    expect(getEnrichment(ctx).offset).toBe(300);
  });

  it('defaults offset to 0 when omitted', async () => {
    mockService.auditCpe.mockResolvedValue(makeAuditResult());
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    await nvdAuditCpe.handler(input, ctx);

    const params = mockService.auditCpe.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(params.offset).toBe(0);
    expect(getEnrichment(ctx).offset).toBe(0);
  });

  it('names the offset rather than the CPE when the page runs past the result set', async () => {
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults: 351,
      returned: 0,
      offset: 5000,
      filteredCount: 0,
      virtualMatchString: 'cpe:2.3:a:apache:http_server:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:apache:http_server:*',
      offset: 5000,
    });
    await nvdAuditCpe.handler(input, ctx);

    const notice = getEnrichment(ctx).notice as string;
    expect(notice).toContain('past the end');
    expect(notice).toContain('351');
    // The CPE matched 351 CVEs — sending the caller to re-check its spelling would be wrong.
    expect(notice).not.toContain('nvd_search_cpes');
  });

  it('keeps the severity-filter notice when an offset-0 page was emptied by severityMin', async () => {
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults: 3,
      returned: 0,
      offset: 0,
      filteredCount: 3,
      cpeName: 'cpe:2.3:a:some:product:1.0:*:*:*:*:*:*:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:some:product:1.0:*:*:*:*:*:*:*',
      severityMin: 'CRITICAL',
      offset: 0,
    });
    await nvdAuditCpe.handler(input, ctx);

    const notice = getEnrichment(ctx).notice as string;
    expect(notice).toContain('CRITICAL');
    expect(notice).not.toContain('past the end');
  });
});

/**
 * Issue #34: the fall-through told a caller to re-check the CPE whenever a page came back empty
 * for any reason the earlier branches did not name — including a valid offset inside a result set
 * NVD said had matches, where the CPE was never the problem.
 */
describe('nvdAuditCpe — empty-page notices (issue #34)', () => {
  const mockService = { auditCpe: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.auditCpe.mockReset();
  });

  /**
   * Notice raised for an empty page. `virtualMatchString` is the audit target throughout: with a
   * `cpeName`, the service throws `cpe_not_found` before a zero-total page can reach the handler.
   */
  async function noticeFor(
    offset: number,
    totalResults: number,
    extra: { severityMin?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'; filteredCount?: number } = {},
  ): Promise<string | undefined> {
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults,
      returned: 0,
      offset,
      filteredCount: extra.filteredCount ?? 0,
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    const ctx = createMockContext();
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
      offset,
      ...(extra.severityMin && { severityMin: extra.severityMin }),
    });
    await nvdAuditCpe.handler(input, ctx);
    return getEnrichment(ctx).notice;
  }

  it('blames the offset only once it has reached totalCount', async () => {
    const notice = await noticeFor(351, 351);

    expect(notice).toContain('past the end');
    expect(notice).toContain('351');
    expect(notice).not.toContain('nvd_search_cpes');
    expect(notice).not.toContain('Retry the query');
  });

  it('does not blame the audit target for an empty page inside the result range', async () => {
    const notice = await noticeFor(40, 351);

    expect(notice).not.toContain('past the end');
    expect(notice).not.toContain('nvd_search_cpes');
    expect(notice).toContain('351');
    expect(notice).toContain('40');
    expect(notice).toContain('Retry the query');
  });

  it('treats an offset one below totalCount as inside the range', async () => {
    const notice = await noticeFor(350, 351);

    expect(notice).not.toContain('past the end');
    expect(notice).toContain('Retry the query');
  });

  it('reports a genuinely unmatched audit target rather than any paging notice', async () => {
    const notice = await noticeFor(0, 0);

    expect(notice).toContain('nvd_search_cpes');
    expect(notice).not.toContain('past the end');
    expect(notice).not.toContain('Retry the query');
  });

  it('keeps the severity-drop notice ahead of the contradicted-count notice', async () => {
    // Both conditions hold: totalCount is non-zero at a valid offset AND severityMin cut the page.
    // The filter is the specific, actionable cause, so it must win.
    const notice = await noticeFor(0, 351, { severityMin: 'CRITICAL', filteredCount: 3 });

    expect(notice).toContain('CRITICAL');
    expect(notice).not.toContain('Retry the query');
    expect(notice).not.toContain('past the end');
  });

  it('falls to the contradicted-count notice when severityMin dropped nothing', async () => {
    const notice = await noticeFor(0, 351, { severityMin: 'CRITICAL', filteredCount: 0 });

    expect(notice).toContain('Retry the query');
    expect(notice).not.toContain('scored below');
    expect(notice).not.toContain('nvd_search_cpes');
  });
});

/**
 * Issue #36: nvd_audit_cpe was the only paginating tool with no partial-page signal, so a caller
 * had to infer from totalCount that more CVEs existed. Unlike the sibling search tools, `returned`
 * here is the count AFTER the client-side severityMin filter, so the next offset has to advance by
 * what NVD's page consumed (`returned + filteredCount`), not by what survived it.
 */
describe('nvdAuditCpe — next-page notice (issue #36)', () => {
  const mockService = { auditCpe: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.auditCpe.mockReset();
  });

  /** Notice for a page of `returned` surviving rows at `offset`, with `filteredCount` dropped. */
  async function noticeFor(
    offset: number,
    returned: number,
    totalResults: number,
    filteredCount = 0,
  ): Promise<string | undefined> {
    mockService.auditCpe.mockResolvedValue({
      cves: Array.from({ length: returned }, (_, i) => ({
        ...FULL_CVE,
        cveId: `CVE-2024-${String(offset + i).padStart(5, '0')}`,
      })),
      totalResults,
      returned,
      offset,
      filteredCount,
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    const ctx = createMockContext();
    await nvdAuditCpe.handler(
      nvdAuditCpe.input.parse({
        cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
        offset,
        limit: Math.max(returned + filteredCount, 1),
      }),
      ctx,
    );
    return getEnrichment(ctx).notice;
  }

  it('names the next page offset on a partial first page', async () => {
    const notice = await noticeFor(0, 3, 10);

    expect(notice).toContain('truncated');
    expect(notice).toContain('10');
    // 3 rows at offset 0 covers indices 0–2, so the next page starts at 3 — not 4.
    expect(notice).toContain('set offset to 3');
    expect(notice).not.toContain('set offset to 4');
  });

  it('advances the named offset by the page size, leaving no gap', async () => {
    const notice = await noticeFor(3, 3, 10);

    expect(notice).toContain('set offset to 6');
  });

  it('omits the notice when the page reaches the end of the result set exactly', async () => {
    expect(await noticeFor(6, 4, 10)).toBeUndefined();
    expect(await noticeFor(0, 10, 10)).toBeUndefined();
  });

  it('omits the notice when a single page carries every match', async () => {
    expect(await noticeFor(0, 1, 1)).toBeUndefined();
  });

  /**
   * The severityMin filter is what makes this tool's arithmetic differ from the search tools:
   * NVD served 3 rows and spent 3 index positions, but only 1 survived the threshold.
   */
  it('advances past rows severityMin dropped rather than re-serving them', async () => {
    const notice = await noticeFor(0, 1, 10, 2);

    // Paging on `returned` alone would say 1 and re-serve the two filtered rows at indices 1–2.
    expect(notice).toContain('set offset to 3');
    expect(notice).not.toContain('set offset to 1');
  });

  it('counts filtered rows toward reaching the end of the result set', async () => {
    // 6 consumed + offset 4 === totalCount 10: nothing remains, even though only 2 rows survived.
    expect(await noticeFor(4, 2, 10, 4)).toBeUndefined();
  });

  it('fires exactly one notice — never a next-page notice on an empty page', async () => {
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults: 10,
      returned: 0,
      offset: 99,
      filteredCount: 0,
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    const ctx = createMockContext();
    await nvdAuditCpe.handler(
      nvdAuditCpe.input.parse({
        cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
        offset: 99,
      }),
      ctx,
    );

    const notice = getEnrichment(ctx).notice as string;
    expect(notice).toContain('past the end');
    expect(notice).not.toContain('truncated');
  });
});

/**
 * The partial-page arm sits on the outer `else` of the empty-page check, so it is structurally
 * exclusive with the four empty-page branches. Assert that rather than trust it: every case must
 * raise a notice, and exactly one of the five shapes.
 */
describe('nvdAuditCpe — exactly one notice per response', () => {
  const mockService = { auditCpe: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.auditCpe.mockReset();
  });

  const SHAPES = {
    pastEnd: 'past the end',
    severityDrop: 'scored below',
    contradictedCount: 'Retry the query',
    genuineZero: 'Verify it exists in the CPE dictionary',
    partialPage: 'Results truncated',
  } as const;

  const CASES: Array<{
    name: keyof typeof SHAPES;
    result: Record<string, unknown>;
    severityMin?: 'CRITICAL';
  }> = [
    { name: 'pastEnd', result: { returned: 0, offset: 500, totalResults: 10, filteredCount: 0 } },
    {
      name: 'severityDrop',
      result: { returned: 0, offset: 0, totalResults: 10, filteredCount: 3 },
      severityMin: 'CRITICAL',
    },
    {
      name: 'contradictedCount',
      result: { returned: 0, offset: 2, totalResults: 10, filteredCount: 0 },
    },
    { name: 'genuineZero', result: { returned: 0, offset: 0, totalResults: 0, filteredCount: 0 } },
    { name: 'partialPage', result: { returned: 3, offset: 0, totalResults: 10, filteredCount: 0 } },
  ];

  it.each(CASES)('raises only the $name notice', async ({ name, result, severityMin }) => {
    const returned = result.returned as number;
    mockService.auditCpe.mockResolvedValue({
      ...result,
      cves: Array.from({ length: returned }, () => FULL_CVE),
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    const ctx = createMockContext();
    await nvdAuditCpe.handler(
      nvdAuditCpe.input.parse({
        virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
        offset: result.offset as number,
        ...(severityMin && { severityMin }),
      }),
      ctx,
    );

    const notice = getEnrichment(ctx).notice as string;
    expect(notice).toBeDefined();
    expect(notice).toContain(SHAPES[name]);

    // Every other shape must be absent — the branches cannot both fire.
    for (const [shapeName, marker] of Object.entries(SHAPES)) {
      if (shapeName !== name) expect(notice).not.toContain(marker);
    }
  });
});
