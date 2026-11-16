/**
 * @fileoverview Tests for nvd_audit_cpe tool.
 * @module tests/tools/nvd-audit-cpe.tool.test
 */

import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { escapeMarkdownInline, markdownLink } from '@cyanheads/mcp-ts-core/utils';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { toJSONSchema } from 'zod/v4/core';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { CveRecord } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';
import * as nvdSourceServiceModule from '@/services/nvd-source/nvd-source-service.js';
import { at } from '../support/at.js';
import { CVE_2021_3007, CVE_2024_23225, nvdFake } from '../support/nvd-affected-fixtures.js';

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
  configurationNodes: [
    {
      groupIndex: 0,
      nodeOperator: 'OR',
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
  references: [
    { url: 'https://logging.apache.org/log4j/2.x/security.html', tags: ['Vendor Advisory'] },
  ],
  cisaKev: {
    exploitAddDate: '2021-12-10',
    actionDueDate: '2021-12-24',
    requiredAction: 'Apply updates per vendor instructions.',
    vulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
  },
  affectedProducts: [],
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
  configurationNodes: [
    {
      groupIndex: 0,
      groupOperator: 'AND',
      nodeOperator: 'OR',
      cpeMatch: [
        { vulnerable: true, criteria: 'cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*' },
        { vulnerable: true, criteria: 'cpe:2.3:o:netapp:a700s_firmware:9.0:*:*:*:*:*:*:*' },
      ],
    },
    {
      groupIndex: 0,
      groupOperator: 'AND',
      nodeOperator: 'OR',
      cpeMatch: [{ vulnerable: false, criteria: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*' }],
    },
  ],
  affectedProducts: [],
};

/** Eight CPE matches split across two groups, beyond the former render cap. */
const MANY_MATCH_CVE: CveRecord = {
  cveId: 'CVE-2021-44224',
  vulnStatus: 'Analyzed',
  published: '2021-12-20T00:00:00.000',
  lastModified: '2023-01-01T00:00:00.000',
  descriptions: [],
  cvssScores: [],
  weaknesses: [],
  configurationNodes: [
    {
      groupIndex: 0,
      nodeOperator: 'OR',
      cpeMatch: Array.from({ length: 3 }, (_, i) => ({
        vulnerable: true,
        criteria: `cpe:2.3:o:fedoraproject:fedora:${30 + i}:*:*:*:*:*:*:*`,
      })),
    },
    {
      groupIndex: 1,
      nodeOperator: 'OR',
      cpeMatch: Array.from({ length: 5 }, (_, i) => ({
        vulnerable: true,
        criteria: `cpe:2.3:o:fedoraproject:fedora:${33 + i}:*:*:*:*:*:*:*`,
      })),
    },
  ],
  affectedProducts: [],
};

const SPARSE_CVE: CveRecord = {
  cveId: 'CVE-2022-11111',
  vulnStatus: 'Awaiting Analysis',
  published: '2022-06-01T00:00:00.000',
  lastModified: '2022-06-02T00:00:00.000',
  descriptions: [],
  cvssScores: [],
  weaknesses: [],
  configurationNodes: [],
  affectedProducts: [],
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

describe('nvdAuditCpe — full rendering parity', () => {
  const record: CveRecord = {
    ...MANY_MATCH_CVE,
    descriptions: [
      { lang: 'en', value: `**literal**\n- ${'detail '.repeat(60)}` },
      { lang: 'es', value: '<b>texto</b>' },
    ],
    references: Array.from({ length: 7 }, (_, i) => ({
      url: `https://example.test/${i}?x=[a]`,
      source: 'name`\n[source]',
      tags: ['**advisory**'],
    })),
  };
  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
      auditCpe: vi.fn().mockResolvedValue(makeAuditResult([record], { filteredCount: 0 })),
    } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
  });
  it('characterizes full structured records without trimming nested sections', async () => {
    const result = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
      allLanguages: true,
    });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ cves: [record] });
  });
  it.each([
    {
      includeConfigurations: false,
      includeReferences: true,
      omitted: 'configurationNodes',
      marker: '**Configurations:**',
    },
    {
      includeConfigurations: true,
      includeReferences: false,
      omitted: 'references',
      marker: '**References (',
    },
  ])(
    'omits $omitted on both surfaces without mutating service records (issue #61)',
    async ({ includeConfigurations, includeReferences, omitted, marker }) => {
      const result = await runToolContract(nvdAuditCpe, {
        cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
        includeConfigurations,
        includeReferences,
      } as never);
      expect(result.isError).toBeFalsy();
      expect(result.structuredContent).toMatchObject({
        cves: [expect.not.objectContaining({ [omitted]: expect.anything() })],
      });
      expect(
        result.content
          .filter((block) => block.type === 'text')
          .map((block) => block.text)
          .join('\n'),
      ).not.toContain(marker);
      expect(record.configurationNodes).toHaveLength(2);
      expect(record.references).toHaveLength(7);
    },
  );
  it('keeps default and explicit selectors identical (issue #61)', async () => {
    const defaults = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
    });
    const explicit = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
      includeConfigurations: true,
      includeReferences: true,
    } as never);
    expect(explicit.structuredContent).toEqual(defaults.structuredContent);
    expect(explicit.content).toEqual(defaults.content);
  });
  it('omits both selected sections on an empty past-end page (issue #61)', async () => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
      auditCpe: vi
        .fn()
        .mockResolvedValue(makeAuditResult([], { totalResults: 1, offset: 1, filteredCount: 0 })),
    } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
    const result = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
      offset: 1,
      includeConfigurations: false,
      includeReferences: false,
    });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({
      cves: [],
      offset: 1,
      returned: 0,
      notice: expect.stringContaining('past the end'),
    });
    expect(result.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ text: expect.stringContaining('No CVEs returned') }),
      ]),
    );
  });
  it('rejects nonboolean section selectors (issue #61)', () => {
    expect(nvdAuditCpe.input.safeParse({ includeConfigurations: 'false' }).success).toBe(false);
    expect(nvdAuditCpe.input.safeParse({ includeReferences: 'false' }).success).toBe(false);
  });
  it('renders every reference, nested criterion and language without losing literal text', async () => {
    const result = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
      allLanguages: true,
    });
    const text = result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
    for (const reference of record.references!)
      expect(text).toContain(markdownLink(reference.url, reference.url));
    for (const node of record.configurationNodes)
      for (const match of node.cpeMatch)
        expect(text).toContain(escapeMarkdownInline(match.criteria));
    for (const description of record.descriptions)
      expect(text).toContain(escapeMarkdownInline(description.value));
    expect(text).toContain(escapeMarkdownInline('name`\n[source]'));
    expect(text).toContain(escapeMarkdownInline('**advisory**'));
    expect(text).not.toContain('…');
  });
  it.each([
    [
      'nvd_invalid_response',
      JsonRpcErrorCode.ServiceUnavailable,
      false,
      'Retry later; report a persistent invalid NVD response.',
    ],
    [
      'nvd_request_blocked',
      JsonRpcErrorCode.Forbidden,
      false,
      'Rephrase query text; otherwise try later or use another network.',
    ],
    [
      'rate_limited',
      JsonRpcErrorCode.RateLimited,
      true,
      'Wait for the NVD rate window to reset, then retry; a server operator can set NVD_API_KEY for higher limits.',
    ],
    [
      'nvd_unavailable',
      JsonRpcErrorCode.ServiceUnavailable,
      true,
      'NVD is failing or unreachable; wait a minute and retry the call.',
    ],
    [
      'nvd_timeout',
      JsonRpcErrorCode.Timeout,
      true,
      'NVD did not answer in time; retry in a minute. A server operator can raise NVD_REQUEST_TIMEOUT_MS.',
    ],
    [
      'nvd_invalid_api_key',
      JsonRpcErrorCode.ConfigurationError,
      false,
      "NVD refused this server's NVD_API_KEY, so no NVD call can succeed until a server operator fixes it: verify the key, request a replacement at https://nvd.nist.gov/developers/request-an-api-key, or unset NVD_API_KEY to run keyless at 5 req/30s.",
    ],
  ] as const)(
    'renders the %s recovery on both error surfaces',
    async (reason, code, retryable, hint) => {
      vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
        auditCpe: vi.fn().mockRejectedValue(new McpError(code, 'NVD request failed.', { reason })),
      } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
      const result = await runToolContract(nvdAuditCpe, {
        cpeName: 'cpe:2.3:a:vendor:product:1:*:*:*:*:*:*:*',
      });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: { code, data: { reason, recovery: { hint } } },
      });
      expect(result.content).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'text', text: expect.stringContaining(hint) }),
        ]),
      );
      expect(nvdAuditCpe.errors?.find((entry) => entry.reason === reason)).toMatchObject({
        thrownBy: 'service',
        retryable,
      });
    },
  );
});

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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(result.cves).toHaveLength(1);
    expect(at(result.cves, 0).cveId).toBe('CVE-2021-44228');

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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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

  // Issue #40: no CVEs for a cpeName is a clean audit result, so nothing is declared for it.
  it('declares no cpe_not_found failure mode', () => {
    expect(nvdAuditCpe.errors?.map((e) => e.reason)).not.toContain('cpe_not_found');
  });

  it('handles sparse CVE without severity or references', async () => {
    mockService.auditCpe.mockResolvedValue(
      makeAuditResult([SPARSE_CVE], {
        virtualMatchString: 'cpe:2.3:a:some_vendor:product:*',
      }),
    );
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      virtualMatchString: 'cpe:2.3:a:some_vendor:product:*',
    });
    const result = await nvdAuditCpe.handler(input, ctx);

    expect(at(result.cves, 0).severity).toBeUndefined();
    expect(at(result.cves, 0).references).toBeUndefined();
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

    expect(text).toContain(escapeMarkdownInline('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'));
    expect(text).toContain('>= 2.0');
    expect(text).toContain('< 2.15.0');
    expect(text).toContain('1 configuration group(s), 1 node(s), 1 CPE match(es)');
    // The operator now qualifies a real criteria line rather than standing alone.
    expect(text).not.toMatch(/^\s*-\s*Operator:/m);
  });

  it('renders both operators and the group index, and flags non-vulnerable context matches', () => {
    const blocks = nvdAuditCpe.format!({ cves: [AND_GROUP_CVE] });
    const text = (blocks[0] as { text: string }).text;

    // Two AND-combined nodes, three criteria: (firmware- OR firmware9.0) AND hardware.
    expect(text).toContain('1 configuration group(s), 2 node(s), 3 CPE match(es)');
    expect(text).toContain(escapeMarkdownInline('cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*'));
    // The group AND marks the two nodes as jointly required; the node OR combines the two
    // firmware criteria as alternatives. Both, plus the shared group, must reach content[].
    expect(text).toContain(
      '[group 0; AND with sibling nodes; OR within node; vulnerable component]',
    );
    expect(text).toContain(
      escapeMarkdownInline('cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*') +
        ' [group 0; AND with sibling nodes; OR within node; not the vulnerable component]',
    );
  });

  it('renders all criteria across nodes past the former cap', () => {
    const blocks = nvdAuditCpe.format!({ cves: [MANY_MATCH_CVE] });
    const text = (blocks[0] as { text: string }).text;

    expect(text).toContain('2 configuration group(s), 2 node(s), 8 CPE match(es)');
    expect(text).not.toContain('… 3 more');
    expect(text.match(/cpe:2\.3:o:fedoraproject/g)).toHaveLength(8);
    expect(text).toContain(
      escapeMarkdownInline('cpe:2.3:o:fedoraproject:fedora:34:*:*:*:*:*:*:*') + ' [group 1',
    );
    expect(text).toContain('fedora:35');
    expect(text).toContain('fedora:37');
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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

  /** Notice raised for an empty page, on either input arm — both reach the handler alike (#40). */
  async function noticeFor(
    offset: number,
    totalResults: number,
    extra: {
      severityMin?: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
      filteredCount?: number;
      cpeName?: string;
    } = {},
  ): Promise<string | undefined> {
    const target = extra.cpeName
      ? { cpeName: extra.cpeName }
      : { virtualMatchString: 'cpe:2.3:a:apache:log4j:*' };
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults,
      returned: 0,
      offset,
      filteredCount: extra.filteredCount ?? 0,
      ...target,
    });
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({
      ...target,
      offset,
      ...(extra.severityMin && { severityMin: extra.severityMin }),
    });
    await nvdAuditCpe.handler(input, ctx);
    const { notice } = getEnrichment(ctx);
    return typeof notice === 'string' ? notice : undefined;
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

  /**
   * A zero-CVE target is the audit's finding. The notice leads with that and keeps the
   * unconfirmed CPE string as the caveat, rather than opening on a diagnosis of the input (#40).
   */
  it('leads with the clean-audit finding and keeps the CPE caveat second', async () => {
    const notice = await noticeFor(0, 0);

    expect(notice).toContain('a clean audit, not a failed one');
    expect(notice?.indexOf('No CVEs in NVD')).toBeLessThan(
      notice?.indexOf('nvd_search_cpes') ?? -1,
    );
    expect(notice).not.toContain('past the end');
    expect(notice).not.toContain('Retry the query');
  });

  // Issue #40: the cpeName arm used to fail before this notice could be reached.
  it('gives a cpeName with no CVEs the same empty-page notice as a virtualMatchString', async () => {
    const viaCpeName = await noticeFor(0, 0, {
      cpeName: 'cpe:2.3:a:gnu:gnubiff:-:*:*:*:*:*:*:*',
    });

    expect(viaCpeName).toBe(await noticeFor(0, 0));
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    await nvdAuditCpe.handler(
      nvdAuditCpe.input.parse({
        cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
        offset,
        limit: Math.max(returned + filteredCount, 1),
      }),
      ctx,
    );
    const { notice } = getEnrichment(ctx);
    return typeof notice === 'string' ? notice : undefined;
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
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
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
 * exclusive with the empty-page branches. Assert that rather than trust it: every case must raise
 * a notice, and exactly one of the shapes. A page severityMin emptied splits by whether CVEs remain
 * past it (#69), and a zero total under a server-side filter is its own shape (#68).
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
    severityDropMidRange: 'To continue at this threshold',
    severityDropExhausted: 'exhausted at this threshold',
    contradictedCount: 'Retry the query',
    genuineZero: 'a clean audit, not a failed one',
    filteredZero: 'match the applied filters',
    partialPage: 'Results truncated',
  } as const;

  const CASES: Array<{
    name: keyof typeof SHAPES;
    result: Record<string, unknown>;
    severityMin?: 'CRITICAL';
    kevOnly?: true;
  }> = [
    { name: 'pastEnd', result: { returned: 0, offset: 500, totalResults: 10, filteredCount: 0 } },
    {
      name: 'severityDropMidRange',
      result: { returned: 0, offset: 0, totalResults: 10, filteredCount: 3 },
      severityMin: 'CRITICAL',
    },
    {
      name: 'severityDropExhausted',
      result: { returned: 0, offset: 7, totalResults: 10, filteredCount: 3 },
      severityMin: 'CRITICAL',
    },
    {
      name: 'contradictedCount',
      result: { returned: 0, offset: 2, totalResults: 10, filteredCount: 0 },
    },
    { name: 'genuineZero', result: { returned: 0, offset: 0, totalResults: 0, filteredCount: 0 } },
    {
      name: 'filteredZero',
      result: { returned: 0, offset: 0, totalResults: 0, filteredCount: 0 },
      kevOnly: true,
    },
    { name: 'partialPage', result: { returned: 3, offset: 0, totalResults: 10, filteredCount: 0 } },
  ];

  it.each(CASES)('raises only the $name notice', async ({ name, result, severityMin, kevOnly }) => {
    const returned = result.returned as number;
    mockService.auditCpe.mockResolvedValue({
      ...result,
      cves: Array.from({ length: returned }, () => FULL_CVE),
      virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
    });
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    await nvdAuditCpe.handler(
      nvdAuditCpe.input.parse({
        virtualMatchString: 'cpe:2.3:a:apache:log4j:*',
        offset: result.offset as number,
        ...(severityMin && { severityMin }),
        ...(kevOnly && { kevOnly }),
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

/**
 * Issue #69: a page severityMin emptied named no way forward, though NVD spent index positions on
 * every row it dropped. While rows remain past that span the notice names `offset + filteredCount`,
 * as a partly filtered page does; once the span reaches totalCount the target is exhausted at this
 * threshold, and raising limit would fetch nothing new.
 */
describe('nvdAuditCpe — page emptied by severityMin (issue #69)', () => {
  const cpeName = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
  const mockService = { auditCpe: vi.fn() };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-15T20:00:00.000Z'));
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.auditCpe.mockReset();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  /** Both surfaces of an audit whose fetched page at `offset` lost all `dropped` rows. */
  async function emptiedPage(offset: number, dropped: number, totalResults: number, extra = {}) {
    mockService.auditCpe.mockResolvedValue({
      cves: [],
      totalResults,
      returned: 0,
      offset,
      filteredCount: dropped,
      cpeName,
    });
    const result = await runToolContract(nvdAuditCpe, {
      cpeName,
      limit: Math.max(dropped, 1),
      offset,
      severityMin: 'CRITICAL',
      ...extra,
    });
    const text = result.content
      .flatMap((block) => (block.type === 'text' ? [block.text] : []))
      .join('\n');
    return { notice: (result.structuredContent as { notice?: string }).notice, text, result };
  }

  it.each([
    [0, 1, 88, 1],
    [40, 5, 88, 45],
  ])(
    'names offset + filteredCount for a page emptied at offset %i (%i dropped of %i)',
    async (offset, dropped, total, next) => {
      const { notice, text, result } = await emptiedPage(offset, dropped, total);
      const expected = `All ${dropped} CVE(s) on the fetched page scored below CRITICAL. To continue at this threshold, set offset to ${next} for the next page. Lower severityMin or raise limit to widen the page NVD returns.`;

      expect(notice).toBe(expected);
      expect(text).toContain(expected);
      expect(result.structuredContent).toMatchObject({
        totalCount: total,
        returned: 0,
        offset,
        filteredCount: dropped,
      });
    },
  );

  it.each([
    [87, 1, 88],
    [85, 5, 88],
  ])(
    'reports the target exhausted at this threshold once offset %i + %i dropped reaches %i',
    async (offset, dropped, total) => {
      const { notice, text } = await emptiedPage(offset, dropped, total);
      const expected = `All ${dropped} CVE(s) on the fetched page scored below CRITICAL, and that page reached the end of the ${total} CVE(s) matching this audit target: the target is exhausted at this threshold. Lower severityMin to see the CVEs it dropped.`;

      expect(notice).toBe(expected);
      expect(text).toContain(expected);
      expect(notice).not.toContain('set offset');
      expect(notice).not.toContain('raise limit');
    },
  );

  it('keeps the past-the-end notice at an offset equal to totalCount', async () => {
    const { notice } = await emptiedPage(88, 0, 88);

    expect(notice).toBe(
      'Offset 88 is past the end of the result set (88 total). Use a lower offset to page through results.',
    );
  });

  it('names the echoed dates when a shorthand set the emptied page’s window', async () => {
    const { notice } = await emptiedPage(0, 1, 88, { lastModDays: 30 });

    expect(notice).toBe(
      'All 1 CVE(s) on the fetched page scored below CRITICAL. To continue at this threshold, set offset to 1 for the next page and send lastModStartDate and lastModEndDate from filtersApplied instead of lastModDays, so the next page reads the same window. Lower severityMin or raise limit to widen the page NVD returns.',
    );
  });
});

/**
 * Issue #68: server-side kevOnly, severity-band, and date-window filters. The window grammar,
 * pairs, ceiling, expansion, and each resolver reason are tabled at the parser's seam
 * (`tests/tools/date-windows.test.ts`, which runs the reasons through both tools); these prove the
 * audit's wiring from tool input through the real service to the outgoing NVD request, and its
 * echo, notices, and contract on both surfaces.
 */
describe('nvdAuditCpe — server-side filters (issue #68)', () => {
  const cpeName = 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*';
  const mockClient = { get: vi.fn() };

  /** An NVD row scored v3.1 HIGH that also carries a v4.0 CRITICAL band. */
  const V3_HIGH_V4_CRITICAL = {
    cve: {
      id: 'CVE-2024-1000',
      metrics: {
        cvssMetricV31: [{ cvssData: { baseScore: 8.1, baseSeverity: 'HIGH' } }],
        cvssMetricV40: [{ cvssData: { baseScore: 9.3, baseSeverity: 'CRITICAL' } }],
      },
    },
  };
  const V3_HIGH = {
    cve: {
      id: 'CVE-2024-1001',
      metrics: { cvssMetricV31: [{ cvssData: { baseScore: 7.5, baseSeverity: 'HIGH' } }] },
    },
  };

  const FILTERED_ZERO =
    'No CVEs for this audit target match the applied filters (see filtersApplied) — this is not a clean audit. Widen or drop a filter; an unfiltered audit shows whether NVD holds any CVEs for the target.';

  const textOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
  const noticeOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    (result.structuredContent as { notice?: string }).notice;
  const sentParams = (call = 0) => mockClient.get.mock.calls[call]?.[1] as Record<string, unknown>;

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-11-15T20:00:00.000Z'));
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      mockClient as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      new NvdCveService({} as never, {} as never),
    );
    vi.spyOn(nvdSourceServiceModule, 'getNvdSourceService').mockReturnValue({
      getResolver: async () => nvdSourceServiceModule.passthroughSourceNames,
    } as unknown as ReturnType<typeof nvdSourceServiceModule.getNvdSourceService>);
    mockClient.get.mockReset();
    mockClient.get.mockResolvedValue({
      totalResults: 2,
      vulnerabilities: [V3_HIGH_V4_CRITICAL, V3_HIGH],
    });
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const ARMS = [
    ['cpeName', { cpeName }, { cpeName, isVulnerable: true }],
    [
      'virtualMatchString',
      {
        virtualMatchString: 'cpe:2.3:a:apache:http_server:*',
        versionStart: '2.4.49',
        versionEnd: '2.4.50',
      },
      {
        virtualMatchString: 'cpe:2.3:a:apache:http_server:*',
        versionStart: '2.4.49',
        versionStartType: 'including',
        versionEnd: '2.4.50',
        versionEndType: 'including',
      },
    ],
  ] as const;

  it.each(ARMS)(
    'sends kevOnly, a KEV window, a shorthand window, and the band to NVD on the %s arm, echoing each on both surfaces',
    async (_arm, target, sentTarget) => {
      const result = await runToolContract(nvdAuditCpe, {
        ...target,
        kevOnly: true,
        kevStartDate: '2021-10-01T00:00:00.000Z',
        kevEndDate: '2022-01-15T00:00:00.000Z',
        lastModDays: 30,
        severity: 'CRITICAL',
      });
      const echoed = {
        severity: 'CRITICAL',
        severityVersion: 'v3',
        lastModStartDate: '2026-10-16T20:00:00.000Z',
        lastModEndDate: '2026-11-15T20:00:00.000Z',
        kevStartDate: '2021-10-01T00:00:00.000Z',
        kevEndDate: '2022-01-15T00:00:00.000Z',
        kevOnly: true,
      };

      expect(result.isError).toBeFalsy();
      expect(sentParams()).toEqual({
        resultsPerPage: 20,
        startIndex: 0,
        ...sentTarget,
        hasKev: true,
        lastModStartDate: echoed.lastModStartDate,
        lastModEndDate: echoed.lastModEndDate,
        kevStartDate: echoed.kevStartDate,
        kevEndDate: echoed.kevEndDate,
        cvssV3Severity: 'CRITICAL',
      });
      expect(result.structuredContent).toHaveProperty('filtersApplied', echoed);
      expect(result.structuredContent).not.toHaveProperty('datesClamped');
      const text = textOf(result);
      expect(text).toContain('**Filters applied:** severity=CRITICAL, severityVersion=v3, ');
      for (const [key, value] of Object.entries(echoed)) expect(text).toContain(`${key}=${value}`);
    },
  );

  it('reports a shorthand clamped to 120 days on both surfaces', async () => {
    const result = await runToolContract(nvdAuditCpe, { cpeName, pubDays: 200 });

    expect(sentParams()).toMatchObject({
      pubStartDate: '2026-07-18T20:00:00.000Z',
      pubEndDate: '2026-11-15T20:00:00.000Z',
    });
    expect(result.structuredContent).toHaveProperty('datesClamped', [
      { param: 'pubDays', original: 200, clamped: 120 },
    ]);
    expect(textOf(result)).toContain(
      'pubDays value 200 exceeded the 120-day maximum and was clamped to 120.',
    );
  });

  it('sends the band on the parameter severityVersion names', async () => {
    const result = await runToolContract(nvdAuditCpe, {
      cpeName,
      severity: 'HIGH',
      severityVersion: 'v2',
    });

    expect(sentParams()).toMatchObject({ cvssV2Severity: 'HIGH' });
    expect(sentParams()).not.toHaveProperty('cvssV3Severity');
    expect(result.structuredContent).toHaveProperty('filtersApplied', {
      severity: 'HIGH',
      severityVersion: 'v2',
    });
  });

  it('rejects CRITICAL on CVSS v2 before any request, with its recovery on both surfaces', async () => {
    const result = await runToolContract(nvdAuditCpe, {
      cpeName,
      severity: 'CRITICAL',
      severityVersion: 'v2',
    });
    const hint = 'Use LOW, MEDIUM, or HIGH when severityVersion is';

    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: {
          reason: 'invalid_severity_for_version',
          recovery: { hint: expect.stringContaining(hint) },
        },
      },
    });
    expect(textOf(result)).toContain(hint);
    expect(mockClient.get).not.toHaveBeenCalled();
  });

  it('declares the band and window reasons exactly as nvd_search_cves does', () => {
    for (const reason of [
      'invalid_severity_for_version',
      'mutually_exclusive_params',
      'missing_date_pair',
      'invalid_date_format',
      'date_range_inverted',
      'date_range_exceeds_max',
    ]) {
      const declared = nvdAuditCpe.errors?.find((entry) => entry.reason === reason);
      expect(declared, reason).toBeDefined();
      expect(declared, reason).toEqual(
        nvdSearchCves.errors?.find((entry) => entry.reason === reason),
      );
    }
  });

  /**
   * The ruled AND: NVD narrows to the v3 band, so totalCount counts the band; severityMin then
   * filters the fetched page across every version — keeping the v3-HIGH row whose v4 band is
   * CRITICAL — and the next offset still advances past the row it dropped.
   */
  it('composes severity with severityMin: band total, page drop count, and paging past the drop', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 13,
      vulnerabilities: [V3_HIGH_V4_CRITICAL, V3_HIGH],
    });
    const result = await runToolContract(nvdAuditCpe, {
      cpeName,
      severity: 'HIGH',
      severityMin: 'CRITICAL',
      limit: 2,
    });

    expect(sentParams()).toMatchObject({ cvssV3Severity: 'HIGH', resultsPerPage: 2 });
    expect(result.structuredContent).toMatchObject({
      cves: [{ cveId: 'CVE-2024-1000' }],
      totalCount: 13,
      returned: 1,
      filteredCount: 1,
      severityMin: 'CRITICAL',
      filtersApplied: { severity: 'HIGH', severityVersion: 'v3' },
      notice:
        'Results truncated — 13 CVEs match this audit target; set offset to 2 for the next page.',
    });
  });

  it.each([
    ['kevOnly', { kevOnly: true }],
    ['severity', { severity: 'CRITICAL', severityVersion: 'v4' }],
    ['a date window', { lastModDays: 7 }],
  ] as const)(
    'answers a zero total under %s with the filter-aware notice on both surfaces',
    async (_filter, filters) => {
      mockClient.get.mockResolvedValue({ totalResults: 0, vulnerabilities: [] });
      const result = await runToolContract(nvdAuditCpe, { cpeName, ...filters });

      expect(noticeOf(result)).toBe(FILTERED_ZERO);
      expect(textOf(result)).toContain(FILTERED_ZERO);
      expect(noticeOf(result)).not.toContain('a clean audit, not a failed one');
      expect(noticeOf(result)).not.toContain('nvd_search_cpes');
    },
  );

  it('adds no parameter, echo, or notice to an audit without the new inputs', async () => {
    const result = await runToolContract(nvdAuditCpe, { cpeName, severityVersion: 'v4' });

    expect(sentParams()).toEqual({
      resultsPerPage: 20,
      startIndex: 0,
      cpeName,
      isVulnerable: true,
    });
    expect(result.structuredContent).not.toHaveProperty('filtersApplied');
    expect(result.structuredContent).not.toHaveProperty('datesClamped');
    expect(result.structuredContent).not.toHaveProperty('notice');
    expect(textOf(result)).not.toContain('Filters applied');
  });

  it('discloses a blank date field without forwarding it, and trims a padded one', async () => {
    const blank = await runToolContract(nvdAuditCpe, { cpeName, pubStartDate: ' \t ' });

    expect(blank.isError).toBeFalsy();
    expect(sentParams()).not.toHaveProperty('pubStartDate');
    expect(blank.structuredContent).not.toHaveProperty('filtersApplied');
    expect(noticeOf(blank)).toBe('Ignored empty pubStartDate.');
    expect(textOf(blank)).toContain('Ignored empty pubStartDate.');

    const dates = {
      pubStartDate: '2026-11-01T00:00:00.000Z',
      pubEndDate: '2026-11-02T00:00:00.000Z',
    };
    const padded = await runToolContract(nvdAuditCpe, {
      cpeName,
      pubStartDate: ` ${dates.pubStartDate} `,
      pubEndDate: `${dates.pubEndDate}\n`,
    });

    expect(sentParams(1)).toMatchObject(dates);
    expect(padded.structuredContent).toHaveProperty('filtersApplied', dates);
  });

  it('names the echoed dates on a shorthand next page, flags re-expansion past offset 0, and replays exactly', async () => {
    mockClient.get.mockResolvedValue({
      totalResults: 39,
      vulnerabilities: [V3_HIGH_V4_CRITICAL, V3_HIGH],
    });
    const nextPage =
      'Results truncated — 39 CVEs match this audit target; set offset to 2 for the next page and send lastModStartDate and lastModEndDate from filtersApplied instead of lastModDays, so the next page reads the same window.';
    const reexpanded =
      'lastModDays was expanded at call time, so the window in filtersApplied can differ from the one earlier pages read; to page one fixed window, send the dates echoed on the first page instead of lastModDays.';

    const first = await runToolContract(nvdAuditCpe, { cpeName, lastModDays: 30, limit: 2 });
    expect(noticeOf(first)).toBe(nextPage);
    expect(textOf(first)).toContain(nextPage);

    const later = await runToolContract(nvdAuditCpe, {
      cpeName,
      lastModDays: 30,
      limit: 2,
      offset: 2,
    });
    // Past offset 0 filtersApplied holds this call's window, so only the first page's dates are named.
    expect(noticeOf(later)).toBe(
      `Results truncated — 39 CVEs match this audit target; set offset to 4 for the next page. ${reexpanded}`,
    );
    expect(textOf(later)).toContain(reexpanded);

    const echoed = (first.structuredContent as { filtersApplied: Record<string, string> })
      .filtersApplied;
    await runToolContract(nvdAuditCpe, { cpeName, ...echoed, limit: 2 });
    expect(sentParams(2)).toEqual(sentParams(0));
  });
});

/**
 * Issue #37: the full-record shape now lives in one place (`tools/schemas/full-cve.ts`) that
 * `nvd_get_cve` also builds from. Consolidation was meant to leave this tool's advertised contract
 * exactly as it was — pin the field list and the required set so a later edit to the shared schema
 * cannot quietly change what this tool promises.
 */
describe('nvdAuditCpe — advertised record contract (issue #37)', () => {
  const item = (
    toJSONSchema(nvdAuditCpe.output as never, {
      io: 'output',
      unrepresentable: 'any',
    }) as unknown as {
      properties: { cves: { items: { properties: Record<string, unknown>; required: string[] } } };
    }
  ).properties.cves.items;

  it('advertises the full-record fields including optional SSVC', () => {
    expect(Object.keys(item.properties)).toEqual([
      'cveId',
      'vulnStatus',
      'published',
      'lastModified',
      'descriptions',
      'cvssScores',
      'severity',
      'ssvc',
      'weaknesses',
      'configurationNodes',
      'references',
      'cisaKev',
      'sourceIdentifier',
      'cveTags',
      'affectedProducts',
    ]);
  });

  /** Configuration selectors may omit nodes; other optional fields depend on upstream data. */
  it('requires only the fields the normalizer assigns unconditionally', () => {
    expect(item.required).toEqual([
      'cveId',
      'vulnStatus',
      'published',
      'lastModified',
      'descriptions',
      'cvssScores',
      'weaknesses',
    ]);
  });
});

/**
 * Issue #45: an NVD CPE parameter rejection used to reach the caller as `nvd_request_rejected` —
 * a reason this tool never declares — with no `Recovery:` line on the rendered error.
 */
describe('nvdAuditCpe — NVD CPE rejection carries the declared contract (issue #45)', () => {
  const mockService = { auditCpe: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.auditCpe.mockReset();
  });

  it('surfaces a service-translated rejection as the declared invalid_cpe_format', async () => {
    const service = new NvdCveService({} as never, {} as never);
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(service);
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue({
      get: vi
        .fn()
        .mockRejectedValue(
          nvdHttpClientModule.nvdRequestRejected(
            'cves/2.0',
            'Invalid cpeName parameter, see documentation.',
          ),
        ),
    } as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>);

    // Through the contract boundary: the declared recovery is filled there, not at the throw site.
    const result = await runToolContract(nvdAuditCpe, { cpeName: 'cpe:2.3:a:zzznotavendor' });

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        data: {
          reason: 'invalid_cpe_format',
          recovery: { hint: expect.stringContaining('nvd_search_cpes') },
        },
      },
    });
  });

  /**
   * Live: a valid CPE with `pubStartDate: "2026-11-01T00:00:00+23:59"` drew NVD's 404 `Invalid ISO
   * 8601 date/time format`, which reached the caller as `invalid_cpe_format` with a recovery to
   * re-resolve the CPE. The fault is the date, so the caller gets NVD's diagnosis under the
   * declared `nvd_request_rejected`, whose recovery names the date form.
   */
  it('surfaces a date rejection as the declared nvd_request_rejected, not a CPE fault', async () => {
    const service = new NvdCveService({} as never, {} as never);
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(service);
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue({
      get: vi
        .fn()
        .mockRejectedValue(
          nvdHttpClientModule.nvdRequestRejected(
            'cves/2.0',
            'Invalid ISO 8601 date/time format, see documentation.',
          ),
        ),
    } as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>);

    const result = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
      pubStartDate: '2026-11-01T00:00:00+12:00',
      pubEndDate: '2026-11-02T00:00:00Z',
    });
    const text = result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: {
          reason: 'nvd_request_rejected',
          recovery: { hint: expect.stringContaining('YYYY-MM-DDThh:mm') },
        },
      },
    });
    expect(text).toContain('Invalid ISO 8601 date/time format');
    expect(text).not.toContain('Invalid CPE string');
  });

  it('names both causes of invalid_cpe_format in the error contract', () => {
    const entry = nvdAuditCpe.errors?.find((e) => e.reason === 'invalid_cpe_format');
    expect(entry?.when).toContain('cpe:2.3:');
    expect(entry?.when).toContain('NVD rejected');
  });
});

/**
 * Both surfaces at once, through the real `tools/call` path: `structuredContent` is parsed against
 * the advertised output schema, and `content[]` comes from `format()`. A client reading either one
 * has to be able to reconstruct the same applicability logic, so the node boundaries and the group
 * they belong to are asserted on both.
 */
describe('nvdAuditCpe — configuration nodes reach structuredContent and content[]', () => {
  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
      auditCpe: vi.fn().mockResolvedValue(
        makeAuditResult([AND_GROUP_CVE], {
          cpeName: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*',
          filteredCount: 0,
        }),
      ),
    } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
  });

  it('carries each node whole, tagged with its group, on both surfaces', async () => {
    const result = await runToolContract(nvdAuditCpe, {
      cpeName: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*',
    } as never);

    expect(result.isError).toBeFalsy();

    const nodes = (
      result.structuredContent as {
        cves: Array<{ configurationNodes: Array<Record<string, unknown>> }>;
      }
    ).cves[0]?.configurationNodes;

    // Two nodes, not one merged array: the group's AND joins nodes, so a single array of three
    // criteria would read as three ANDed products rather than (firmware OR firmware) AND hardware.
    expect(nodes).toHaveLength(2);
    expect(at(nodes, 0)).toMatchObject({ groupIndex: 0, groupOperator: 'AND', nodeOperator: 'OR' });
    expect(at(nodes, 0).cpeMatch).toHaveLength(2);
    expect(at(nodes, 1)).toMatchObject({ groupIndex: 0, groupOperator: 'AND', nodeOperator: 'OR' });
    expect(at(nodes, 1).cpeMatch).toHaveLength(1);

    const text = (at(result.content as Array<{ text?: string }>) as { text: string }).text;
    expect(text).toContain('1 configuration group(s), 2 node(s), 3 CPE match(es)');
    expect(text).toContain(
      escapeMarkdownInline('cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*') +
        ' [group 0; AND with sibling nodes; OR within node; not the vulnerable component]',
    );
  });
});

/**
 * Issue #65 wiring on the audit surface: raw NVD records through the real normalizer and resolver.
 * The rendering table is pinned at the shared renderer's seam (`tests/tools/full-record.test.ts`)
 * and the normalization at the service's; this proves the audit carries both and honors its
 * selector.
 */
describe('nvdAuditCpe — CNA/ADP statements reach both surfaces (issue #65)', () => {
  const cpeName = 'cpe:2.3:o:apple:macos:12.0.0:*:*:*:*:*:*:*';
  const textOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
  const cvesOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    (result.structuredContent as { cves: Array<Record<string, unknown>> }).cves;

  beforeEach(() => {
    const fake = nvdFake([CVE_2024_23225, CVE_2021_3007]);
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      fake as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      new NvdCveService({} as never, {} as never),
    );
    vi.spyOn(nvdSourceServiceModule, 'getNvdSourceService').mockReturnValue(
      new nvdSourceServiceModule.NvdSourceService({} as never, {} as never),
    );
  });

  it('carries resolved affected products, record tags, and score sources by default', async () => {
    const result = await runToolContract(nvdAuditCpe, { cpeName });
    expect(result.isError).toBeFalsy();

    const apple = at(cvesOf(result), 0);
    const disputed = at(cvesOf(result), 1);
    expect((apple.affectedProducts as Array<{ source: string }>).map((p) => p.source)).toEqual([
      'product-security@apple.com',
      'product-security@apple.com',
      'CISA-ADP',
      'CISA-ADP',
    ]);
    expect(disputed).toMatchObject({
      sourceIdentifier: 'cve@mitre.org',
      cveTags: [{ source: 'cve@mitre.org', tags: ['disputed'] }],
    });

    const text = textOf(result);
    expect(text).toContain('**Affected Products (CNA/ADP):** 4 product(s)');
    expect(text).toContain('  - [CISA-ADP] apple / macos · defaultStatus: unknown\n');
    expect(text).toContain(
      '| **Source:** cve@mitre.org | **CVE Tags:** [cve@mitre.org] disputed\n',
    );
  });

  it('omits affectedProducts from both surfaces with includeAffected: false', async () => {
    const result = await runToolContract(nvdAuditCpe, { cpeName, includeAffected: false });
    expect(result.isError).toBeFalsy();
    for (const cve of cvesOf(result)) expect(cve).not.toHaveProperty('affectedProducts');
    expect(textOf(result)).not.toContain('Affected Products');
    expect(at(cvesOf(result), 1)).toHaveProperty('cveTags');
  });

  it('treats an omitted includeAffected as true', async () => {
    const omitted = await runToolContract(nvdAuditCpe, { cpeName });
    const explicit = await runToolContract(nvdAuditCpe, { cpeName, includeAffected: true });
    expect(explicit.structuredContent).toEqual(omitted.structuredContent);
    expect(explicit.content).toEqual(omitted.content);
  });

  it('keeps the affected selector independent of the other two', async () => {
    const result = await runToolContract(nvdAuditCpe, {
      cpeName,
      includeConfigurations: false,
      includeReferences: false,
    });
    const apple = at(cvesOf(result));
    expect(apple).not.toHaveProperty('configurationNodes');
    expect(apple).not.toHaveProperty('references');
    expect(apple.affectedProducts).toHaveLength(4);
  });

  /** Characterization: a record carrying no source, tags, scorer, or affected products renders with the plain status and CVSS lines. */
  it('renders the status and CVSS lines of a record without the new fields unchanged', () => {
    const lines = (nvdAuditCpe.format!({ cves: [FULL_CVE] })[0] as { text: string }).text.split(
      '\n',
    );
    expect(lines).toContain(
      '**Status:** Analyzed | **Published:** 2021-12-10T10:15:00.000 | **Last Modified:** 2023-11-06T03:18:00.000',
    );
    expect(lines).toContain(
      '  - v3.1 (Primary): 10 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    );
  });
});
