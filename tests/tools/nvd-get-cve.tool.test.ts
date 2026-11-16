/**
 * @fileoverview Tests for nvd_get_cve tool.
 * @module tests/tools/nvd-get-cve.tool.test
 */

import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { escapeMarkdownInline, markdownLink } from '@cyanheads/mcp-ts-core/utils';
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from 'vitest';
import { toJSONSchema } from 'zod/v4/core';
import * as serverConfigModule from '@/config/server-config.js';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdGetCve } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { BRIEF_DESCRIPTION_CHARS, NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { CveRecord, RawCveItem, RawCveResponse } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';
import * as nvdSourceServiceModule from '@/services/nvd-source/nvd-source-service.js';
import { at } from '../support/at.js';
import { expectLinearCost } from '../support/cpu-linearity.js';
import {
  CVE_2021_3007,
  CVE_2021_44228,
  CVE_2024_23225,
  CVE_2026_115946,
  nvdFake,
} from '../support/nvd-affected-fixtures.js';

/**
 * Source-name resolution has its own suite; every assertion here is about other fields, so the
 * contributor dictionary is stubbed to a passthrough that costs no upstream call and leaves
 * identifiers exactly as the fixtures wrote them.
 */
beforeEach(() => {
  vi.spyOn(nvdSourceServiceModule, 'getNvdSourceService').mockReturnValue({
    getResolver: async () => nvdSourceServiceModule.passthroughSourceNames,
  } as unknown as ReturnType<typeof nvdSourceServiceModule.getNvdSourceService>);
});

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
      cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*' }],
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

const SPARSE_CVE: CveRecord = {
  cveId: 'CVE-2022-00001',
  vulnStatus: 'Awaiting Analysis',
  published: '2022-01-01T00:00:00.000',
  lastModified: '2022-01-02T00:00:00.000',
  descriptions: [],
  cvssScores: [],
  weaknesses: [],
  configurationNodes: [],
  affectedProducts: [],
};

/**
 * The record shape `nvdGetCve.format()` accepts. The fixtures below are deliberately partial —
 * each pins one rendering concern — so they are built loosely and cast to this at the boundary.
 */
type GetCveRow = Parameters<NonNullable<typeof nvdGetCve.format>>[0]['cves'][number];

describe('nvdGetCve — full rendering parity', () => {
  const record: CveRecord = {
    ...FULL_CVE,
    descriptions: [
      { lang: 'en', value: `**literal**\n- ${'detail '.repeat(60)}` },
      { lang: 'es', value: '<b>texto</b>' },
    ],
    configurationNodes: [
      {
        groupIndex: 0,
        groupOperator: 'AND',
        nodeOperator: 'OR',
        cpeMatch: Array.from({ length: 8 }, (_, i) => ({
          vulnerable: i !== 7,
          criteria: `cpe:2.3:a:vendor:product:${i}:*:*:*:*:*:*:*`,
          versionEndExcluding: '2`\n[bound]',
        })),
      },
    ],
    references: Array.from({ length: 17 }, (_, i) => ({
      url: `https://example.test/${i}?x=[a]`,
      source: 'name`\n[source]',
      tags: ['**advisory**'],
    })),
  };
  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
      fetchById: vi
        .fn()
        .mockResolvedValue({ cves: [record], returned: 1, requested: 1, missingIds: [] }),
    } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
  });
  it('characterizes full structured records without trimming nested sections', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: record.cveId, allLanguages: true });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({ cves: [record] });
  });
  it('omits configurations on both surfaces without mutating full service records (issue #61)', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: record.cveId,
      includeConfigurations: false,
    } as never);
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({
      cves: [expect.not.objectContaining({ configurationNodes: expect.anything() })],
    });
    expect(
      result.content
        .filter((block) => block.type === 'text')
        .map((block) => block.text)
        .join('\n'),
    ).not.toContain('**Configurations:**');
    expect(record.configurationNodes[0]?.cpeMatch).toHaveLength(8);
  });
  it('keeps default and explicit selectors identical (issue #61)', async () => {
    const defaults = await runToolContract(nvdGetCve, { cveIds: record.cveId });
    const explicit = await runToolContract(nvdGetCve, {
      cveIds: record.cveId,
      includeConfigurations: true,
      includeReferences: true,
    } as never);
    expect(explicit.structuredContent).toEqual(defaults.structuredContent);
    expect(explicit.content).toEqual(defaults.content);
  });
  it('keeps brief mode free of full sections even with configuration selectors (issue #61)', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: record.cveId,
      brief: true,
      includeConfigurations: false,
    });
    expect(result.isError).toBeFalsy();
    expect(result.structuredContent).toMatchObject({
      brief: true,
      cves: [expect.not.objectContaining({ configurationNodes: expect.anything() })],
    });
    expect(
      result.content
        .filter((block) => block.type === 'text')
        .map((block) => block.text)
        .join('\n'),
    ).not.toContain('**Configurations:**');
  });
  it('rejects nonboolean configuration selectors (issue #61)', () => {
    expect(
      nvdGetCve.input.safeParse({ cveIds: record.cveId, includeConfigurations: 'false' }).success,
    ).toBe(false);
  });
  it('renders every reference, nested criterion and language without losing literal text', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: record.cveId, allLanguages: true });
    const text = result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
    for (const reference of record.references!)
      expect(text).toContain(markdownLink(reference.url, reference.url));
    for (const match of record.configurationNodes[0]!.cpeMatch)
      expect(text).toContain(escapeMarkdownInline(match.criteria));
    for (const description of record.descriptions)
      expect(text).toContain(escapeMarkdownInline(description.value));
    expect(text).toContain(escapeMarkdownInline('name`\n[source]'));
    expect(text).toContain(escapeMarkdownInline('**advisory**'));
    expect(text).toContain(escapeMarkdownInline('2`\n[bound]'));
    expect(text).toContain('AND with sibling nodes; OR within node; not the vulnerable component');
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
        fetchById: vi.fn().mockRejectedValue(new McpError(code, 'NVD request failed.', { reason })),
      } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
      const result = await runToolContract(nvdGetCve, { cveIds: record.cveId });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: { code, data: { reason, recovery: { hint } } },
      });
      expect(result.content).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'text', text: expect.stringContaining(hint) }),
        ]),
      );
      expect(nvdGetCve.errors?.find((entry) => entry.reason === reason)).toMatchObject({
        thrownBy: 'service',
        retryable,
      });
    },
  );
});

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
    const ctx = createMockContext({ errors: nvdGetCve.errors });
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
    const ctx = createMockContext({ errors: nvdGetCve.errors });
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
    const ctx = createMockContext({ errors: nvdGetCve.errors });
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
    const ctx = createMockContext({ errors: nvdGetCve.errors });
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
    const ctx = createMockContext({ errors: nvdGetCve.errors });
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
      cves: [FULL_CVE as unknown as GetCveRow],
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
        } as unknown as GetCveRow,
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
        } as unknown as GetCveRow,
      ],
    };
    const blocks = nvdGetCve.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
    expect(text).not.toMatch(/Severity:.*undefined/);
  });

  // Issue #23: English-only is the default; other languages gate behind allLanguages.
  it('threads allLanguages through to fetchById when set', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228', allLanguages: true });
    await nvdGetCve.handler(input, ctx);

    expect(mockService.fetchById).toHaveBeenCalledWith(
      ['CVE-2021-44228'],
      { includeReferences: true, allLanguages: true, resolveSources: true },
      ctx,
    );
  });

  it('waives source-name resolution for a brief fetch, whose rows drop the field', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228', brief: true });
    await nvdGetCve.handler(input, ctx);

    // Resolving here would spend an upstream dictionary request on values `toBriefCve` discards.
    expect(mockService.fetchById).toHaveBeenCalledWith(
      ['CVE-2021-44228'],
      { includeReferences: true, allLanguages: false, resolveSources: false },
      ctx,
    );
  });

  it('defaults allLanguages to false (English-only) when omitted', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228' });
    await nvdGetCve.handler(input, ctx);

    expect(mockService.fetchById).toHaveBeenCalledWith(
      ['CVE-2021-44228'],
      { includeReferences: true, allLanguages: false, resolveSources: true },
      ctx,
    );
  });

  // Issue #23: a fallback record with no English entry must still render prose, not blank.
  it('renders a non-English description when a full record has no English entry', () => {
    const spanishOnly = {
      ...FULL_CVE,
      descriptions: [{ lang: 'es', value: 'Vulnerabilidad JNDI en Apache Log4j2.' }],
    };
    const output = {
      brief: false,
      cves: [spanishOnly as unknown as GetCveRow],
    };
    const blocks = nvdGetCve.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Vulnerabilidad JNDI en Apache Log4j2.');
  });

  // Issue #25: the advertised rate_limited code must match the client's thrown RateLimited.
  it('declares rate_limited with the RateLimited error code', () => {
    const entry = nvdGetCve.errors?.find((e) => e.reason === 'rate_limited');
    expect(entry?.code).toBe(JsonRpcErrorCode.RateLimited);
  });

  // Issue #32: brief rows carried no prose, so a bulk lookup said nothing about what each CVE is.
  it('puts a truncated description on brief rows and renders it', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228', brief: true });
    const result = await nvdGetCve.handler(input, ctx);

    const cve = result.cves[0] as { description?: string };
    expect(cve.description).toBe('Apache Log4j2 JNDI vulnerability.');

    const text = (nvdGetCve.format!(result)[0] as { text: string }).text;
    expect(text).toContain('Apache Log4j2 JNDI vulnerability.');
  });

  it('truncates a long brief description at the shared 200-character budget', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [{ ...FULL_CVE, descriptions: [{ lang: 'en', value: `${'A'.repeat(400)}END` }] }],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228', brief: true });
    const result = await nvdGetCve.handler(input, ctx);

    const description = (result.cves[0] as { description?: string }).description as string;
    expect(description).toBe(`${'A'.repeat(BRIEF_DESCRIPTION_CHARS)}…`);
    expect(description).not.toContain('END');
  });

  it('falls back to non-English prose on a brief row with no English entry', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [
        {
          ...FULL_CVE,
          descriptions: [{ lang: 'es', value: 'Vulnerabilidad JNDI en Apache Log4j2.' }],
        },
      ],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228', brief: true });
    const result = await nvdGetCve.handler(input, ctx);

    expect((result.cves[0] as { description?: string }).description).toBe(
      'Vulnerabilidad JNDI en Apache Log4j2.',
    );
  });

  it('omits description from a brief row when the record carries none', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [SPARSE_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2022-00001', brief: true });
    const result = await nvdGetCve.handler(input, ctx);

    expect(result.cves[0]).not.toHaveProperty('description');
    const text = (nvdGetCve.format!(result)[0] as { text: string }).text;
    expect(text).not.toContain('undefined');
  });
});

/**
 * Issue #30: full-mode format() dropped data structuredContent carried — configurations rendered
 * as a bare group count, references were cut at five, and allLanguages never reached content[].
 */
describe('nvdGetCve — full-mode format() parity (issue #52)', () => {
  /** `count` CPE matches in one node, including the former cap boundary. */
  function cveWithMatches(count: number): GetCveRow {
    return {
      ...FULL_CVE,
      configurationNodes: [
        {
          groupIndex: 0,
          nodeOperator: 'OR',
          cpeMatch: Array.from({ length: count }, (_, i) => ({
            vulnerable: true,
            criteria: `cpe:2.3:o:fedoraproject:fedora:${30 + i}:*:*:*:*:*:*:*`,
            versionEndExcluding: '2.15.0',
          })),
        },
      ],
    } as unknown as GetCveRow;
  }

  function cveWithReferences(count: number): GetCveRow {
    return {
      ...FULL_CVE,
      references: Array.from({ length: count }, (_, i) => ({
        url: `https://example.invalid/advisory/${i}`,
        tags: ['Vendor Advisory'],
      })),
    } as unknown as GetCveRow;
  }

  const render = (cves: GetCveRow[]) =>
    (nvdGetCve.format!({ brief: false, cves })[0] as { text: string }).text;

  it('renders actual CPE match criteria and version bounds, not just a group count', () => {
    const text = render([cveWithMatches(1)]);

    expect(text).toContain(escapeMarkdownInline('cpe:2.3:o:fedoraproject:fedora:30:*:*:*:*:*:*:*'));
    expect(text).toContain('< 2.15.0');
    expect(text).toContain('1 configuration group(s), 1 node(s), 1 CPE match(es)');
    // The old formatter stopped at the group count and printed no criteria at all.
    expect(text).not.toMatch(/\*\*Configurations:\*\* 1 configuration group\(s\)\s*$/m);
  });

  it('renders every criterion at the former cap boundary', () => {
    const text = render([cveWithMatches(5)]);

    expect(text.match(/cpe:2\.3:o:fedoraproject/g)).toHaveLength(5);
    expect(text).not.toContain('more —');
  });

  it('renders all criteria at one past the former cap', () => {
    const text = render([cveWithMatches(6)]);

    expect(text.match(/cpe:2\.3:o:fedoraproject/g)).toHaveLength(6);
    expect(text).not.toContain('…');
  });

  it('renders every reference at the former cap boundary', () => {
    const text = render([cveWithReferences(15)]);

    expect(text.match(/example\.invalid\/advisory/g)).toHaveLength(30);
    expect(text).not.toContain('more references');
  });

  it('renders all references at one past the former cap', () => {
    const text = render([cveWithReferences(16)]);

    expect(text.match(/example\.invalid\/advisory/g)).toHaveLength(32);
    expect(text).not.toContain('…');
  });

  it('renders every language a record carries so allLanguages reaches content[]', () => {
    const bilingual = {
      ...FULL_CVE,
      descriptions: [
        { lang: 'en', value: 'Buffer overflow in mod_lua.' },
        { lang: 'es', value: 'Desbordamiento de bufer en mod_lua.' },
      ],
    } as unknown as GetCveRow;
    const text = render([bilingual]);

    expect(text).toContain('Buffer overflow in mod_lua.');
    // Previously the picker took the English entry and the Spanish one never rendered.
    expect(text).toContain('Desbordamiento de bufer en mod_lua.');
    expect(text).toContain('[en]');
    expect(text).toContain('[es]');
  });

  it('renders the single English description under the default language policy', () => {
    const text = render([FULL_CVE as unknown as GetCveRow]);

    expect(text).toContain('[en] Apache Log4j2 JNDI vulnerability.');
    expect(text).not.toContain('[es]');
  });

  it('renders nothing for descriptions when a record carries none', () => {
    const text = render([SPARSE_CVE as unknown as GetCveRow]);

    expect(text).toContain('CVE-2022-00001');
    expect(text).not.toContain('undefined');
    expect(text).not.toMatch(/\[\w*\]\s*$/m);
  });
});

/**
 * Issue #35: brief mode rebuilt the brief-row shape inline instead of calling `toBriefCve`, so the
 * two surfaces could drift apart silently. Both now run the same upstream payload through the same
 * builder — assert row-for-row equality across the shapes that differ from one another.
 */
describe('nvdGetCve — brief-row parity with nvd_search_cves (issue #35)', () => {
  /** In the KEV catalog, with an English description. */
  const RAW_KEV: RawCveItem = {
    id: 'CVE-2021-44228',
    vulnStatus: 'Analyzed',
    published: '2021-12-10T10:15:00.000',
    lastModified: '2023-11-06T03:18:00.000',
    descriptions: [{ lang: 'en', value: 'Apache Log4j2 JNDI vulnerability.' }],
    metrics: {
      cvssMetricV31: [
        {
          type: 'Primary',
          cvssData: { version: '3.1', baseScore: 10.0, baseSeverity: 'CRITICAL' },
        },
      ],
    },
    cisaExploitAdd: '2021-12-10',
    cisaActionDue: '2021-12-24',
    cisaRequiredAction: 'Apply updates per vendor instructions.',
    cisaVulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
  };

  /** Not in the KEV catalog. */
  const RAW_NO_KEV: RawCveItem = {
    id: 'CVE-2023-11111',
    vulnStatus: 'Analyzed',
    published: '2023-02-01T00:00:00.000',
    lastModified: '2023-03-01T00:00:00.000',
    descriptions: [{ lang: 'en', value: 'Buffer overflow in mod_lua.' }],
    metrics: {
      cvssMetricV31: [
        { type: 'Primary', cvssData: { version: '3.1', baseScore: 7.5, baseSeverity: 'HIGH' } },
      ],
    },
  };

  /** In the KEV catalog but carrying no description at all. */
  const RAW_KEV_NO_DESCRIPTION: RawCveItem = {
    ...RAW_KEV,
    id: 'CVE-2024-22222',
    descriptions: [],
  };

  /** No description, no CVSS scores, no KEV — every optional brief field absent. */
  const RAW_BARE: RawCveItem = {
    id: 'CVE-2022-00001',
    vulnStatus: 'Awaiting Analysis',
    published: '2022-01-01T00:00:00.000',
    lastModified: '2022-01-02T00:00:00.000',
  };

  /** Longer than the snippet budget — proves both surfaces truncate at the same point. */
  const RAW_LONG_DESCRIPTION: RawCveItem = {
    ...RAW_NO_KEV,
    id: 'CVE-2025-33333',
    descriptions: [{ lang: 'en', value: `${'A'.repeat(400)}END` }],
  };

  /** No English entry — both surfaces must fall back to the same prose. */
  const RAW_NON_ENGLISH: RawCveItem = {
    ...RAW_NO_KEV,
    id: 'CVE-2025-44444',
    descriptions: [{ lang: 'es', value: 'Vulnerabilidad JNDI en Apache Log4j2.' }],
  };

  /** Shellshock shape: the v2 headline (HIGH 10.0) outranks the v3.1 score (CRITICAL 9.8). */
  const RAW_DIVERGENT: RawCveItem = {
    id: 'CVE-2014-6271',
    vulnStatus: 'Analyzed',
    published: '2014-09-24T00:00:00.000',
    lastModified: '2021-11-01T00:00:00.000',
    descriptions: [{ lang: 'en', value: 'Shellshock.' }],
    metrics: {
      // NVD puts a v2 metric's baseSeverity beside cvssData, not inside it.
      cvssMetricV2: [
        { type: 'Primary', baseSeverity: 'HIGH', cvssData: { version: '2.0', baseScore: 10.0 } },
      ],
      cvssMetricV31: [
        { type: 'Primary', cvssData: { version: '3.1', baseScore: 9.8, baseSeverity: 'CRITICAL' } },
      ],
    },
  };

  const RAW_ITEMS = [
    RAW_KEV,
    RAW_NO_KEV,
    RAW_KEV_NO_DESCRIPTION,
    RAW_BARE,
    RAW_LONG_DESCRIPTION,
    RAW_NON_ENGLISH,
    RAW_DIVERGENT,
  ];

  const RESPONSE: RawCveResponse = {
    totalResults: RAW_ITEMS.length,
    vulnerabilities: RAW_ITEMS.map((cve) => ({ cve })),
  };

  const mockClient = { get: vi.fn() };
  const service = new NvdCveService({} as never, {} as never);

  beforeEach(() => {
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      mockClient as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(service);
    mockClient.get.mockReset();
    mockClient.get.mockResolvedValue(RESPONSE);
  });

  /** Brief rows from the nvd_get_cve surface for the whole fixture set. */
  async function briefRows() {
    const input = nvdGetCve.input.parse({
      cveIds: RAW_ITEMS.map((i) => i.id as string),
      brief: true,
    });
    const result = await nvdGetCve.handler(input, createMockContext({ errors: nvdGetCve.errors }));
    return result.cves;
  }

  it('emits rows identical to the search surface for the same upstream payload', async () => {
    const searched = await service.searchCves(
      { keyword: 'anything' },
      createMockContext({ errors: nvdGetCve.errors }),
    );
    const fetched = await briefRows();

    expect(fetched).toEqual(searched.cves);
    expect(fetched).toHaveLength(RAW_ITEMS.length);
  });

  it('carries the KEV name on a KEV record and omits the field entirely otherwise', async () => {
    const [kev, noKev] = await briefRows();

    expect(kev).toHaveProperty(
      'cisaVulnerabilityName',
      'Apache Log4j2 Remote Code Execution Vulnerability',
    );
    expect(noKev).not.toHaveProperty('cisaVulnerabilityName');
  });

  it('omits description on records that carry none and keeps every other field', async () => {
    const rows = await briefRows();
    const kevNoDescription = rows[2];
    const bare = rows[3];

    expect(kevNoDescription).not.toHaveProperty('description');
    expect(kevNoDescription).toHaveProperty('cveId', 'CVE-2024-22222');
    expect(kevNoDescription).toHaveProperty('severity');

    expect(bare).toEqual({
      cveId: 'CVE-2022-00001',
      vulnStatus: 'Awaiting Analysis',
      published: '2022-01-01T00:00:00.000',
    });
  });

  it('truncates and falls back to non-English prose the same way on both surfaces', async () => {
    const rows = await briefRows();

    expect(rows[4]).toHaveProperty('description', `${'A'.repeat(BRIEF_DESCRIPTION_CHARS)}…`);
    expect(rows[5]).toHaveProperty('description', 'Vulnerabilidad JNDI en Apache Log4j2.');
  });

  /**
   * The only field toBriefCve adds beyond the brief row is gated on a severity filter, which
   * nvd_get_cve has no input for — a row growing one here would be an output change, not a
   * consolidation.
   */
  it('never emits filteredSeverity, even on a record whose CVSS versions diverge', async () => {
    const rows = await briefRows();

    expect(rows[6]).toHaveProperty('cveId', 'CVE-2014-6271');
    expect(rows[6]).toHaveProperty('severity', { label: 'HIGH', score: 10.0, fromVersion: '2.0' });
    expect(rows[6]).not.toHaveProperty('filteredSeverity');
    expect(rows.some((r) => 'filteredSeverity' in r)).toBe(false);
  });

  it('leaves the search surface free to add filteredSeverity when a filter diverges', async () => {
    const searched = await service.searchCves(
      { severityParam: 'CRITICAL', severityVersion: 'v3' },
      createMockContext({ errors: nvdGetCve.errors }),
    );

    // Same record, same builder — only the filter version the search surface passes differs.
    expect(at(searched.cves, 6).filteredSeverity).toEqual({
      label: 'CRITICAL',
      score: 9.8,
      fromVersion: '3.1',
    });
  });
});

/**
 * Issues #37 and #38: the full-record shape was declared twice — once inside `nvd_audit_cpe`, and
 * not at all here, where the advertised item was the brief row reused for both modes. A schema-
 * driven client reading the default (`brief: false`) surface saw two fields it could never
 * receive and none of the seven it would.
 */
describe('nvdGetCve — advertised item schema (issues #37, #38)', () => {
  const jsonSchema = (def: { output: unknown }) =>
    toJSONSchema(def.output as never, { io: 'output', unrepresentable: 'any' }) as unknown as {
      properties: { cves: { items: { properties: Record<string, unknown>; required: string[] } } };
    };

  const getCveItem = jsonSchema(nvdGetCve).properties.cves.items;
  const auditCpeItem = jsonSchema(nvdAuditCpe).properties.cves.items;

  /** Every field the full record adds beyond the three both modes always carry. */
  const FULL_RECORD_FIELDS = [
    'lastModified',
    'descriptions',
    'cvssScores',
    'severity',
    'weaknesses',
    'configurationNodes',
    'references',
    'cisaKev',
    'sourceIdentifier',
    'cveTags',
    'affectedProducts',
  ];

  it('declares the full-record fields the default call actually returns', () => {
    expect(Object.keys(getCveItem.properties)).toEqual(expect.arrayContaining(FULL_RECORD_FIELDS));
  });

  it('still declares the two brief-only substitutes', () => {
    expect(Object.keys(getCveItem.properties)).toEqual(
      expect.arrayContaining(['description', 'cisaVulnerabilityName']),
    );
  });

  it.each(FULL_RECORD_FIELDS)('describes %s identically to nvd_audit_cpe', (field) => {
    expect(getCveItem.properties[field]).toEqual(auditCpeItem.properties[field]);
  });

  /**
   * The framework parses every success return against this schema, so a field promoted to
   * required over a value one mode omits is a runtime outage, not a documentation nit.
   */
  it('requires only the three fields both modes always carry', () => {
    expect(getCveItem.required).toEqual(['cveId', 'vulnStatus', 'published']);
  });

  it('parses a brief row and a full record against the same declared output', () => {
    expect(() =>
      nvdGetCve.output.parse({
        brief: true,
        cves: [
          {
            cveId: 'CVE-2021-44228',
            vulnStatus: 'Analyzed',
            published: '2021-12-10T10:15:00.000',
            description: 'Apache Log4j2 JNDI vulnerability.',
            severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
            cisaVulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
          },
        ],
      }),
    ).not.toThrow();

    expect(() => nvdGetCve.output.parse({ brief: false, cves: [FULL_CVE] })).not.toThrow();
  });

  it('keeps the full record intact through the output parse', () => {
    const parsed = nvdGetCve.output.parse({ brief: false, cves: [FULL_CVE] });
    expect(parsed.cves[0]).toEqual(FULL_CVE);
  });
});

/**
 * Issue #38: `format()` branched on `brief` and rendered one field set per call, so the widened
 * schema would leave the other branch's fields unrendered. It is now one total pass keyed on
 * field presence.
 */
describe('nvdGetCve — total format() across both modes (issue #38)', () => {
  /** Every declared field populated at once — the shape the format-parity walk feeds. */
  const BOTH_MODES = {
    ...FULL_CVE,
    description: 'Truncated brief prose.',
    cisaVulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
  } as unknown as GetCveRow;

  const render = (cves: GetCveRow[], brief = false) =>
    (nvdGetCve.format!({ brief, cves })[0] as { text: string }).text;

  it('renders both modes field sets from one sample, whatever brief says', () => {
    for (const brief of [true, false]) {
      const text = render([BOTH_MODES], brief);

      // Brief-only fields.
      expect(text).toContain('Truncated brief prose.');
      expect(text).toContain('**CISA KEV:** Apache Log4j2 Remote Code Execution Vulnerability');
      // Full-only fields.
      expect(text).toContain('2023-11-06T03:18:00.000');
      expect(text).toContain('[en] Apache Log4j2 JNDI vulnerability.');
      expect(text).toContain('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
      expect(text).toContain(escapeMarkdownInline('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*'));
      expect(text).toContain('**CISA KEV Details:**');
    }
  });

  it('renders the weakness source alongside its CWE ids', () => {
    expect(render([FULL_CVE as unknown as GetCveRow])).toContain('NVD: CWE-20');
  });

  /**
   * A KEV listing is the line a triage read scans a brief row for. Rendering it after the
   * description would fold it into that paragraph, behind 200 characters of prose.
   */
  it('keeps a brief row KEV name with the metadata, above the description', () => {
    const briefRow = {
      cveId: 'CVE-2021-44228',
      vulnStatus: 'Analyzed',
      published: '2021-12-10T10:15:00.000',
      severity: { label: 'CRITICAL', score: 10, fromVersion: '3.1' },
      description: 'Truncated brief prose.',
      cisaVulnerabilityName: 'Apache Log4j2 Remote Code Execution Vulnerability',
    };
    const text = render([briefRow], true);

    expect(text.indexOf('**Severity:**')).toBeLessThan(text.indexOf('**CISA KEV:**'));
    expect(text.indexOf('**CISA KEV:**')).toBeLessThan(text.indexOf('Truncated brief prose.'));
  });

  it('renders a reference source when NVD supplies one', () => {
    const withSource = {
      ...FULL_CVE,
      references: [
        { url: 'https://example.invalid/a', source: 'cve@mitre.org', tags: ['Vendor Advisory'] },
      ],
    } as unknown as GetCveRow;

    expect(render([withSource])).toContain(
      '[https://example.invalid/a](<https://example.invalid/a>) [cve@mitre.org] (Vendor Advisory)',
    );
  });

  it('omits the Last Modified segment on a brief row that carries none', () => {
    const briefRow = {
      cveId: 'CVE-2021-44228',
      vulnStatus: 'Analyzed',
      published: '2021-12-10T10:15:00.000',
    };
    const text = render([briefRow], true);

    expect(text).toContain('**Status:** Analyzed | **Published:** 2021-12-10T10:15:00.000');
    expect(text).not.toContain('Last Modified');
    expect(text).not.toContain('undefined');
  });
});

/**
 * Raw NVD payload through the real normalizer and out both surfaces. The tool tests above stub the
 * service, so this is the one place the nested `configurations[].nodes[].cpeMatch[]` upstream shape
 * is exercised end to end: the hoisted result has to parse against the advertised output schema
 * (`structuredContent`) and render through `format()` (`content[]`) carrying the same logic.
 */
describe('nvdGetCve — upstream nesting reaches both surfaces intact', () => {
  /**
   * Two groups. The first AND-combines two nodes — (firmware- OR firmware9.0) AND hardware — which
   * is the case a group-level flatten destroys. The second is an unqualified single node.
   */
  const NESTED_PAYLOAD: RawCveResponse = {
    totalResults: 1,
    vulnerabilities: [
      {
        cve: {
          id: 'CVE-2022-1292',
          vulnStatus: 'Analyzed',
          published: '2022-05-03T00:00:00.000',
          lastModified: '2023-01-01T00:00:00.000',
          descriptions: [{ lang: 'en', value: 'c_rehash script command injection.' }],
          configurations: [
            {
              operator: 'AND',
              nodes: [
                {
                  operator: 'OR',
                  cpeMatch: [
                    {
                      vulnerable: true,
                      criteria: 'cpe:2.3:o:netapp:a700s_firmware:-:*:*:*:*:*:*:*',
                    },
                    {
                      vulnerable: true,
                      criteria: 'cpe:2.3:o:netapp:a700s_firmware:9.0:*:*:*:*:*:*:*',
                    },
                  ],
                },
                {
                  operator: 'OR',
                  cpeMatch: [
                    { vulnerable: false, criteria: 'cpe:2.3:h:netapp:a700s:-:*:*:*:*:*:*:*' },
                  ],
                },
              ],
            },
            {
              nodes: [
                {
                  cpeMatch: [
                    {
                      vulnerable: true,
                      criteria: 'cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*',
                      versionEndExcluding: '1.1.1o',
                    },
                  ],
                },
              ],
            },
          ],
        },
      },
    ],
  };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      new NvdCveService({} as never, {} as never),
    );
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue({
      get: vi.fn().mockResolvedValue(NESTED_PAYLOAD),
    } as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>);
  });

  it('parses the hoisted nodes into structuredContent and renders them into content[]', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: 'CVE-2022-1292' } as never);

    expect(result.isError).toBeFalsy();

    const nodes = (
      result.structuredContent as {
        cves: Array<{ configurationNodes: Array<Record<string, unknown>> }>;
      }
    ).cves[0]?.configurationNodes;

    // Three nodes across two groups — the AND group's members stay distinguishable.
    expect(nodes).toHaveLength(3);
    expect(nodes?.map((n) => n.groupIndex)).toEqual([0, 0, 1]);
    expect(at(nodes, 0)).toMatchObject({ groupOperator: 'AND', nodeOperator: 'OR' });
    expect(at(nodes, 0).cpeMatch).toHaveLength(2);
    expect(at(nodes, 2).groupOperator).toBeUndefined();
    expect(at(nodes, 2).nodeOperator).toBeUndefined();

    const text = (at(result.content as Array<{ text?: string }>) as { text: string }).text;
    expect(text).toContain('2 configuration group(s), 3 node(s), 4 CPE match(es)');
    expect(text).toContain(
      escapeMarkdownInline('cpe:2.3:o:netapp:a700s_firmware:9.0:*:*:*:*:*:*:*') +
        ' [group 0; AND with sibling nodes; OR within node; vulnerable component]',
    );
    expect(text).toContain(
      escapeMarkdownInline('cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:* (< 1.1.1o)') +
        ' [group 1; vulnerable component]',
    );
  });
});

/**
 * Issue #65, end to end: raw NVD records through the real normalizer and resolver, out both
 * surfaces. The rendering table itself is pinned at the renderer's own seam
 * (`tests/tools/full-record.test.ts`); these prove the wiring and the selector.
 */
describe('nvdGetCve — CNA/ADP statements reach both surfaces (issue #65)', () => {
  const textOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
  const cvesOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    (result.structuredContent as { cves: Array<Record<string, unknown>> }).cves;

  beforeEach(() => {
    const fake = nvdFake([CVE_2026_115946, CVE_2021_44228, CVE_2024_23225, CVE_2021_3007]);
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

  it('carries the CPANSec package entry, record source, and scorer on both surfaces', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: 'CVE-2026-115946' });
    expect(result.isError).toBeFalsy();

    const cve = at(cvesOf(result));
    expect(cve).toMatchObject({
      sourceIdentifier: 'CPANSec',
      cvssScores: [{ version: '3.1', sourceType: 'Secondary', source: 'CISA-ADP' }],
      affectedProducts: [
        {
          source: 'CPANSec',
          collectionURL: 'https://cpan.org/modules',
          packageName: 'XS-libbrotli',
          packageURL: 'pkg:cpan/XS-libbrotli',
          modules: ['XS::libbrotli'],
          programFiles: ['brotli/c/dec/decode.c'],
          defaultStatus: 'unaffected',
          versions: [
            { version: '0', lessThan: '1.2.1.0', versionType: 'custom', status: 'affected' },
          ],
        },
      ],
    });

    const lines = textOf(result).split('\n');
    expect(lines).toContain(
      '**Status:** Deferred | **Published:** 2026-11-01T00:16:34.437 | **Last Modified:** 2026-11-09T17:17:12.067 | **Source:** CPANSec',
    );
    expect(lines).toContain(
      '- v3.1 (Secondary) [CISA-ADP]: 9.8 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    );
    expect(lines).toContain('**Affected Products (CNA/ADP):** 1 product(s)');
    expect(lines).toContain(
      '  - [CPANSec] packageName: XS-libbrotli · collectionURL: https://cpan.org/modules · packageURL: pkg:cpan/XS-libbrotli · defaultStatus: unaffected',
    );
    expect(lines).toContain('    - modules: XS::libbrotli');
    expect(lines).toContain('    - programFiles: brotli/c/dec/decode.c');
    expect(lines).toContain('    - >= 0 < 1.2.1.0 (custom): affected');
  });

  it("renders a range's changes directly under it, so fixed points never read as affected", async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: 'CVE-2021-44228' });
    const product = at(cvesOf(result).flatMap((c) => c.affectedProducts as object[]));
    expect(product).toMatchObject({
      versionChanges: [
        { versionIndex: 0, at: '2.3.1', status: 'unaffected' },
        { versionIndex: 0, at: '2.4', status: 'affected' },
        { versionIndex: 0, at: '2.12.2', status: 'unaffected' },
        { versionIndex: 0, at: '2.13.0', status: 'affected' },
        { versionIndex: 0, at: '2.15.0', status: 'unaffected' },
      ],
    });

    const lines = textOf(result).split('\n');
    const range = lines.indexOf(
      `    - >= 2.0-beta9 < ${escapeMarkdownInline('log4j-core*')} (custom): affected`,
    );
    expect(range).toBeGreaterThan(0);
    expect(lines.slice(range + 1, range + 6)).toEqual([
      '      - from 2.3.1: unaffected',
      '      - from 2.4: affected',
      '      - from 2.12.2: unaffected',
      '      - from 2.13.0: affected',
      '      - from 2.15.0: unaffected',
    ]);
  });

  it('leads every product line of a two-group record with that group’s own source', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: 'CVE-2024-23225' });
    expect(
      (at(cvesOf(result)).affectedProducts as Array<{ source: string }>).map((p) => p.source),
    ).toEqual(['product-security@apple.com', 'product-security@apple.com', 'CISA-ADP', 'CISA-ADP']);

    const text = textOf(result);
    expect(text).toContain('**Affected Products (CNA/ADP):** 4 product(s)');
    expect(text).toContain('  - [product-security@apple.com] Apple / iOS and iPadOS\n');
    expect(text).toContain('  - [CISA-ADP] apple / ipad_os · defaultStatus: unknown\n');
    expect(text).toContain(
      `    - cpes: ${escapeMarkdownInline('cpe:2.3:o:apple:ipad_os:17.0:*:*:*:*:*:*:*')}\n`,
    );
  });

  it('puts record tags with their source on the status line', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: 'CVE-2021-3007' });
    expect(at(cvesOf(result)).cveTags).toEqual([{ source: 'cve@mitre.org', tags: ['disputed'] }]);
    expect(textOf(result)).toContain(
      '| **Source:** cve@mitre.org | **CVE Tags:** [cve@mitre.org] disputed\n',
    );
  });

  it('omits affectedProducts from both surfaces with includeAffected: false', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: ['CVE-2026-115946', 'CVE-2024-23225'],
      includeAffected: false,
    });
    expect(result.isError).toBeFalsy();
    for (const cve of cvesOf(result)) expect(cve).not.toHaveProperty('affectedProducts');
    expect(textOf(result)).not.toContain('Affected Products');
    // The selector touches nothing else: the record's own source and the scorer remain.
    expect(at(cvesOf(result))).toMatchObject({ sourceIdentifier: 'CPANSec' });
  });

  it('treats an omitted includeAffected as true', async () => {
    const omitted = await runToolContract(nvdGetCve, { cveIds: 'CVE-2024-23225' });
    const explicit = await runToolContract(nvdGetCve, {
      cveIds: 'CVE-2024-23225',
      includeAffected: true,
    });
    expect(explicit.structuredContent).toEqual(omitted.structuredContent);
    expect(explicit.content).toEqual(omitted.content);
    expect(at(cvesOf(omitted))).toHaveProperty('affectedProducts');
  });

  it('keeps the two section selectors independent', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: 'CVE-2024-23225',
      includeConfigurations: false,
    });
    const cve = at(cvesOf(result));
    expect(cve).not.toHaveProperty('configurationNodes');
    expect(cve.affectedProducts).toHaveLength(4);
  });

  // CVE-2021-3007 carries all three in full: tags, an affected block, and a record source.
  it('never adds the new fields to brief rows, whatever the selector says', async () => {
    for (const includeAffected of [true, false]) {
      const result = await runToolContract(nvdGetCve, {
        cveIds: 'CVE-2021-3007',
        brief: true,
        includeAffected,
      });
      const row = at(cvesOf(result));
      for (const field of ['affectedProducts', 'cveTags', 'sourceIdentifier'])
        expect(row).not.toHaveProperty(field);
      expect(textOf(result)).not.toContain('Affected Products');
    }
  });

  it('rejects a nonboolean includeAffected', () => {
    expect(
      nvdGetCve.input.safeParse({ cveIds: 'CVE-2024-23225', includeAffected: 'false' }).success,
    ).toBe(false);
  });

  /** Characterization: a record carrying no source, tags, scorer, or affected products renders with the plain status and CVSS lines. */
  it('renders the status and CVSS lines of a record without the new fields unchanged', () => {
    const lines = (
      nvdGetCve.format!({ brief: false, cves: [FULL_CVE] })[0] as { text: string }
    ).text.split('\n');
    expect(lines).toContain(
      '**Status:** Analyzed | **Published:** 2021-12-10T10:15:00.000 | **Last Modified:** 2023-11-06T03:18:00.000',
    );
    expect(lines).toContain(
      '- v3.1 (Primary): 10 CRITICAL — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
    );
  });
});

describe('nvdGetCve — joined cveIds strings and distinct IDs (issue #71)', () => {
  let fake: ReturnType<typeof nvdFake>;
  const textOf = (result: Awaited<ReturnType<typeof runToolContract>>) =>
    result.content
      .filter((block) => block.type === 'text')
      .map((block) => block.text)
      .join('\n');
  /** The `cveIds` parameter of every CVE request the call sent to NVD, in order. */
  const sentIds = () =>
    fake.get.mock.calls
      .filter(([endpoint]) => endpoint === 'cves/2.0')
      .map(([, params]) => params?.cveIds);
  const distinctIds = (count: number) =>
    Array.from({ length: count }, (_, i) => `CVE-2021-${10_000 + i}`);

  beforeEach(() => {
    fake = nvdFake([CVE_2021_44228, CVE_2024_23225]);
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      fake as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      new NvdCveService({} as never, {} as never),
    );
  });

  it.each([
    'CVE-2021-44228,CVE-2024-23225',
    'CVE-2021-44228 CVE-2024-23225',
    'CVE-2021-44228, cve-2024-23225,',
    '\n CVE-2021-44228\t,\r\nCVE-2024-23225 ',
  ])('fetches both IDs named by %j in one request', async (cveIds) => {
    const result = await runToolContract(nvdGetCve, { cveIds, brief: true });
    expect(result.isError).toBeFalsy();
    expect(sentIds()).toEqual(['CVE-2021-44228,CVE-2024-23225']);
    expect(result.structuredContent).toMatchObject({
      requested: 2,
      returned: 2,
      cves: [{ cveId: 'CVE-2021-44228' }, { cveId: 'CVE-2024-23225' }],
    });
    expect(result.structuredContent).not.toHaveProperty('missingIds');
    const lines = textOf(result).split('\n');
    for (const id of ['CVE-2021-44228', 'CVE-2024-23225'])
      expect(lines).toContain(`## ${escapeMarkdownInline(id)}`);
    expect(textOf(result)).toContain('**Requested:** 2');
  });

  it('quotes only the malformed piece of a joined string and sends nothing', async () => {
    const result = await runToolContract(nvdGetCve, { cveIds: 'CVE-2021-44228,bogus' });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cve_id_format', cveId: 'bogus' } },
    });
    expect(textOf(result)).toContain('Invalid CVE ID format: "bogus".');
    expect(fake.get).not.toHaveBeenCalled();
  });

  it('validates pieces past the 100th before spending a request', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: `${distinctIds(150).join(',')},bogus`,
    });
    expect(result.structuredContent).toMatchObject({
      error: { data: { reason: 'invalid_cve_id_format', cveId: 'bogus' } },
    });
    expect(fake.get).not.toHaveBeenCalled();
  });

  /** Characterization: a string naming no ID fails as it always has. */
  it.each(['', '   ', ' , ', ',,\n'])(
    'fails %j as an invalid ID before any request',
    async (cveIds) => {
      const result = await runToolContract(nvdGetCve, { cveIds });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: { data: { reason: 'invalid_cve_id_format' } },
      });
      expect(textOf(result)).toContain('Invalid CVE ID format');
      expect(fake.get).not.toHaveBeenCalled();
    },
  );

  /** Characterization: only the string form is a list; an array element is one ID. */
  it('never splits an array element', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: ['CVE-2021-44228,CVE-2024-23225'],
    });
    expect(result.structuredContent).toMatchObject({
      error: {
        data: { reason: 'invalid_cve_id_format', cveId: 'CVE-2021-44228,CVE-2024-23225' },
      },
    });
    expect(fake.get).not.toHaveBeenCalled();
  });

  it.each<[string, string | string[]]>([
    ['an array', ['CVE-2021-44228', 'cve-2021-44228', ' CVE-2021-44228 ']],
    ['a joined string', 'CVE-2021-44228 cve-2021-44228,CVE-2021-44228'],
  ])('fetches an ID repeated across case in %s once and counts it once', async (_form, cveIds) => {
    const result = await runToolContract(nvdGetCve, { cveIds, brief: true });
    expect(sentIds()).toEqual(['CVE-2021-44228']);
    expect(result.structuredContent).toMatchObject({
      requested: 1,
      returned: 1,
      cves: [{ cveId: 'CVE-2021-44228' }],
    });
    expect(textOf(result)).toContain('**Requested:** 1');
  });

  it('keeps first-occurrence order when it drops a repeat', async () => {
    const result = await runToolContract(nvdGetCve, {
      cveIds: 'CVE-2024-23225 CVE-2021-44228 cve-2024-23225',
      brief: true,
    });
    expect(sentIds()).toEqual(['CVE-2024-23225,CVE-2021-44228']);
    expect(result.structuredContent).toMatchObject({ requested: 2, returned: 2 });
  });

  it('advertises the string form as a list handled like the array', () => {
    const cveIds = toJSONSchema(nvdGetCve.input).properties?.cveIds as {
      anyOf: Array<{ type: string; description: string }>;
    };
    const branch = (type: string) =>
      cveIds.anyOf.find((option) => option.type === type)?.description;
    expect(branch('string')).toContain('separated by commas or whitespace');
    expect(branch('array')).toContain('never split');
    expect(branch('array')).toContain('distinct');
  });

  describe('with NVD_CLAMP_LIMITS=false', () => {
    let config: MockInstance<typeof serverConfigModule.getServerConfig>;
    beforeEach(() => {
      config = vi
        .spyOn(serverConfigModule, 'getServerConfig')
        .mockReturnValue({ requestTimeoutMs: 10_000, clampLimits: false });
    });
    afterEach(() => config.mockRestore());

    it('rejects a string naming more than 100 distinct IDs before any request', async () => {
      const result = await runToolContract(nvdGetCve, { cveIds: distinctIds(101).join(',') });
      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: {
          code: JsonRpcErrorCode.ValidationError,
          data: {
            reason: 'too_many_cve_ids',
            recovery: { hint: expect.stringContaining('at most 100 distinct CVE IDs') },
          },
        },
      });
      const text = textOf(result);
      expect(text).toContain('101 distinct CVE IDs');
      expect(text).toContain('at most 100 distinct CVE IDs');
      expect(fake.get).not.toHaveBeenCalled();
    });

    it('accepts a string whose 104 pieces name 100 distinct IDs, with no clamp fields', async () => {
      const ids = distinctIds(100);
      const cveIds = [...ids, ...ids.slice(0, 4).map((id) => id.toLowerCase())].join(' ');
      const result = await runToolContract(nvdGetCve, { cveIds, brief: true });
      expect(result.isError).toBeFalsy();
      expect(sentIds()).toEqual([ids.join(',')]);
      expect(result.structuredContent).toMatchObject({ requested: 100 });
      for (const field of ['requestedLimit', 'effectiveLimit', 'unprocessedIds', 'notice'])
        expect(result.structuredContent).not.toHaveProperty(field);
    });
  });

  /**
   * The split runs over a caller-sized string, so its cost is held linear. Timed through the
   * handler with the service stubbed: nothing waits on a request, so each measurement batches
   * calls, since one call on a 5k input sits below the timer's resolution. The separator pattern
   * stays out of Bun's slower regex mode on every shape here, so each one carries the full span.
   */
  describe('cost on caller-sized cveIds strings', { timeout: 0 }, () => {
    const ctx = createMockContext({ errors: nvdGetCve.errors });
    const FULL_SPAN = 320_000;

    beforeEach(() => {
      vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
        fetchById: async (ids: string[]) => ({
          cves: [],
          returned: 0,
          requested: ids.length,
          missingIds: ids,
        }),
      } as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>);
    });

    /**
     * Runs the handler on `value` to completion, reporting whether it accepted the string. Only the
     * format rejection reads as `false`; any other throw fails the test rather than passing as one.
     */
    async function accepts(value: string): Promise<boolean> {
      try {
        await nvdGetCve.handler(nvdGetCve.input.parse({ cveIds: value, brief: true }), ctx);
        return true;
      } catch (err) {
        if (err instanceof McpError && err.data?.reason === 'invalid_cve_id_format') return false;
        throw err;
      }
    }

    it.each([
      ['a long line ending in a break', (n: number) => `${'§1 x'.repeat(n / 4)}\ny`, false],
      ['breaks throughout', (n: number) => '  \r\n'.repeat(n / 4), false],
      ['an ID with a long digit run', (n: number) => `CVE-2021-${'4'.repeat(n)}`, true],
      ['a long digit run with no closer', (n: number) => `CVE-2021-${'4'.repeat(n)}x`, false],
      [
        'distinct IDs joined by a comma and a space',
        (n: number) => distinctIds(Math.ceil(n / 16)).join(', '),
        true,
      ],
    ] as const)('stays linear on %s', async (_shape, build, expected) => {
      await expectLinearCost({
        build,
        expected,
        maxSize: FULL_SPAN,
        run: accepts,
        boundMicros: (size) => 2_000 + size / 10,
      });
    });
  });
});
