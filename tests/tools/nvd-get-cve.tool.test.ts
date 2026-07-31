/**
 * @fileoverview Tests for nvd_get_cve tool.
 * @module tests/tools/nvd-get-cve.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { toJSONSchema } from 'zod/v4/core';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdGetCve, REFERENCE_CAP } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
import { CPE_MATCH_CAP } from '@/mcp-server/tools/formatting/cpe-match.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { BRIEF_DESCRIPTION_CHARS, NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { CveRecord, RawCveItem, RawCveResponse } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';
import * as nvdSourceServiceModule from '@/services/nvd-source/nvd-source-service.js';

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

  // Issue #23: English-only is the default; other languages gate behind allLanguages.
  it('threads allLanguages through to fetchById when set', async () => {
    mockService.fetchById.mockResolvedValue({
      cves: [FULL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    const ctx = createMockContext();
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
    const ctx = createMockContext();
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
    const ctx = createMockContext();
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
      cves: [spanishOnly as unknown as Record<string, unknown>],
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
    const ctx = createMockContext();
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
    const ctx = createMockContext();
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
    const ctx = createMockContext();
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
    const ctx = createMockContext();
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
describe('nvdGetCve — full-mode format() parity (issue #30)', () => {
  /** `count` CPE matches in one node, so the cap boundary can be driven exactly. */
  function cveWithMatches(count: number): Record<string, unknown> {
    return {
      ...FULL_CVE,
      configurations: [
        {
          nodes: [
            {
              operator: 'OR',
              cpeMatch: Array.from({ length: count }, (_, i) => ({
                vulnerable: true,
                criteria: `cpe:2.3:o:fedoraproject:fedora:${30 + i}:*:*:*:*:*:*:*`,
                versionEndExcluding: '2.15.0',
              })),
            },
          ],
        },
      ],
    } as unknown as Record<string, unknown>;
  }

  function cveWithReferences(count: number): Record<string, unknown> {
    return {
      ...FULL_CVE,
      references: Array.from({ length: count }, (_, i) => ({
        url: `https://example.invalid/advisory/${i}`,
        tags: ['Vendor Advisory'],
      })),
    } as unknown as Record<string, unknown>;
  }

  const render = (cves: Record<string, unknown>[]) =>
    (nvdGetCve.format!({ brief: false, cves })[0] as { text: string }).text;

  it('renders actual CPE match criteria and version bounds, not just a group count', () => {
    const text = render([cveWithMatches(1)]);

    expect(text).toContain('cpe:2.3:o:fedoraproject:fedora:30:*:*:*:*:*:*:*');
    expect(text).toContain('< 2.15.0');
    expect(text).toContain('1 node group(s), 1 CPE match(es)');
    // The old formatter stopped at the group count and printed no criteria at all.
    expect(text).not.toMatch(/\*\*Configurations:\*\* 1 node group\(s\)\s*$/m);
  });

  it('omits the CPE-match trailer when the count is exactly the cap', () => {
    const text = render([cveWithMatches(CPE_MATCH_CAP)]);

    expect(text.match(/cpe:2\.3:o:fedoraproject/g)).toHaveLength(CPE_MATCH_CAP);
    expect(text).not.toContain('more —');
  });

  it('adds the CPE-match trailer at one past the cap and points at the retrieval path', () => {
    const text = render([cveWithMatches(CPE_MATCH_CAP + 1)]);

    expect(text.match(/cpe:2\.3:o:fedoraproject/g)).toHaveLength(CPE_MATCH_CAP);
    expect(text).toContain('… 1 more');
    // A capped remainder with no way to reach it is a dead end — name the tool that gets there.
    expect(text).toContain('nvd_audit_cpe');
  });

  it('omits the references trailer when the count is exactly the cap', () => {
    const text = render([cveWithReferences(REFERENCE_CAP)]);

    expect(text.match(/example\.invalid\/advisory/g)).toHaveLength(REFERENCE_CAP);
    expect(text).not.toContain('more references');
  });

  it('adds the references trailer at one past the cap', () => {
    const text = render([cveWithReferences(REFERENCE_CAP + 1)]);

    expect(text.match(/example\.invalid\/advisory/g)).toHaveLength(REFERENCE_CAP);
    expect(text).toContain('… 1 more references');
  });

  it('renders every language a record carries so allLanguages reaches content[]', () => {
    const bilingual = {
      ...FULL_CVE,
      descriptions: [
        { lang: 'en', value: 'Buffer overflow in mod_lua.' },
        { lang: 'es', value: 'Desbordamiento de bufer en mod_lua.' },
      ],
    } as unknown as Record<string, unknown>;
    const text = render([bilingual]);

    expect(text).toContain('Buffer overflow in mod_lua.');
    // Previously the picker took the English entry and the Spanish one never rendered.
    expect(text).toContain('Desbordamiento de bufer en mod_lua.');
    expect(text).toContain('[en]');
    expect(text).toContain('[es]');
  });

  it('renders the single English description under the default language policy', () => {
    const text = render([FULL_CVE as unknown as Record<string, unknown>]);

    expect(text).toContain('[en] Apache Log4j2 JNDI vulnerability.');
    expect(text).not.toContain('[es]');
  });

  it('renders nothing for descriptions when a record carries none', () => {
    const text = render([SPARSE_CVE as unknown as Record<string, unknown>]);

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
    const result = await nvdGetCve.handler(input, createMockContext());
    return result.cves;
  }

  it('emits rows identical to the search surface for the same upstream payload', async () => {
    const searched = await service.searchCves({ keyword: 'anything' }, createMockContext());
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
      createMockContext(),
    );

    // Same record, same builder — only the filter version the search surface passes differs.
    expect(searched.cves[6].filteredSeverity).toEqual({
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
    toJSONSchema(def.output as never, { io: 'output', unrepresentable: 'any' }) as {
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
    'configurations',
    'references',
    'cisaKev',
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
  } as unknown as Record<string, unknown>;

  const render = (cves: Record<string, unknown>[], brief = false) =>
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
      expect(text).toContain('cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*');
      expect(text).toContain('**CISA KEV Details:**');
    }
  });

  it('renders the weakness source alongside its CWE ids', () => {
    expect(render([FULL_CVE as unknown as Record<string, unknown>])).toContain('NVD: CWE-20');
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
    } as unknown as Record<string, unknown>;

    expect(render([withSource])).toContain(
      'https://example.invalid/a [cve@mitre.org] (Vendor Advisory)',
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
