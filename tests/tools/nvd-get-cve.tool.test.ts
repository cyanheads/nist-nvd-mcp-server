/**
 * @fileoverview Tests for nvd_get_cve tool.
 * @module tests/tools/nvd-get-cve.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdGetCve, REFERENCE_CAP } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
import { CPE_MATCH_CAP } from '@/mcp-server/tools/formatting/cpe-match.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { BRIEF_DESCRIPTION_CHARS } from '@/services/nvd-cve/nvd-cve-service.js';
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
      { includeReferences: true, allLanguages: true },
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
      { includeReferences: true, allLanguages: false },
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
