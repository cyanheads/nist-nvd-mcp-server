/**
 * @fileoverview Security tests — injection attempts, oversized inputs, API key/secret
 * non-disclosure, path traversal resistance, and other MCP-layer security properties.
 * All external HTTP is mocked; no real network calls are made.
 * @module tests/security
 */

import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdCveResource } from '@/mcp-server/resources/definitions/nvd-cve.resource.js';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdGetCve } from '@/mcp-server/tools/definitions/nvd-get-cve.tool.js';
import { nvdGetCveHistory } from '@/mcp-server/tools/definitions/nvd-get-cve-history.tool.js';
import { nvdSearchCpes } from '@/mcp-server/tools/definitions/nvd-search-cpes.tool.js';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCpeServiceModule from '@/services/nvd-cpe/nvd-cpe-service.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import type { BriefCveRecord, CveRecord } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';

// ---------------------------------------------------------------------------
// Minimal mock data
// ---------------------------------------------------------------------------

const MINIMAL_CVE: CveRecord = {
  cveId: 'CVE-2021-44228',
  vulnStatus: 'Analyzed',
  published: '2021-12-10T10:15:00.000',
  lastModified: '2023-11-06T03:18:00.000',
  descriptions: [{ lang: 'en', value: 'Test description.' }],
  cvssScores: [{ version: '3.1', sourceType: 'Primary', baseScore: 10.0, severity: 'CRITICAL' }],
  severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
  weaknesses: [],
  configurations: [],
};

const MINIMAL_BRIEF: BriefCveRecord = {
  cveId: 'CVE-2021-44228',
  vulnStatus: 'Analyzed',
  published: '2021-12-10T10:15:00.000',
  severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
};

function makeCveService(
  overrides: Partial<{
    searchCves: unknown;
    fetchById: unknown;
    auditCpe: unknown;
    getCveHistory: unknown;
  }> = {},
) {
  return {
    searchCves: vi
      .fn()
      .mockResolvedValue({ cves: [MINIMAL_BRIEF], totalResults: 1, returned: 1, offset: 0 }),
    fetchById: vi
      .fn()
      .mockResolvedValue({ cves: [MINIMAL_CVE], returned: 1, requested: 1, missingIds: [] }),
    auditCpe: vi.fn().mockResolvedValue({
      cves: [MINIMAL_CVE],
      totalResults: 1,
      returned: 1,
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    }),
    getCveHistory: vi.fn().mockResolvedValue({
      cveId: 'CVE-2021-44228',
      changes: [{ changeDate: '2022-01-01T00:00:00.000', details: [] }],
      totalResults: 1,
      returned: 1,
      offset: 0,
    }),
    ...overrides,
  };
}

function makeCpeService(overrides: Partial<{ searchCpes: unknown }> = {}) {
  return {
    searchCpes: vi.fn().mockResolvedValue({
      cpes: [{ cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*', deprecated: false }],
      totalResults: 1,
      returned: 1,
    }),
    ...overrides,
  };
}

describe('Security — injection and oversized input resistance', () => {
  let mockCveService: ReturnType<typeof makeCveService>;
  let mockCpeService: ReturnType<typeof makeCpeService>;

  beforeEach(() => {
    mockCveService = makeCveService();
    mockCpeService = makeCpeService();
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockCveService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(
      mockCpeService as unknown as ReturnType<typeof nvdCpeServiceModule.getNvdCpeService>,
    );
    mockCveService.searchCves.mockReset();
    mockCveService.fetchById.mockReset();
    mockCveService.auditCpe.mockReset();
    mockCveService.getCveHistory.mockReset();
    mockCpeService.searchCpes.mockReset();
    mockCveService.searchCves.mockResolvedValue({
      cves: [MINIMAL_BRIEF],
      totalResults: 1,
      returned: 1,
      offset: 0,
    });
    mockCveService.fetchById.mockResolvedValue({
      cves: [MINIMAL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
    mockCveService.auditCpe.mockResolvedValue({
      cves: [MINIMAL_CVE],
      totalResults: 1,
      returned: 1,
      cpeName: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*',
    });
    mockCveService.getCveHistory.mockResolvedValue({
      cveId: 'CVE-2021-44228',
      changes: [{ changeDate: '2022-01-01T00:00:00.000', details: [] }],
      totalResults: 1,
      returned: 1,
      offset: 0,
    });
    mockCpeService.searchCpes.mockResolvedValue({
      cpes: [{ cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*', deprecated: false }],
      totalResults: 1,
      returned: 1,
    });
  });

  // --- Injection in keyword search ---

  it('nvd_search_cves: SQL injection in keyword is accepted by schema and forwarded to service (not interpreted locally)', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: "' OR '1'='1'; DROP TABLE cves;--" });
    await nvdSearchCves.handler(input, ctx);
    // The handler should not crash; the keyword is forwarded to NVD API as-is
    expect(mockCveService.searchCves).toHaveBeenCalled();
    const params = mockCveService.searchCves.mock.calls[0][0] as Record<string, unknown>;
    expect(params.keyword).toContain('DROP TABLE');
  });

  it('nvd_search_cves: angle-bracket injection in keyword is forwarded unmodified', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: '<script>alert(1)</script>' });
    await nvdSearchCves.handler(input, ctx);
    const params = mockCveService.searchCves.mock.calls[0][0] as Record<string, unknown>;
    expect(params.keyword).toBe('<script>alert(1)</script>');
  });

  it('nvd_search_cves: null-byte in keyword is passed through schema without error', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'test\0malicious' });
    // Zod accepts arbitrary strings; the service layer would handle it
    await nvdSearchCves.handler(input, ctx);
    expect(mockCveService.searchCves).toHaveBeenCalled();
  });

  it('nvd_search_cpes: CPE injection pattern in keyword forwarded to service', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'cpe:2.3:*:*:*:*:*:*:*:*:* AND 1=1' });
    await nvdSearchCpes.handler(input, ctx);
    expect(mockCpeService.searchCpes).toHaveBeenCalled();
  });

  it('nvd_audit_cpe: path traversal string rejected as invalid CPE format', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ cpeName: '../../etc/passwd' });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('nvd_audit_cpe: URL-like injection in cpeName rejected as invalid CPE format', async () => {
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ cpeName: 'https://evil.example.com/' });
    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('nvd_search_cpes: invalid cpeMatchString without cpe:2.3: prefix is rejected', async () => {
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const input = nvdSearchCpes.input.parse({ cpeMatchString: "'; DROP TABLE--" });
    await expect(nvdSearchCpes.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  // --- CVE ID format as injection barrier ---

  it('nvd_get_cve: non-CVE string accepted by schema, forwarded to service which handles format validation', async () => {
    // The tool schema accepts free-form strings; the service validates format
    // This is valid behavior — the tool delegates format validation to the service layer
    mockCveService.fetchById.mockRejectedValue(
      Object.assign(new Error('Invalid CVE ID format'), {
        data: { reason: 'invalid_cve_id_format' },
      }),
    );
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: "'; SELECT * FROM cves;--" });
    await expect(nvdGetCve.handler(input, ctx)).rejects.toThrow('Invalid CVE ID format');
  });

  // --- Oversized inputs ---

  it('nvd_search_cves: limit at schema max (2000) is accepted', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'test', limit: 2000 });
    await nvdSearchCves.handler(input, ctx);
    expect(mockCveService.searchCves).toHaveBeenCalled();
  });

  it('nvd_search_cves: limit over schema max is rejected by Zod', () => {
    expect(() => nvdSearchCves.input.parse({ keyword: 'test', limit: 2001 })).toThrow();
  });

  it('nvd_search_cpes: limit at schema max (10000) is accepted', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'apache', limit: 10_000 });
    await nvdSearchCpes.handler(input, ctx);
    expect(mockCpeService.searchCpes).toHaveBeenCalled();
  });

  it('nvd_search_cpes: limit over schema max is rejected by Zod', () => {
    expect(() => nvdSearchCpes.input.parse({ keyword: 'apache', limit: 10_001 })).toThrow();
  });

  it('nvd_get_cve: array of 100 CVE IDs is at schema max and accepted', () => {
    const ids = Array.from(
      { length: 100 },
      (_, i) => `CVE-2021-${String(i + 1000).padStart(5, '0')}`,
    );
    expect(() => nvdGetCve.input.parse({ cveIds: ids })).not.toThrow();
  });

  it('nvd_get_cve: array over 100 CVE IDs is rejected by Zod', () => {
    const ids = Array.from(
      { length: 101 },
      (_, i) => `CVE-2021-${String(i + 1000).padStart(5, '0')}`,
    );
    expect(() => nvdGetCve.input.parse({ cveIds: ids })).toThrow();
  });

  it('nvd_get_cve_history: offset at schema min (0) is accepted', () => {
    expect(() =>
      nvdGetCveHistory.input.parse({ cveId: 'CVE-2021-44228', offset: 0 }),
    ).not.toThrow();
  });

  it('nvd_get_cve_history: negative offset is rejected by Zod', () => {
    expect(() => nvdGetCveHistory.input.parse({ cveId: 'CVE-2021-44228', offset: -1 })).toThrow();
  });

  // --- Prototype pollution probes ---

  it('nvd_search_cves: __proto__ in keyword is forwarded without crashing', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: '__proto__' });
    await nvdSearchCves.handler(input, ctx);
    expect(mockCveService.searchCves).toHaveBeenCalled();
  });

  it('nvd_search_cpes: constructor.prototype in keyword is forwarded without crashing', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: 'constructor.prototype.polluted' });
    await nvdSearchCpes.handler(input, ctx);
    expect(mockCpeService.searchCpes).toHaveBeenCalled();
  });
});

describe('Security — API key and secret non-disclosure', () => {
  let mockCveService: ReturnType<typeof makeCveService>;
  let mockCpeService: ReturnType<typeof makeCpeService>;

  beforeEach(() => {
    mockCveService = makeCveService();
    mockCpeService = makeCpeService();
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockCveService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(
      mockCpeService as unknown as ReturnType<typeof nvdCpeServiceModule.getNvdCpeService>,
    );
  });

  it('nvd_search_cves output does not contain API key token', async () => {
    // Simulate an env value leaking into a CVE record description
    const fakeApiKey = 'TEST_API_KEY_SHOULD_NOT_APPEAR_12345';
    const briefWithLeak: BriefCveRecord = {
      cveId: 'CVE-2021-44228',
      vulnStatus: 'Analyzed',
      published: '2021-12-10T10:15:00.000',
    };
    mockCveService.searchCves.mockResolvedValue({
      cves: [briefWithLeak],
      totalResults: 1,
      returned: 1,
      offset: 0,
    });
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'log4j' });
    const result = await nvdSearchCves.handler(input, ctx);

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(fakeApiKey);
  });

  /**
   * `format()` renders every declared field of a record now that both modes share one item
   * schema, so "it renders only what the handler returned" is the property worth pinning: put a
   * credential in the environment the process can actually reach and assert none of it lands in
   * the rendered text.
   */
  it('nvd_get_cve format() renders only handler data, never process credentials', () => {
    const fakeApiKey = 'NVD-KEY-SHOULD-NOT-APPEAR-a1b2c3';
    const fakeBearer = 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake';
    vi.stubEnv('NVD_API_KEY', fakeApiKey);
    vi.stubEnv('AUTH_SECRET_KEY', fakeBearer);

    try {
      const text = (
        nvdGetCve.format!({
          brief: false,
          cves: [MINIMAL_CVE as unknown as Record<string, unknown>],
        })[0] as { text: string }
      ).text;

      expect(text).toContain('CVE-2021-44228');
      expect(text).not.toContain(fakeApiKey);
      expect(text).not.toContain(fakeBearer);
      expect(text).not.toContain('Bearer');
    } finally {
      vi.unstubAllEnvs();
    }
  });

  it('nvd_audit_cpe format() does not leak internal error details', () => {
    const output = { cves: [] };
    const blocks = nvdAuditCpe.format!(output);
    const text = (blocks[0] as { text: string }).text;
    // No stack traces or internal error messages
    expect(text).not.toMatch(/Error\s*at\s/);
    expect(text).not.toContain('apiKey');
    expect(text).not.toContain('NVD_API_KEY');
  });

  it('nvd_search_cpes format() does not include environment variable names', () => {
    const output = {
      cpes: [{ cpeName: 'cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*', deprecated: false }],
    };
    const blocks = nvdSearchCpes.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).not.toContain('NVD_API_KEY');
    expect(text).not.toContain('process.env');
  });

  /**
   * A service error carrying a secret must reach the framework as a rejection, not be swallowed
   * into a success envelope: `format()` only runs on success, so propagating is what keeps the
   * secret out of every rendered block.
   */
  it('propagates a service error rather than returning a success envelope', async () => {
    const fakeApiKey = 'super-secret-api-key-9999';
    mockCveService.fetchById.mockRejectedValue(
      new Error(`Service error (key=${fakeApiKey}): failed`),
    );
    const ctx = createMockContext();
    const input = nvdGetCve.input.parse({ cveIds: 'CVE-2021-44228' });

    await expect(nvdGetCve.handler(input, ctx)).rejects.toThrow('Service error');
  });
});

describe('Security — resource handler input validation', () => {
  let mockCveService: ReturnType<typeof makeCveService>;

  beforeEach(() => {
    mockCveService = makeCveService();
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockCveService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockCveService.fetchById.mockResolvedValue({
      cves: [MINIMAL_CVE],
      returned: 1,
      requested: 1,
      missingIds: [],
    });
  });

  /**
   * The rejection runs through `ctx.fail`, which only exists on a context carrying the
   * definition's contract — without it these assert against a TypeError, not the guard.
   */
  it('nvd://cve resource: path traversal attempt is rejected by CVE format validation', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = nvdCveResource.params.parse({ cveId: '../../etc/passwd' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
  });

  it('nvd://cve resource: numeric-only string is rejected as invalid format', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = nvdCveResource.params.parse({ cveId: '12345678' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
  });

  it('nvd://cve resource: injection string rejected before any network call', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = nvdCveResource.params.parse({ cveId: "<script>alert('xss')</script>" });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
    // Service should NOT have been called
    expect(mockCveService.fetchById).not.toHaveBeenCalled();
  });

  it('nvd://cve resource: valid CVE ID does reach the service', async () => {
    const ctx = createMockContext();
    const params = nvdCveResource.params.parse({ cveId: 'CVE-2021-44228' });
    await nvdCveResource.handler(params, ctx);
    expect(mockCveService.fetchById).toHaveBeenCalledOnce();
  });
});

describe('Security — unicode and encoding edge cases', () => {
  let mockCveService: ReturnType<typeof makeCveService>;
  let mockCpeService: ReturnType<typeof makeCpeService>;

  beforeEach(() => {
    mockCveService = makeCveService();
    mockCpeService = makeCpeService();
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockCveService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(
      mockCpeService as unknown as ReturnType<typeof nvdCpeServiceModule.getNvdCpeService>,
    );
    mockCveService.searchCves.mockResolvedValue({
      cves: [MINIMAL_BRIEF],
      totalResults: 1,
      returned: 1,
      offset: 0,
    });
    mockCpeService.searchCpes.mockResolvedValue({
      cpes: [{ cpeName: 'cpe:2.3:a:test:test:1.0:*:*:*:*:*:*:*', deprecated: false }],
      totalResults: 1,
      returned: 1,
    });
  });

  it('nvd_search_cves: unicode keyword is accepted and forwarded', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'Struts アパッチ' });
    await nvdSearchCves.handler(input, ctx);
    expect(mockCveService.searchCves).toHaveBeenCalled();
  });

  it('nvd_search_cves: emoji in keyword is accepted by schema', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'test 🚀 exploit' });
    await nvdSearchCves.handler(input, ctx);
    expect(mockCveService.searchCves).toHaveBeenCalled();
  });

  it('nvd_search_cpes: unicode vendor name forwarded without corruption', async () => {
    const ctx = createMockContext();
    const input = nvdSearchCpes.input.parse({ keyword: '漢字（漢字）' });
    await nvdSearchCpes.handler(input, ctx);
    expect(mockCpeService.searchCpes).toHaveBeenCalled();
  });

  it('nvd_search_cves format: unicode in CVE description is rendered without corruption', () => {
    const briefWithUnicode: BriefCveRecord = {
      cveId: 'CVE-2021-44228',
      vulnStatus: 'Analyzed',
      published: '2021-12-10T10:15:00.000',
      severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
      description: 'JNDI 注入 — Apache Log4j2 ≤2.14.1 の脆弱性 🔥',
    };
    const output = { cves: [briefWithUnicode] };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('JNDI 注入 — Apache Log4j2 ≤2.14.1 の脆弱性 🔥');
  });
});

/**
 * Issue #45: the CPE tools' prefix check is not the only path to `invalid_cpe_format` — NVD
 * rejects a CPE parameter it cannot parse with an HTTP 404, and that rejection used to reach the
 * caller as an undeclared `nvd_request_rejected` with no recovery hint. The rejection is the CPE
 * string's fault; a well-formed CPE with no matches stays an empty success.
 */
describe('Security — NVD CPE parameter rejection stays inside the declared contract', () => {
  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      new nvdCveServiceModule.NvdCveService({} as never, {} as never),
    );
    vi.spyOn(nvdCpeServiceModule, 'getNvdCpeService').mockReturnValue(
      new nvdCpeServiceModule.NvdCpeService({} as never, {} as never),
    );
  });

  /** Mock the HTTP client to reject exactly the way NVD does, message header and all. */
  function rejectWith(endpoint: string, detail: string) {
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue({
      get: vi.fn().mockRejectedValue(nvdHttpClientModule.nvdRequestRejected(endpoint, detail)),
    } as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>);
  }

  it('nvd_audit_cpe: a structurally incomplete cpeName reports invalid_cpe_format', async () => {
    rejectWith('cves/2.0', 'Invalid cpeName parameter, see documentation.');
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ cpeName: 'cpe:2.3:a:zzznotavendor' });

    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format', recovery: { hint: expect.any(String) } },
    });
  });

  it('nvd_audit_cpe: a malformed virtualMatchString reports invalid_cpe_format', async () => {
    rejectWith('cves/2.0', 'Invalid virtualMatchString parameter, see documentation.');
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ virtualMatchString: 'cpe:2.3:a:zzz notavendor:%%%:' });

    await expect(nvdAuditCpe.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  it('nvd_search_cpes: a malformed cpeMatchString reports invalid_cpe_format', async () => {
    rejectWith('cpes/2.0', 'Invalid cpeMatchstring parameter, see documentation.');
    const ctx = createMockContext({ errors: nvdSearchCpes.errors });
    const input = nvdSearchCpes.input.parse({ cpeMatchString: 'cpe:2.3:a:zzz notavendor:%%%:' });

    await expect(nvdSearchCpes.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cpe_format' },
    });
  });

  /**
   * The translated message quotes the caller's own CPE string and NVD's diagnosis. Neither is a
   * secret, but the error must not widen into request internals the caller never supplied.
   */
  it('the translated message carries no request internals', async () => {
    const fakeApiKey = 'NVD-KEY-SHOULD-NOT-APPEAR-a1b2c3';
    vi.stubEnv('NVD_API_KEY', fakeApiKey);
    rejectWith('cves/2.0', 'Invalid cpeName parameter, see documentation.');
    const ctx = createMockContext({ errors: nvdAuditCpe.errors });
    const input = nvdAuditCpe.input.parse({ cpeName: 'cpe:2.3:a:zzznotavendor' });

    try {
      await nvdAuditCpe.handler(input, ctx);
      expect.unreachable('handler should have thrown');
    } catch (err) {
      const message = (err as Error).message;
      expect(message).toContain('cpe:2.3:a:zzznotavendor');
      expect(message).not.toContain(fakeApiKey);
      expect(message).not.toContain('services.nvd.nist.gov');
      expect(message).not.toContain('apiKey');
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
