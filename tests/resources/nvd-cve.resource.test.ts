/**
 * @fileoverview Tests for nvd://cve/{cveId} resource.
 * @module tests/resources/nvd-cve.resource.test
 */

import { forbidden, JsonRpcErrorCode, serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { createWorkerHandler } from '@cyanheads/mcp-ts-core/worker';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdCveResource } from '@/mcp-server/resources/definitions/nvd-cve.resource.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { CveRecord } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';

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
  configurationNodes: [],
};

describe('nvdCveResource JSON-RPC failure contract', () => {
  it.each([
    [
      'nvd_invalid_response',
      JsonRpcErrorCode.ServiceUnavailable,
      'Try again later; if the failure persists, report the failing tool call.',
    ],
    [
      'nvd_request_blocked',
      JsonRpcErrorCode.Forbidden,
      'Rephrase query text, or try again later or from another network.',
    ],
  ] as const)('fills %s recovery at resources/read', async (reason, code, hint) => {
    const error =
      reason === 'nvd_invalid_response'
        ? serviceUnavailable('Unusable response', { reason, retryable: false })
        : forbidden('Blocked request', { reason, retryable: false });
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue({
      fetchById: vi.fn().mockRejectedValue(error),
    } as never);
    const worker = createWorkerHandler({
      name: 'resource-contract-test',
      resources: [nvdCveResource],
      sessionMode: 'stateless',
    });
    const response = await worker.fetch(
      new Request('http://localhost/mcp', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json, text/event-stream',
          'MCP-Protocol-Version': '2025-11-25',
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'resources/read',
          params: { uri: 'nvd://cve/CVE-2024-1709' },
        }),
      }),
      {
        MCP_AUTH_MODE: 'none',
        STORAGE_PROVIDER_TYPE: 'in-memory',
        OTEL_ENABLED: 'false',
        LOG_LEVEL: 'emerg',
      },
      { waitUntil() {} } as never,
    );
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).toContain(reason);
    expect(body).toContain(hint);
    expect(body).toContain(String(code));
    expect(body).toContain('"error":');
    expect(body).not.toContain('structuredContent');
  });
});

/**
 * `params` is optional on a resource definition — this one declares it, and every case below
 * depends on that. Resolve it once so a regression that dropped the schema fails loudly here
 * rather than silently degrading every parse call.
 */
const resourceParams = nvdCveResource.params;
if (!resourceParams) throw new Error('nvdCveResource must declare a params schema');

/** The `recovery` text the resource declares for `reason` — what the framework puts on the wire. */
function declaredRecovery(reason: string): string | undefined {
  return nvdCveResource.errors?.find((e) => e.reason === reason)?.recovery;
}

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
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'CVE-2021-44228' });
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
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'cve-2021-44228' });
    await nvdCveResource.handler(params, ctx);

    expect(mockService.fetchById).toHaveBeenCalledWith(
      ['CVE-2021-44228'],
      { includeReferences: true, allLanguages: false },
      ctx,
    );
  });

  it('throws validationError for an invalid CVE ID format', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'INVALID-ID' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
  });

  it('throws validationError for a malformed CVE ID (no year)', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'CVE-12345' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/Invalid CVE ID format/);
  });

  /**
   * Issue #33: a resource read of a malformed URI surfaced neither reason nor recovery hint. The
   * handler names the reason; the framework fills the hint from the matching `errors[]` entry at
   * the resource boundary, so both halves are pinned here.
   */
  it('carries the reason whose declared recovery hint names the URI form', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'INVALID-ID' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_cve_id_format', cveId: 'INVALID-ID' },
    });
    expect(declaredRecovery('invalid_cve_id_format')).toContain('nvd://cve/');
  });

  it('propagates service errors (e.g. rate_limited)', async () => {
    mockService.fetchById.mockRejectedValue(new Error('NVD rate limit exceeded'));
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'CVE-2021-44228' });
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
      configurationNodes: [],
    };
    mockService.fetchById.mockResolvedValue({ cves: [sparseCve], returned: 1, requested: 1 });
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'CVE-2022-00001' });
    const result = await nvdCveResource.handler(params, ctx);

    const cve = result as CveRecord;
    expect(cve.cveId).toBe('CVE-2022-00001');
    expect(cve.severity).toBeUndefined();
    expect(cve.cisaKev).toBeUndefined();
  });
});

/**
 * A single-ID miss raises `cve_not_found` inside `fetchById`, so the resource never sees an empty
 * result. These run the real service over a mocked HTTP client to exercise that path end to end —
 * mocking the service would only reach a branch the handler no longer has.
 */
describe('nvdCveResource — absent CVE (service-level throw)', () => {
  const mockClient = { get: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      mockClient as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      new NvdCveService({} as never, {} as never),
    );
    mockClient.get.mockReset();
    mockClient.get.mockResolvedValue({ totalResults: 0, vulnerabilities: [] });
  });

  it('throws notFound when NVD holds no record for a valid ID', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'CVE-9999-99999' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toThrow(/not found/i);
  });

  /**
   * The resource's cve_not_found errors[] entry is what the framework fills onto the service
   * throw at the resource boundary — dropping the entry would silently blank the hint.
   */
  it('carries the reason whose declared recovery hint points at nvd_search_cves', async () => {
    const ctx = createMockContext({ errors: nvdCveResource.errors });
    const params = resourceParams.parse({ cveId: 'CVE-9999-99999' });
    await expect(nvdCveResource.handler(params, ctx)).rejects.toMatchObject({
      data: { reason: 'cve_not_found' },
    });
    expect(declaredRecovery('cve_not_found')).toContain('nvd_search_cves');
  });
});
