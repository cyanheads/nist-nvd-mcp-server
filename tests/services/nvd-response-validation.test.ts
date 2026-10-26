/**
 * @fileoverview NVD envelope validation through real HTTP parsing and service boundaries.
 * @module tests/services/nvd-response-validation.test
 */
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NvdCpeService } from '@/services/nvd-cpe/nvd-cpe-service.js';
import { NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import { rawCveHistoryResponseSchema, rawCveResponseSchema } from '@/services/nvd-cve/types.js';
import { initNvdHttpClient, NvdHttpClient } from '@/services/nvd-http/nvd-http-client.js';
import { NvdSourceService } from '@/services/nvd-source/nvd-source-service.js';

const cve = new NvdCveService({} as never, {} as never);
const cpe = new NvdCpeService({} as never, {} as never);
const calls = {
  search: () => cve.searchCves({ keyword: 'test' }, createMockContext()),
  audit: () => cve.auditCpe({ virtualMatchString: 'cpe:2.3:a:vendor' }, createMockContext()),
  fetch: () =>
    cve.fetchById(
      ['CVE-2024-1709'],
      { allLanguages: false, includeReferences: false, resolveSources: false },
      createMockContext(),
    ),
  history: () =>
    cve.getCveHistory(
      { cveId: 'CVE-2024-1709', limit: 1, offset: 0, order: 'oldest' },
      createMockContext(),
    ),
  cpes: () => cpe.searchCpes({ keyword: 'test' }, createMockContext()),
};

function respond(value: unknown) {
  const fetch = vi.fn(async () => new Response(JSON.stringify(value)));
  vi.stubGlobal('fetch', fetch);
  return fetch;
}

describe('NVD validated response boundaries', () => {
  beforeEach(() => {
    vi.useFakeTimers({ now: new Date('2026-01-01T00:00:00Z') });
    initNvdHttpClient(undefined, 100);
  });
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('preserves sparse CVE and CPE records without requiring optional enrichment', async () => {
    respond({
      totalResults: 1,
      vulnerabilities: [{ cve: { id: 'CVE-2024-1709', futureSsvc: { options: ['unknown'] } } }],
    });
    expect(await calls.search()).toEqual({
      cves: [{ cveId: 'CVE-2024-1709', published: '', vulnStatus: '' }],
      totalResults: 1,
      returned: 1,
      offset: 0,
    });
    initNvdHttpClient(undefined, 100);
    respond({ totalResults: 1, products: [{ cpe: {} }] });
    expect(await calls.cpes()).toMatchObject({
      cpes: [{ cpeName: '', deprecated: false }],
      returned: 1,
    });
  });

  it('preserves structured history detail values', async () => {
    respond({
      totalResults: 1,
      cveChanges: [
        {
          change: { details: [{ oldValue: ['one', { two: 2 }], newValue: { future: ['ssvc'] } }] },
        },
      ],
    });
    expect(await calls.history()).toMatchObject({
      changes: [{ details: [{ oldValue: '["one",{"two":2}]', newValue: '{"future":["ssvc"]}' }] }],
    });
  });

  it('retains unknown fields throughout parsed envelopes and nested records', () => {
    const record = {
      totalResults: 1,
      futureEnvelope: true,
      vulnerabilities: [
        {
          futureWrapper: 3,
          cve: {
            id: 'CVE-2024-1709',
            futureSsvc: { values: [null, true] },
            metrics: {
              futureMetric: { score: 1 },
              cvssMetricV31: [{ futureField: 'kept', cvssData: { futureData: 'kept' } }],
            },
          },
        },
      ],
    };
    expect(rawCveResponseSchema.parse(record)).toEqual(record);
    const history = {
      totalResults: 1,
      cveChanges: [
        {
          change: {
            future: { retained: true },
            details: [{ oldValue: { nested: ['kept'] }, future: null }],
          },
        },
      ],
    };
    expect(rawCveHistoryResponseSchema.parse(history)).toEqual(history);
  });

  it.each(Object.keys(calls) as Array<keyof typeof calls>)(
    'rejects a wrong %s envelope rather than returning an empty result',
    async (name) => {
      const fetch = respond({ message: 'upstream schema changed' });
      await expect(calls[name]()).rejects.toMatchObject({
        code: JsonRpcErrorCode.ServiceUnavailable,
        data: { reason: 'nvd_invalid_response', retryable: false },
      });
      expect(fetch).toHaveBeenCalledTimes(1);
    },
  );

  it.each([
    { vulnerabilities: [] },
    { totalResults: 0 },
    { totalResults: '0', vulnerabilities: [] },
    { totalResults: 1, vulnerabilities: [{ cve: {} }] },
    { totalResults: 1, vulnerabilities: [{}] },
  ])('rejects an invalid CVE count, collection, or identity: %j', async (response) => {
    const fetch = respond(response);
    await expect(calls.search()).rejects.toMatchObject({
      data: { reason: 'nvd_invalid_response', retryable: false },
    });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it.each([
    ['search', { totalResults: 0, vulnerabilities: [] }],
    ['cpes', { totalResults: 0, products: [] }],
    ['history', { totalResults: 0, cveChanges: [] }],
  ] as const)('accepts a valid empty %s envelope', async (name, response) => {
    respond(response);
    expect(await calls[name]()).toMatchObject({ totalResults: 0, returned: 0 });
  });

  it('does not retry malformed completed JSON and releases the queue', async () => {
    const fetch = vi.fn(async () => new Response(fetch.mock.calls.length === 1 ? '{' : '{}'));
    vi.stubGlobal('fetch', fetch);
    const client = new NvdHttpClient(undefined, 100);
    const first = client.get('cves/2.0', {}, createMockContext()).catch((error: unknown) => error);
    const next = client.get('cves/2.0', {}, createMockContext());
    await vi.advanceTimersByTimeAsync(60_000);
    expect(await first).toMatchObject({
      data: { reason: 'nvd_invalid_response', retryable: false },
    });
    expect(await next).toEqual({});
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('negative-caches invalid source envelopes and retries after the failure TTL', async () => {
    const fetch = respond({ message: 'wrong envelope' });
    const service = new NvdSourceService({} as never, {} as never);
    const ctx = createMockContext();
    expect((await service.getResolver(ctx))('opaque')).toBe('opaque');
    await vi.advanceTimersByTimeAsync(300_001);
    await service.getResolver(ctx);
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
