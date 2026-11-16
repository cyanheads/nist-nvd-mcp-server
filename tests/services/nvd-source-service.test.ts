/**
 * @fileoverview Tests for NvdSourceService and the source-name resolution it feeds into
 * `normalizeCve` — GUID resolution, email passthrough, unknown-identifier passthrough,
 * degradation when the dictionary is unavailable, and the caching that keeps it to one
 * upstream request. Fixtures mirror the live `/rest/json/source/2.0` payload.
 * @module tests/services/nvd-source-service.test
 */

import {
  JsonRpcErrorCode,
  requestCancelled,
  serviceUnavailable,
} from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, type MockContextLogger } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import type { CveRecord, RawCveResponse } from '@/services/nvd-cve/types.js';
import * as nvdHttpClientModule from '@/services/nvd-http/nvd-http-client.js';
import {
  initNvdSourceService,
  NvdSourceService,
  type SourceNameResolver,
} from '@/services/nvd-source/nvd-source-service.js';
import type { RawNvdSourceResponse } from '@/services/nvd-source/types.js';
import { at } from '../support/at.js';

/** Three real dictionary entries: two GUID-only contributors and one identified by email. */
const SOURCE_RESPONSE: RawNvdSourceResponse = {
  resultsPerPage: 3,
  startIndex: 0,
  totalResults: 3,
  sources: [
    {
      name: 'CVE',
      contactEmail: 'cve-request@mitre.org',
      sourceIdentifiers: ['af854a3a-2127-422b-91ae-364da2661108'],
    },
    {
      name: 'CISA-ADP',
      contactEmail: 'cisa@example.com',
      sourceIdentifiers: ['134c704f-9b21-4f2e-91b3-4a467353bcc0'],
    },
    {
      name: 'Apache Software Foundation',
      contactEmail: 'security@apache.org',
      sourceIdentifiers: ['security@apache.org', 'f0158376-9dc2-43b6-827c-5f631a4d8d09'],
    },
  ],
};

/**
 * The three identifier forms a modern record carries on one CVE, as CVE-2024-23225 does: the
 * CVE Program GUID, the CISA-ADP GUID, and a CNA's email address.
 */
const CVE_RESPONSE: RawCveResponse = {
  totalResults: 1,
  vulnerabilities: [
    {
      cve: {
        id: 'CVE-2024-23225',
        vulnStatus: 'Modified',
        published: '2024-03-05T23:15:00.000',
        lastModified: '2025-11-03T22:16:00.000',
        weaknesses: [
          {
            source: '134c704f-9b21-4f2e-91b3-4a467353bcc0',
            description: [{ lang: 'en', value: 'CWE-787' }],
          },
          { source: 'security@apache.org', description: [{ lang: 'en', value: 'CWE-20' }] },
          {
            source: '00000000-0000-0000-0000-000000000000',
            description: [{ lang: 'en', value: 'CWE-119' }],
          },
        ],
        references: [
          {
            url: 'https://support.apple.com/en-us/HT214081',
            source: 'af854a3a-2127-422b-91ae-364da2661108',
            tags: ['Release Notes'],
          },
          { url: 'https://httpd.apache.org/security/', source: 'security@apache.org' },
          { url: 'https://example.invalid/adv', source: '00000000-0000-0000-0000-000000000000' },
        ],
      },
    },
  ],
};

/** Route the mocked client by endpoint so the dictionary and CVE calls stay distinguishable. */
function makeClient(sourceResult: () => Promise<unknown>) {
  const get = vi.fn(
    async (
      endpoint: string,
      _params?: Record<string, unknown>,
      _ctx?: unknown,
      _budget?: { maxRetries?: number; timeoutMs?: number },
    ) => (endpoint === 'source/2.0' ? await sourceResult() : CVE_RESPONSE),
  );
  return {
    get,
    sourceCalls: () => get.mock.calls.filter(([endpoint]) => endpoint === 'source/2.0').length,
  };
}

describe('NvdSourceService — source identifier resolution', () => {
  let client: ReturnType<typeof makeClient>;

  function install(sourceResult: () => Promise<unknown> = async () => SOURCE_RESPONSE) {
    client = makeClient(sourceResult);
    vi.spyOn(nvdHttpClientModule, 'getNvdHttpClient').mockReturnValue(
      client as unknown as ReturnType<typeof nvdHttpClientModule.getNvdHttpClient>,
    );
  }

  beforeEach(() => {
    // A fresh instance per test — the dictionary cache is per-instance and holds for a day.
    initNvdSourceService({} as never, {} as never);
    install();
  });

  const service = new NvdCveService({} as never, {} as never);

  async function fetchOne() {
    const result = await service.fetchById(
      ['CVE-2024-23225'],
      { includeReferences: true, allLanguages: false },
      createMockContext(),
    );
    return at(result.cves);
  }

  it('resolves a GUID identifier to its published contributor name', async () => {
    const cve = await fetchOne();
    expect(at(cve.weaknesses, 0).source).toBe('CISA-ADP');
    expect(at(cve.references, 0).source).toBe('CVE');
  });

  it('leaves an email-form identifier untouched', async () => {
    const cve = await fetchOne();
    // `security@apache.org` is already legible — it must not become "Apache Software Foundation".
    expect(at(cve.weaknesses, 1).source).toBe('security@apache.org');
    expect(at(cve.references, 1).source).toBe('security@apache.org');
  });

  it('passes an identifier the dictionary does not carry through as its raw value', async () => {
    const cve = await fetchOne();
    expect(at(cve.weaknesses, 2).source).toBe('00000000-0000-0000-0000-000000000000');
    expect(at(cve.references, 2).source).toBe('00000000-0000-0000-0000-000000000000');
  });

  it('degrades to raw identifiers when the dictionary request fails, without failing the call', async () => {
    install(async () => {
      throw serviceUnavailable('NVD API returned HTTP 503.');
    });
    const cve = await fetchOne();

    expect(cve.cveId).toBe('CVE-2024-23225');
    expect(at(cve.weaknesses, 0).source).toBe('134c704f-9b21-4f2e-91b3-4a467353bcc0');
    expect(at(cve.references, 0).source).toBe('af854a3a-2127-422b-91ae-364da2661108');
  });

  it('degrades to raw identifiers when the dictionary body is unusable', async () => {
    // An invalid HTTP 200 envelope follows the unavailable-dictionary fallback.
    install(async () => ({ totalResults: 0 }));
    const cve = await fetchOne();
    expect(at(cve.weaknesses, 0).source).toBe('134c704f-9b21-4f2e-91b3-4a467353bcc0');
  });

  it('fetches the dictionary once across repeated calls', async () => {
    await fetchOne();
    await fetchOne();
    await fetchOne();

    expect(client.sourceCalls()).toBe(1);
  });

  it('does not refetch the dictionary on every call after a failure', async () => {
    install(async () => {
      throw serviceUnavailable('NVD API returned HTTP 503.');
    });
    await fetchOne();
    await fetchOne();

    // A sustained outage must not cost an upstream request per tool call.
    expect(client.sourceCalls()).toBe(1);
  });

  it('shares one in-flight request across concurrent cold-cache callers', async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    install(async () => {
      await gate;
      return SOURCE_RESPONSE;
    });

    const calls = Promise.all([fetchOne(), fetchOne(), fetchOne()]);
    release?.();
    const cves = await calls;

    expect(client.sourceCalls()).toBe(1);
    for (const cve of cves) expect(at(cve.weaknesses, 0).source).toBe('CISA-ADP');
  });

  it('does not fetch the dictionary for a search, whose brief rows carry no source field', async () => {
    await service.searchCves({ keyword: 'apple' }, createMockContext());
    expect(client.sourceCalls()).toBe(0);
  });

  it('does not fetch the dictionary for an audit that returned no CVEs', async () => {
    client.get.mockImplementation(async (endpoint: string) =>
      endpoint === 'source/2.0' ? SOURCE_RESPONSE : { totalResults: 0, vulnerabilities: [] },
    );
    const result = await service.auditCpe(
      { virtualMatchString: 'cpe:2.3:a:nonexistent:product:*' },
      createMockContext(),
    );

    expect(result.cves).toHaveLength(0);
    expect(client.sourceCalls()).toBe(0);
  });

  it('resolves identifiers on the audit surface too', async () => {
    const result = await service.auditCpe(
      { cpeName: 'cpe:2.3:a:apple:macos:14.3:*:*:*:*:*:*:*' },
      createMockContext(),
    );

    expect(at(at(result.cves).weaknesses, 0).source).toBe('CISA-ADP');
    expect(at(at(result.cves).references, 0).source).toBe('CVE');
  });

  it('requests the dictionary within the endpoint page-size ceiling', async () => {
    await new NvdSourceService({} as never, {} as never).getResolver(createMockContext());

    const call = client.get.mock.calls.find(([endpoint]) => endpoint === 'source/2.0');
    expect(call).toBeDefined();
    const params = call?.[1] ?? {};
    // `source/2.0` answers a resultsPerPage above 1000 with the same HTTP 404 it uses to reject
    // any other bad parameter, so the request must stay at or under it.
    expect(Number(params.resultsPerPage)).toBeLessThanOrEqual(1000);
  });

  it('gives the dictionary one 20 s attempt rather than a retry ladder', async () => {
    await new NvdSourceService({} as never, {} as never).getResolver(createMockContext());

    const call = client.get.mock.calls.find(([endpoint]) => endpoint === 'source/2.0');
    const budget = call?.[3];
    /**
     * The load sits inside the calling tool and shares one pacing queue with the CVE requests, so
     * an unreachable endpoint must cost a single wait — not attempts × timeout × backoff. The wait
     * is long enough for `source/2.0` at ordinary NVD latency; the client caps it by what remains
     * of the call's deadline.
     */
    expect(budget?.maxRetries).toBe(0);
    expect(budget?.timeoutMs).toBe(20_000);
  });

  it('warns and resolves the rest raw when the dictionary page is truncated', async () => {
    // One page short of what NVD reports it holds — the shape a >1000-contributor dictionary takes.
    install(async () => ({ ...SOURCE_RESPONSE, totalResults: 1_200 }));
    const ctx = createMockContext();
    const resolve = await new NvdSourceService({} as never, {} as never).getResolver(ctx);

    const warning = (ctx.log as MockContextLogger).calls.find((c) => c.level === 'warning');
    expect(warning?.msg).toContain('incomplete');
    expect(warning?.data).toMatchObject({ returned: 3, totalResults: 1_200 });
    // Entries on the page still resolve; everything past it degrades to the raw identifier.
    expect(resolve('af854a3a-2127-422b-91ae-364da2661108')).toBe('CVE');
    expect(resolve('0253b833-3e77-4dfe-9d57-17db1a2f0a74')).toBe(
      '0253b833-3e77-4dfe-9d57-17db1a2f0a74',
    );
  });

  it('does not remember a caller-cancelled load as an outage', async () => {
    const controller = new AbortController();
    install(async () => {
      controller.abort();
      throw requestCancelled('NVD request cancelled by caller.');
    });
    const service = new NvdSourceService({} as never, {} as never);

    await expect(
      service.getResolver(createMockContext({ signal: controller.signal })),
    ).rejects.toMatchObject({ code: -32011 });
    // A caller walking away says nothing about NVD's health, so the next call retries rather than
    // serving raw identifiers for the whole failure window.
    install();
    const resolve = await service.getResolver(createMockContext());
    expect(resolve('af854a3a-2127-422b-91ae-364da2661108')).toBe('CVE');
  });

  it('does not fetch the dictionary for a brief fetch, whose rows drop the source field', async () => {
    await service.fetchById(
      ['CVE-2024-23225'],
      { includeReferences: false, allLanguages: false, resolveSources: false },
      createMockContext(),
    );

    expect(client.sourceCalls()).toBe(0);
  });
});

/** The one deadline every NVD request a tool call makes settles inside, from the call's start. */
const CALL_DEADLINE_MS = 55_000;
const CISA_ADP_GUID = '134c704f-9b21-4f2e-91b3-4a467353bcc0';

/** How one stubbed request answers: given its abort signal, the response it settles with. */
type Answer = (signal: AbortSignal | undefined) => Promise<Response>;

/** Answers with `body` after `ms`, unless the request aborts first. */
function answerAfter(ms: number, body: unknown): Answer {
  return (signal) =>
    new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve(new Response(JSON.stringify(body))), ms);
      signal?.addEventListener(
        'abort',
        () => {
          clearTimeout(timer);
          reject(new DOMException('Aborted', 'AbortError'));
        },
        { once: true },
      );
    });
}

/** Never answers: the request settles only when it aborts. */
const silent: Answer = (signal) =>
  new Promise((_resolve, reject) => {
    signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')), {
      once: true,
    });
  });

/**
 * Stub fetch by endpoint: `source` answers the `index`-th dictionary request, `cve` every CVE
 * request. Returns the virtual-clock time each dictionary request went out.
 */
function routeFetch(source: (index: number) => Answer, cve: Answer = answerAfter(0, CVE_RESPONSE)) {
  const sourceSentAt: number[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn((input: string | URL | Request, init?: RequestInit) => {
      const signal = init?.signal ?? undefined;
      if (!String(input).includes('/source/2.0')) return cve(signal);
      sourceSentAt.push(Date.now());
      return source(sourceSentAt.length - 1)(signal);
    }),
  );
  return sourceSentAt;
}

/** Records the virtual-clock instant a promise settles, and what it settled with. */
function whenSettled<T>(promise: Promise<T>): { value?: unknown; at?: number } {
  const outcome: { value?: unknown; at?: number } = {};
  promise.then(
    (value) => {
      outcome.value = value;
      outcome.at = Date.now();
    },
    (err: unknown) => {
      outcome.value = err;
      outcome.at = Date.now();
    },
  );
  return outcome;
}

/**
 * The dictionary load through the real client and the call deadline it shares with the CVE
 * request ahead of it: the budget, what a load cut short leaves behind, and how a call waiting on
 * a load another call opened settles.
 */
describe('NvdSourceService — the dictionary load inside the call deadline', () => {
  const service = new NvdCveService({} as never, {} as never);

  function fetchFull(ctx = createMockContext()) {
    return service.fetchById(
      ['CVE-2024-23225'],
      { includeReferences: true, allLanguages: false },
      ctx,
    );
  }

  /** The SSVC/weakness source of the one record a full fetch returns. */
  function weaknessSource(outcome: { value?: unknown }): string {
    return at(at((outcome.value as { cves: CveRecord[] }).cves).weaknesses).source;
  }

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.useFakeTimers({ now: new Date('2026-01-01T00:00:00Z') });
    // Long attempts, so each case is bounded by the dictionary budget or the call deadline alone.
    nvdHttpClientModule.initNvdHttpClient('test-api-key', 60_000);
    initNvdSourceService({} as never, {} as never);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('resolves names on a cold cache when source/2.0 answers inside its 20 s', async () => {
    const sourceSentAt = routeFetch(() => answerAfter(15_000, SOURCE_RESPONSE));

    const call = whenSettled(fetchFull());
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);

    expect(weaknessSource(call)).toBe('CISA-ADP');
    expect(sourceSentAt).toHaveLength(1);
  });

  it('keeps raw identifiers past its own 20 s timeout and remembers that failure', async () => {
    const sourceSentAt = routeFetch(() => silent);

    const first = whenSettled(fetchFull());
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);

    // One attempt of exactly the dictionary budget, and the call still succeeds.
    expect(first.at).toBe(at(sourceSentAt) + 20_000);
    expect(weaknessSource(first)).toBe(CISA_ADP_GUID);

    // A failure of the load itself opens the failure window: the next call sends no dictionary request.
    const second = whenSettled(fetchFull());
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);
    expect(weaknessSource(second)).toBe(CISA_ADP_GUID);
    expect(sourceSentAt).toHaveLength(1);
  });

  it('leaves the cache as it was when the call deadline cuts the load short', async () => {
    // The CVE request takes 50 s, leaving the dictionary 5 s of the call rather than its own 20 s.
    const sourceSentAt = routeFetch(
      (index) => (index === 0 ? silent : answerAfter(0, SOURCE_RESPONSE)),
      answerAfter(50_000, CVE_RESPONSE),
    );
    const startedAt = Date.now();

    const first = whenSettled(fetchFull());
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);

    expect(first.at).toBe(startedAt + CALL_DEADLINE_MS);
    expect(weaknessSource(first)).toBe(CISA_ADP_GUID);

    // Running out of call time says nothing about NVD's health, so the next call loads again.
    const second = whenSettled(fetchFull());
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);
    expect(sourceSentAt).toHaveLength(2);
    expect(weaknessSource(second)).toBe('CISA-ADP');
  });

  it('settles a call waiting on a load another call cancelled with the names already cached', async () => {
    const sourceSentAt = routeFetch((index) =>
      index === 0 ? silent : answerAfter(0, SOURCE_RESPONSE),
    );
    const sources = new NvdSourceService({} as never, {} as never);
    const opener = new AbortController();

    const opened = whenSettled(sources.getResolver(createMockContext({ signal: opener.signal })));
    const waiting = whenSettled(sources.getResolver(createMockContext()));
    await vi.advanceTimersByTimeAsync(1_000);
    const cancelledAt = Date.now();
    opener.abort();
    await vi.advanceTimersByTimeAsync(0);

    expect(opened.value).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    // The waiter was never cancelled, so it is never failed: it proceeds on the cold cache.
    expect(waiting.at).toBe(cancelledAt);
    expect((waiting.value as SourceNameResolver)(CISA_ADP_GUID)).toBe(CISA_ADP_GUID);

    // The cancelled load left the cache cold rather than remembered as an outage.
    const next = whenSettled(sources.getResolver(createMockContext()));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(sourceSentAt).toHaveLength(2);
    expect((next.value as SourceNameResolver)(CISA_ADP_GUID)).toBe('CISA-ADP');
  });

  it('stops a call waiting on a load another call opened at its own deadline', async () => {
    const sourceSentAt = routeFetch(() => answerAfter(15_000, SOURCE_RESPONSE));
    const sources = new NvdSourceService({} as never, {} as never);
    // This call has already spent 50 s when another call opens the load.
    const waiterCtx = createMockContext();
    const waiterStartedAt = Date.now();
    await vi.advanceTimersByTimeAsync(50_000);

    const opened = whenSettled(sources.getResolver(createMockContext()));
    const waiting = whenSettled(sources.getResolver(waiterCtx));
    await vi.advanceTimersByTimeAsync(5_000);

    expect(waiting.at).toBe(waiterStartedAt + CALL_DEADLINE_MS);
    expect((waiting.value as SourceNameResolver)(CISA_ADP_GUID)).toBe(CISA_ADP_GUID);
    // The load runs on to the deadline of the call that opened it.
    expect(opened.at).toBeUndefined();
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);
    expect((opened.value as SourceNameResolver)(CISA_ADP_GUID)).toBe('CISA-ADP');
    expect(sourceSentAt).toHaveLength(1);
  });

  it('settles a waiting call at once on its own cancellation and leaves the load to its opener', async () => {
    const sourceSentAt = routeFetch(() => answerAfter(15_000, SOURCE_RESPONSE));
    const sources = new NvdSourceService({} as never, {} as never);
    const waiter = new AbortController();

    const opened = whenSettled(sources.getResolver(createMockContext()));
    const waiting = whenSettled(sources.getResolver(createMockContext({ signal: waiter.signal })));
    await vi.advanceTimersByTimeAsync(1_000);
    const cancelledAt = Date.now();
    waiter.abort();
    await vi.advanceTimersByTimeAsync(0);

    expect(waiting.at).toBe(cancelledAt);
    expect(waiting.value).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);
    expect((opened.value as SourceNameResolver)(CISA_ADP_GUID)).toBe('CISA-ADP');
    expect(sourceSentAt).toHaveLength(1);
  });
});
