/**
 * @fileoverview Tests for NvdHttpClient — rate-limit pacing, retry composition, and HTTP status
 * classification.
 *
 * These assert the budget properties an agent actually observes: how many real requests one
 * logical call spends against NVD's 5-per-30s keyless window, and how far apart they land.
 * A test that only checks "an error surfaced" passes just as happily while the client bursts
 * four unpaced requests, so every case here counts fetches and measures gaps.
 *
 * @module tests/services/nvd-http-client.test
 */

import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdGetCveHistory } from '@/mcp-server/tools/definitions/nvd-get-cve-history.tool.js';
import { initNvdCveService } from '@/services/nvd-cve/nvd-cve-service.js';
import {
  initNvdHttpClient,
  isNvdRequestRejected,
  NvdHttpClient,
} from '@/services/nvd-http/nvd-http-client.js';

/** Keyless pacing floor — ceil(30000 / 5). */
const KEYLESS_GAP_MS = 6_000;
/** NVD's rate-limit window, and the Retry-After it sends with a 403. */
const WINDOW_MS = 30_000;
/** The MCP SDK's default client request deadline — a call that outlasts it is cancelled. */
const MCP_REQUEST_DEADLINE_MS = 60_000;

const API_KEY = 'test-api-key';

/**
 * Replace global fetch, recording the virtual-clock time of every real request.
 * `respond` receives the zero-based request index so a case can change status mid-sequence.
 */
function stubFetch(respond: (callIndex: number) => Response) {
  const at: number[] = [];
  const mock = vi.fn((_input: string | URL | Request, _init?: RequestInit) => {
    const index = at.length;
    at.push(Date.now());
    return Promise.resolve(respond(index));
  });
  vi.stubGlobal('fetch', mock);
  return { at, mock };
}

/** Recorded request at `index`, or a loud failure naming how many were actually made. */
function requestAt(at: readonly number[], index: number): number {
  const value = at[index];
  if (value === undefined) {
    throw new Error(`expected a request at index ${index}; only ${at.length} were made`);
  }
  return value;
}

/** Virtual-clock gap between two recorded requests. */
function gapBetween(at: readonly number[], first: number, second: number): number {
  return requestAt(at, second) - requestAt(at, first);
}

type FetchMock = ReturnType<typeof stubFetch>['mock'];

/** The URL of the `index`-th recorded request. */
function requestUrl(mock: FetchMock, index: number): URL {
  const call = mock.mock.calls[index];
  if (!call) throw new Error(`expected a request at index ${index}`);
  return new URL(String(call[0]));
}

/** The headers of the `index`-th recorded request. */
function requestHeaders(mock: FetchMock, index: number): Record<string, string> {
  const call = mock.mock.calls[index];
  if (!call) throw new Error(`expected a request at index ${index}`);
  return (call[1]?.headers ?? {}) as Record<string, string>;
}

const rateLimitedResponse = () =>
  new Response('{}', { status: 403, headers: { 'Retry-After': String(WINDOW_MS / 1000) } });

/** Attach handlers up front so a rejection is never unhandled while the clock is advanced. */
function settled<T>(promise: Promise<T>): Promise<T | unknown> {
  return promise.then(
    (value) => value,
    (err: unknown) => err,
  );
}

/** Run every pending timer well past any backoff this client could schedule. */
async function drainClock(): Promise<void> {
  await vi.advanceTimersByTimeAsync(5 * WINDOW_MS);
}

/** The one deadline every NVD request a tool call makes must settle inside, from the call's start. */
const CALL_DEADLINE_MS = 55_000;

/**
 * Replace global fetch with one that never answers on its own: each request settles only when its
 * signal aborts, the shape of an NVD that accepts the connection and goes quiet. `respond` may
 * answer a given request index instead. Records when each request went out and when it aborted.
 */
function stubSilentFetch(
  respond?: (callIndex: number) => Response | Promise<Response> | undefined,
) {
  const at: number[] = [];
  const abortedAt: number[] = [];
  const mock = vi.fn((_input: string | URL | Request, init?: RequestInit) => {
    const index = at.length;
    at.push(Date.now());
    const answer = respond?.(index);
    if (answer) return Promise.resolve(answer);
    return new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener(
        'abort',
        () => {
          abortedAt[index] = Date.now();
          reject(new DOMException('Aborted', 'AbortError'));
        },
        { once: true },
      );
    });
  });
  vi.stubGlobal('fetch', mock);
  return { at, abortedAt, mock };
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

describe('NvdHttpClient', () => {
  beforeEach(() => {
    // A realistic epoch: at t=0 the pacer would read `now - lastRequestAt` as 0 and stall the
    // very first request behind a full gap, which never happens against a real clock.
    vi.useFakeTimers({ now: new Date('2026-01-01T00:00:00Z') });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('spends one request and returns parsed JSON on success', async () => {
    const { mock } = stubFetch(() => new Response('{"totalResults":1}', { status: 200 }));
    const client = new NvdHttpClient(undefined, 10_000);

    const result = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();

    expect(await result).toEqual({ totalResults: 1 });
    expect(mock).toHaveBeenCalledTimes(1);
  });

  /**
   * NVD's `hasKev`, `noRejected`, and `keywordExactMatch` are valueless flags: their presence is
   * the signal. A `true` becomes a bare key, a `false` is left off entirely — sending
   * `keywordExactMatch=false` would still enable it.
   */
  it('serializes boolean params as valueless flags and omits false ones', async () => {
    const { mock } = stubFetch(() => new Response('{}', { status: 200 }));
    const client = new NvdHttpClient(undefined, 10_000);

    const result = settled(
      client.get(
        'cves/2.0',
        { keywordSearch: 'remote code execution', keywordExactMatch: true, hasKev: false },
        createMockContext(),
      ),
    );
    await drainClock();
    await result;

    const url = requestUrl(mock, 0);
    expect(url.searchParams.get('keywordExactMatch')).toBe('');
    expect(url.searchParams.has('hasKev')).toBe(false);
    expect(url.searchParams.get('keywordSearch')).toBe('remote code execution');
  });

  it('paces each retry through the rate-limit queue instead of bursting inside one slot', async () => {
    const { at } = stubFetch(() => new Response('{}', { status: 503 }));
    const client = new NvdHttpClient(undefined, 10_000);

    const result = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();
    const err = (await result) as McpError;

    // Keyless budget is 5 per 30s — one transient blip must not eat four of those slots.
    expect(at).toHaveLength(2);
    expect(gapBetween(at, 0, 1)).toBeGreaterThanOrEqual(KEYLESS_GAP_MS);
    expect(err.code).toBe(JsonRpcErrorCode.ServiceUnavailable);
  });

  it('fails fast on a keyless 403 and names NVD_API_KEY rather than retrying into a closed window', async () => {
    const { mock } = stubFetch(rateLimitedResponse);
    const client = new NvdHttpClient(undefined, 10_000);

    const result = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();
    const err = (await result) as McpError;

    const recovery = err.data?.recovery as { hint: string } | undefined;
    expect(mock).toHaveBeenCalledTimes(1);
    expect(err.code).toBe(JsonRpcErrorCode.RateLimited);
    expect(recovery?.hint).toContain('NVD_API_KEY');
    // The caller is an agent and cannot set server env vars, so the key is the operator's lever.
    expect(recovery?.hint).toContain('server operator can set NVD_API_KEY');
    // Retries were declined outright, not attempted and exhausted.
    expect(err.message).not.toContain('failed after');
  });

  it('waits out Retry-After once when an API key is set, then stops inside the request deadline', async () => {
    const { at } = stubFetch(rateLimitedResponse);
    const client = new NvdHttpClient(API_KEY, 10_000);

    const result = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();

    expect(await result).toBeInstanceOf(McpError);
    expect(at).toHaveLength(2);
    // The parsed Retry-After governs the wait, not withRetry's 2s exponential.
    expect(gapBetween(at, 0, 1)).toBeGreaterThanOrEqual(WINDOW_MS);
    // A second patient retry would land past the deadline and surface as an opaque client hang.
    expect(gapBetween(at, 0, 1)).toBeLessThan(MCP_REQUEST_DEADLINE_MS);
  });

  it('holds a queued call until the 403 Retry-After window has elapsed', async () => {
    const { at } = stubFetch((index) =>
      index === 0 ? rateLimitedResponse() : new Response('{"totalResults":0}', { status: 200 }),
    );
    const client = new NvdHttpClient(undefined, 10_000);

    const first = settled(client.get('cves/2.0', {}, createMockContext()));
    const second = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();

    expect(await first).toBeInstanceOf(McpError);
    expect(await second).toEqual({ totalResults: 0 });
    expect(at).toHaveLength(2);
    expect(gapBetween(at, 0, 1)).toBeGreaterThanOrEqual(WINDOW_MS);
  });

  it('fails fast on 404 — a rejected request cannot succeed on retry', async () => {
    // NVD returns 404 with an empty body and its diagnosis in a `message` header. Verified live:
    // a malformed cveId answers `Invalid cveId parameter.`
    const { mock } = stubFetch(
      () => new Response('', { status: 404, headers: { message: 'Invalid cveId parameter.' } }),
    );
    const client = new NvdHttpClient(undefined, 10_000);

    const result = settled(client.get('cves/2.0', { cveIds: 'CVE-BAD' }, createMockContext()));
    await drainClock();
    const err = (await result) as McpError;

    expect(mock).toHaveBeenCalledTimes(1);
    expect(isNvdRequestRejected(err)).toBe(true);
    expect(err.data?.retryable).toBe(false);
    // NVD names the offending parameter; the generic text cannot.
    expect(err.message).toContain('Invalid cveId parameter.');
  });

  it('reports an invalid API key as a config fault, not a malformed parameter', async () => {
    // NVD answers a bad apiKey with the SAME 404 as a bad parameter, differing only in this
    // header (verified live). Conflating them tells the caller to fix an ID that is already fine.
    const { mock } = stubFetch(
      () => new Response('', { status: 404, headers: { message: 'Invalid apiKey.' } }),
    );
    const client = new NvdHttpClient(API_KEY, 10_000);

    const result = settled(
      client.get('cves/2.0', { cveIds: 'CVE-2021-44228' }, createMockContext()),
    );
    await drainClock();
    const err = (await result) as McpError;
    const recovery = err.data?.recovery as { hint: string } | undefined;

    expect(mock).toHaveBeenCalledTimes(1);
    expect(err.code).toBe(JsonRpcErrorCode.ConfigurationError);
    expect(err.data?.reason).toBe('nvd_invalid_api_key');
    // Must NOT be translated into "your CVE IDs are malformed" by the CVE service.
    expect(isNvdRequestRejected(err)).toBe(false);
    expect(recovery?.hint).toContain('NVD_API_KEY');
    // No call the agent can make fixes a refused key; only the server operator can.
    expect(recovery?.hint).toContain('server operator');
  });

  it('does not spend a slot once the caller has aborted', async () => {
    const { at, mock } = stubFetch(() => new Response('{}', { status: 200 }));
    const aborted = new AbortController();
    aborted.abort();
    const client = new NvdHttpClient(undefined, 10_000);
    const startedAt = Date.now();

    const dead = settled(client.get('cves/2.0', {}, createMockContext({ signal: aborted.signal })));
    // A live call queued behind it must not be charged a gap for a request that never went out.
    const live = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();

    expect(await dead).toBeInstanceOf(McpError);
    expect(await live).toEqual({});
    expect(mock).toHaveBeenCalledTimes(1);
    expect(at[0]).toBe(startedAt);
  });

  it('falls back to the full window when a 403 omits Retry-After', async () => {
    const { at } = stubFetch(() => new Response('Rate limit exceeded', { status: 403 }));
    const client = new NvdHttpClient(API_KEY, 10_000);

    const result = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();
    const err = (await result) as McpError;

    // An absent or unparseable header must not disable the backoff via NaN.
    expect(err.data?.retryAfter).toBe(WINDOW_MS / 1000);
    expect(gapBetween(at, 0, 1)).toBeGreaterThanOrEqual(WINDOW_MS);
  });

  it('sends the API key header only when one is configured', async () => {
    const { mock } = stubFetch(() => new Response('{}', { status: 200 }));
    const headersOf = (call: number) => requestHeaders(mock, call);

    const keyed = settled(
      new NvdHttpClient(API_KEY, 10_000).get('cves/2.0', {}, createMockContext()),
    );
    await drainClock();
    await keyed;

    const keyless = settled(
      new NvdHttpClient(undefined, 10_000).get('cves/2.0', {}, createMockContext()),
    );
    await drainClock();
    await keyless;

    expect(headersOf(0).apiKey).toBe(API_KEY);
    expect(headersOf(1).apiKey).toBeUndefined();
  });

  it.each([
    ['caller', 200],
    ['deadline', 200],
    ['caller', 403],
    ['deadline', 403],
  ] as const)(
    'keeps %s cancellation attached while consuming a %i body and releases the queue',
    async (mode, status) => {
      const caller = new AbortController();
      let finishBody: (() => void) | undefined;
      let fetchSignal: AbortSignal | undefined;
      const mock = vi.fn(async (_input: unknown, init?: RequestInit) => {
        if (mock.mock.calls.length > 1) return new Response('{}');
        fetchSignal = init?.signal ?? undefined;
        return new Response(
          new ReadableStream({
            start(controller) {
              finishBody = () => {
                controller.enqueue(new TextEncoder().encode('{}'));
                controller.close();
              };
              fetchSignal?.addEventListener(
                'abort',
                () => controller.error(new DOMException('Aborted', 'AbortError')),
                { once: true },
              );
            },
          }),
          { status },
        );
      });
      vi.stubGlobal('fetch', mock);
      const client = new NvdHttpClient(undefined, 100);
      const first = settled(
        client.get('cves/2.0', {}, createMockContext({ signal: caller.signal }), { maxRetries: 0 }),
      );
      const next = settled(client.get('cves/2.0', {}, createMockContext(), { maxRetries: 0 }));
      await vi.advanceTimersByTimeAsync(0);
      if (mode === 'caller') caller.abort();
      await vi.advanceTimersByTimeAsync(101);
      const aborted = fetchSignal?.aborted;
      if (!aborted) finishBody?.();
      await drainClock();
      expect(aborted).toBe(true);
      expect(await first).toMatchObject({
        code: mode === 'caller' ? JsonRpcErrorCode.RequestCancelled : JsonRpcErrorCode.Timeout,
      });
      expect(await next).toEqual({});
      expect(mock).toHaveBeenCalledTimes(2);
      expect(vi.getTimerCount()).toBe(0);
    },
  );

  it('classifies caller cancellation before headers as RequestCancelled', async () => {
    const caller = new AbortController();
    vi.stubGlobal(
      'fetch',
      vi.fn(
        (_input: unknown, init?: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init?.signal?.addEventListener(
              'abort',
              () => reject(new DOMException('Aborted', 'AbortError')),
              { once: true },
            );
          }),
      ),
    );
    const result = settled(
      new NvdHttpClient(undefined, 100).get(
        'cves/2.0',
        {},
        createMockContext({ signal: caller.signal }),
        { maxRetries: 0 },
      ),
    );
    await vi.advanceTimersByTimeAsync(0);
    caller.abort();
    await vi.advanceTimersByTimeAsync(0);
    expect(await result).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    expect(vi.getTimerCount()).toBe(0);
  });

  it('classifies a blocked request without retrying or delaying the queue beyond pacing', async () => {
    const { at, mock } = stubFetch((index) =>
      index === 0
        ? new Response('<html>Sorry, you have been blocked</html>', {
            status: 403,
            headers: { 'Content-Type': 'text/html' },
          })
        : new Response('{}'),
    );
    const client = new NvdHttpClient(API_KEY, 100);
    const first = settled(client.get('cves/2.0', {}, createMockContext()));
    const next = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();
    expect(await first).toMatchObject({
      code: JsonRpcErrorCode.Forbidden,
      data: { reason: 'nvd_request_blocked', retryable: false },
    });
    expect(await next).toEqual({});
    expect(mock).toHaveBeenCalledTimes(2);
    expect(gapBetween(at, 0, 1)).toBe(600);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each([
    { body: '', headers: { 'Retry-After': '30' } },
    { body: '{}', headers: { 'Retry-After': '30', 'Content-Type': 'application/json' } },
    {
      body: '<html>Sorry, you have been blocked</html>',
      headers: { 'Retry-After': '30', 'Content-Type': 'text/html' },
    },
    { body: 'Rate limit exceeded', headers: {} },
    { body: '<html>Other error</html>', headers: { 'Content-Type': 'text/html' } },
  ])('preserves ordinary 403 backoff for %j', async ({ body, headers }) => {
    const { at } = stubFetch((index) =>
      index === 0 ? new Response(body, { status: 403, headers }) : new Response('{}'),
    );
    const client = new NvdHttpClient(undefined, 100);
    const first = settled(client.get('cves/2.0', {}, createMockContext()));
    const next = settled(client.get('cves/2.0', {}, createMockContext()));
    await drainClock();
    expect(await first).toMatchObject({
      code: JsonRpcErrorCode.RateLimited,
      data: { reason: 'rate_limited', retryAfter: 30 },
    });
    expect(await next).toEqual({});
    expect(gapBetween(at, 0, 1)).toBe(WINDOW_MS);
  });

  /**
   * Every transport failure a call can end in, tabled once at the client that classifies it. The
   * agent routes on `data.reason` and `retryable`; the client attaches no hint, so each
   * definition's declared recovery is what fills `data.recovery` at the handler boundary.
   */
  it.each([
    {
      ladder: 'HTTP 5xx with an API key',
      apiKey: API_KEY,
      timeoutMs: 10_000,
      answer: async () => new Response('', { status: 503 }),
      attempts: 4,
      code: JsonRpcErrorCode.ServiceUnavailable,
      reason: 'nvd_unavailable',
      status: 503,
    },
    {
      ladder: 'HTTP 5xx without an API key',
      apiKey: undefined,
      timeoutMs: 10_000,
      answer: async () => new Response('', { status: 500 }),
      attempts: 2,
      code: JsonRpcErrorCode.ServiceUnavailable,
      reason: 'nvd_unavailable',
      status: 500,
    },
    {
      ladder: 'a network failure',
      apiKey: API_KEY,
      timeoutMs: 10_000,
      answer: async (): Promise<Response> => {
        throw new TypeError('fetch failed');
      },
      attempts: 4,
      code: JsonRpcErrorCode.ServiceUnavailable,
      reason: 'nvd_unavailable',
      status: undefined,
    },
    {
      ladder: 'a failed body read',
      apiKey: API_KEY,
      timeoutMs: 10_000,
      answer: async () =>
        new Response(
          new ReadableStream({
            start(controller) {
              controller.error(new TypeError('terminated'));
            },
          }),
        ),
      attempts: 4,
      code: JsonRpcErrorCode.ServiceUnavailable,
      reason: 'nvd_unavailable',
      status: undefined,
    },
    {
      ladder: 'an attempt timeout',
      apiKey: API_KEY,
      timeoutMs: 1_000,
      answer: (signal?: AbortSignal | null) =>
        new Promise<Response>((_resolve, reject) => {
          signal?.addEventListener(
            'abort',
            () => reject(new DOMException('Aborted', 'AbortError')),
            { once: true },
          );
        }),
      attempts: 4,
      code: JsonRpcErrorCode.Timeout,
      reason: 'nvd_timeout',
      status: undefined,
    },
  ])(
    'classifies $ladder on every attempt as $reason, retryable, with the endpoint',
    async ({ apiKey, timeoutMs, answer, attempts, code, reason, status }) => {
      const mock = vi.fn((_input: unknown, init?: RequestInit) => answer(init?.signal));
      vi.stubGlobal('fetch', mock);

      const result = settled(
        new NvdHttpClient(apiKey, timeoutMs).get('cves/2.0', {}, createMockContext()),
      );
      await drainClock();
      const err = (await result) as McpError;

      expect(err).toBeInstanceOf(McpError);
      // retryable: true keeps the client's own retries: every attempt the budget allows was spent.
      expect(mock).toHaveBeenCalledTimes(attempts);
      expect(err.code).toBe(code);
      // The reason and flag survive withRetry's exhaustion rewrap, beside its attempt count.
      expect(err.data).toMatchObject({
        reason,
        retryable: true,
        endpoint: 'cves/2.0',
        retryAttempts: attempts,
      });
      expect(err.message).toMatch(new RegExp(`\\(failed after ${attempts} attempts\\)$`));
      expect(err.data?.status).toBe(status);
      expect(err.data).not.toHaveProperty('recovery');
    },
  );

  it('leaves an unexpected non-5xx status unclassified rather than telling the caller to wait', async () => {
    const { mock } = stubFetch(() => new Response('', { status: 400 }));

    const result = settled(
      new NvdHttpClient(undefined, 10_000).get('cves/2.0', {}, createMockContext()),
    );
    await drainClock();
    const err = (await result) as McpError;

    expect(mock).toHaveBeenCalledTimes(2);
    expect(err.code).toBe(JsonRpcErrorCode.ServiceUnavailable);
    expect(err.data).toMatchObject({ endpoint: 'cves/2.0', status: 400 });
    expect(err.data).not.toHaveProperty('reason');
    expect(err.data).not.toHaveProperty('retryable');
  });

  it('ends four 20 s attempt timeouts at the 55 s call deadline instead of after them', async () => {
    const { at, abortedAt } = stubSilentFetch();
    const startedAt = Date.now();

    const outcome = whenSettled(
      new NvdHttpClient(API_KEY, 20_000).get('cves/2.0', {}, createMockContext()),
    );
    await vi.advanceTimersByTimeAsync(2 * MCP_REQUEST_DEADLINE_MS);

    expect(outcome.at).toBe(startedAt + CALL_DEADLINE_MS);
    expect(outcome.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cves/2.0', retryAttempts: 3 },
    });
    // The third attempt got what remained of the deadline, not a full 20 s, and none followed it.
    expect(at).toHaveLength(3);
    expect(abortedAt[2]).toBe(startedAt + CALL_DEADLINE_MS);
  });

  it('settles a keyed Retry-After wait followed by attempt timeouts inside the call deadline', async () => {
    const { at } = stubSilentFetch((index) => (index === 0 ? rateLimitedResponse() : undefined));
    const startedAt = Date.now();

    const outcome = whenSettled(
      new NvdHttpClient(API_KEY, 10_000).get('cves/2.0', {}, createMockContext()),
    );
    await vi.advanceTimersByTimeAsync(2 * MCP_REQUEST_DEADLINE_MS);

    expect(outcome.at).toBeLessThanOrEqual(startedAt + CALL_DEADLINE_MS);
    expect(outcome.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cves/2.0' },
    });
    // The one Retry-After wait still came first, and the deadline left room for two attempts after it.
    expect(gapBetween(at, 0, 1)).toBeGreaterThanOrEqual(WINDOW_MS);
    expect(at).toHaveLength(3);
  });

  it('charges every request one call makes to the same deadline', async () => {
    // The first page answers after 50 s, the second never does: one tool call, two requests.
    const { at, abortedAt } = stubSilentFetch((index) =>
      index === 0
        ? new Promise<Response>((resolve) => setTimeout(() => resolve(new Response('{}')), 50_000))
        : undefined,
    );
    const client = new NvdHttpClient(API_KEY, 60_000);
    const ctx = createMockContext();
    const startedAt = Date.now();

    const first = whenSettled(client.get('cvehistory/2.0', {}, ctx));
    await vi.advanceTimersByTimeAsync(50_000);
    const second = whenSettled(client.get('cvehistory/2.0', {}, ctx));
    await vi.advanceTimersByTimeAsync(2 * MCP_REQUEST_DEADLINE_MS);

    expect(first.value).toEqual({});
    // The second request got the 5 s the first left, not a fresh 55 s or its own 60 s timeout.
    expect(second.at).toBe(startedAt + CALL_DEADLINE_MS);
    expect(second.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cvehistory/2.0' },
    });
    expect(at).toHaveLength(2);
    expect(abortedAt[1]).toBe(startedAt + CALL_DEADLINE_MS);
  });

  it('settles a call still queued at its deadline without sending its request', async () => {
    const { mock } = stubSilentFetch();
    const client = new NvdHttpClient(API_KEY, 60_000);
    const queuedCtx = createMockContext();
    const startedAt = Date.now();
    await vi.advanceTimersByTimeAsync(10_000);

    // A call that started 10 s later holds the one in-flight slot past the earlier call's deadline.
    const holder = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    const queued = whenSettled(client.get('cves/2.0', {}, queuedCtx));
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS - 10_000);

    expect(queued.at).toBe(startedAt + CALL_DEADLINE_MS);
    expect(queued.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cves/2.0' },
    });
    expect(mock).toHaveBeenCalledTimes(1);
    expect(holder.at).toBeUndefined();

    await drainClock();
    expect(holder.value).toMatchObject({ data: { reason: 'nvd_timeout' } });
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it('sends nothing for a queued call whose turn comes on its deadline', async () => {
    const { mock } = stubSilentFetch();
    const client = new NvdHttpClient(API_KEY, 60_000);
    const startedAt = Date.now();

    const holder = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    const queued = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    await vi.advanceTimersByTimeAsync(2 * MCP_REQUEST_DEADLINE_MS);

    /**
     * The holder's attempt ends on the instant both calls' deadlines share, which hands the queued
     * call its turn with nothing left — and an attempt timeout of zero still puts a request out.
     */
    expect(holder.at).toBe(startedAt + CALL_DEADLINE_MS);
    expect(queued.at).toBe(startedAt + CALL_DEADLINE_MS);
    expect(queued.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cves/2.0' },
    });
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it('sends nothing for a turn that comes as the deadline fires a millisecond before the clock reaches it', async () => {
    const { mock } = stubSilentFetch();
    const client = new NvdHttpClient(API_KEY, 60_000);

    const holder = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    const queued = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    // Node fires a timer up to 1 ms before Date.now() reaches its target: replay that once both deadlines are armed.
    vi.setSystemTime(Date.now() - 1);
    await vi.advanceTimersByTimeAsync(2 * MCP_REQUEST_DEADLINE_MS);

    expect(holder.value).toMatchObject({ data: { reason: 'nvd_timeout' } });
    expect(queued.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cves/2.0' },
    });
    expect(mock).toHaveBeenCalledTimes(1);
  });

  it('charges no pacing slot to an attempt that bails on its deadline', async () => {
    const { at, mock } = stubSilentFetch((index) => (index === 1 ? new Response('{}') : undefined));
    const client = new NvdHttpClient(API_KEY, 60_000);
    const startedAt = Date.now();

    whenSettled(client.get('cves/2.0', {}, createMockContext()));
    const expiring = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    await vi.advanceTimersByTimeAsync(10_000);
    // Started 10 s later, so its deadline outlives the turn the expiring call gives up.
    const live = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    await vi.advanceTimersByTimeAsync(2 * MCP_REQUEST_DEADLINE_MS);

    expect(expiring.value).toMatchObject({ data: { reason: 'nvd_timeout' } });
    // The expiring call sent nothing, so the live call goes out on the same instant, not a gap later.
    expect(live.value).toEqual({});
    expect(mock).toHaveBeenCalledTimes(2);
    expect(requestAt(at, 1)).toBe(startedAt + CALL_DEADLINE_MS);
  });

  it('sends nothing for a call that reaches the client after its deadline', async () => {
    const { mock } = stubSilentFetch();
    const ctx = createMockContext();
    await vi.advanceTimersByTimeAsync(CALL_DEADLINE_MS);

    const outcome = whenSettled(new NvdHttpClient(API_KEY, 10_000).get('cves/2.0', {}, ctx));
    await vi.advanceTimersByTimeAsync(0);

    expect(outcome.value).toMatchObject({
      code: JsonRpcErrorCode.Timeout,
      data: { reason: 'nvd_timeout', retryable: true, endpoint: 'cves/2.0' },
    });
    expect(mock).not.toHaveBeenCalled();
    await drainClock();
  });

  /**
   * Caller cancellation at every stage a call can be in. It stays RequestCancelled — never a
   * transport reason, never retryable — settles the instant the caller leaves, and stops the
   * upstream work rather than outliving it: the request aborts, or never goes out at all.
   */
  it.each([
    {
      stage: 'before headers',
      start: (signal: AbortSignal) => {
        const { at, abortedAt } = stubSilentFetch();
        const call = new NvdHttpClient(API_KEY, 10_000).get(
          'cves/2.0',
          {},
          createMockContext({ signal }),
        );
        return { call, sent: () => at.length, upstreamAborted: () => abortedAt[0] !== undefined };
      },
    },
    {
      stage: 'mid-body',
      start: (signal: AbortSignal) => {
        let fetchSignal: AbortSignal | undefined;
        const mock = vi.fn(async (_input: unknown, init?: RequestInit) => {
          fetchSignal = init?.signal ?? undefined;
          return new Response(
            new ReadableStream({
              start(controller) {
                controller.enqueue(new TextEncoder().encode('{"partial":'));
                fetchSignal?.addEventListener(
                  'abort',
                  () => controller.error(new DOMException('Aborted', 'AbortError')),
                  { once: true },
                );
              },
            }),
          );
        });
        vi.stubGlobal('fetch', mock);
        const call = new NvdHttpClient(API_KEY, 10_000).get(
          'cves/2.0',
          {},
          createMockContext({ signal }),
        );
        return {
          call,
          sent: () => mock.mock.calls.length,
          upstreamAborted: () => fetchSignal?.aborted === true,
        };
      },
    },
    {
      stage: 'mid-backoff',
      start: (signal: AbortSignal) => {
        const { at } = stubSilentFetch(() => new Response('', { status: 503 }));
        const call = new NvdHttpClient(API_KEY, 10_000).get(
          'cves/2.0',
          {},
          createMockContext({ signal }),
        );
        // Nothing is in flight to abort; the retry it was waiting for never goes out.
        return { call, sent: () => at.length, upstreamAborted: () => true };
      },
    },
    {
      stage: 'while queued behind another call',
      start: (signal: AbortSignal) => {
        const { at } = stubSilentFetch();
        const client = new NvdHttpClient(API_KEY, 10_000);
        void settled(client.get('cves/2.0', {}, createMockContext()));
        const call = client.get('cves/2.0', {}, createMockContext({ signal }));
        // The one request out is the holder's; the cancelled call never had one to abort.
        return { call, sent: () => at.length, upstreamAborted: () => true };
      },
    },
    {
      stage: 'while held by a Retry-After window',
      start: (signal: AbortSignal) => {
        const { at } = stubSilentFetch((index) =>
          index === 0 ? rateLimitedResponse() : new Response('{}'),
        );
        const client = new NvdHttpClient(API_KEY, 10_000);
        void settled(client.get('cves/2.0', {}, createMockContext()));
        const call = client.get('cves/2.0', {}, createMockContext({ signal }));
        return { call, sent: () => at.length, upstreamAborted: () => true };
      },
    },
  ])('settles caller cancellation $stage as RequestCancelled', async ({ start }) => {
    const caller = new AbortController();
    const { call, sent, upstreamAborted } = start(caller.signal);
    const outcome = whenSettled(call);
    await vi.advanceTimersByTimeAsync(1_000);
    const sentBeforeAbort = sent();

    const abortedAt = Date.now();
    caller.abort();
    await vi.advanceTimersByTimeAsync(0);

    expect(outcome.at).toBe(abortedAt);
    expect(outcome.value).toBeInstanceOf(McpError);
    const err = outcome.value as McpError;
    expect(err.code).toBe(JsonRpcErrorCode.RequestCancelled);
    expect(err.data?.reason).toBeUndefined();
    expect(err.data?.retryable).toBeUndefined();
    // One request was on the wire before the abort, and nothing more went out after it.
    expect(sentBeforeAbort).toBe(1);
    expect(sent()).toBe(1);
    expect(upstreamAborted()).toBe(true);
    await drainClock();
  });

  it('keeps serving the calls behind a queued call its caller withdrew', async () => {
    const { at, mock } = stubSilentFetch((index) => (index === 0 ? undefined : new Response('{}')));
    const client = new NvdHttpClient(API_KEY, 10_000);
    const caller = new AbortController();

    const holder = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    const withdrawn = whenSettled(
      client.get('cves/2.0', {}, createMockContext({ signal: caller.signal })),
    );
    const behind = whenSettled(client.get('cves/2.0', {}, createMockContext()));
    await vi.advanceTimersByTimeAsync(1_000);
    caller.abort();
    await drainClock();

    expect(withdrawn.value).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
    // The call behind took the slot the moment the holder's first attempt timed out.
    expect(behind.value).toEqual({});
    expect(requestAt(at, 1)).toBe(requestAt(at, 0) + 10_000);
    expect(holder.value).toEqual({});
    expect(mock).toHaveBeenCalledTimes(3);
  });

  /**
   * A call sleeping out the pacing gap or a 403's Retry-After window has left the queue and holds
   * the head alone. Withdrawing it must cancel that sleep, so its request never goes out, and hand
   * the turn to the call behind it, which otherwise waits for a drain nothing will resume.
   */
  it.each([
    { hold: 'the pacing gap', first: () => new Response('{}'), turnMs: KEYLESS_GAP_MS },
    { hold: 'a Retry-After window', first: rateLimitedResponse, turnMs: WINDOW_MS },
  ])(
    'hands the turn on when the call sleeping out $hold is withdrawn',
    async ({ first, turnMs }) => {
      const { at, mock } = stubFetch((index) =>
        index === 0 ? first() : new Response('{"totalResults":0}'),
      );
      const client = new NvdHttpClient(undefined, 10_000);
      const caller = new AbortController();

      whenSettled(client.get('cves/2.0', { caller: 'holder' }, createMockContext()));
      await vi.advanceTimersByTimeAsync(0);
      const withdrawn = whenSettled(
        client.get(
          'cves/2.0',
          { caller: 'withdrawn' },
          createMockContext({ signal: caller.signal }),
        ),
      );
      const behind = whenSettled(client.get('cves/2.0', { caller: 'behind' }, createMockContext()));
      await vi.advanceTimersByTimeAsync(1_000);
      caller.abort();
      await drainClock();

      expect(withdrawn.value).toMatchObject({ code: JsonRpcErrorCode.RequestCancelled });
      // The call behind went out the moment the withdrawn call's turn would have come, and resolved.
      expect(behind.value).toEqual({ totalResults: 0 });
      expect(requestAt(at, 1)).toBe(requestAt(at, 0) + turnMs);
      // Every request on the wire is the holder's or the one behind; the withdrawn call sent none.
      expect(
        mock.mock.calls.map((_, index) => requestUrl(mock, index).searchParams.get('caller')),
      ).toEqual(['holder', 'behind']);
    },
  );

  /**
   * The wire end of the ladders above, through one definition: the client attaches no hint, so
   * the tool's own declared recovery is what reaches structuredContent and content[].
   */
  it.each([
    [
      'nvd_unavailable',
      JsonRpcErrorCode.ServiceUnavailable,
      (): Response | undefined => new Response('', { status: 502 }),
    ],
    ['nvd_timeout', JsonRpcErrorCode.Timeout, (): Response | undefined => undefined],
  ] as const)(
    'carries %s and its declared recovery to the tool wire',
    async (reason, code, answer) => {
      stubSilentFetch(answer);
      initNvdHttpClient(API_KEY, 1_000);
      initNvdCveService({} as never, {} as never);
      const declared =
        nvdGetCveHistory.errors?.find((entry) => entry.reason === reason)?.recovery ??
        expect.unreachable(`nvd_get_cve_history declares no ${reason}`);

      const pending = settled(runToolContract(nvdGetCveHistory, { cveId: 'CVE-2021-44228' }));
      await drainClock();
      const result = (await pending) as Awaited<ReturnType<typeof runToolContract>>;

      expect(result.isError).toBe(true);
      expect(result.structuredContent).toMatchObject({
        error: {
          code,
          data: {
            reason,
            retryable: true,
            endpoint: 'cvehistory/2.0',
            recovery: { hint: declared },
          },
        },
      });
      expect(result.content).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ type: 'text', text: expect.stringContaining(declared) }),
        ]),
      );
    },
  );

  /**
   * The client attaches its own operator hint to a refused key, and a throw-site hint wins over
   * the declared one, so the two must say the same thing: the declared entry is what the contract
   * advertises, the client's hint is what the caller reads.
   */
  it('carries nvd_invalid_api_key to the tool wire with the hint the tools declare', async () => {
    stubFetch(() => new Response('', { status: 404, headers: { message: 'Invalid apiKey.' } }));
    initNvdHttpClient(API_KEY, 1_000);
    initNvdCveService({} as never, {} as never);
    const declared =
      nvdGetCveHistory.errors?.find((entry) => entry.reason === 'nvd_invalid_api_key')?.recovery ??
      expect.unreachable('nvd_get_cve_history declares no nvd_invalid_api_key');

    const pending = settled(runToolContract(nvdGetCveHistory, { cveId: 'CVE-2021-44228' }));
    await drainClock();
    const result = (await pending) as Awaited<ReturnType<typeof runToolContract>>;

    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ConfigurationError,
        data: {
          reason: 'nvd_invalid_api_key',
          retryable: false,
          endpoint: 'cvehistory/2.0',
          recovery: { hint: declared },
        },
      },
    });
    expect(result.content).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: 'text', text: expect.stringContaining(declared) }),
      ]),
    );
  });
});
