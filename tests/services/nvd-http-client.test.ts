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
import { createMockContext } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { isNvdRequestRejected, NvdHttpClient } from '@/services/nvd-http/nvd-http-client.js';

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
  const mock = vi.fn(() => {
    const index = at.length;
    at.push(Date.now());
    return Promise.resolve(respond(index));
  });
  vi.stubGlobal('fetch', mock);
  return { at, mock };
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

    const url = new URL(mock.mock.calls[0]?.[0] as string);
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
    expect(at[1] - at[0]).toBeGreaterThanOrEqual(KEYLESS_GAP_MS);
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
    expect(at[1] - at[0]).toBeGreaterThanOrEqual(WINDOW_MS);
    // A second patient retry would land past the deadline and surface as an opaque client hang.
    expect(at[1] - at[0]).toBeLessThan(MCP_REQUEST_DEADLINE_MS);
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
    expect(at[1] - at[0]).toBeGreaterThanOrEqual(WINDOW_MS);
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
    expect(at[1] - at[0]).toBeGreaterThanOrEqual(WINDOW_MS);
  });

  it('sends the API key header only when one is configured', async () => {
    const { mock } = stubFetch(() => new Response('{}', { status: 200 }));
    const headersOf = (call: number) =>
      (mock.mock.calls[call][1] as RequestInit).headers as Record<string, string>;

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
});
