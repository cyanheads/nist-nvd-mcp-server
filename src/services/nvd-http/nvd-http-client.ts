/**
 * @fileoverview HTTP client for the NIST NVD API 2.0 with rate-limit pacing.
 * Manages API key injection, queue-based pacing of every request attempt, retry with backoff,
 * and Retry-After header parsing.
 * @module services/nvd-http/nvd-http-client
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import {
  configurationError,
  McpError,
  rateLimited,
  serviceUnavailable,
  timeout,
  validationError,
} from '@cyanheads/mcp-ts-core/errors';
import { withRetry } from '@cyanheads/mcp-ts-core/utils';

const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json';

/**
 * Sliding-window rate-limit config per NVD documentation:
 * - Without API key: 5 requests per 30-second window
 * - With API key: 50 requests per 30-second window
 */
const RATE_LIMIT_WINDOW_MS = 30_000;
const RATE_LIMIT_WITHOUT_KEY = 5;
const RATE_LIMIT_WITH_KEY = 50;

/**
 * Retry budget per logical call. Every attempt occupies a rate-limit slot, so the keyless
 * budget (5 per 30s) cannot afford the framework default of 4 attempts on one call.
 */
const MAX_RETRIES_WITH_KEY = 3;
const MAX_RETRIES_WITHOUT_KEY = 1;

/** `data.reason` on the error thrown when NVD rejects a request's parameters with HTTP 404. */
const REQUEST_REJECTED_REASON = 'nvd_request_rejected';

/** `data.reason` on the error thrown when NVD rejects the configured API key. */
const INVALID_API_KEY_REASON = 'nvd_invalid_api_key';

/**
 * NVD's own diagnosis for a 404, returned in a `message` response header rather than a body
 * (e.g. `Invalid cveId parameter.`, `Invalid apiKey.`). It is the only thing separating the
 * two unrelated faults NVD answers 404 with.
 */
const NVD_MESSAGE_HEADER = 'message';

/** NVD's `message` when the API key itself is the fault, not the request parameters. */
const INVALID_API_KEY_MESSAGE = /^invalid\s+apikey/i;

/** Minimum gap between requests in milliseconds derived from window/limit. */
function minGapMs(hasKey: boolean): number {
  const limit = hasKey ? RATE_LIMIT_WITH_KEY : RATE_LIMIT_WITHOUT_KEY;
  return Math.ceil(RATE_LIMIT_WINDOW_MS / limit);
}

/**
 * The error thrown when NVD answers HTTP 404 because it rejected the request parameters
 * (malformed CVE ID, unusable match string) rather than reporting an absent record.
 * Deterministic, so it carries `retryable: false`: the framework's opt-out stops `withRetry`
 * from re-sending a request that can never succeed.
 *
 * `detail` is NVD's own diagnosis from the `message` header — it names the offending parameter,
 * which the generic text cannot.
 *
 * Exported so callers translate it to a domain error and tests reproduce it exactly.
 */
export function nvdRequestRejected(endpoint: string, detail?: string): McpError {
  return validationError(
    detail
      ? `NVD rejected the request parameters (HTTP 404): ${detail}`
      : 'NVD rejected the request parameters (HTTP 404).',
    { reason: REQUEST_REJECTED_REASON, endpoint, retryable: false },
  );
}

/** True when `err` is the {@link nvdRequestRejected} throw. */
export function isNvdRequestRejected(err: unknown): boolean {
  return err instanceof McpError && err.data?.reason === REQUEST_REJECTED_REASON;
}

export class NvdHttpClient {
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private lastRequestAt = 0;
  /** Epoch ms before which no request may be sent — set from a 403's Retry-After. */
  private backoffUntil = 0;
  private queue: Array<() => void> = [];
  private draining = false;

  constructor(apiKey: string | undefined, timeoutMs: number) {
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Fetch from the NVD API.
   *
   * Retry wraps the pacing queue rather than sitting inside it, so every attempt — the first
   * try and each retry — waits its turn and counts against the rate budget.
   */
  get<T>(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
    ctx: Context,
  ): Promise<T> {
    let attemptIndex = 0;
    return withRetry(
      () => {
        /**
         * NVD's Retry-After is a full 30s window and the MCP client request deadline is 60s, so
         * only one such wait fits inside a single call — spend it on the first attempt or not at
         * all. Keyless has no budget to wait with; that arm fails fast and names NVD_API_KEY.
         */
        const mayWaitOutRateLimit = attemptIndex++ === 0 && !!this.apiKey;
        return this.schedule(() => this.fetchOnce<T>(endpoint, params, ctx, mayWaitOutRateLimit));
      },
      {
        operation: `NvdHttpClient.get:${endpoint}`,
        maxRetries: this.apiKey ? MAX_RETRIES_WITH_KEY : MAX_RETRIES_WITHOUT_KEY,
        baseDelayMs: 2_000,
        signal: ctx.signal,
      },
    );
  }

  /** Enqueue one request attempt, paced behind the inter-request gap and any active 403 backoff. */
  private schedule<T>(run: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queue.push(() => {
        run()
          .then(resolve, reject)
          .finally(() => this.drainNext());
      });
      if (!this.draining) this.drainNext();
    });
  }

  private drainNext(): void {
    const task = this.queue.shift();
    if (!task) {
      this.draining = false;
      return;
    }
    this.draining = true;

    const now = Date.now();
    const delay = Math.max(
      0,
      minGapMs(!!this.apiKey) - (now - this.lastRequestAt),
      this.backoffUntil - now,
    );

    if (delay > 0) setTimeout(task, delay);
    else task();
  }

  private async fetchOnce<T>(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
    ctx: Context,
    mayWaitOutRateLimit: boolean,
  ): Promise<T> {
    // A queued attempt can wait out a rate-limit window; don't spend a slot once the caller is gone.
    if (ctx.signal.aborted) throw timeout('NVD request cancelled by caller.');

    const url = this.buildUrl(endpoint, params);
    ctx.log.debug('NVD API request', { endpoint, url: url.toString() });

    // Advance the pacer only once a request is actually going out — an attempt that bailed above
    // sent nothing, so charging it a slot would delay the next live caller for no upstream cost.
    this.lastRequestAt = Date.now();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    // Chain caller's signal
    const onAbort = () => controller.abort();
    ctx.signal.addEventListener('abort', onAbort, { once: true });

    let response: Response;
    try {
      response = await fetch(url.toString(), {
        headers: this.buildHeaders(),
        signal: controller.signal,
      });
    } catch (err) {
      if ((err as Error).name === 'AbortError') {
        if (ctx.signal.aborted) throw timeout('NVD request cancelled by caller.');
        throw timeout(`NVD request timed out after ${this.timeoutMs}ms.`);
      }
      throw serviceUnavailable(
        `NVD API network error: ${(err as Error).message}`,
        { endpoint },
        { cause: err as Error },
      );
    } finally {
      clearTimeout(timer);
      ctx.signal.removeEventListener('abort', onAbort);
    }

    if (response.status === 403) {
      throw this.rateLimitError(response, mayWaitOutRateLimit);
    }

    if (response.status === 404) {
      throw this.rejectionFor(endpoint, response.headers.get(NVD_MESSAGE_HEADER));
    }

    if (!response.ok) {
      throw serviceUnavailable(`NVD API returned HTTP ${response.status}.`, {
        endpoint,
        status: response.status,
      });
    }

    const text = await response.text();
    if (/^\s*<(!DOCTYPE\s+html|html[\s>])/i.test(text)) {
      throw serviceUnavailable(
        'NVD API returned HTML instead of JSON — likely rate-limited or a temporary outage.',
      );
    }

    try {
      return JSON.parse(text) as T;
    } catch (err) {
      throw serviceUnavailable(
        'NVD API returned malformed JSON.',
        { endpoint },
        { cause: err as Error },
      );
    }
  }

  /**
   * Classify NVD's HTTP 404, which covers two unrelated faults separated only by the `message`
   * header: a rejected request parameter, or an unusable API key. Reporting a malformed CVE ID
   * when the real fault is `NVD_API_KEY` sends the caller to fix the wrong thing — no correction
   * to the ID can succeed while the key is refused. Both are deterministic, so neither retries.
   */
  private rejectionFor(endpoint: string, detail: string | null): McpError {
    if (detail && INVALID_API_KEY_MESSAGE.test(detail)) {
      const windowSec = RATE_LIMIT_WINDOW_MS / 1000;
      return configurationError(`NVD rejected the configured API key: ${detail}`, {
        reason: INVALID_API_KEY_REASON,
        endpoint,
        retryable: false,
        recovery: {
          hint: `NVD refused the NVD_API_KEY value. Verify the key, request a replacement at https://nvd.nist.gov/developers/request-an-api-key, or unset NVD_API_KEY to run keyless at ${RATE_LIMIT_WITHOUT_KEY} req/${windowSec}s.`,
        },
      });
    }
    return nvdRequestRejected(endpoint, detail ?? undefined);
  }

  /**
   * Build the 403 error and hold the queue until NVD's window resets, so every pending request —
   * not just this call's retry — stops firing into a limit that is already exceeded.
   */
  private rateLimitError(response: Response, mayWaitOutRateLimit: boolean): McpError {
    const windowSec = RATE_LIMIT_WINDOW_MS / 1000;
    const header = Number(response.headers.get('Retry-After'));
    // Clamp to the documented window: a missing, unparseable, or oversized header must not
    // disable the backoff (NaN) or stall the queue past the caller's deadline.
    const retryAfter = header > 0 ? Math.min(header, windowSec) : windowSec;
    this.backoffUntil = Date.now() + retryAfter * 1000;

    return rateLimited(`NVD rate limit exceeded. Retry after ${retryAfter}s.`, {
      reason: 'rate_limited',
      retryAfter,
      retryable: mayWaitOutRateLimit,
      recovery: {
        hint: this.apiKey
          ? `The NVD rate limit was exceeded (${RATE_LIMIT_WITH_KEY} req/${windowSec}s with an API key). Wait ${retryAfter}s for the window to reset, or reduce concurrent calls.`
          : `The NVD rate limit was exceeded (${RATE_LIMIT_WITHOUT_KEY} req/${windowSec}s without an API key). Set NVD_API_KEY to raise it to ${RATE_LIMIT_WITH_KEY} req/${windowSec}s, or wait ${retryAfter}s for the window to reset.`,
      },
    });
  }

  private buildUrl(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
  ): URL {
    const url = new URL(`${NVD_BASE_URL}/${endpoint}`);
    for (const [key, value] of Object.entries(params)) {
      if (value === undefined || value === null) continue;
      if (typeof value === 'boolean') {
        // Boolean flag params are sent without a value (e.g., &hasKev)
        if (value) url.searchParams.append(key, '');
      } else {
        url.searchParams.set(key, String(value));
      }
    }
    return url;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };
    if (this.apiKey) {
      headers.apiKey = this.apiKey;
    }
    return headers;
  }
}

// --- Init/accessor pattern ---

let _client: NvdHttpClient | undefined;

export function initNvdHttpClient(apiKey: string | undefined, timeoutMs: number): void {
  _client = new NvdHttpClient(apiKey, timeoutMs);
}

export function getNvdHttpClient(): NvdHttpClient {
  if (!_client) {
    throw new Error('NvdHttpClient not initialized — call initNvdHttpClient() in setup()');
  }
  return _client;
}
