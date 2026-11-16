/**
 * @fileoverview HTTP client for the NIST NVD API 2.0 with rate-limit pacing.
 * Manages API key injection, queue-based pacing of every request attempt, retry with backoff,
 * Retry-After header parsing, and the one deadline that bounds every request a tool call makes.
 * @module services/nvd-http/nvd-http-client
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import {
  configurationError,
  forbidden,
  JsonRpcErrorCode,
  McpError,
  rateLimited,
  requestCancelled,
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

/**
 * Every NVD request one tool call makes — its queue wait, attempts, backoff, and any Retry-After
 * wait — settles within this many milliseconds of the call's start. MCP SDK clients give up on a
 * request at 60 s by default, and a failure that lands after that never reaches the caller.
 */
const CALL_DEADLINE_MS = 55_000;

/** `data.reason` on the error thrown when NVD rejects a request's parameters with HTTP 404. */
const REQUEST_REJECTED_REASON = 'nvd_request_rejected';

/** `data.reason` on the error thrown when NVD rejects the configured API key. */
const INVALID_API_KEY_REASON = 'nvd_invalid_api_key';

/** `data.reason` on an HTTP 5xx, or a request or body read that failed on the network. */
const UNAVAILABLE_REASON = 'nvd_unavailable';

/** `data.reason` on an attempt that outlived its timeout, or a call that ran out its deadline. */
const TIMEOUT_REASON = 'nvd_timeout';

/** The reason `withRetry` stamps on its own deadline expiry, which leaves as {@link TIMEOUT_REASON}. */
const RETRY_DEADLINE_REASON = 'retry_deadline_exceeded';

const CANCELLED_MESSAGE = 'NVD request cancelled by caller.';

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

/**
 * True when `err` is the {@link nvdRequestRejected} throw. Narrows to {@link McpError} so a
 * caller translating the rejection can read NVD's own diagnosis off `message` and chain it as
 * `cause` without casting back off `unknown`.
 */
export function isNvdRequestRejected(err: unknown): err is McpError {
  return err instanceof McpError && err.data?.reason === REQUEST_REJECTED_REASON;
}

/**
 * Milliseconds left of the deadline the tool call behind `ctx` shares across every NVD request it
 * makes, and anything it waits on; 0 once spent. It counts from the call's own start — the
 * `timestamp` the framework stamps on the call's context — so a second request, or a wait on a
 * load another call opened, gets only what the first left.
 */
export function remainingCallMs(ctx: Context): number {
  return Math.max(0, Date.parse(ctx.timestamp) + CALL_DEADLINE_MS - Date.now());
}

/**
 * The timeout a call ends in once its deadline is spent, whether before a request went out or
 * during one. Retryable: a later call, with a fresh deadline, can succeed.
 */
function callDeadlineExceeded(
  endpoint: string,
  expiry?: { retryAttempts: unknown; cause: unknown },
): McpError {
  return timeout(
    `The NVD request did not complete within the call's ${CALL_DEADLINE_MS / 1000}s deadline.`,
    {
      reason: TIMEOUT_REASON,
      endpoint,
      retryable: true,
      ...(expiry && { retryAttempts: expiry.retryAttempts }),
    },
    expiry && { cause: expiry.cause },
  );
}

/**
 * Per-call overrides of the client's default effort. A secondary lookup the caller can proceed
 * without must not spend the same retry and timeout budget as the record it decorates: on the
 * default budget an unreachable endpoint stretches the calling tool by the full product of
 * attempts and timeout, and holds the shared pacing queue for the same span.
 */
export interface NvdRequestBudget {
  /** Retry attempts beyond the first. Defaults to the key-dependent budget. */
  maxRetries?: number;
  /**
   * Per-attempt timeout in milliseconds. Defaults to the configured request timeout. Either way an
   * attempt gets no more than what remains of its call's deadline.
   */
  timeoutMs?: number;
}

/** One request attempt waiting in the pacing queue; calling it sends the request. */
type QueuedAttempt = () => void;

export class NvdHttpClient {
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private lastRequestAt = 0;
  /** Epoch ms before which no request may be sent — set from a 403's Retry-After. */
  private backoffUntil = 0;
  private queue: QueuedAttempt[] = [];
  /** The head attempt sleeping out its pacing delay, held so a withdrawal can cancel the sleep. */
  private pacing: { attempt: QueuedAttempt; timer: ReturnType<typeof setTimeout> } | undefined;
  private draining = false;

  constructor(apiKey: string | undefined, timeoutMs: number) {
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Fetch from the NVD API.
   *
   * Retry wraps the pacing queue rather than sitting inside it, so every attempt — the first
   * try and each retry — waits its turn and counts against the rate budget. The whole ladder,
   * queue waits included, runs inside what remains of the call's deadline.
   */
  async get(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
    ctx: Context,
    budget?: NvdRequestBudget,
  ): Promise<unknown> {
    const deadlineMs = remainingCallMs(ctx);
    if (deadlineMs === 0) throw callDeadlineExceeded(endpoint);
    let attemptIndex = 0;
    const timeoutMs = budget?.timeoutMs ?? this.timeoutMs;
    let text: string;
    try {
      text = await withRetry(
        ({ signal }) => {
          /**
           * NVD's Retry-After is a full 30s window and the call's deadline is 55s, so only one
           * such wait fits inside a single call — spend it on the first attempt or not at all.
           * Keyless has no budget to wait with; that arm fails fast and names NVD_API_KEY.
           */
          const mayWaitOutRateLimit = attemptIndex++ === 0 && !!this.apiKey;
          return this.schedule(
            signal,
            () =>
              ctx.signal.aborted
                ? requestCancelled(CANCELLED_MESSAGE)
                : callDeadlineExceeded(endpoint),
            () => this.fetchOnce(endpoint, params, ctx, signal, mayWaitOutRateLimit, timeoutMs),
          );
        },
        {
          operation: `NvdHttpClient.get:${endpoint}`,
          maxRetries:
            budget?.maxRetries ?? (this.apiKey ? MAX_RETRIES_WITH_KEY : MAX_RETRIES_WITHOUT_KEY),
          baseDelayMs: 2_000,
          signal: ctx.signal,
          deadlineMs,
        },
      );
    } catch (err) {
      /**
       * `withRetry` ends two ways on its own terms. A caller abort that lands mid-backoff arrives
       * as the raw abort reason, and leaves as `RequestCancelled` like every other cancellation —
       * which also outranks any failure the same moment produced. Its deadline expiry leaves as
       * `nvd_timeout`, the reason each definition declares, with the endpoint it was spent on.
       */
      if (ctx.signal.aborted) {
        throw err instanceof McpError && err.code === JsonRpcErrorCode.RequestCancelled
          ? err
          : requestCancelled(CANCELLED_MESSAGE, undefined, { cause: err });
      }
      if (err instanceof McpError && err.data?.reason === RETRY_DEADLINE_REASON) {
        throw callDeadlineExceeded(endpoint, { retryAttempts: err.data.retryAttempts, cause: err });
      }
      throw err;
    }
    try {
      const value: unknown = JSON.parse(text);
      return value;
    } catch (err) {
      throw serviceUnavailable(
        'NVD API returned an invalid response.',
        { endpoint, reason: 'nvd_invalid_response', retryable: false },
        { cause: err },
      );
    }
  }

  /**
   * Enqueue one request attempt, paced behind the inter-request gap and any active 403 backoff.
   *
   * A queued attempt can wait out a whole rate-limit window. If `signal` aborts first — its caller
   * gone, or its call's deadline spent — the attempt leaves the queue at once, sends nothing, and
   * rejects with `ended()`, so a cancelled or expired call never lingers behind others' traffic.
   */
  private schedule<T>(
    signal: AbortSignal,
    ended: () => McpError,
    run: () => Promise<T>,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      if (signal.aborted) {
        reject(ended());
        return;
      }
      const attempt: QueuedAttempt = () => {
        signal.removeEventListener('abort', withdraw);
        run()
          .then(resolve, reject)
          .finally(() => this.drainNext());
      };
      const withdraw = () => {
        if (this.pacing?.attempt === attempt) {
          clearTimeout(this.pacing.timer);
          this.pacing = undefined;
          this.drainNext();
        } else {
          this.queue.splice(this.queue.indexOf(attempt), 1);
        }
        reject(ended());
      };
      signal.addEventListener('abort', withdraw, { once: true });
      this.queue.push(attempt);
      if (!this.draining) this.drainNext();
    });
  }

  private drainNext(): void {
    const attempt = this.queue.shift();
    if (!attempt) {
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

    if (delay > 0) {
      const timer = setTimeout(() => {
        this.pacing = undefined;
        attempt();
      }, delay);
      this.pacing = { attempt, timer };
    } else {
      attempt();
    }
  }

  /**
   * Send one attempt. `signal` is the attempt's own from `withRetry`: it aborts on the caller's
   * cancellation and on the call's deadline alike, and either one ends the request in flight.
   */
  private async fetchOnce(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
    ctx: Context,
    signal: AbortSignal,
    mayWaitOutRateLimit: boolean,
    timeoutMs: number,
  ): Promise<string> {
    /**
     * An attempt whose turn comes on its call's deadline sends nothing. The turn can land on that
     * instant before the deadline's own timer fires — when the attempt ahead ends on the same
     * deadline — and a zero-length timeout still puts the request on the wire before it aborts.
     */
    const remainingMs = remainingCallMs(ctx);
    if (remainingMs === 0) throw callDeadlineExceeded(endpoint);
    const attemptTimeoutMs = Math.min(timeoutMs, remainingMs);

    const url = this.buildUrl(endpoint, params);
    // The endpoint only: the full URL carries caller-supplied query values into the log record.
    ctx.log.debug('NVD API request', { endpoint });

    // Advance the pacer only once a request is actually going out — an attempt that bailed above
    // sent nothing, so charging it a slot would delay the next live caller for no upstream cost.
    this.lastRequestAt = Date.now();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), attemptTimeoutMs);
    const onAbort = () => controller.abort();
    signal.addEventListener('abort', onAbort, { once: true });

    try {
      const response = await fetch(url.toString(), {
        headers: this.buildHeaders(),
        signal: controller.signal,
      });

      if (response.status === 403) {
        if (!response.headers.has('Retry-After')) {
          const text = await response.text();
          const mediaType = response.headers
            .get('Content-Type')
            ?.split(';', 1)[0]
            ?.trim()
            .toLowerCase();
          if (mediaType === 'text/html' && text.includes('Sorry, you have been blocked')) {
            throw forbidden('NVD security layer blocked the request.', {
              endpoint,
              reason: 'nvd_request_blocked',
              retryable: false,
            });
          }
        }
        throw this.rateLimitError(response, mayWaitOutRateLimit);
      }

      if (response.status === 404) {
        throw this.rejectionFor(endpoint, response.headers.get(NVD_MESSAGE_HEADER));
      }

      if (!response.ok) {
        /**
         * Only a 5xx says NVD itself is failing, so only a 5xx tells the caller to wait and retry.
         * Any other unexpected status stays unclassified: waiting cannot be shown to fix it.
         */
        throw serviceUnavailable(
          `NVD API returned HTTP ${response.status}.`,
          response.status >= 500
            ? { endpoint, status: response.status, reason: UNAVAILABLE_REASON, retryable: true }
            : { endpoint, status: response.status },
        );
      }

      return await response.text();
    } catch (err) {
      if (ctx.signal.aborted) throw requestCancelled(CANCELLED_MESSAGE, undefined, { cause: err });
      if (controller.signal.aborted)
        throw timeout(
          `NVD request timed out after ${attemptTimeoutMs}ms.`,
          { reason: TIMEOUT_REASON, endpoint, retryable: true },
          { cause: err },
        );
      if (err instanceof McpError) throw err;
      throw serviceUnavailable(
        'NVD API network request or response body failed.',
        { endpoint, reason: UNAVAILABLE_REASON, retryable: true },
        { cause: err },
      );
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
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
          hint: `NVD refused this server's NVD_API_KEY, so no NVD call can succeed until a server operator fixes it: verify the key, request a replacement at https://nvd.nist.gov/developers/request-an-api-key, or unset NVD_API_KEY to run keyless at ${RATE_LIMIT_WITHOUT_KEY} req/${windowSec}s.`,
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
          : `The NVD rate limit was exceeded (${RATE_LIMIT_WITHOUT_KEY} req/${windowSec}s without an API key). Wait ${retryAfter}s for the window to reset; a server operator can set NVD_API_KEY to raise the limit to ${RATE_LIMIT_WITH_KEY} req/${windowSec}s.`,
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
