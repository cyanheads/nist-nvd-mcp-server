/**
 * @fileoverview HTTP client for the NIST NVD API 2.0 with token-bucket rate limiting.
 * Manages API key injection, queue-based rate limiting, retry with backoff, and Retry-After header parsing.
 * @module services/nvd-http/nvd-http-client
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import { rateLimited, serviceUnavailable, timeout } from '@cyanheads/mcp-ts-core/errors';
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

/** Minimum gap between requests in milliseconds derived from window/limit. */
function minGapMs(hasKey: boolean): number {
  const limit = hasKey ? RATE_LIMIT_WITH_KEY : RATE_LIMIT_WITHOUT_KEY;
  return Math.ceil(RATE_LIMIT_WINDOW_MS / limit);
}

export class NvdHttpClient {
  private readonly apiKey: string | undefined;
  private readonly timeoutMs: number;
  private lastRequestAt = 0;
  private queue: Array<() => void> = [];
  private draining = false;

  constructor(apiKey: string | undefined, timeoutMs: number) {
    this.apiKey = apiKey;
    this.timeoutMs = timeoutMs;
  }

  /**
   * Enqueue and execute a request to the NVD API.
   * Enforces minimum inter-request gap to stay within NVD rate limits.
   */
  // biome-ignore lint/suspicious/useAwait: returns Promise via new Promise() constructor — async typing is correct
  async get<T>(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
    ctx: Context,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const task = () => {
        this.executeRequest<T>(endpoint, params, ctx)
          .then(resolve)
          .catch(reject)
          .finally(() => this.drainNext());
      };
      this.queue.push(task);
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

    const gap = minGapMs(!!this.apiKey);
    const now = Date.now();
    const elapsed = now - this.lastRequestAt;
    const delay = Math.max(0, gap - elapsed);

    if (delay > 0) {
      setTimeout(() => {
        this.lastRequestAt = Date.now();
        task();
      }, delay);
    } else {
      this.lastRequestAt = Date.now();
      task();
    }
  }

  // biome-ignore lint/suspicious/useAwait: delegates to withRetry() which returns a Promise — async typing is correct
  private async executeRequest<T>(
    endpoint: string,
    params: Record<string, string | number | boolean | undefined>,
    ctx: Context,
  ): Promise<T> {
    return withRetry(
      async () => {
        const url = this.buildUrl(endpoint, params);
        ctx.log.debug('NVD API request', { endpoint, url: url.toString() });

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
          const retryAfter = response.headers.get('Retry-After');
          throw rateLimited(
            `NVD rate limit exceeded. ${retryAfter ? `Retry after ${retryAfter}s.` : ''}`,
            {
              reason: 'rate_limited',
              retryAfter: retryAfter ? Number(retryAfter) : 30,
              recovery: {
                hint: 'The NVD rate limit was exceeded. Wait for the retry window to reset or add an API key via NVD_API_KEY.',
              },
            },
          );
        }

        if (response.status === 404) {
          // NVD returns 404 for malformed CVE IDs (empty body)
          throw new Error('NVD returned HTTP 404 — likely a malformed CVE ID format.');
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
      },
      {
        operation: `NvdHttpClient.get:${endpoint}`,
        baseDelayMs: 2_000,
        signal: ctx.signal,
      },
    );
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
