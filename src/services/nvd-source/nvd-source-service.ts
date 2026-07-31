/**
 * @fileoverview Service for the NVD source dictionary (`/rest/json/source/2.0`).
 * Resolves the identifiers NVD stamps on weaknesses and references to their published
 * contributor names, cached so the dictionary costs one upstream request a day rather than one
 * per record, per reference, or per call.
 * @module services/nvd-source/nvd-source-service
 */

import type { Context } from '@cyanheads/mcp-ts-core';
import type { AppConfig } from '@cyanheads/mcp-ts-core/config';
import type { StorageService } from '@cyanheads/mcp-ts-core/storage';
import { getNvdHttpClient, type NvdRequestBudget } from '../nvd-http/nvd-http-client.js';
import type { RawNvdSourceResponse } from './types.js';

/**
 * Maps an NVD source identifier to its published contributor name, returning the identifier
 * unchanged when the dictionary holds no entry for it.
 */
export type SourceNameResolver = (identifier: string) => string;

/** Returns every identifier untouched — for surfaces that emit no `source` field at all. */
export const passthroughSourceNames: SourceNameResolver = (identifier) => identifier;

/**
 * `source/2.0` caps `resultsPerPage` at 1,000 and answers anything above it with the same HTTP
 * 404 it uses for a rejected parameter. The dictionary held 496 contributors as of this writing
 * and has grown by 55–60 a year since 2024, so one page covers it well past the point where
 * paging would earn its complexity. A truncated page is logged, and the identifiers it left out
 * fall through as raw values like any other unknown.
 */
const SOURCE_PAGE_SIZE = 1000;

/** How long a loaded dictionary is served before the next lookup refetches it. */
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;

/**
 * How long a failed load is remembered. Short enough that a transient outage self-heals inside a
 * session, long enough that a sustained one cannot cost an upstream request per tool call — the
 * keyless NVD budget is 5 requests per 30 seconds, and a CVE lookup must not compete with a
 * secondary metadata endpoint for it.
 */
const FAILURE_TTL_MS = 5 * 60 * 1000;

/**
 * Effort spent on the dictionary, deliberately a fraction of what a CVE request gets. This runs
 * inside the calling tool, ahead of a record the caller already has in hand, and shares the one
 * pacing queue every NVD request passes through — so on the default budget an unreachable
 * `source/2.0` holds a CVE lookup for every attempt that budget allows, each with the full
 * request timeout and a backoff between them, with every queued CVE request stuck behind it. One
 * attempt on a short deadline reaches the raw-identifier fallback in seconds instead, and
 * {@link FAILURE_TTL_MS} keeps the next call from paying even that.
 */
const SOURCE_REQUEST_BUDGET: NvdRequestBudget = { maxRetries: 0, timeoutMs: 3_000 };

export class NvdSourceService {
  private names = new Map<string, string>();
  private expiresAt = 0;
  private inFlight: Promise<Map<string, string>> | undefined;

  // biome-ignore lint/complexity/noUselessConstructor: preserves framework init-pattern signature
  constructor(_config: AppConfig, _storage: StorageService) {}

  /**
   * A resolver over the cached dictionary, loading it first when the cache is cold or stale.
   *
   * The dictionary is one small document every record resolves against, and it turns over by a
   * handful of entries a year, so it is fetched on the cadence of {@link CACHE_TTL_MS} rather
   * than per CVE, per reference, or per call. Concurrent first callers share the single in-flight
   * request: a burst of tool calls must not stampede the endpoint.
   */
  async getResolver(ctx: Context): Promise<SourceNameResolver> {
    if (Date.now() >= this.expiresAt) {
      this.inFlight ??= this.load(ctx).finally(() => {
        this.inFlight = undefined;
      });
      this.names = await this.inFlight;
    }
    const names = this.names;
    return (identifier) => names.get(identifier) ?? identifier;
  }

  /**
   * Load the dictionary, degrading to whatever is already cached when NVD cannot serve it. A CVE
   * lookup must not start failing because a secondary metadata endpoint is down, so this never
   * throws — an unresolvable identifier reaching the caller raw is the documented fallback.
   */
  private async load(ctx: Context): Promise<Map<string, string>> {
    try {
      const response = await getNvdHttpClient().get<RawNvdSourceResponse>(
        'source/2.0',
        { resultsPerPage: SOURCE_PAGE_SIZE },
        ctx,
        SOURCE_REQUEST_BUDGET,
      );

      const sources = response.sources ?? [];
      const names = new Map<string, string>();
      for (const source of sources) {
        if (!source.name) continue;
        for (const identifier of source.sourceIdentifiers ?? []) {
          /**
           * An email identifier already names its contributor, so it is never indexed and always
           * resolves to itself — `security@apache.org` stays the value a reader recognizes rather
           * than becoming `Apache Software Foundation`.
           */
          if (identifier.includes('@')) continue;
          names.set(identifier, source.name);
        }
      }

      const totalResults = response.totalResults ?? sources.length;
      if (totalResults > sources.length) {
        ctx.log.warning(
          'NVD source dictionary page is incomplete — the rest resolve as raw values',
          {
            returned: sources.length,
            totalResults,
          },
        );
      }

      this.expiresAt = Date.now() + CACHE_TTL_MS;
      ctx.log.debug('NVD source dictionary loaded', {
        sources: sources.length,
        identifiers: names.size,
      });
      return names;
    } catch (err) {
      /**
       * The caller that opened this load can also cancel it, and its walking away says nothing
       * about whether NVD can serve the dictionary. Leaving the cache cold lets the next call try
       * again, rather than committing every caller to raw identifiers for the whole failure
       * window on the strength of an unrelated cancellation.
       */
      if (ctx.signal.aborted) {
        ctx.log.debug('NVD source dictionary load cancelled with its caller — cache left cold');
        return this.names;
      }
      ctx.log.warning('NVD source dictionary unavailable — source identifiers pass through raw', {
        error: (err as Error).message,
      });
      this.expiresAt = Date.now() + FAILURE_TTL_MS;
      // Keep any dictionary already in hand; a stale name beats an opaque identifier.
      return this.names;
    }
  }
}

// --- Init/accessor pattern ---

let _service: NvdSourceService | undefined;

export function initNvdSourceService(config: AppConfig, storage: StorageService): void {
  _service = new NvdSourceService(config, storage);
}

export function getNvdSourceService(): NvdSourceService {
  if (!_service) {
    throw new Error('NvdSourceService not initialized — call initNvdSourceService() in setup()');
  }
  return _service;
}
