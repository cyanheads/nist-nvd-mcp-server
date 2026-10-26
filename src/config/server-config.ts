/**
 * @fileoverview Server-specific configuration for nist-nvd-mcp-server.
 * Loads cwd env settings and parses NVD credentials, timeout, and read-limit policy.
 * @module config/server-config
 */

import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';
import { configurationError } from '@cyanheads/mcp-ts-core/errors';

const ServerConfigSchema = z.object({
  apiKey: z
    .string()
    .optional()
    .describe(
      'NIST NVD API key. Without it, rate limit is 5 req/30s. With it, 50 req/30s. Get one free at nvd.nist.gov/developers/request-an-api-key.',
    ),
  requestTimeoutMs: z.coerce
    .number()
    .default(10_000)
    .describe('HTTP request timeout in milliseconds. Default: 10000 (10s).'),
  clampLimits: z
    .stringbool()
    .default(true)
    .describe('Clamp oversized read requests to NVD limits; false rejects them.'),
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

let _config: ServerConfig | undefined;

/** Loads cwd .env and parses once; exported values win. Throws on invalid config or unreadable files. */
export function getServerConfig(): ServerConfig {
  if (_config) return _config;
  try {
    process.loadEnvFile();
  } catch (cause) {
    if (!(cause instanceof Error && 'code' in cause && cause.code === 'ENOENT')) {
      throw configurationError(
        'Could not load the working-directory .env file. Check that it is a readable file.',
        undefined,
        { cause },
      );
    }
  }
  _config = parseEnvConfig(ServerConfigSchema, {
    apiKey: 'NVD_API_KEY',
    requestTimeoutMs: 'NVD_REQUEST_TIMEOUT_MS',
    clampLimits: 'NVD_CLAMP_LIMITS',
  });
  return _config;
}
