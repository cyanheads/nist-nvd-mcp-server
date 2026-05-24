/**
 * @fileoverview Server-specific configuration for nist-nvd-mcp-server.
 * Parses NVD API key and request timeout from environment variables.
 * @module config/server-config
 */

import { z } from '@cyanheads/mcp-ts-core';
import { parseEnvConfig } from '@cyanheads/mcp-ts-core/config';

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
});

export type ServerConfig = z.infer<typeof ServerConfigSchema>;

let _config: ServerConfig | undefined;

/** Returns the parsed server config, parsing from environment variables on first call. */
export function getServerConfig(): ServerConfig {
  _config ??= parseEnvConfig(ServerConfigSchema, {
    apiKey: 'NVD_API_KEY',
    requestTimeoutMs: 'NVD_REQUEST_TIMEOUT_MS',
  });
  return _config;
}
