/**
 * @fileoverview Isolated Node and Bun checks for server configuration and cwd env files.
 * @module tests/config/server-config.test
 */

import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, delimiter, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const configUrl = new URL('../../src/config/server-config.ts', import.meta.url).href;
const cases = {
  explicit: { env: { NVD_API_KEY: 'fixture-key', NVD_REQUEST_TIMEOUT_MS: '1234' } },
  defaults: { cached: true },
  disabled: { env: { NVD_CLAMP_LIMITS: 'false' } },
  file: { file: 'NVD_CLAMP_LIMITS=false\nNVD_REQUEST_TIMEOUT_MS=2345\n' },
  precedence: { env: { NVD_CLAMP_LIMITS: 'true' }, file: 'NVD_CLAMP_LIMITS=false\n' },
  invalid: { env: { NVD_CLAMP_LIMITS: 'sometimes' } },
  invalidFile: { file: 'NVD_CLAMP_LIMITS=sometimes\n' },
  unreadable: { directory: true },
};

type Outcome = {
  config?: { apiKey?: string; requestTimeoutMs: number; clampLimits: boolean };
  same?: boolean;
  error?: { code: number; causeCode?: string };
};

describe.each(['node', 'bun'])('%s server config', (runtime) => {
  let fixtureRoot: string;
  let results: Record<keyof typeof cases, Outcome>;

  beforeAll(() => {
    fixtureRoot = mkdtempSync(join(tmpdir(), 'nvd-config-test-'));
    symlinkSync(
      new URL('../../node_modules', import.meta.url),
      join(fixtureRoot, 'node_modules'),
      'dir',
    );
    writeFileSync(join(fixtureRoot, 'package.json'), '{"type":"module"}');
    const configSource = readFileSync(new URL(configUrl), 'utf8');
    const inputs = Object.entries(cases).map(([name, options]) => {
      const cwd = join(fixtureRoot, name);
      mkdirSync(cwd);
      const modulePath = join(cwd, 'config.ts');
      writeFileSync(modulePath, configSource);
      if ('file' in options) writeFileSync(join(cwd, '.env'), options.file);
      if ('directory' in options) mkdirSync(join(cwd, '.env'));
      return { name, cwd, configUrl: pathToFileURL(modulePath).href, ...options };
    });
    const env = { ...process.env };
    for (const key of Object.keys(env)) {
      if (key.startsWith('NVD_') || key.startsWith('MCP_')) delete env[key];
    }
    // Bun prepends a node→bun shim; select the actual Node binary for the Node cases.
    const executable =
      runtime === 'node'
        ? process.env.PATH?.split(delimiter)
            .map((directory) => join(directory, 'node'))
            .find(
              (candidate) => existsSync(candidate) && basename(realpathSync(candidate)) === 'node',
            )
        : 'bun';
    if (!executable) throw new Error('Node is required for the server configuration tests.');
    // Separate files isolate each config cache on both runtimes without reloading the framework.
    const script = `(async () => { const results = {}; for (const input of ${JSON.stringify(inputs)}) { process.chdir(input.cwd); for (const key of Object.keys(process.env)) if (key.startsWith('NVD_')) delete process.env[key]; Object.assign(process.env, input.env); const { getServerConfig } = await import(input.configUrl); try { const config = getServerConfig(); if (input.cached) { process.env.NVD_CLAMP_LIMITS = 'false'; process.env.NVD_REQUEST_TIMEOUT_MS = '17'; } results[input.name] = { config, same: config === getServerConfig() }; } catch (error) { results[input.name] = { error: { code: error.code, causeCode: error.cause?.code } }; } } console.log(JSON.stringify(results)); })();`;
    results = JSON.parse(
      execFileSync(executable, ['--eval', script], {
        cwd: fixtureRoot,
        env,
        encoding: 'utf8',
        timeout: 10_000,
      }),
    );
  });

  afterAll(() => {
    if (fixtureRoot) rmSync(fixtureRoot, { recursive: true });
  });

  it('preserves explicit API key and request timeout', () => {
    expect(results.explicit.config).toMatchObject({
      apiKey: 'fixture-key',
      requestTimeoutMs: 1234,
    });
  });

  it('defaults to clamping and caches the parsed configuration', () => {
    expect(results.defaults).toEqual({
      config: { requestTimeoutMs: 10_000, clampLimits: true },
      same: true,
    });
  });

  it('parses an exported false without coercing its truthiness', () => {
    expect(results.disabled.config?.clampLimits).toBe(false);
  });

  it('loads cwd .env before parsing server configuration', () => {
    expect(results.file.config).toMatchObject({ clampLimits: false, requestTimeoutMs: 2345 });
  });

  it('keeps exported values ahead of cwd .env values', () => {
    expect(results.precedence.config?.clampLimits).toBe(true);
  });

  it('rejects invalid exported and cwd .env switch values', () => {
    expect(results.invalid.error?.code).toBe(JsonRpcErrorCode.ConfigurationError);
    expect(results.invalidFile.error?.code).toBe(JsonRpcErrorCode.ConfigurationError);
  });

  it('preserves non-ENOENT env-file failures as typed configuration causes', () => {
    expect(results.unreadable.error).toEqual({
      code: JsonRpcErrorCode.ConfigurationError,
      causeCode: runtime === 'node' ? 'ERR_INVALID_ARG_TYPE' : 'EISDIR',
    });
  });
});
