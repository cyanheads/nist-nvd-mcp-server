/** @fileoverview Shared read-limit schema and observable clamp telemetry. */
import { z } from '@cyanheads/mcp-ts-core';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, describe, expect, it, vi } from 'vitest';
import * as config from '@/config/server-config.js';
import { applyReadLimit, readLimitSchema } from '@/mcp-server/tools/read-limit.js';

const { add } = vi.hoisted(() => ({ add: vi.fn() }));
vi.mock('@cyanheads/mcp-ts-core/utils', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@cyanheads/mcp-ts-core/utils')>()),
  createCounter: () => ({ add }),
}));

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('read-limit policy', () => {
  it('advertises and enforces the ceiling only when clamping is disabled', () => {
    vi.spyOn(config, 'getServerConfig').mockReturnValue({
      requestTimeoutMs: 10000,
      clampLimits: false,
    });
    const schema = readLimitSchema(2000, 20);
    expect(z.toJSONSchema(schema)).toMatchObject({ maximum: 2000 });
    expect(schema.safeParse(2001).success).toBe(false);
    expect(schema.parse(2000)).toBe(2000);
  });
  it('records one counter increment and log per clamp with a bounded tool label', () => {
    vi.spyOn(config, 'getServerConfig').mockReturnValue({
      requestTimeoutMs: 10000,
      clampLimits: true,
    });
    const ctx = createMockContext();
    const log = vi.spyOn(ctx.log, 'notice');
    expect(applyReadLimit(20, 2000, 'nvd_search_cves', ctx)).toEqual({ limit: 20 });
    expect(getEnrichment(ctx)).toEqual({});
    expect(applyReadLimit(2001, 2000, 'nvd_search_cves', ctx)).toEqual({
      limit: 2000,
      notice: 'Requested limit 2001 was clamped to 2000.',
    });
    expect(getEnrichment(ctx)).toEqual({ requestedLimit: 2001, effectiveLimit: 2000 });
    expect(add).toHaveBeenCalledExactlyOnceWith(1, { tool: 'nvd_search_cves' });
    expect(log).toHaveBeenCalledTimes(1);
  });
  it('restores all advertised maxima with the switch disabled before definition construction', async () => {
    vi.resetModules();
    vi.stubEnv('NVD_CLAMP_LIMITS', 'false');
    const { nvdSearchCves } = await import(
      '@/mcp-server/tools/definitions/nvd-search-cves.tool.js'
    );
    const { nvdAuditCpe } = await import('@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js');
    const { nvdGetCveHistory } = await import(
      '@/mcp-server/tools/definitions/nvd-get-cve-history.tool.js'
    );
    const { nvdSearchCpes } = await import(
      '@/mcp-server/tools/definitions/nvd-search-cpes.tool.js'
    );
    const { nvdGetCve } = await import('@/mcp-server/tools/definitions/nvd-get-cve.tool.js');
    for (const tool of [nvdSearchCves, nvdAuditCpe, nvdGetCveHistory]) {
      expect(z.toJSONSchema(tool.input).properties?.limit).toMatchObject({ maximum: 2000 });
    }
    expect(z.toJSONSchema(nvdSearchCpes.input).properties?.limit).toMatchObject({ maximum: 10000 });
    const batchSchema = z.toJSONSchema(nvdGetCve.input).properties?.cveIds;
    expect(batchSchema).toMatchObject({
      anyOf: expect.arrayContaining([expect.objectContaining({ type: 'array', maxItems: 100 })]),
    });
    expect(
      nvdGetCve.input.safeParse({ cveIds: Array.from({ length: 101 }, () => 'CVE-2021-44228') })
        .success,
    ).toBe(false);
  });
});
