/**
 * @fileoverview Tests for nvd_search_cves tool.
 * @module tests/tools/nvd-search-cves.tool.test
 */

import { JsonRpcErrorCode } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import type { BriefCveRecord } from '@/services/nvd-cve/types.js';

const BRIEF_CVE: BriefCveRecord = {
  cveId: 'CVE-2021-44228',
  vulnStatus: 'Analyzed',
  published: '2021-12-10T10:15:00.000',
  severity: { label: 'CRITICAL', score: 10.0, fromVersion: '3.1' },
};

const BRIEF_CVE_NO_SEVERITY: BriefCveRecord = {
  cveId: 'CVE-2022-00001',
  vulnStatus: 'Awaiting Analysis',
  published: '2022-01-01T00:00:00.000',
};

/** Shellshock shape: v2 headline (HIGH 10.0) diverges from the v3 filter version (CRITICAL 9.8). */
const BRIEF_CVE_DIVERGENT: BriefCveRecord = {
  cveId: 'CVE-2014-6271',
  vulnStatus: 'Analyzed',
  published: '2014-09-24T00:00:00.000',
  severity: { label: 'HIGH', score: 10.0, fromVersion: '2.0' },
  filteredSeverity: { label: 'CRITICAL', score: 9.8, fromVersion: '3.1' },
};

function makeSearchResult(cves: BriefCveRecord[] = [BRIEF_CVE], total = 1) {
  return { cves, totalResults: total, returned: cves.length, offset: 0 };
}

describe('nvdSearchCves', () => {
  const mockService = { searchCves: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.searchCves.mockReset();
  });

  it('returns CVE summaries and enrichment for a keyword search', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ keyword: 'log4j' });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves).toHaveLength(1);
    expect(result.cves[0].cveId).toBe('CVE-2021-44228');

    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(1);
    expect(enrichment.returned).toBe(1);
    expect(enrichment.offset).toBe(0);
    expect(enrichment.datesClamped).toBeUndefined();
  });

  it('applies defaults when no filters are provided', async () => {
    mockService.searchCves.mockResolvedValue({ cves: [], totalResults: 0, returned: 0, offset: 0 });
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({});
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves).toHaveLength(0);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(0);
  });

  it('clamps pubDays over 120 and reports clamping in enrichment', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ pubDays: 200 });
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.datesClamped).toHaveLength(1);
    expect(enrichment.datesClamped![0].param).toBe('pubDays');
    expect(enrichment.datesClamped![0].original).toBe(200);
    expect(enrichment.datesClamped![0].clamped).toBe(120);
  });

  it('clamps lastModDays over 120 and reports clamping', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ lastModDays: 150 });
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.datesClamped).toHaveLength(1);
    expect(enrichment.datesClamped![0].param).toBe('lastModDays');
    expect(enrichment.datesClamped![0].original).toBe(150);
  });

  it('throws mutually_exclusive_params when pubDays and pubStartDate are both provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubDays: 30,
      pubStartDate: '2024-01-01T00:00:00.000',
      pubEndDate: '2024-01-30T00:00:00.000',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mutually_exclusive_params' },
    });
  });

  it('throws mutually_exclusive_params when lastModDays and lastModStartDate are both provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      lastModDays: 30,
      lastModStartDate: '2024-01-01T00:00:00.000',
      lastModEndDate: '2024-01-30T00:00:00.000',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'mutually_exclusive_params' },
    });
  });

  it('throws date_range_exceeds_max when explicit pub date range spans more than 120 days', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubStartDate: '2024-01-01T00:00:00.000',
      pubEndDate: '2024-06-01T00:00:00.000',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'date_range_exceeds_max' },
    });
  });

  it('preserves CVEs without severity in output (sparse upstream payload)', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult([BRIEF_CVE_NO_SEVERITY], 1));
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({});
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves[0].severity).toBeUndefined();
    expect(result.cves[0].cveId).toBe('CVE-2022-00001');
  });

  it('formats output with CVE IDs and severity present', () => {
    const output = { cves: [BRIEF_CVE] };
    const blocks = nvdSearchCves.format!(output);
    expect(blocks[0].type).toBe('text');
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('10');
  });

  it('formats empty result with no-match placeholder', () => {
    const output = { cves: [] };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toBeTruthy();
    // format() renders domain payload only; enrichment trailer carries notices
  });

  it('formats CVE without severity using "Not available"', () => {
    const output = { cves: [BRIEF_CVE_NO_SEVERITY] };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('Not available');
    expect(text).not.toMatch(/Severity:.*undefined/);
  });

  it('throws missing_date_pair when only pubStartDate is provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ pubStartDate: '2024-01-01T00:00:00.000Z' });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'missing_date_pair' },
    });
  });

  it('throws missing_date_pair when only pubEndDate is provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ pubEndDate: '2024-01-31T00:00:00.000Z' });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'missing_date_pair' },
    });
  });

  it('throws missing_date_pair when only lastModStartDate is provided', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ lastModStartDate: '2024-01-01T00:00:00.000Z' });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'missing_date_pair' },
    });
  });

  it('throws date_range_inverted when pubEndDate is before pubStartDate', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubStartDate: '2024-06-01T00:00:00.000Z',
      pubEndDate: '2024-01-01T00:00:00.000Z',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'date_range_inverted' },
    });
  });

  it('throws date_range_inverted when lastModEndDate is before lastModStartDate', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      lastModStartDate: '2024-06-01T00:00:00.000Z',
      lastModEndDate: '2024-01-01T00:00:00.000Z',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'date_range_inverted' },
    });
  });

  it('daysAgo/nowIso produce parseable ISO 8601 dates (forwarded to service)', async () => {
    // Capture what date strings get passed to the service when pubDays is used
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ pubDays: 30 });
    await nvdSearchCves.handler(input, ctx);

    const call = mockService.searchCves.mock.calls[0][0] as Record<string, unknown>;
    const startDate = new Date(call.pubStartDate as string);
    const endDate = new Date(call.pubEndDate as string);
    expect(Number.isNaN(startDate.getTime())).toBe(false);
    expect(Number.isNaN(endDate.getTime())).toBe(false);
  });

  it('mutually_exclusive_params for lastModDays conflict includes lastMod-specific recovery hint', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      lastModDays: 30,
      lastModStartDate: '2024-01-01T00:00:00.000Z',
      lastModEndDate: '2024-01-30T00:00:00.000Z',
    });
    try {
      await nvdSearchCves.handler(input, ctx);
      expect.fail('should have thrown');
    } catch (err) {
      const mcpErr = err as { data?: { reason?: string; recovery?: { hint?: string } } };
      expect(mcpErr.data?.reason).toBe('mutually_exclusive_params');
      expect(mcpErr.data?.recovery?.hint).toContain('lastModDays');
    }
  });

  // Issue #9: invalid date format errors must include data.reason
  it('throws invalid_date_format with data.reason for invalid pubStartDate', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubStartDate: 'garbage',
      pubEndDate: '2024-01-31T00:00:00.000Z',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_date_format' },
    });
  });

  it('throws invalid_date_format with data.reason for invalid pubEndDate', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      pubStartDate: '2024-01-01T00:00:00.000Z',
      pubEndDate: 'not-a-date',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_date_format' },
    });
  });

  it('throws invalid_date_format with data.reason for invalid lastModStartDate', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      lastModStartDate: 'garbage',
      lastModEndDate: '2024-01-31T00:00:00.000Z',
    });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_date_format' },
    });
  });

  // Issue #13: severity=CRITICAL with severityVersion=v2 should fail at validation
  it('throws invalid_severity_for_version when severity=CRITICAL and severityVersion=v2', async () => {
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ severity: 'CRITICAL', severityVersion: 'v2' });
    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      data: { reason: 'invalid_severity_for_version' },
    });
  });

  it('allows severity=HIGH with severityVersion=v2 (valid combination)', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ severity: 'HIGH', severityVersion: 'v2' });
    const result = await nvdSearchCves.handler(input, ctx);
    expect(result.cves).toHaveLength(1);
  });

  it('allows severity=CRITICAL with severityVersion=v3 (valid combination)', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ severity: 'CRITICAL', severityVersion: 'v3' });
    const result = await nvdSearchCves.handler(input, ctx);
    expect(result.cves).toHaveLength(1);
  });

  it('enriches notice when offset is past end of result set', async () => {
    mockService.searchCves.mockResolvedValue({
      cves: [],
      totalResults: 3095,
      returned: 0,
      offset: 9999,
    });
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ offset: 9999 });
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('9999');
    expect(enrichment.notice).toContain('3095');
  });

  it('enriches notice when no CVEs matched at all (totalResults=0)', async () => {
    mockService.searchCves.mockResolvedValue({
      cves: [],
      totalResults: 0,
      returned: 0,
      offset: 0,
    });
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({});
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('No CVEs matched');
  });

  it('enriches datesClamped when pubDays exceeds 120', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ pubDays: 200 });
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.datesClamped).toHaveLength(1);
    expect(enrichment.datesClamped![0].param).toBe('pubDays');
    expect(enrichment.datesClamped![0].original).toBe(200);
    expect(enrichment.datesClamped![0].clamped).toBe(120);
  });

  // Issue #12: description accuracy (regression guard — the description text is read in catalog tests)
  it('description does not claim no-filter returns most recently modified CVEs', () => {
    expect(nvdSearchCves.description).not.toContain('most recently modified');
  });

  // Issue #28: severity is an exact-band NVD filter, never a floor — neither surface may imply one.
  it('severity descriptions do not promise a floor', () => {
    const severityInput = nvdSearchCves.input.shape.severity.description ?? '';
    expect(severityInput).not.toContain('or above');
    expect(severityInput).toContain('exactly this CVSS severity band');

    const echoed =
      nvdSearchCves.enrichment.filtersApplied.unwrap().shape.severity.description ?? '';
    expect(echoed).not.toContain('floor');
    expect(echoed).toContain('exact');
  });

  // Issue #24: the per-row filtered-version severity passes through and renders.
  it('passes filteredSeverity through from the service to output', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult([BRIEF_CVE_DIVERGENT]));
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({ severity: 'CRITICAL', severityVersion: 'v3' });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves[0].filteredSeverity).toEqual({
      label: 'CRITICAL',
      score: 9.8,
      fromVersion: '3.1',
    });
  });

  it('renders both the headline and the filtered-version severity in format()', () => {
    const output = { cves: [BRIEF_CVE_DIVERGENT] };
    const blocks = nvdSearchCves.format!(output);
    const text = (blocks[0] as { text: string }).text;
    expect(text).toContain('CVE-2014-6271');
    // Cross-version headline (HIGH) and the reconciled filter-version score (CRITICAL 9.8).
    expect(text).toContain('HIGH');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('9.8');
  });

  // Issue #19: the query echoes the non-default filters it actually applied.
  it('echoes non-default filters in the filtersApplied enrichment', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({
      keyword: 'log4j',
      severity: 'CRITICAL',
      kevOnly: true,
    });
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.filtersApplied).toMatchObject({
      keyword: 'log4j',
      severity: 'CRITICAL',
      severityVersion: 'v3',
      kevOnly: true,
    });
    // Defaulted filters the caller never chose must not be echoed.
    expect(enrichment.filtersApplied).not.toHaveProperty('noRejected');
  });

  it('omits filtersApplied when the query ran unfiltered', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext();
    const input = nvdSearchCves.input.parse({});
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.filtersApplied).toBeUndefined();
  });

  // Issue #25: the advertised rate_limited code must match the client's thrown RateLimited.
  it('declares rate_limited with the RateLimited error code', () => {
    const entry = nvdSearchCves.errors?.find((e) => e.reason === 'rate_limited');
    expect(entry?.code).toBe(JsonRpcErrorCode.RateLimited);
  });
});
