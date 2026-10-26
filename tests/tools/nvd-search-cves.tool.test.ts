/**
 * @fileoverview Tests for nvd_search_cves tool.
 * @module tests/tools/nvd-search-cves.tool.test
 */

import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { createMockContext, getEnrichment, runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import type { BriefCveRecord } from '@/services/nvd-cve/types.js';
import { nvdRequestRejected } from '@/services/nvd-http/nvd-http-client.js';
import { at } from '../support/at.js';

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

/** Every text block, including enrichment and error recovery. */
function resultText(result: Awaited<ReturnType<typeof runToolContract>>): string {
  return result.content.flatMap((block) => (block.type === 'text' ? [block.text] : [])).join('\n');
}

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

/**
 * `getEnrichment` hands back an untyped bag, so read `datesClamped` through a narrowing that
 * fails loudly rather than an index into `unknown`.
 */
function clampedEntries(ctx: Parameters<typeof getEnrichment>[0]): Array<{
  param: string;
  original: number;
  clamped: number;
}> {
  const value = getEnrichment(ctx).datesClamped;
  if (!Array.isArray(value)) {
    throw new Error(`expected a datesClamped array on the enrichment, got ${typeof value}`);
  }
  return value as Array<{ param: string; original: number; clamped: number }>;
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
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ keyword: 'log4j' });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves).toHaveLength(1);
    expect(at(result.cves, 0).cveId).toBe('CVE-2021-44228');

    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(1);
    expect(enrichment.returned).toBe(1);
    expect(enrichment.offset).toBe(0);
    expect(enrichment.datesClamped).toBeUndefined();
  });

  it('applies defaults when no filters are provided', async () => {
    mockService.searchCves.mockResolvedValue({ cves: [], totalResults: 0, returned: 0, offset: 0 });
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({});
    const result = await nvdSearchCves.handler(input, ctx);

    expect(result.cves).toHaveLength(0);
    const enrichment = getEnrichment(ctx);
    expect(enrichment.totalCount).toBe(0);
  });

  it('clamps pubDays over 120 and reports clamping in enrichment', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ pubDays: 200 });
    await nvdSearchCves.handler(input, ctx);

    expect(clampedEntries(ctx)).toHaveLength(1);
    expect(at(clampedEntries(ctx)).param).toBe('pubDays');
    expect(at(clampedEntries(ctx)).original).toBe(200);
    expect(at(clampedEntries(ctx)).clamped).toBe(120);
  });

  it('clamps lastModDays over 120 and reports clamping', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ lastModDays: 150 });
    await nvdSearchCves.handler(input, ctx);

    expect(clampedEntries(ctx)).toHaveLength(1);
    expect(at(clampedEntries(ctx)).param).toBe('lastModDays');
    expect(at(clampedEntries(ctx)).original).toBe(150);
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
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({});
    const result = await nvdSearchCves.handler(input, ctx);

    expect(at(result.cves, 0).severity).toBeUndefined();
    expect(at(result.cves, 0).cveId).toBe('CVE-2022-00001');
  });

  it('formats output with CVE IDs and severity present', () => {
    const output = { cves: [BRIEF_CVE] };
    const blocks = nvdSearchCves.format!(output);
    expect(at(blocks, 0).type).toBe('text');
    const text = (at(blocks, 0) as { text: string }).text;
    expect(text).toContain('CVE-2021-44228');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('10');
  });

  it('formats empty result with no-match placeholder', () => {
    const output = { cves: [] };
    const blocks = nvdSearchCves.format!(output);
    const text = (at(blocks, 0) as { text: string }).text;
    expect(text).toBeTruthy();
    // format() renders domain payload only; enrichment trailer carries notices
  });

  it('formats CVE without severity using "Not available"', () => {
    const output = { cves: [BRIEF_CVE_NO_SEVERITY] };
    const blocks = nvdSearchCves.format!(output);
    const text = (at(blocks, 0) as { text: string }).text;
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
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ pubDays: 30 });
    await nvdSearchCves.handler(input, ctx);

    const call = at(mockService.searchCves.mock.calls)[0] as Record<string, unknown>;
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
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ offset: 9999 });
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('9999');
    expect(enrichment.notice).toContain('3095');
    expect(enrichment.notice).toContain('past the end');
  });

  it('enriches notice when no CVEs matched at all (totalResults=0)', async () => {
    mockService.searchCves.mockResolvedValue({
      cves: [],
      totalResults: 0,
      returned: 0,
      offset: 0,
    });
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({});
    await nvdSearchCves.handler(input, ctx);

    const enrichment = getEnrichment(ctx);
    expect(enrichment.notice).toContain('No CVEs matched');
  });

  it('enriches datesClamped when pubDays exceeds 120', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ pubDays: 200 });
    await nvdSearchCves.handler(input, ctx);

    expect(clampedEntries(ctx)).toHaveLength(1);
    expect(at(clampedEntries(ctx)).param).toBe('pubDays');
    expect(at(clampedEntries(ctx)).original).toBe(200);
    expect(at(clampedEntries(ctx)).clamped).toBe(120);
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

    const enrichmentShape = nvdSearchCves.enrichment;
    if (!enrichmentShape) throw new Error('nvdSearchCves must declare an enrichment block');
    const echoed = enrichmentShape.filtersApplied.unwrap().shape.severity.description ?? '';
    expect(echoed).not.toContain('floor');
    expect(echoed).toContain('exact');
  });

  // Issue #24: the per-row filtered-version severity passes through and renders.
  it('passes filteredSeverity through from the service to output', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult([BRIEF_CVE_DIVERGENT]));
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ severity: 'CRITICAL', severityVersion: 'v3' });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(at(result.cves, 0).filteredSeverity).toEqual({
      label: 'CRITICAL',
      score: 9.8,
      fromVersion: '3.1',
    });
  });

  it('renders both the headline and the filtered-version severity in format()', () => {
    const output = { cves: [BRIEF_CVE_DIVERGENT] };
    const blocks = nvdSearchCves.format!(output);
    const text = (at(blocks, 0) as { text: string }).text;
    expect(text).toContain('CVE-2014-6271');
    // Cross-version headline (HIGH) and the reconciled filter-version score (CRITICAL 9.8).
    expect(text).toContain('HIGH');
    expect(text).toContain('CRITICAL');
    expect(text).toContain('9.8');
  });

  // Issue #19: the query echoes the non-default filters it actually applied.
  it('echoes non-default filters in the filtersApplied enrichment', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
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

  // Issue #44: exact-phrase search reaches the service and stays accountable in the echo.
  it('threads exactPhrase to the service and echoes it alongside the keyword', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({
      keyword: 'remote code execution',
      exactPhrase: true,
    });
    await nvdSearchCves.handler(input, ctx);

    const params = mockService.searchCves.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(params.exactPhrase).toBe(true);
    expect(getEnrichment(ctx).filtersApplied).toMatchObject({
      keyword: 'remote code execution',
      exactPhrase: true,
    });
  });

  it('leaves exactPhrase false by default and out of the echo', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ keyword: 'log4j' });
    await nvdSearchCves.handler(input, ctx);

    const params = mockService.searchCves.mock.calls[0]?.[0] as Record<string, unknown>;
    expect(params.exactPhrase).toBe(false);
    expect(getEnrichment(ctx).filtersApplied).not.toHaveProperty('exactPhrase');
  });

  /**
   * A modifier the server accepts and then drops runs a broader search than the caller asked
   * for and says nothing about it, so the missing companion is a declared failure instead.
   */
  it('rejects exactPhrase without a keyword rather than searching unmodified', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ exactPhrase: true, cweId: 'CWE-79' });

    await expect(nvdSearchCves.handler(input, ctx)).rejects.toMatchObject({
      code: JsonRpcErrorCode.ValidationError,
      data: { reason: 'exact_phrase_without_keyword' },
    });
    expect(mockService.searchCves).not.toHaveBeenCalled();
  });

  it('omits filtersApplied when the query ran unfiltered', async () => {
    mockService.searchCves.mockResolvedValue(makeSearchResult());
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
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

  // Issue #32: rows carried identifiers with no prose, so nothing told one result from another.
  it('carries the description snippet through to the returned rows', async () => {
    mockService.searchCves.mockResolvedValue(
      makeSearchResult([{ ...BRIEF_CVE, description: 'Apache Log4j2 JNDI vulnerability.' }]),
    );
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    const input = nvdSearchCves.input.parse({ keyword: 'log4j' });
    const result = await nvdSearchCves.handler(input, ctx);

    expect(at(result.cves, 0).description).toBe('Apache Log4j2 JNDI vulnerability.');
  });

  it('renders the description snippet in format() so content[] matches structuredContent', () => {
    const blocks = nvdSearchCves.format!({
      cves: [{ ...BRIEF_CVE, description: 'Apache Log4j2 JNDI vulnerability.' }],
    });
    const text = (at(blocks, 0) as { text: string }).text;

    expect(text).toContain('Apache Log4j2 JNDI vulnerability.');
    expect(text).toContain('CVE-2021-44228');
  });

  it('renders a truncated snippet with its ellipsis intact', () => {
    const truncated = `${'A'.repeat(200)}…`;
    const blocks = nvdSearchCves.format!({ cves: [{ ...BRIEF_CVE, description: truncated }] });
    const text = (at(blocks, 0) as { text: string }).text;

    expect(text).toContain(truncated);
  });

  it('renders a row with no description without emitting an undefined placeholder', () => {
    const blocks = nvdSearchCves.format!({ cves: [BRIEF_CVE_NO_SEVERITY] });
    const text = (at(blocks, 0) as { text: string }).text;

    expect(text).toContain('CVE-2022-00001');
    expect(text).not.toContain('undefined');
  });
});

describe('nvdSearchCves — effective filter context', () => {
  const mockService = { searchCves: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(mockService as never);
    mockService.searchCves.mockReset();
    mockService.searchCves.mockResolvedValue(makeSearchResult());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it.each([
    ['nvd_invalid_response', JsonRpcErrorCode.ServiceUnavailable, 'Try again later'],
    ['nvd_request_blocked', JsonRpcErrorCode.Forbidden, 'Rephrase'],
  ] as const)('renders recovery for %s at the tool boundary', async (reason, code, hint) => {
    mockService.searchCves.mockRejectedValue(
      new McpError(code, 'NVD request failed.', { reason, retryable: false }),
    );
    const result = await runToolContract(nvdSearchCves, { keyword: 'log4j' });
    expect(result.isError).toBe(true);
    expect(result.structuredContent).toMatchObject({
      error: {
        code,
        data: { reason, retryable: false, recovery: { hint: expect.stringContaining(hint) } },
      },
    });
    expect(resultText(result)).toContain(hint);
  });

  it('keeps an omitted filter absent without an ignored-field notice', async () => {
    const result = await runToolContract(nvdSearchCves, {});
    expect(result.isError).not.toBe(true);
    expect(result.structuredContent).not.toHaveProperty('filtersApplied');
    expect(result.structuredContent).not.toHaveProperty('notice');
    expect(mockService.searchCves).toHaveBeenCalledWith(
      expect.not.objectContaining({ keyword: expect.anything() }),
      expect.anything(),
    );
  });

  it('echoes both explicit date pairs on both surfaces', async () => {
    const dates = {
      pubStartDate: '2024-01-01T00:00:00.000Z',
      pubEndDate: '2024-01-02T00:00:00.000Z',
      lastModStartDate: '2024-02-01T00:00:00.000Z',
      lastModEndDate: '2024-02-02T00:00:00.000Z',
    };
    const result = await runToolContract(nvdSearchCves, dates);
    expect(result.structuredContent).toHaveProperty('filtersApplied', dates);
    expect(mockService.searchCves).toHaveBeenCalledWith(
      expect.objectContaining(dates),
      expect.anything(),
    );
    for (const [key, value] of Object.entries(dates))
      expect(resultText(result)).toContain(`${key}=${value}`);
  });

  it('echoes expanded and clamped windows and permits their exact replay', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-10-25T12:00:00.000Z'));
    const dates = {
      pubStartDate: '2026-06-27T12:00:00.000Z',
      pubEndDate: '2026-10-25T12:00:00.000Z',
      lastModStartDate: '2026-10-11T12:00:00.000Z',
      lastModEndDate: '2026-10-25T12:00:00.000Z',
    };
    const result = await runToolContract(nvdSearchCves, { pubDays: 200, lastModDays: 14 });
    expect(result.structuredContent).toHaveProperty('filtersApplied', dates);
    expect(result.structuredContent).toHaveProperty('datesClamped', [
      { param: 'pubDays', original: 200, clamped: 120 },
    ]);
    for (const [key, value] of Object.entries(dates))
      expect(resultText(result)).toContain(`${key}=${value}`);
    await runToolContract(nvdSearchCves, dates);
    expect(mockService.searchCves.mock.calls[1]?.[0]).toEqual(
      mockService.searchCves.mock.calls[0]?.[0],
    );
  });

  it.each([
    'keyword',
    'cweId',
    'pubStartDate',
    'pubEndDate',
    'lastModStartDate',
    'lastModEndDate',
  ] as const)('discloses blank %s without forwarding it', async (field) => {
    for (const value of ['', ' \t\n ']) {
      mockService.searchCves.mockClear();
      const result = await runToolContract(nvdSearchCves, { [field]: value });
      expect(result.isError).not.toBe(true);
      expect(mockService.searchCves.mock.calls[0]?.[0]).not.toHaveProperty(field);
      expect(result.structuredContent).not.toHaveProperty('filtersApplied');
      expect(result.structuredContent).toHaveProperty('notice', `Ignored empty ${field}.`);
      expect(resultText(result)).toContain(`Ignored empty ${field}.`);
    }
  });

  it('normalizes nonblank filters before forwarding and echoing', async () => {
    const result = await runToolContract(nvdSearchCves, {
      keyword: '  log4j  ',
      cweId: ' CWE-79 ',
      pubStartDate: ' 2024-01-01T00:00:00.000Z ',
      pubEndDate: ' 2024-01-02T00:00:00.000Z ',
    });
    const effective = {
      keyword: 'log4j',
      cweId: 'CWE-79',
      pubStartDate: '2024-01-01T00:00:00.000Z',
      pubEndDate: '2024-01-02T00:00:00.000Z',
    };
    expect(mockService.searchCves).toHaveBeenCalledWith(
      expect.objectContaining(effective),
      expect.anything(),
    );
    expect(result.structuredContent).toHaveProperty('filtersApplied', effective);
  });

  it.each([
    [{ exactPhrase: true, keyword: ' ' }, 'exact_phrase_without_keyword'],
    [{ pubStartDate: ' ', pubEndDate: '2024-01-02T00:00:00.000Z' }, 'missing_date_pair'],
  ] as const)('preserves companion checks after blank normalization', async (input, reason) => {
    const result = await runToolContract(nvdSearchCves, input);
    expect(result.structuredContent).toMatchObject({ error: { data: { reason } } });
    expect(mockService.searchCves).not.toHaveBeenCalled();
  });

  it.each([
    [{ cves: [BRIEF_CVE], totalResults: 2, returned: 1, offset: 0 }, 'set offset to 1'],
    [{ cves: [], totalResults: 0, returned: 0, offset: 0 }, 'No CVEs matched'],
    [{ cves: [], totalResults: 1, returned: 0, offset: 2 }, 'past the end'],
  ])('keeps paging and empty-result guidance alongside ignored fields', async (page, guidance) => {
    mockService.searchCves.mockResolvedValue(page);
    const result = await runToolContract(nvdSearchCves, {
      keyword: '',
      cweId: ' ',
      offset: page.offset,
    });
    expect(result.structuredContent).toHaveProperty(
      'notice',
      expect.stringContaining('Ignored empty keyword, cweId.'),
    );
    expect(result.structuredContent).toHaveProperty('notice', expect.stringContaining(guidance));
    expect(resultText(result)).toContain('Ignored empty keyword, cweId.');
    expect(resultText(result)).toContain(guidance);
  });

  it.each([
    [{ cweId: '79' }, 'Invalid cweId parameter.'],
    [{ cweId: 'cwe-79' }, 'Invalid cweId parameter.'],
    [
      { pubStartDate: '2024-01-01', pubEndDate: '2024-01-02T00:00:00.000Z' },
      'Invalid ISO 8601 date/time format, see documentation.',
    ],
  ])('supplies recovery for NVD-rejected CWE and date forms', async (input, detail) => {
    mockService.searchCves.mockRejectedValue(nvdRequestRejected('cves/2.0', detail));
    const result = await runToolContract(nvdSearchCves, input);
    expect(result.structuredContent).toMatchObject({
      error: {
        code: JsonRpcErrorCode.ValidationError,
        data: {
          reason: 'nvd_request_rejected',
          retryable: false,
          recovery: { hint: expect.stringContaining('CWE-<number>') },
        },
      },
    });
    for (const value of ['NVD-CWE-Other', 'NVD-CWE-noinfo', '2024-01-01T00:00:00.000Z'])
      expect(resultText(result)).toContain(value);
  });
});

/**
 * Issue #34: an empty page was diagnosed as an offset overrun on `totalResults > 0` alone, so a
 * valid offset was reported as the caller's mistake. The overrun notice now needs the offset to
 * have reached totalCount, matching the guard nvd_search_cpes and nvd_audit_cpe use.
 */
describe('nvdSearchCves — empty-page notices (issue #34)', () => {
  const mockService = { searchCves: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.searchCves.mockReset();
  });

  /** Notice raised for an empty page at `offset` when NVD reports `totalResults` matches. */
  async function noticeFor(offset: number, totalResults: number): Promise<string | undefined> {
    mockService.searchCves.mockResolvedValue({ cves: [], totalResults, returned: 0, offset });
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    await nvdSearchCves.handler(nvdSearchCves.input.parse({ offset }), ctx);
    const { notice } = getEnrichment(ctx);
    return typeof notice === 'string' ? notice : undefined;
  }

  it('blames the offset only once it has reached totalCount', async () => {
    const notice = await noticeFor(3095, 3095);

    expect(notice).toContain('past the end');
    expect(notice).toContain('3095');
    expect(notice).not.toContain('Retry the query');
  });

  it('does not blame the offset for an empty page inside the result range', async () => {
    const notice = await noticeFor(40, 3095);

    expect(notice).not.toContain('past the end');
    expect(notice).not.toContain('lower offset');
    expect(notice).toContain('3095');
    expect(notice).toContain('40');
    expect(notice).toContain('Retry the query');
  });

  it('treats an offset one below totalCount as inside the range', async () => {
    const notice = await noticeFor(3094, 3095);

    expect(notice).not.toContain('past the end');
    expect(notice).toContain('Retry the query');
  });

  it('reports a genuinely unmatched query rather than either paging notice', async () => {
    const notice = await noticeFor(0, 0);

    expect(notice).toContain('No CVEs matched');
    expect(notice).not.toContain('past the end');
    expect(notice).not.toContain('Retry the query');
  });

  it('raises no empty-page notice when the page carries results', async () => {
    mockService.searchCves.mockResolvedValue({
      cves: [BRIEF_CVE],
      totalResults: 3095,
      returned: 1,
      offset: 40,
    });
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    await nvdSearchCves.handler(nvdSearchCves.input.parse({ offset: 40 }), ctx);

    // A non-empty partial page gets the next-page notice (#36) and none of the empty-page ones.
    const notice = getEnrichment(ctx).notice as string;
    expect(notice).toContain('set offset to 41');
    expect(notice).not.toContain('past the end');
    expect(notice).not.toContain('Retry the query');
    expect(notice).not.toContain('No CVEs matched');
  });
});

/**
 * Issue #36: a partial page gave no sign that more results existed, leaving a caller to infer it
 * from totalCount and compute the next offset itself. Offset is zero-based, so `offset + returned`
 * IS the next page's offset — naming anything higher would skip a record.
 */
describe('nvdSearchCves — next-page notice (issue #36)', () => {
  const mockService = { searchCves: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(
      mockService as unknown as ReturnType<typeof nvdCveServiceModule.getNvdCveService>,
    );
    mockService.searchCves.mockReset();
  });

  /** Notice raised for a page of `returned` rows at `offset` out of `totalResults`. */
  async function noticeFor(
    offset: number,
    returned: number,
    totalResults: number,
  ): Promise<string | undefined> {
    mockService.searchCves.mockResolvedValue({
      cves: Array.from({ length: returned }, (_, i) => ({
        ...BRIEF_CVE,
        cveId: `CVE-2024-${String(offset + i).padStart(5, '0')}`,
      })),
      totalResults,
      returned,
      offset,
    });
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    await nvdSearchCves.handler(
      nvdSearchCves.input.parse({ keyword: 'log4j', offset, limit: returned || 1 }),
      ctx,
    );
    const { notice } = getEnrichment(ctx);
    return typeof notice === 'string' ? notice : undefined;
  }

  it('names the next page offset on a partial first page', async () => {
    const notice = await noticeFor(0, 20, 32);

    expect(notice).toContain('truncated');
    expect(notice).toContain('32');
    // 20 rows at offset 0 covers indices 0–19, so the next page starts at 20 — not 21.
    expect(notice).toContain('set offset to 20');
    expect(notice).not.toContain('set offset to 21');
  });

  it('advances the named offset by the page size, leaving no gap', async () => {
    const notice = await noticeFor(20, 10, 32);

    expect(notice).toContain('set offset to 30');
  });

  it('omits the notice when the page reaches the end of the result set exactly', async () => {
    expect(await noticeFor(30, 2, 32)).toBeUndefined();
    expect(await noticeFor(0, 32, 32)).toBeUndefined();
  });

  it('omits the notice when a single page carries every match', async () => {
    expect(await noticeFor(0, 1, 1)).toBeUndefined();
  });

  it('fires exactly one notice — never a next-page notice on an empty page', async () => {
    // Empty and partial are mutually exclusive: the next-page branch is the outer `else`.
    mockService.searchCves.mockResolvedValue({
      cves: [],
      totalResults: 32,
      returned: 0,
      offset: 99,
    });
    const ctx = createMockContext({ errors: nvdSearchCves.errors });
    await nvdSearchCves.handler(nvdSearchCves.input.parse({ keyword: 'log4j', offset: 99 }), ctx);

    const notice = getEnrichment(ctx).notice as string;
    expect(notice).toContain('past the end');
    expect(notice).not.toContain('truncated');
  });
});
