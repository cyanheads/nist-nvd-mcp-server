/**
 * @fileoverview Seam tests for the shared date-window policy: the date grammar NVD accepts
 * (#71), UTC span reading, the per-axis pair/exclusion/span contract, exact N × 24 h shorthand
 * expansion in any time zone (#66), the moving-window paging guidance (#67), and the resolver's
 * cost on caller-sized strings. Tools that spread these fields prove only their wiring.
 * @module tests/tools/date-windows.test
 */

import { z } from '@cyanheads/mcp-ts-core';
import { JsonRpcErrorCode, McpError } from '@cyanheads/mcp-ts-core/errors';
import { runToolContract } from '@cyanheads/mcp-ts-core/testing';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  type DateWindowInput,
  dateWindowInput,
  renderDatesClamped,
  resolveDateWindows,
  windowReexpandedNotice,
  windowReplayClause,
} from '@/mcp-server/tools/date-windows.js';
import { nvdAuditCpe } from '@/mcp-server/tools/definitions/nvd-audit-cpe.tool.js';
import { nvdSearchCves } from '@/mcp-server/tools/definitions/nvd-search-cves.tool.js';
import * as nvdCveServiceModule from '@/services/nvd-cve/nvd-cve-service.js';
import { expectLinearCost } from '../support/cpu-linearity.js';
import { inZone } from '../support/time-zone.js';

const NOW = Date.parse('2026-11-15T20:00:00.000Z');
const DAY_MS = 86_400_000;
const ACCEPTED_FORM =
  'YYYY-MM-DDThh:mm[:ss[.fraction]] with an optional Z or ±hh:mm offset, e.g. 2024-01-01T00:00:00.000Z';

/** The failure `resolveDateWindows` throws for `input`. */
function failure(input: DateWindowInput, nowMs = NOW): McpError {
  try {
    resolveDateWindows(input, nowMs);
  } catch (err) {
    if (err instanceof McpError) return err;
    throw err;
  }
  throw new Error(`expected ${JSON.stringify(input)} to be rejected`);
}

const AXES = [
  { days: 'pubDays', start: 'pubStartDate', end: 'pubEndDate', label: 'Publication' },
  {
    days: 'lastModDays',
    start: 'lastModStartDate',
    end: 'lastModEndDate',
    label: 'Last-modified',
  },
  { days: 'kevDays', start: 'kevStartDate', end: 'kevEndDate', label: 'KEV-addition' },
] as const;

describe('date grammar (#71)', () => {
  /** Every form NVD answered on the live API, plus forms the grammar implies but NVD never saw. */
  const ACCEPTED = [
    '2026-11-01T00:00:00Z',
    '2026-11-01T00:00:00.000Z',
    '2026-11-01T00:00:00.1Z',
    '2026-11-01T00:00:00.123456Z',
    '2026-11-01T00:00:00',
    '2026-11-01T00:00:00.000',
    '2026-11-01T00:00',
    '2026-11-01T00:00Z',
    '2026-11-01T00:00:00+00:00',
    '2026-11-01T00:00:00-05:00',
    '2026-11-01T00:00:00.000+05:30',
    '2026-11-01t00:00:00z',
    '+002026-11-01T00:00:00Z',
    '2026-11-01T00:00:00.123456789Z',
    // NVD's widest offset: +18:00 answers 200; the negative side mirrors it.
    '2026-11-01T00:00:00+18:00',
    '2026-11-01T00:00:00-18:00',
    // Not probed against NVD; the grammar accepts them, so NVD stays the judge.
    '2026-11-01T00:00-05:00',
    '2026-11-01T00:00:00.1234567Z',
    '-000001-01-01T00:00:00Z',
    // Calendar edges.
    '2024-02-29T00:00:00Z',
    '2026-12-31T23:59:59.999Z',
    '0001-01-01T00:00:00Z',
  ];

  /** Every form NVD answered with 404 `Invalid ISO 8601 date/time format`, plus off-calendar values. */
  const REJECTED = [
    '2026-11-01',
    '2026-11',
    '2026',
    '2026-11-01 00:00:00',
    '2026-11-01 00:00:00Z',
    '2026-11-01T05:30:00+0530',
    '2026-11-01T24:00:00Z',
    '2026-02-30T00:00:00Z',
    '2026/11/01',
    '11/01/2026',
    'Nov 1 2026',
    '1 November 2026',
    'Sun, 01 Nov 2026 00:00:00 GMT',
    '0',
    // Off the calendar or the clock.
    '2025-02-29T00:00:00Z',
    '2026-13-01T00:00:00Z',
    '2026-11-00T00:00:00Z',
    '2026-11-01T23:60:00Z',
    '2026-11-01T00:00:60Z',
    '2026-11-01T00:00:00+24:00',
    '2026-11-01T00:00:00+05:60',
    // Past NVD's ±18:00 offset bound: +18:01 and +23:59 answer 404; the negative side mirrors it.
    '2026-11-01T00:00:00+18:01',
    '2026-11-01T00:00:00+23:59',
    '2026-11-01T00:00:00-18:01',
    '2026-11-01T00:00:00-23:59',
    // Past nanoseconds: a 9-digit fraction answers 200 and a 10-digit one 404.
    '2026-11-01T00:00:00.1234567891Z',
    '-000000-01-01T00:00:00Z',
    // Shapes next to the grammar.
    '2026-11-01T00',
    '2026-11-01T00:00:00.Z',
    '2026-11-01T00:00.5Z',
    '26-11-01T00:00:00Z',
    '2026-11-01T00:00:00Z\n',
    // The tools trim before resolving; the resolver itself takes the value as given.
    ' 2026-11-01T00:00:00Z',
  ];

  it.each(ACCEPTED)('accepts %s and sends it unchanged', (value) => {
    expect(resolveDateWindows({ pubStartDate: value, pubEndDate: value }, NOW).dates).toEqual({
      pubStartDate: value,
      pubEndDate: value,
    });
  });

  it.each(REJECTED)('rejects %j as invalid_date_format, naming the accepted form', (value) => {
    const err = failure({ pubStartDate: value, pubEndDate: '2026-11-02T00:00:00Z' });

    expect(err.code).toBe(JsonRpcErrorCode.ValidationError);
    expect(err.data).toEqual({ reason: 'invalid_date_format' });
    expect(err.message).toBe(
      `Invalid date for pubStartDate: "${value}". Expected ${ACCEPTED_FORM}.`,
    );
  });

  it.each(AXES)('names the malformed end on the $label axis', ({ start, end }) => {
    const err = failure({ [start]: '2026-11-01T00:00:00Z', [end]: '2026-11-02' });

    expect(err.data).toEqual({ reason: 'invalid_date_format' });
    expect(err.message).toBe(`Invalid date for ${end}: "2026-11-02". Expected ${ACCEPTED_FORM}.`);
  });

  it('names the start when both ends are malformed', () => {
    expect(failure({ pubStartDate: '2026-11-01', pubEndDate: '2026-11-02' }).message).toBe(
      `Invalid date for pubStartDate: "2026-11-01". Expected ${ACCEPTED_FORM}.`,
    );
  });
});

describe('span reading', () => {
  it.each(['America/Los_Angeles', 'Europe/Berlin'])(
    'reads an offset-less value as UTC under %s',
    async (zone) => {
      await inZone(zone, () => {
        // Exactly 120 days in UTC; read as local time it gains the hour autumn gives back.
        expect(
          resolveDateWindows(
            { pubStartDate: '2026-07-18T00:00:00', pubEndDate: '2026-11-15T00:00:00' },
            NOW,
          ).dates,
        ).toEqual({ pubStartDate: '2026-07-18T00:00:00', pubEndDate: '2026-11-15T00:00:00' });
        // 120 days + 30 min in UTC; read as local time it loses the hour spring takes.
        expect(
          failure({ pubStartDate: '2026-03-01T00:00:00', pubEndDate: '2026-06-29T00:30:00' }).data,
        ).toEqual({ reason: 'date_range_exceeds_max' });
      });
    },
  );

  it('honors offsets on both ends', () => {
    // 2026-07-18T00:00Z → 2026-11-15T00:00Z, exactly 120 days.
    expect(() =>
      resolveDateWindows(
        { pubStartDate: '2026-07-18T05:30:00+05:30', pubEndDate: '2026-11-14T19:00:00-05:00' },
        NOW,
      ),
    ).not.toThrow();
    expect(
      failure({
        pubStartDate: '2026-07-18T05:30:00+05:30',
        pubEndDate: '2026-11-14T19:00:01-05:00',
      }).data,
    ).toEqual({ reason: 'date_range_exceeds_max' });
    // 05:00Z start, 04:00Z end: inverted only once the offset is applied.
    expect(
      failure({ pubStartDate: '2026-11-01T00:00:00-05:00', pubEndDate: '2026-11-01T04:00:00Z' })
        .data,
    ).toEqual({ reason: 'date_range_inverted' });
  });

  it('reads case, minutes-only, and fraction forms as the same instant', () => {
    expect(() =>
      resolveDateWindows(
        { pubStartDate: '2026-11-01t00:00z', pubEndDate: '2026-11-01T00:00:00.000+00:00' },
        NOW,
      ),
    ).not.toThrow();
    // A fraction past milliseconds truncates, as Date truncates it: .9999 reads as .999.
    expect(() =>
      resolveDateWindows(
        { pubStartDate: '2026-11-01T00:00:00.9999Z', pubEndDate: '2026-11-01T00:00:00.999Z' },
        NOW,
      ),
    ).not.toThrow();
    expect(
      failure({ pubStartDate: '2026-11-01T00:00:00.9999Z', pubEndDate: '2026-11-01T00:00:00.998Z' })
        .data,
    ).toEqual({ reason: 'date_range_inverted' });
  });
});

describe.each(AXES)('the $label window contract', ({ days, start, end, label }) => {
  it('rejects the shorthand beside either explicit end, with an axis-specific recovery', () => {
    for (const explicit of [
      { [start]: '2026-11-01T00:00:00Z', [end]: '2026-11-02T00:00:00Z' },
      { [end]: '2026-11-02T00:00:00Z' },
      { [start]: '2026-11-01T00:00:00Z' },
    ]) {
      const err = failure({ [days]: 7, ...explicit });

      expect(err.code).toBe(JsonRpcErrorCode.ValidationError);
      expect(err.message).toBe(`${days} and ${start}/${end} are mutually exclusive.`);
      expect(err.data).toEqual({
        reason: 'mutually_exclusive_params',
        recovery: {
          hint: `Use either the convenience shorthand (${days}) or the explicit date range (${start} + ${end}), not both.`,
        },
      });
    }
  });

  it('requires both explicit ends', () => {
    const noEnd = failure({ [start]: '2026-11-01T00:00:00Z' });
    expect(noEnd.message).toBe(`${start} requires ${end}.`);
    expect(noEnd.data).toEqual({ reason: 'missing_date_pair' });

    const noStart = failure({ [end]: '2026-11-02T00:00:00Z' });
    expect(noStart.message).toBe(`${end} requires ${start}.`);
    expect(noStart.data).toEqual({ reason: 'missing_date_pair' });
  });

  it('rejects an end before its start', () => {
    const err = failure({ [start]: '2026-11-15T00:00:00Z', [end]: '2026-10-01T00:00:00Z' });

    expect(err.message).toBe(`${end} is before ${start} — the date range is inverted.`);
    expect(err.data).toEqual({ reason: 'date_range_inverted' });
  });

  it('passes exactly 120 days and a zero-length range, sending both unchanged', () => {
    for (const pair of [
      { [start]: '2026-07-18T00:00:00.000Z', [end]: '2026-11-15T00:00:00.000Z' },
      { [start]: '2026-11-01T00:00:00Z', [end]: '2026-11-01T00:00:00Z' },
    ]) {
      expect(resolveDateWindows(pair, NOW)).toEqual({
        dates: pair,
        datesClamped: [],
        shorthands: [],
      });
    }
  });

  it('rejects anything past 120 days, down to one millisecond', () => {
    for (const overrun of ['2026-11-15T00:00:01.000Z', '2026-11-15T00:00:00.001Z']) {
      const err = failure({ [start]: '2026-07-18T00:00:00.000Z', [end]: overrun });

      expect(err.message).toBe(`${label} date range spans 121 days; maximum is 120.`);
      expect(err.data).toEqual({ reason: 'date_range_exceeds_max' });
    }
  });

  it('expands the shorthand to exactly N × 24 h ending at call time', () => {
    expect(resolveDateWindows({ [days]: 7 }, NOW)).toEqual({
      dates: { [start]: '2026-11-08T20:00:00.000Z', [end]: '2026-11-15T20:00:00.000Z' },
      datesClamped: [],
      shorthands: [days],
    });
    expect(resolveDateWindows({ [days]: 120 }, NOW).dates).toEqual({
      [start]: '2026-07-18T20:00:00.000Z',
      [end]: '2026-11-15T20:00:00.000Z',
    });
  });

  it('clamps a shorthand over 120 to 120 days and reports it', () => {
    expect(resolveDateWindows({ [days]: 121 }, NOW)).toEqual({
      dates: { [start]: '2026-07-18T20:00:00.000Z', [end]: '2026-11-15T20:00:00.000Z' },
      datesClamped: [{ param: days, original: 121, clamped: 120 }],
      shorthands: [days],
    });
  });
});

describe('shorthand expansion', () => {
  it('returns an empty resolution when no date field is set', () => {
    expect(resolveDateWindows({}, NOW)).toEqual({ dates: {}, datesClamped: [], shorthands: [] });
  });

  it('ends every shorthand at one instant, floored to the second, and lists them in axis order', () => {
    const resolution = resolveDateWindows(
      {
        kevDays: 200,
        lastModStartDate: '2026-11-01T00:00:00Z',
        lastModEndDate: '2026-11-02T00:00:00Z',
        pubDays: 365,
      },
      NOW + 750,
    );

    expect(resolution).toEqual({
      dates: {
        pubStartDate: '2026-07-18T20:00:00.000Z',
        pubEndDate: '2026-11-15T20:00:00.000Z',
        lastModStartDate: '2026-11-01T00:00:00Z',
        lastModEndDate: '2026-11-02T00:00:00Z',
        kevStartDate: '2026-07-18T20:00:00.000Z',
        kevEndDate: '2026-11-15T20:00:00.000Z',
      },
      datesClamped: [
        { param: 'pubDays', original: 365, clamped: 120 },
        { param: 'kevDays', original: 200, clamped: 120 },
      ],
      shorthands: ['pubDays', 'kevDays'],
    });
  });

  /**
   * Local-calendar arithmetic made a 120-day shorthand 120 days ± 1 h whenever a clock change fell
   * inside it, and NVD rejects the long side. The expansion is UTC milliseconds now; each zone below
   * has a DST change inside at least one of these windows.
   */
  describe.each(['America/Los_Angeles', 'Europe/Berlin', 'Australia/Sydney'])(
    'under %s',
    (zone) => {
      it.each([
        ['2026-11-15T20:00:00.000Z', '2026-07-18T20:00:00.000Z'],
        ['2026-10-25T12:00:00.000Z', '2026-06-27T12:00:00.000Z'],
        ['2026-03-20T19:00:00.000Z', '2025-11-20T19:00:00.000Z'],
      ])('expands every 120-day shorthand ending %s to start at %s', async (now, start) => {
        await inZone(zone, () => {
          const { dates } = resolveDateWindows(
            { pubDays: 120, lastModDays: 120, kevDays: 120 },
            Date.parse(now),
          );

          expect(dates).toEqual({
            pubStartDate: start,
            pubEndDate: now,
            lastModStartDate: start,
            lastModEndDate: now,
            kevStartDate: start,
            kevEndDate: now,
          });
          expect(Date.parse(now) - Date.parse(start)).toBe(120 * DAY_MS);
        });
      });
    },
  );
});

describe('paging guidance (#67)', () => {
  it('ends a next-page notice with the echoed keys to send in place of each shorthand', () => {
    expect(windowReplayClause([], 0)).toBeUndefined();
    expect(windowReplayClause(['pubDays'], 0)).toBe(
      'send pubStartDate and pubEndDate from filtersApplied instead of pubDays, so the next page reads the same window',
    );
    expect(windowReplayClause(['lastModDays', 'kevDays'], 0)).toBe(
      'send lastModStartDate, lastModEndDate, kevStartDate, and kevEndDate from filtersApplied instead of lastModDays and kevDays, so the next page reads the same window',
    );
    expect(windowReplayClause(['pubDays', 'lastModDays', 'kevDays'], 0)).toBe(
      'send pubStartDate, pubEndDate, lastModStartDate, lastModEndDate, kevStartDate, and kevEndDate from filtersApplied instead of pubDays, lastModDays, and kevDays, so the next page reads the same window',
    );
  });

  it('leaves the replay to the re-expansion notice past offset 0, where filtersApplied holds this call’s window, not the first page’s', () => {
    expect(windowReplayClause(['pubDays'], 1)).toBeUndefined();
    expect(windowReplayClause(['lastModDays', 'kevDays'], 40)).toBeUndefined();
  });

  it('names only the shorthand axes when an explicit pair shares the page', () => {
    const { shorthands } = resolveDateWindows(
      { pubDays: 7, kevStartDate: '2026-10-01T00:00:00Z', kevEndDate: '2026-11-01T00:00:00Z' },
      NOW,
    );

    expect(windowReplayClause(shorthands, 0)).toBe(
      'send pubStartDate and pubEndDate from filtersApplied instead of pubDays, so the next page reads the same window',
    );
  });

  it('flags a shorthand window read past offset 0, and nothing else', () => {
    expect(windowReexpandedNotice([], 20)).toBeUndefined();
    expect(windowReexpandedNotice(['pubDays'], 0)).toBeUndefined();
    expect(windowReexpandedNotice(['kevDays'], 1)).toBe(
      'kevDays was expanded at call time, so the window in filtersApplied can differ from the one earlier pages read; to page one fixed window, send the dates echoed on the first page instead of kevDays.',
    );
    expect(windowReexpandedNotice(['pubDays', 'lastModDays', 'kevDays'], 40)).toBe(
      'pubDays, lastModDays, and kevDays were expanded at call time, so the window in filtersApplied can differ from the one earlier pages read; to page one fixed window, send the dates echoed on the first page instead of pubDays, lastModDays, and kevDays.',
    );
  });
});

describe('shared schema and trailer', () => {
  const schema = z.object(dateWindowInput);

  it('accepts a positive whole-day shorthand and rejects anything else', () => {
    expect(schema.safeParse({ kevDays: 1 }).success).toBe(true);
    for (const kevDays of [0, -1, 1.5, '7'])
      expect(schema.safeParse({ kevDays }).success).toBe(false);
  });

  it('renders one trailer note per clamped shorthand, and nothing without one', () => {
    expect(renderDatesClamped(undefined)).toBe('');
    expect(renderDatesClamped([])).toBe('');
    expect(
      renderDatesClamped([
        { param: 'pubDays', original: 200, clamped: 120 },
        { param: 'kevDays', original: 121, clamped: 120 },
      ]),
    ).toBe(
      '> **Note:** pubDays value 200 exceeded the 120-day maximum and was clamped to 120.\n> **Note:** kevDays value 121 exceeded the 120-day maximum and was clamped to 120.',
    );
  });
});

/**
 * Wiring on both tools that spread these fields: each resolver reason reaches the caller as a
 * declared failure carrying its recovery on both surfaces, before any request. One case per reason
 * per tool; the inputs behind each reason are tabled above.
 */
describe('both tools raise every window reason before any request', () => {
  const service = { searchCves: vi.fn(), auditCpe: vi.fn() };

  beforeEach(() => {
    vi.spyOn(nvdCveServiceModule, 'getNvdCveService').mockReturnValue(service as never);
    service.searchCves.mockReset();
    service.auditCpe.mockReset();
  });

  const TOOLS = [
    ['nvd_search_cves', (dates: DateWindowInput) => runToolContract(nvdSearchCves, dates)],
    [
      'nvd_audit_cpe',
      (dates: DateWindowInput) =>
        runToolContract(nvdAuditCpe, {
          cpeName: 'cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*',
          ...dates,
        }),
    ],
  ] as const;

  const REASONS: Array<[string, DateWindowInput, string]> = [
    [
      'mutually_exclusive_params',
      { kevDays: 7, kevEndDate: '2026-11-15T00:00:00.000Z' },
      'Use either the convenience shorthand (kevDays) or the explicit date range (kevStartDate + kevEndDate), not both.',
    ],
    [
      'missing_date_pair',
      { lastModStartDate: '2026-10-01T00:00:00.000Z' },
      'Provide both the start and end date',
    ],
    [
      'invalid_date_format',
      { pubStartDate: '2026-11-01', pubEndDate: '2026-11-02T00:00:00Z' },
      // The recovery's own tail: content[] escapes the brackets in the grammar both strings carry.
      'e.g. 2024-01-01T00:00:00.000Z; a value without an offset is read as UTC.',
    ],
    [
      'date_range_inverted',
      { pubStartDate: '2026-11-02T00:00:00Z', pubEndDate: '2026-11-01T00:00:00Z' },
      'Ensure the end date is after the start date.',
    ],
    [
      'date_range_exceeds_max',
      { kevStartDate: '2026-07-18T00:00:00.000Z', kevEndDate: '2026-11-15T00:00:01.000Z' },
      'Narrow the date range to 120 days or fewer',
    ],
  ];

  describe.each(TOOLS)('%s', (_tool, call) => {
    it.each(REASONS)(
      'raises %s with its recovery on both surfaces',
      async (reason, dates, hint) => {
        const result = await call(dates);
        const text = result.content
          .flatMap((block) => (block.type === 'text' ? [block.text] : []))
          .join('\n');

        expect(result.structuredContent).toMatchObject({
          error: {
            code: JsonRpcErrorCode.ValidationError,
            data: { reason, recovery: { hint: expect.stringContaining(hint) } },
          },
        });
        expect(text).toContain(hint);
        expect(service.searchCves).not.toHaveBeenCalled();
        expect(service.auditCpe).not.toHaveBeenCalled();
      },
    );
  });
});

/** Below Bun's regex mode switch near 80k characters; the digit runs carry the full 64× span. */
const BELOW_SWITCH = 80_000;
const FULL_SPAN = 320_000;

describe('cost on caller-sized date strings', { timeout: 0 }, () => {
  /**
   * Resolves `value` as a publication start, reporting whether it was accepted. Only the format
   * rejection reads as `false`; any other throw fails the test rather than passing as one.
   */
  function resolvesAsStart(value: string): boolean {
    try {
      resolveDateWindows({ pubStartDate: value, pubEndDate: '2026-11-02T00:00:00.000Z' }, NOW);
      return true;
    } catch (err) {
      if (err instanceof McpError && err.data?.reason === 'invalid_date_format') return false;
      throw err;
    }
  }

  it.each([
    [
      'a fraction digit run',
      (n: number) => `2026-11-01T00:00:00.${'7'.repeat(n)}Z`,
      false,
      FULL_SPAN,
    ],
    [
      'a fraction digit run with no closer',
      (n: number) => `2026-11-01T00:00:00.${'7'.repeat(n)}x`,
      false,
      FULL_SPAN,
    ],
    [
      'an offset with an overlong tail',
      (n: number) => `2026-11-01T00:00:00+05:${'0'.repeat(n)}`,
      false,
      BELOW_SWITCH,
    ],
    [
      'repeated date prefixes',
      (n: number) => '2026-11-01T'.repeat(Math.ceil(n / 11)),
      false,
      BELOW_SWITCH,
    ],
    [
      'a long line ending in a break',
      (n: number) => `${'§1 x'.repeat(n / 4)}\ny`,
      false,
      BELOW_SWITCH,
    ],
    ['breaks throughout', (n: number) => '  \r\n'.repeat(n / 4), false, BELOW_SWITCH],
  ] as const)('stays linear on %s', async (_shape, build, expected, maxSize) => {
    await expectLinearCost({
      build,
      maxSize,
      expected,
      run: resolvesAsStart,
      boundMicros: (size) => 1_000 + size / 20,
    });
  });
});
