/**
 * @fileoverview Shared date-window policy for NVD's three CVE date axes — publication,
 * last-modified, and the date CISA added a CVE to the KEV catalog. Owns the input fields, the
 * resolver that validates explicit ranges and expands the day-count shorthands, the date echo and
 * `datesClamped` enrichment, the `filtersApplied` trailer render, and the paging guidance for a
 * window a shorthand set. Each tool that
 * spreads these fields declares the resolver's five failure reasons inline with
 * `thrownBy: 'service'`.
 * @module src/mcp-server/tools/date-windows
 */

import { z } from '@cyanheads/mcp-ts-core';
import { validationError } from '@cyanheads/mcp-ts-core/errors';
import { escapeMarkdownInline } from '@cyanheads/mcp-ts-core/utils';

/** NVD rejects a date range longer than this on every axis; exactly 120 days passes. */
const MAX_WINDOW_DAYS = 120;

const DAY_MS = 86_400_000;

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

type Axis = (typeof AXES)[number];

/** A day-count shorthand: `pubDays`, `lastModDays`, or `kevDays`. */
export type DateShorthand = Axis['days'];

/** One end of an explicit range, `pubStartDate` through `kevEndDate`. */
export type DateField = Axis['start'] | Axis['end'];

/** The accepted date form, as every date field description and `invalid_date_format` names it. */
const DATE_FORM =
  'YYYY-MM-DDThh:mm[:ss[.fraction]] with an optional Z or ±hh:mm offset, e.g. 2024-01-01T00:00:00.000Z';

/** NVD's widest offset: `+18:00` answers 200 and `+18:01` a 404; the negative side mirrors it. */
const MAX_OFFSET_MINUTES = 18 * 60;

/**
 * The date-time forms NVD answers, measured against the live API: a four-digit or signed six-digit
 * year, `T`, hours and minutes, optional seconds with an optional fraction of at most nine digits,
 * then an optional `Z` or `±hh:mm` offset of at most {@link MAX_OFFSET_MINUTES}, `T` and `Z` in
 * either case. NVD answers a date alone, a space separator, a colonless offset, a fraction past
 * nanoseconds, and every non-ISO shape with a 404.
 */
const DATE_TIME =
  /^([+-]\d{6}|\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,9}))?)?(?:Z|([+-])(\d{2}):(\d{2}))?$/i;

/** Input fields for the three date axes, spread into a tool's `input`. */
export const dateWindowInput = {
  pubDays: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      'CVEs published in the last N days: expanded to pubStartDate/pubEndDate spanning exactly N × 24 hours up to call time (max 120; values over 120 are clamped). Mutually exclusive with pubStartDate/pubEndDate. Each call re-expands it, so page with the dates echoed in filtersApplied.',
    ),
  pubStartDate: z
    .string()
    .optional()
    .describe(
      `Publication range start, as ${DATE_FORM}; a value without an offset is read as UTC. Both pubStartDate and pubEndDate required together, at most 120 days apart. Mutually exclusive with pubDays.`,
    ),
  pubEndDate: z
    .string()
    .optional()
    .describe(
      'Publication range end, in the same form as pubStartDate. Both pubStartDate and pubEndDate required together.',
    ),
  lastModDays: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      'CVEs last modified in the last N days: expanded to lastModStartDate/lastModEndDate spanning exactly N × 24 hours up to call time (max 120; values over 120 are clamped). Mutually exclusive with lastModStartDate/lastModEndDate. Each call re-expands it, so page with the dates echoed in filtersApplied.',
    ),
  lastModStartDate: z
    .string()
    .optional()
    .describe(
      `Last-modified range start, as ${DATE_FORM}; a value without an offset is read as UTC. Both lastModStartDate and lastModEndDate required together, at most 120 days apart. Mutually exclusive with lastModDays.`,
    ),
  lastModEndDate: z
    .string()
    .optional()
    .describe(
      'Last-modified range end, in the same form as lastModStartDate. Both lastModStartDate and lastModEndDate required together.',
    ),
  kevDays: z
    .number()
    .int()
    .positive()
    .optional()
    .describe(
      'CVEs CISA added to the Known Exploited Vulnerabilities catalog in the last N days: expanded to kevStartDate/kevEndDate spanning exactly N × 24 hours up to call time (max 120; values over 120 are clamped). Returns only catalog members. Mutually exclusive with kevStartDate/kevEndDate. Each call re-expands it, so page with the dates echoed in filtersApplied.',
    ),
  kevStartDate: z
    .string()
    .optional()
    .describe(
      `Start of the window in which CISA added the CVE to the KEV catalog, as ${DATE_FORM}; a value without an offset is read as UTC. Both kevStartDate and kevEndDate required together, at most 120 days apart. Returns only catalog members. Mutually exclusive with kevDays.`,
    ),
  kevEndDate: z
    .string()
    .optional()
    .describe(
      'End of the KEV-addition window, in the same form as kevStartDate. Both kevStartDate and kevEndDate required together.',
    ),
};

/** The effective date fields a tool echoes in `filtersApplied`, spread into its schema. */
export const dateWindowEcho = {
  pubStartDate: z.string().optional().describe('Effective publication range start sent to NVD.'),
  pubEndDate: z.string().optional().describe('Effective publication range end sent to NVD.'),
  lastModStartDate: z
    .string()
    .optional()
    .describe('Effective last-modified range start sent to NVD.'),
  lastModEndDate: z.string().optional().describe('Effective last-modified range end sent to NVD.'),
  kevStartDate: z.string().optional().describe('Effective KEV-addition window start sent to NVD.'),
  kevEndDate: z.string().optional().describe('Effective KEV-addition window end sent to NVD.'),
};

/** The `datesClamped` enrichment field, spread into a tool's `enrichment`. */
export const dateWindowEnrichment = {
  datesClamped: z
    .array(
      z
        .object({
          param: z
            .string()
            .describe('The shorthand that was clamped (pubDays, lastModDays, or kevDays).'),
          original: z.number().describe('The original value supplied.'),
          clamped: z.number().describe('The clamped value used (max 120).'),
        })
        .describe('A single clamping event for one convenience date parameter.'),
    )
    .optional()
    .describe(
      'Entries for any pubDays, lastModDays, or kevDays value that exceeded 120 and was clamped. Absent when no clamping occurred.',
    ),
};

/** One shorthand reduced to the 120-day maximum. */
export interface DateClamp {
  clamped: number;
  original: number;
  param: DateShorthand;
}

/** `enrichmentTrailer` renderer for `datesClamped`: one note per clamped shorthand. */
export function renderDatesClamped(
  clamped: readonly { clamped: number; original: number; param: string }[] | undefined,
): string {
  return (
    clamped
      ?.map(
        (c) =>
          `> **Note:** ${c.param} value ${c.original} exceeded the 120-day maximum and was clamped to ${c.clamped}.`,
      )
      .join('\n') ?? ''
  );
}

/** `enrichmentTrailer` renderer for `filtersApplied`: one `key=value` list, values escaped. */
export function renderFiltersApplied(filters: Record<string, unknown> | undefined): string {
  return filters
    ? `**Filters applied:** ${Object.entries(filters)
        .map(([key, value]) => `${key}=${escapeMarkdownInline(String(value))}`)
        .join(', ')}`
    : '';
}

/** The date fields of a tool's input: blank strings already removed. */
export type DateWindowInput = {
  [K in keyof typeof dateWindowInput]?: z.output<(typeof dateWindowInput)[K]>;
};

/** Effective dates for the axes in use, keyed as NVD's parameters are. */
export type DateWindowDates = Partial<Record<DateField, string>>;

export interface DateWindowResolution {
  /** The pairs to send to NVD and echo in `filtersApplied`: explicit values unchanged, shorthands expanded. */
  dates: DateWindowDates;
  /** One entry per shorthand over 120 days. */
  datesClamped: DateClamp[];
  /** Shorthands that set a window at call time, in axis order. */
  shorthands: DateShorthand[];
}

/**
 * Validates every explicit range in `input` and expands each shorthand to a window ending at
 * `nowMs` (read once per call by the caller, so every axis ends at the same instant). Arithmetic
 * is UTC milliseconds, so a shorthand spans exactly N × 24 h whatever the server's time zone.
 *
 * Throws `validationError` with `data.reason`, before any request: `mutually_exclusive_params`
 * (with an explicit, axis-specific recovery hint), `missing_date_pair`, `invalid_date_format`,
 * `date_range_inverted`, or `date_range_exceeds_max`.
 */
export function resolveDateWindows(input: DateWindowInput, nowMs: number): DateWindowResolution {
  // Whole seconds: flooring the shared end keeps both ends of a shorthand on `.000`.
  const windowEndMs = Math.floor(nowMs / 1000) * 1000;
  const resolution: DateWindowResolution = { dates: {}, datesClamped: [], shorthands: [] };

  for (const axis of AXES) {
    const days = input[axis.days];
    const start = input[axis.start];
    const end = input[axis.end];

    if (days !== undefined) {
      if (start !== undefined || end !== undefined) {
        throw validationError(
          `${axis.days} and ${axis.start}/${axis.end} are mutually exclusive.`,
          {
            reason: 'mutually_exclusive_params',
            recovery: {
              hint: `Use either the convenience shorthand (${axis.days}) or the explicit date range (${axis.start} + ${axis.end}), not both.`,
            },
          },
        );
      }
      const span = Math.min(days, MAX_WINDOW_DAYS);
      if (span < days) {
        resolution.datesClamped.push({ param: axis.days, original: days, clamped: span });
      }
      resolution.dates[axis.start] = new Date(windowEndMs - span * DAY_MS).toISOString();
      resolution.dates[axis.end] = new Date(windowEndMs).toISOString();
      resolution.shorthands.push(axis.days);
      continue;
    }

    if (start === undefined && end === undefined) continue;
    if (end === undefined) {
      throw validationError(`${axis.start} requires ${axis.end}.`, { reason: 'missing_date_pair' });
    }
    if (start === undefined) {
      throw validationError(`${axis.end} requires ${axis.start}.`, { reason: 'missing_date_pair' });
    }

    const startMs = epochMs(axis.start, start);
    const spanMs = epochMs(axis.end, end) - startMs;
    if (spanMs < 0) {
      throw validationError(`${axis.end} is before ${axis.start} — the date range is inverted.`, {
        reason: 'date_range_inverted',
      });
    }
    if (spanMs > MAX_WINDOW_DAYS * DAY_MS) {
      throw validationError(
        `${axis.label} date range spans ${Math.ceil(spanMs / DAY_MS)} days; maximum is 120.`,
        { reason: 'date_range_exceeds_max' },
      );
    }
    resolution.dates[axis.start] = start;
    resolution.dates[axis.end] = end;
  }

  return resolution;
}

/**
 * Epoch milliseconds of `value`, the instant NVD reads it as: a value without an offset is UTC.
 * Throws `invalid_date_format` for anything outside {@link DATE_TIME} or off the calendar.
 */
function epochMs(field: DateField, value: string): number {
  const ms = parseDateTime(value);
  if (ms === undefined) {
    throw validationError(`Invalid date for ${field}: "${value}". Expected ${DATE_FORM}.`, {
      reason: 'invalid_date_format',
    });
  }
  return ms;
}

function parseDateTime(value: string): number | undefined {
  const match = DATE_TIME.exec(value);
  if (!match) return;
  const [
    ,
    year = '',
    month = '',
    day = '',
    hour = '',
    minute = '',
    second = '0',
    fraction = '',
    sign,
    offsetHour = '0',
    offsetMinute = '0',
  ] = match;
  // ECMAScript and ISO 8601 both refuse a negative year zero.
  if (year === '-000000') return;
  if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) return;
  const offsetMinutes = Number(offsetHour) * 60 + Number(offsetMinute);
  if (Number(offsetMinute) > 59 || offsetMinutes > MAX_OFFSET_MINUTES) return;

  const date = new Date(0);
  date.setUTCFullYear(Number(year), Number(month) - 1, Number(day));
  // A day the month lacks (February 30) rolls into the next month; NVD rejects it.
  if (date.getUTCMonth() !== Number(month) - 1 || date.getUTCDate() !== Number(day)) return;
  // Truncated to whole milliseconds, as `Date` truncates a longer fraction.
  const millis = Number(fraction.slice(0, 3).padEnd(3, '0'));
  date.setUTCHours(Number(hour), Number(minute), Number(second), millis);

  const offsetMs = offsetMinutes * 60_000;
  return date.getTime() + (sign === '-' ? offsetMs : -offsetMs);
}

/** `a`, `a and b`, `a, b, and c`. */
function listOf(items: readonly string[]): string {
  return items.length <= 2
    ? items.join(' and ')
    : `${items.slice(0, -1).join(', ')}, and ${items.at(-1)}`;
}

/**
 * The clause that ends a next-page notice when the page's window came from a shorthand: a
 * shorthand re-expands on every call, so offset paging over it skips or repeats records unless the
 * next page sends the echoed dates instead. Undefined when every window was explicit, and past
 * offset 0, where filtersApplied holds this call's re-expanded window rather than the first page's
 * and {@link windowReexpandedNotice} names the dates to send.
 */
export function windowReplayClause(
  shorthands: readonly DateShorthand[],
  offset: number,
): string | undefined {
  if (shorthands.length === 0 || offset > 0) return;
  const keys = AXES.filter((axis) => shorthands.includes(axis.days)).flatMap((axis) => [
    axis.start,
    axis.end,
  ]);
  return `send ${listOf(keys)} from filtersApplied instead of ${listOf(shorthands)}, so the next page reads the same window`;
}

/**
 * Notice for a shorthand window read past offset 0, where this call's expansion may not be the
 * window the caller's earlier pages read. Undefined at offset 0 or when every window was explicit.
 */
export function windowReexpandedNotice(
  shorthands: readonly DateShorthand[],
  offset: number,
): string | undefined {
  if (shorthands.length === 0 || offset === 0) return;
  const named = listOf(shorthands);
  return `${named} ${shorthands.length === 1 ? 'was' : 'were'} expanded at call time, so the window in filtersApplied can differ from the one earlier pages read; to page one fixed window, send the dates echoed on the first page instead of ${named}.`;
}
