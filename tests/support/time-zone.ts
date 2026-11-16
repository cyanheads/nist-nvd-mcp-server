/**
 * @fileoverview Runs a test body under a named process time zone. Test files run in their own
 * forked process, so the change never reaches another file.
 * @module tests/support/time-zone
 */

import { expect } from 'vitest';

/**
 * Runs `body` with `process.env.TZ` set to `zone`, then restores the previous zone. Checks first
 * that the zone took effect, since a runtime that ignored the assignment would leave the test
 * passing vacuously in UTC — `zone` must observe a non-zero offset on 2026-07-01.
 */
export async function inZone<T>(zone: string, body: () => T | Promise<T>): Promise<T> {
  const previous = process.env.TZ;
  process.env.TZ = zone;
  try {
    expect(new Date('2026-07-01T00:00:00.000Z').getTimezoneOffset()).not.toBe(0);
    return await body();
  } finally {
    if (previous === undefined) delete process.env.TZ;
    else process.env.TZ = previous;
  }
}
