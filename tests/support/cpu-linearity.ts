/**
 * @fileoverview CPU-cost linearity harness for code that parses caller-sized strings. Shared by
 * the date-window and `cveIds` suites, which hold their parsers to linear cost on adversarial
 * shapes.
 * @module tests/support/cpu-linearity
 */

import { expect } from 'vitest';

const BASE_SIZE = 5_000;

/** Thread CPU microseconds per call of `run`, over `calls` back-to-back calls. */
async function cpuMicrosPerCall(run: () => unknown, calls: number): Promise<number> {
  const start = process.threadCpuUsage();
  for (let call = 0; call < calls; call += 1) await run();
  const used = process.threadCpuUsage(start);
  return (used.user + used.system) / calls;
}

export interface LinearCostCase<T> {
  /** The absolute ceiling, in CPU microseconds per call, at `size`. */
  boundMicros: (size: number) => number;
  /** Builds an input of about `size` characters. */
  build: (size: number) => string;
  /** The value `run` must return at every size, so a shape that stops being parsed fails loudly. */
  expected: T;
  /** Largest input size in characters; sizes double from 5k up to this. */
  maxSize: number;
  /** The code under test, called with one built input. */
  run: (value: string) => T | Promise<T>;
}

/**
 * Asserts `run(build(size))` costs CPU linear in `size` as it doubles from 5k to `maxSize`. Each
 * size is checked before the next is built, so a super-linear regression fails early instead of
 * stalling on the largest input. At each size the 5k baseline is timed again beside it over five
 * rounds in alternating order: the least per-call time must stay under `boundMicros`, and the
 * least growth over the baseline under 4× the size ratio (256 across 5k → 320k). Small inputs run
 * as a batch per measurement, since one call sits below the timer's resolution.
 */
export async function expectLinearCost<T>(c: LinearCostCase<T>): Promise<void> {
  const baseline = c.build(BASE_SIZE);
  expect(await c.run(baseline)).toBe(c.expected);
  const calls = (size: number) => Math.max(1, Math.round((64 * BASE_SIZE) / size));
  for (let size = BASE_SIZE * 2; size <= c.maxSize; size *= 2) {
    const value = c.build(size);
    expect(await c.run(value), `${size} characters, result`).toBe(c.expected);
    const timeBase = () => cpuMicrosPerCall(() => c.run(baseline), calls(BASE_SIZE));
    const timeSize = () => cpuMicrosPerCall(() => c.run(value), calls(size));
    let least = Number.POSITIVE_INFINITY;
    let leastGrowth = Number.POSITIVE_INFINITY;
    for (let round = 0; round < 5; round += 1) {
      let base: number;
      let atSize: number;
      if (round % 2 === 0) {
        base = await timeBase();
        atSize = await timeSize();
      } else {
        atSize = await timeSize();
        base = await timeBase();
      }
      least = Math.min(least, atSize);
      leastGrowth = Math.min(leastGrowth, atSize / Math.max(base, 0.1));
    }
    expect(least, `${size} characters, µs per call`).toBeLessThan(c.boundMicros(size));
    expect(leastGrowth, `${size} characters, growth over 5k`).toBeLessThan((4 * size) / BASE_SIZE);
  }
}
