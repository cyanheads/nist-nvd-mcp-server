/**
 * @fileoverview Index helpers for the test suite. `tests/` typechecks under
 * `noUncheckedIndexedAccess`, which types every element read as `T | undefined`. Optional
 * chaining would silence that but also weaken the assertion — `expect(rows[0]?.x).toBeUndefined()`
 * passes on an empty array. These read the element and fail loudly when it isn't there, so the
 * assertion that follows keeps testing what it was written to test.
 * @module tests/support/at
 */

/** Element at `index`, or a loud failure naming what the array actually held. */
export function at<T>(items: readonly T[] | undefined, index = 0): T {
  if (items === undefined) throw new Error('expected an array, got undefined');
  const value = items[index];
  if (value === undefined) {
    throw new Error(`expected an element at index ${index}; the array holds ${items.length}`);
  }
  return value;
}
