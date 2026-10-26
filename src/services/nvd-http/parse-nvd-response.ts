/**
 * @fileoverview Validate completed NVD envelopes outside transport retries.
 * @module services/nvd-http/parse-nvd-response
 */
import type { z } from '@cyanheads/mcp-ts-core';
import { serviceUnavailable } from '@cyanheads/mcp-ts-core/errors';

/** Throws a nonretryable upstream-data error without exposing the response payload. */
export function parseNvdResponse<T>(schema: z.ZodType<T>, value: unknown, endpoint: string): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw serviceUnavailable(
      'NVD API returned an invalid response.',
      { endpoint, reason: 'nvd_invalid_response', retryable: false },
      { cause: result.error },
    );
  }
  return result.data;
}
