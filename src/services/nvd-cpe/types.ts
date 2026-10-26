/**
 * @fileoverview Domain types for the NVD CPE API 2.0 response shapes and normalized domain objects.
 * @module services/nvd-cpe/types
 */

import { z } from '@cyanheads/mcp-ts-core';

const rawCpeItemSchema = z.looseObject({
  cpeName: z.string().optional(),
  cpeNameId: z.string().optional(),
  created: z.string().optional(),
  deprecated: z.boolean().optional(),
  deprecatedBy: z
    .array(z.looseObject({ cpeName: z.string().optional(), cpeNameId: z.string().optional() }))
    .optional(),
  lastModified: z.string().optional(),
  titles: z
    .array(z.looseObject({ title: z.string().optional(), lang: z.string().optional() }))
    .optional(),
});

/** Raw CPE item with optional fields and unknown upstream additions preserved. */
export type RawCpeItem = z.infer<typeof rawCpeItemSchema>;

/** Raw NVD CPE search response. */
export const rawCpeResponseSchema = z.looseObject({
  format: z.string().optional(),
  products: z.array(z.looseObject({ cpe: rawCpeItemSchema.optional() })),
  resultsPerPage: z.number().optional(),
  startIndex: z.number().optional(),
  timestamp: z.string().optional(),
  totalResults: z.number(),
  version: z.string().optional(),
});

/** Parsed NVD CPE envelope. */
export type RawCpeResponse = z.infer<typeof rawCpeResponseSchema>;

/** Normalized CPE record. */
export interface CpeRecord {
  cpeName: string;
  deprecated: boolean;
  deprecatedBy?: string[];
  lastModified?: string;
  title?: string;
}
