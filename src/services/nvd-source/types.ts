/**
 * @fileoverview Raw response shapes for the NVD source dictionary API (`/rest/json/source/2.0`).
 * @module services/nvd-source/types
 */

import { z } from '@cyanheads/mcp-ts-core';

const rawNvdSourceSchema = z.looseObject({
  contactEmail: z.string().optional(),
  name: z.string().optional(),
  sourceIdentifiers: z.array(z.string()).optional(),
});

/** One contributor's optional metadata and source identifiers. */
export type RawNvdSource = z.infer<typeof rawNvdSourceSchema>;

/** Raw NVD source dictionary response. */
export const rawNvdSourceResponseSchema = z.looseObject({
  resultsPerPage: z.number().optional(),
  sources: z.array(rawNvdSourceSchema),
  startIndex: z.number().optional(),
  totalResults: z.number(),
});

/** Parsed source dictionary envelope. */
export type RawNvdSourceResponse = z.infer<typeof rawNvdSourceResponseSchema>;
