/**
 * @fileoverview Raw response shapes for the NVD source dictionary API (`/rest/json/source/2.0`).
 * @module services/nvd-source/types
 */

/** One contributor entry from the NVD source dictionary. */
export interface RawNvdSource {
  contactEmail?: string;
  name?: string;
  /** Every identifier NVD attributes to this contributor — opaque GUIDs alongside email forms. */
  sourceIdentifiers?: string[];
}

/** Raw NVD source dictionary response. */
export interface RawNvdSourceResponse {
  resultsPerPage?: number;
  sources?: RawNvdSource[];
  startIndex?: number;
  totalResults?: number;
}
