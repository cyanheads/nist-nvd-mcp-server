/**
 * @fileoverview Domain types for the NVD CPE API 2.0 response shapes and normalized domain objects.
 * @module services/nvd-cpe/types
 */

/** Raw CPE item from the NVD API response. */
export interface RawCpeItem {
  cpeName?: string;
  cpeNameId?: string;
  created?: string;
  deprecated?: boolean;
  deprecatedBy?: Array<{ cpeName?: string; cpeNameId?: string }>;
  lastModified?: string;
  titles?: Array<{ title?: string; lang?: string }>;
}

/** Raw NVD CPE search response. */
export interface RawCpeResponse {
  format?: string;
  products?: Array<{ cpe?: RawCpeItem }>;
  resultsPerPage?: number;
  startIndex?: number;
  timestamp?: string;
  totalResults?: number;
  version?: string;
}

/** Normalized CPE record. */
export interface CpeRecord {
  cpeName: string;
  deprecated: boolean;
  deprecatedBy?: string[];
  lastModified?: string;
  title?: string;
}
