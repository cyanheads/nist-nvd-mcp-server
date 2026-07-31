/**
 * @fileoverview Domain types for the NVD CVE API 2.0 response shapes and normalized domain objects.
 * @module services/nvd-cve/types
 */

/**
 * Raw CVSS metric from the NVD API response.
 *
 * `baseSeverity` appears at one of two depths depending on the metric array: `cvssMetricV2`
 * carries it here, as a sibling of `cvssData`, while `cvssMetricV30`/`V31`/`V40` carry it inside
 * `cvssData`. Both are declared so neither shape has to be inferred from the score.
 */
export interface RawCvssMetric {
  baseSeverity?: string;
  cvssData?: {
    version?: string;
    vectorString?: string;
    baseScore?: number;
    baseSeverity?: string;
  };
  exploitabilityScore?: number;
  impactScore?: number;
  source?: string;
  type?: string;
}

/** Raw CVE item from the NVD API response. */
export interface RawCveItem {
  cisaActionDue?: string;
  cisaExploitAdd?: string;
  cisaRequiredAction?: string;
  cisaVulnerabilityName?: string;
  configurations?: Array<{
    /** Combines this group's sibling nodes — an `AND` means every node must match. */
    operator?: string;
    nodes?: Array<{
      operator?: string;
      negate?: boolean;
      cpeMatch?: Array<{
        vulnerable?: boolean;
        criteria?: string;
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
        matchCriteriaId?: string;
      }>;
    }>;
  }>;
  descriptions?: Array<{ lang?: string; value?: string }>;
  id?: string;
  lastModified?: string;
  metrics?: {
    cvssMetricV2?: RawCvssMetric[];
    cvssMetricV30?: RawCvssMetric[];
    cvssMetricV31?: RawCvssMetric[];
    cvssMetricV40?: RawCvssMetric[];
  };
  published?: string;
  references?: Array<{ url?: string; source?: string; tags?: string[] }>;
  sourceIdentifier?: string;
  vulnStatus?: string;
  weaknesses?: Array<{
    source?: string;
    type?: string;
    description?: Array<{ lang?: string; value?: string }>;
  }>;
}

/** Raw NVD CVE search response. */
export interface RawCveResponse {
  format?: string;
  resultsPerPage?: number;
  startIndex?: number;
  timestamp?: string;
  totalResults?: number;
  version?: string;
  vulnerabilities?: Array<{ cve?: RawCveItem }>;
}

/** Raw NVD CVE History response. */
export interface RawCveHistoryResponse {
  cveChanges?: Array<{
    change?: {
      cveId?: string;
      eventName?: string;
      cveChangeId?: string;
      sourceIdentifier?: string;
      created?: string;
      /**
       * `oldValue`/`newValue` are usually strings, but NVD emits an array for `Affected` details
       * and an object for `SSVC` details — normalization serializes those to JSON.
       */
      details?: Array<{
        action?: string;
        type?: string;
        oldValue?: unknown;
        newValue?: unknown;
      }>;
    };
  }>;
  resultsPerPage?: number;
  startIndex?: number;
  totalResults?: number;
}

/** Normalized CVSS score entry. */
export interface CvssScore {
  /** Base score (0.0–10.0). */
  baseScore: number;
  /** Severity label (e.g., "CRITICAL", "HIGH", "MEDIUM", "LOW"). */
  severity: string;
  /** Score source type ("Primary" = NVD, "Secondary" = CNA). */
  sourceType: string;
  /** CVSS vector string. */
  vectorString?: string;
  /** CVSS version (e.g., "2.0", "3.1", "4.0"). */
  version: string;
}

/** Normalized top severity derived from all available CVSS scores. */
export interface TopSeverity {
  /** Which CVSS version this came from. */
  fromVersion: string;
  /** Severity label. */
  label: string;
  /** Base score. */
  score: number;
}

/** Normalized CISA KEV fields — only present when CVE is in the KEV catalog. */
export interface CisaKev {
  actionDueDate: string;
  exploitAddDate: string;
  requiredAction: string;
  vulnerabilityName: string;
}

/**
 * Full CVE record (normalized from raw API response).
 *
 * Declared as a type alias, not an interface: both record shapes are returned straight from tool
 * handlers whose output schemas allow unknown extra keys, and only an alias carries the implicit
 * index signature that assignment needs — an interface would force a cast and lose the field check.
 */
export type CveRecord = {
  cisaKev?: CisaKev;
  configurations: Array<{
    /** Combines this group's sibling nodes — an `AND` means every node must match. */
    operator?: string;
    nodes: Array<{
      /** Combines this node's own cpeMatch entries. */
      operator?: string;
      cpeMatch: Array<{
        vulnerable: boolean;
        criteria: string;
        versionStartIncluding?: string;
        versionStartExcluding?: string;
        versionEndIncluding?: string;
        versionEndExcluding?: string;
      }>;
    }>;
  }>;
  cveId: string;
  cvssScores: CvssScore[];
  descriptions: Array<{ lang: string; value: string }>;
  lastModified: string;
  published: string;
  references?: Array<{ url: string; source?: string; tags?: string[] }>;
  severity?: TopSeverity;
  vulnStatus: string;
  weaknesses: Array<{ source: string; cweIds: string[] }>;
};

/** Brief CVE record for search results and bulk lookups. See `CveRecord` on the alias form. */
export type BriefCveRecord = {
  cisaVulnerabilityName?: string;
  cveId: string;
  /**
   * Opening slice of the English description (falling back to whatever prose exists), truncated
   * so a search page stays cheap. Absent when the record carries no description at all.
   */
  description?: string;
  /**
   * Severity at the CVSS version a `severity` filter selected on, when that disagrees with the
   * cross-version `severity` headline. Absent when no filter was applied or the two agree.
   */
  filteredSeverity?: TopSeverity;
  published: string;
  severity?: TopSeverity;
  vulnStatus: string;
};

/** CVE change event from the history API. */
export interface CveChangeEvent {
  changeDate: string;
  /** Values are always flat strings — structured upstream values arrive JSON-serialized. */
  details: Array<{
    action?: string;
    type?: string;
    oldValue?: string;
    newValue?: string;
  }>;
  eventName?: string;
}
