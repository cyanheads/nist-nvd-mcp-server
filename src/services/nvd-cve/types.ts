/**
 * @fileoverview Domain types for the NVD CVE API 2.0 response shapes and normalized domain objects.
 * @module services/nvd-cve/types
 */

import { z } from '@cyanheads/mcp-ts-core';

const rawCvssMetricSchema = z.looseObject({
  baseSeverity: z.string().optional(),
  cvssData: z
    .looseObject({
      version: z.string().optional(),
      vectorString: z.string().optional(),
      baseScore: z.number().optional(),
      baseSeverity: z.string().optional(),
    })
    .optional(),
  exploitabilityScore: z.number().optional(),
  impactScore: z.number().optional(),
  source: z.string().optional(),
  type: z.string().optional(),
});

/** Raw CVSS metric; v2 severity can be beside cvssData instead of inside it. */
export type RawCvssMetric = z.infer<typeof rawCvssMetricSchema>;

/** SSVC assessments carry source outside the versioned assessment data. */
export const rawSsvcMetricsSchema = z.array(
  z.looseObject({
    source: z.string(),
    ssvcData: z.looseObject({
      role: z.string(),
      version: z.string(),
      timestamp: z.string().optional(),
      options: z.array(z.record(z.string(), z.union([z.string(), z.array(z.string())]))),
    }),
  }),
);

/** Current SSVC assessment with decision-point order and repeated keys preserved. */
export type SsvcAssessment = {
  source: string;
  role: string;
  version: string;
  timestamp?: string;
  decisionPoints: z.infer<typeof rawSsvcMetricsSchema>[number]['ssvcData']['options'];
};

/** Raw CVE item from the NVD API response. */
const rawCveItemSchema = z.looseObject({
  cisaActionDue: z.string().optional(),
  cisaExploitAdd: z.string().optional(),
  cisaRequiredAction: z.string().optional(),
  cisaVulnerabilityName: z.string().optional(),
  configurations: z
    .array(
      z.looseObject({
        operator: z.string().optional(),
        nodes: z
          .array(
            z.looseObject({
              operator: z.string().optional(),
              negate: z.boolean().optional(),
              cpeMatch: z
                .array(
                  z.looseObject({
                    vulnerable: z.boolean().optional(),
                    criteria: z.string().optional(),
                    versionStartIncluding: z.string().optional(),
                    versionStartExcluding: z.string().optional(),
                    versionEndIncluding: z.string().optional(),
                    versionEndExcluding: z.string().optional(),
                    matchCriteriaId: z.string().optional(),
                  }),
                )
                .optional(),
            }),
          )
          .optional(),
      }),
    )
    .optional(),
  descriptions: z
    .array(z.looseObject({ lang: z.string().optional(), value: z.string().optional() }))
    .optional(),
  id: z.string(),
  lastModified: z.string().optional(),
  metrics: z
    .looseObject({
      cvssMetricV2: z.array(rawCvssMetricSchema).optional(),
      cvssMetricV30: z.array(rawCvssMetricSchema).optional(),
      cvssMetricV31: z.array(rawCvssMetricSchema).optional(),
      cvssMetricV40: z.array(rawCvssMetricSchema).optional(),
    })
    .optional(),
  published: z.string().optional(),
  references: z
    .array(
      z.looseObject({
        url: z.string().optional(),
        source: z.string().optional(),
        tags: z.array(z.string()).optional(),
      }),
    )
    .optional(),
  sourceIdentifier: z.string().optional(),
  vulnStatus: z.string().optional(),
  weaknesses: z
    .array(
      z.looseObject({
        source: z.string().optional(),
        type: z.string().optional(),
        description: z
          .array(z.looseObject({ lang: z.string().optional(), value: z.string().optional() }))
          .optional(),
      }),
    )
    .optional(),
});

/** Validated CVE identity with optional upstream enrichment and unknown fields preserved. */
export type RawCveItem = z.infer<typeof rawCveItemSchema>;

/** Raw NVD CVE search response. */
export const rawCveResponseSchema = z.looseObject({
  format: z.string().optional(),
  resultsPerPage: z.number().optional(),
  startIndex: z.number().optional(),
  timestamp: z.string().optional(),
  totalResults: z.number(),
  version: z.string().optional(),
  vulnerabilities: z.array(z.looseObject({ cve: rawCveItemSchema })),
});

/** Parsed NVD CVE envelope. */
export type RawCveResponse = z.infer<typeof rawCveResponseSchema>;

/** Raw NVD CVE History response. */
export const rawCveHistoryResponseSchema = z.looseObject({
  cveChanges: z.array(
    z.looseObject({
      change: z
        .looseObject({
          cveId: z.string().optional(),
          eventName: z.string().optional(),
          cveChangeId: z.string().optional(),
          sourceIdentifier: z.string().optional(),
          created: z.string().optional(),
          details: z
            .array(
              z.looseObject({
                action: z.string().optional(),
                type: z.string().optional(),
                oldValue: z.unknown().optional(),
                newValue: z.unknown().optional(),
              }),
            )
            .optional(),
        })
        .optional(),
    }),
  ),
  resultsPerPage: z.number().optional(),
  startIndex: z.number().optional(),
  totalResults: z.number(),
});

/** Parsed history envelope; detail values retain structured upstream data. */
export type RawCveHistoryResponse = z.infer<typeof rawCveHistoryResponseSchema>;

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
  ssvc?: SsvcAssessment[];
  cisaKev?: CisaKev;
  /**
   * Upstream's `configurations[].nodes[]` with the group level hoisted away: one entry per node,
   * tagged with the index of the group it came from. Node boundaries are the applicability
   * semantics — a group's `AND` combines whole nodes, not individual criteria — so the node stays
   * the entry and `groupIndex` carries the membership a flattened group array would destroy.
   */
  configurationNodes: Array<{
    /** Zero-based index of the upstream group this node came from. Siblings share it. */
    groupIndex: number;
    /** Combines the group's sibling nodes — an `AND` means every node must match. */
    groupOperator?: string;
    /** Combines this node's own criteria. */
    nodeOperator?: string;
    /** This node's criteria, in upstream order. */
    cpeMatch: Array<{
      vulnerable: boolean;
      criteria: string;
      versionStartIncluding?: string;
      versionStartExcluding?: string;
      versionEndIncluding?: string;
      versionEndExcluding?: string;
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
