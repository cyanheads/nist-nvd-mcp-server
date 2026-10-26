/** @fileoverview Shared read-limit policy and bounded-label clamp telemetry. */
import { type Context, z } from '@cyanheads/mcp-ts-core';
import { createCounter } from '@cyanheads/mcp-ts-core/utils';
import { getServerConfig } from '@/config/server-config.js';

type ReadTool =
  | 'nvd_search_cves'
  | 'nvd_audit_cpe'
  | 'nvd_get_cve_history'
  | 'nvd_search_cpes'
  | 'nvd_get_cve';
let clampCounter: ReturnType<typeof createCounter> | undefined;

/** Advertises a maximum only when configured to reject oversized requests. */
export function readLimitSchema(maximum: number, defaultValue: number) {
  const schema = z.number().int().min(1);
  return (getServerConfig().clampLimits ? schema : schema.max(maximum)).default(defaultValue);
}

/** Counts are absent for requests that already fit the upstream limit. */
export const readLimitEnrichment = {
  requestedLimit: z
    .number()
    .optional()
    .describe('Requested page size or ID count before clamping.'),
  effectiveLimit: z.number().optional().describe('Page size or ID count used after clamping.'),
};

/** Reports a clamp once; callers combine its notice with their pagination guidance. */
export function applyReadLimit(requested: number, maximum: number, tool: ReadTool, ctx: Context) {
  if (!getServerConfig().clampLimits || requested <= maximum) return { limit: requested };
  ctx.enrich({ requestedLimit: requested, effectiveLimit: maximum });
  ctx.log.notice('Read limit clamped', {
    tool,
    requestedLimit: requested,
    effectiveLimit: maximum,
  });
  clampCounter ??= createCounter(
    'nvd.read_limit.clamped',
    'Read requests clamped to the upstream limit',
  );
  clampCounter.add(1, { tool });
  return { limit: maximum, notice: `Requested limit ${requested} was clamped to ${maximum}.` };
}
