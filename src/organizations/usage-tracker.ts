/**
 * @file usage-tracker.ts
 * @module src/organizations
 *
 * Fire-and-forget per-org daily usage analytics (M12G).
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 * Only aggregate counts and numeric risk scores are stored.
 * No raw prompts, PII values, secrets, entity strings, or detector evidence
 * may enter this table. The function signature enforces this: only primitive
 * scalars are accepted.
 *
 * ── Design ───────────────────────────────────────────────────────────────────
 * Follows the same fire-and-forget pattern as logSecurityEvent() in
 * audit-logger.ts — the function is synchronous from the caller's perspective
 * and MUST NOT block the request path.
 */

import { sql } from "kysely";
import { getConfig } from "../config";
import { createLogDatabase, type LogKysely, migrateLogDatabase } from "../logging/db";

// ── Singleton ─────────────────────────────────────────────────────────────────

let defaultDbInstance: LogKysely | null = null;
let defaultDbReady: Promise<void> | null = null;

function getDb(customDb?: LogKysely): { db: LogKysely; ready: Promise<void> } {
  if (customDb) {
    return { db: customDb, ready: Promise.resolve() };
  }
  if (!defaultDbInstance) {
    const config = getConfig();
    const { db, driver } = createLogDatabase(config);
    defaultDbInstance = db;
    defaultDbReady = migrateLogDatabase(db, driver);
  }
  return { db: defaultDbInstance, ready: defaultDbReady! };
}

// ── Types ─────────────────────────────────────────────────────────────────────

export interface OrgUsageDay {
  organizationId: string;
  date: string; // YYYY-MM-DD UTC
  totalRequests: number;
  allowedRequests: number;
  maskedRequests: number;
  blockedRequests: number;
  totalTokens: number | null;
  avgRiskScore: number | null;
}

// ── Internal async implementation ─────────────────────────────────────────────

async function recordOrgUsageAsync(
  db: LogKysely,
  ready: Promise<void>,
  orgId: string,
  decision: "allow" | "mask" | "block",
  tokens?: number,
  riskScore?: number,
): Promise<void> {
  await ready;

  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD UTC
  const now = new Date().toISOString();

  const isAllow = decision === "allow" ? 1 : 0;
  const isMask = decision === "mask" ? 1 : 0;
  const isBlock = decision === "block" ? 1 : 0;

  // Upsert: insert new row or atomically increment existing counters.
  // SQLite ON CONFLICT DO UPDATE uses excluded.* to reference the proposed values.
  await sql`
    INSERT INTO tenant_usage_daily (
      organization_id, date,
      total_requests, allowed_requests, masked_requests, blocked_requests,
      total_tokens, avg_risk_score,
      created_at, updated_at
    )
    VALUES (
      ${orgId}, ${today},
      1, ${isAllow}, ${isMask}, ${isBlock},
      ${tokens ?? null},
      ${riskScore ?? null},
      ${now}, ${now}
    )
    ON CONFLICT (organization_id, date) DO UPDATE SET
      total_requests   = tenant_usage_daily.total_requests + 1,
      allowed_requests = tenant_usage_daily.allowed_requests + ${isAllow},
      masked_requests  = tenant_usage_daily.masked_requests  + ${isMask},
      blocked_requests = tenant_usage_daily.blocked_requests + ${isBlock},
      total_tokens     = CASE
        WHEN ${tokens ?? null} IS NULL THEN tenant_usage_daily.total_tokens
        ELSE COALESCE(tenant_usage_daily.total_tokens, 0) + ${tokens ?? 0}
      END,
      avg_risk_score = CASE
        WHEN ${riskScore ?? null} IS NULL THEN tenant_usage_daily.avg_risk_score
        ELSE (
          COALESCE(tenant_usage_daily.avg_risk_score, 0) *
            (tenant_usage_daily.total_requests)
          + ${riskScore ?? 0}
        ) / (tenant_usage_daily.total_requests + 1)
      END,
      updated_at = ${now}
  `.execute(db);
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Record one request's outcome in the organization's daily usage aggregate.
 *
 * Fire-and-forget: this function is synchronous from the caller's perspective.
 * Errors are silently swallowed and logged to stderr — never thrown to the
 * request path.
 *
 * @param orgId    - Organization ID from JWT / API key context.
 * @param decision - Policy engine decision for this request.
 * @param tokens   - Total tokens consumed (prompt + completion). Optional.
 * @param riskScore - Numeric risk score (0–100). Optional.
 * @param customDb  - Injected DB for testing. Omit in production.
 */
export function trackOrgUsage(
  orgId: string,
  decision: "allow" | "mask" | "block",
  tokens?: number,
  riskScore?: number,
  customDb?: LogKysely,
): void {
  const { db, ready } = getDb(customDb);
  recordOrgUsageAsync(db, ready, orgId, decision, tokens, riskScore).catch((err: unknown) => {
    console.error("[UsageTracker] Failed to record org usage:", err);
  });
}

/**
 * Query the daily usage aggregates for an organization.
 * Returns rows ordered by date descending.
 *
 * @param orgId     - Organization to query. Non-admin callers must match their JWT org.
 * @param days      - Number of recent days to return (default 30).
 * @param customDb  - Injected DB for testing.
 */
export async function getOrgUsage(
  orgId: string,
  days = 30,
  customDb?: LogKysely,
): Promise<OrgUsageDay[]> {
  const { db, ready } = getDb(customDb);
  await ready;

  const cutoff = new Date();
  cutoff.setUTCDate(cutoff.getUTCDate() - days);
  const cutoffDate = cutoff.toISOString().slice(0, 10);

  const rows = await db
    .selectFrom("tenant_usage_daily")
    .selectAll()
    .where("organization_id", "=", orgId)
    .where("date", ">=", cutoffDate)
    .orderBy("date", "desc")
    .execute();

  return rows.map((row) => ({
    organizationId: row.organization_id,
    date: row.date,
    totalRequests: row.total_requests,
    allowedRequests: row.allowed_requests,
    maskedRequests: row.masked_requests,
    blockedRequests: row.blocked_requests,
    totalTokens: row.total_tokens,
    avgRiskScore: row.avg_risk_score,
  }));
}
