/**
 * @file audit-query.ts
 * @module src/logging
 *
 * Advanced query engine for `security_events` audit records (M6B).
 * Supports filtering by action, risk level, score range, provider, model,
 * detector, category/subtype, time range, and request/event ID, with
 * pagination and custom sorting.
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 *
 * All returned audit records sanitize candidate objects to {@link CandidateSummary}
 * containing strictly: `id`, `category`, `subtype`, `severity`, `confidence`, `detector`.
 * No raw values, normalized values, locations, evidence details, or raw prompts
 * are ever exposed.
 */

import type { CandidateSummary } from "@promptwall/engine";
import { getConfig } from "../config";
import type { StoredSecurityEvent } from "./audit-logger";
import { createLogDatabase, type LogKysely, migrateLogDatabase } from "./db";

// ── Query Filter Interface ───────────────────────────────────────────────────

export interface AuditQueryFilter {
  readonly action?: "allow" | "mask" | "block";
  readonly riskLevel?: "low" | "medium" | "high" | "critical";
  readonly minRiskScore?: number;
  readonly maxRiskScore?: number;
  readonly provider?: string;
  readonly model?: string;
  readonly detector?: string;
  readonly category?: string;
  readonly subtype?: string;
  readonly startTime?: string;
  readonly endTime?: string;
  readonly requestId?: string;
  readonly eventId?: string;
  readonly limit?: number;
  readonly offset?: number;
  readonly sortBy?: "timestamp" | "riskScore" | "latencyMs";
  readonly sortOrder?: "asc" | "desc";
  /** M12: restrict results to a specific organization. Enforced for non-ADMIN callers. */
  readonly organizationId?: string;
}

export interface AuditQueryResult {
  readonly events: readonly StoredSecurityEvent[];
  readonly total: number;
  readonly limit: number;
  readonly offset: number;
}

// ── Helper to ensure database is ready ───────────────────────────────────────

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

// ── Main Query Function ───────────────────────────────────────────────────────

/**
 * Query security audit events with flexible filtering, pagination, and sorting.
 *
 * @param filter - Search criteria and pagination parameters.
 * @param customDb - Optional Kysely database instance (used in tests).
 */
export async function querySecurityEvents(
  filter: AuditQueryFilter = {},
  customDb?: LogKysely,
): Promise<AuditQueryResult> {
  const { db, ready } = getDb(customDb);
  await ready;

  // Pagination bounds: default 50, max 500, min 1
  const limit = Math.min(Math.max(filter.limit ?? 50, 1), 500);
  const offset = Math.max(filter.offset ?? 0, 0);

  // Sorting defaults
  const sortByField = filter.sortBy ?? "timestamp";
  const sortOrder = filter.sortOrder ?? "desc";

  // Map user sortBy name to DB column name
  const dbColumnMap: Record<string, "timestamp" | "risk_score" | "latency_ms"> = {
    timestamp: "timestamp",
    riskScore: "risk_score",
    latencyMs: "latency_ms",
  };
  const sortColumn = dbColumnMap[sortByField] ?? "timestamp";

  let query = db.selectFrom("security_events");

  // Apply basic column filters
  if (filter.action) {
    query = query.where("action", "=", filter.action);
  }
  if (filter.riskLevel) {
    query = query.where("risk_level", "=", filter.riskLevel);
  }
  if (filter.minRiskScore !== undefined) {
    query = query.where("risk_score", ">=", filter.minRiskScore);
  }
  if (filter.maxRiskScore !== undefined) {
    query = query.where("risk_score", "<=", filter.maxRiskScore);
  }
  if (filter.provider) {
    query = query.where("provider", "=", filter.provider);
  }
  if (filter.model) {
    query = query.where("model", "=", filter.model);
  }
  if (filter.startTime) {
    query = query.where("timestamp", ">=", filter.startTime);
  }
  if (filter.endTime) {
    query = query.where("timestamp", "<=", filter.endTime);
  }
  if (filter.requestId) {
    query = query.where("request_id", "=", filter.requestId);
  }
  if (filter.eventId) {
    query = query.where("event_id", "=", filter.eventId);
  }
  if (filter.detector) {
    query = query.where("detectors_triggered", "like", `%"${filter.detector}"%`);
  }
  // M12: tenant isolation — restrict to a specific organization's events
  if (filter.organizationId) {
    query = query.where("organization_id", "=", filter.organizationId);
  }

  // Count total matching records before applying limit/offset
  const countResult = await query
    .select((eb) => eb.fn.countAll<number>().as("total"))
    .executeTakeFirst();
  const total = Number(countResult?.total ?? 0);

  // Fetch paginated results
  const rows = await query
    .select([
      "id",
      "event_id",
      "request_id",
      "timestamp",
      "source",
      "provider",
      "model",
      "risk_score",
      "risk_level",
      "action",
      "decision_reason",
      "candidates",
      "detectors_triggered",
      "matched_rule_ids",
      "latency_ms",
    ])
    .orderBy(sortColumn, sortOrder)
    .limit(limit)
    .offset(offset)
    .execute();

  const events: StoredSecurityEvent[] = [];

  for (const row of rows) {
    const rawCandidates = JSON.parse(row.candidates) as CandidateSummary[];

    // Post-filter in JS for JSON array attributes if specified
    if (filter.category && !rawCandidates.some((c) => c.category === filter.category)) {
      continue;
    }
    if (filter.subtype && !rawCandidates.some((c) => c.subtype === filter.subtype)) {
      continue;
    }

    // Ensure CandidateSummary contains ONLY safe fields
    const sanitizedCandidates: CandidateSummary[] = rawCandidates.map((c) => ({
      id: c.id,
      category: c.category,
      subtype: c.subtype,
      severity: c.severity,
      confidence: c.confidence,
      detector: c.detector,
    }));

    events.push({
      id: Number(row.id),
      eventId: row.event_id,
      requestId: row.request_id,
      timestamp: row.timestamp,
      source: (row.source as "promptwall") || "promptwall",
      provider: row.provider,
      model: row.model,
      riskScore: Number(row.risk_score),
      riskLevel: row.risk_level,
      action: row.action,
      decisionReason: row.decision_reason,
      candidates: sanitizedCandidates,
      detectorsTriggered: JSON.parse(row.detectors_triggered) as string[],
      matchedRuleIds: JSON.parse(row.matched_rule_ids) as string[],
      latencyMs: Number(row.latency_ms),
    });
  }

  return {
    events,
    total,
    limit,
    offset,
  };
}

// ── Single Event Lookup ───────────────────────────────────────────────────────

/**
 * Retrieve a single security event by its eventId or DB id.
 */
export async function getSecurityEventById(
  idOrEventId: string | number,
  customDb?: LogKysely,
): Promise<StoredSecurityEvent | null> {
  const { db, ready } = getDb(customDb);
  await ready;

  let query = db
    .selectFrom("security_events")
    .select([
      "id",
      "event_id",
      "request_id",
      "timestamp",
      "source",
      "provider",
      "model",
      "risk_score",
      "risk_level",
      "action",
      "decision_reason",
      "candidates",
      "detectors_triggered",
      "matched_rule_ids",
      "latency_ms",
    ]);

  if (typeof idOrEventId === "number" || /^\d+$/.test(String(idOrEventId))) {
    query = query.where("id", "=", Number(idOrEventId));
  } else {
    query = query.where("event_id", "=", String(idOrEventId));
  }

  const row = await query.executeTakeFirst();
  if (!row) return null;

  const rawCandidates = JSON.parse(row.candidates) as CandidateSummary[];
  const sanitizedCandidates: CandidateSummary[] = rawCandidates.map((c) => ({
    id: c.id,
    category: c.category,
    subtype: c.subtype,
    severity: c.severity,
    confidence: c.confidence,
    detector: c.detector,
  }));

  return {
    id: Number(row.id),
    eventId: row.event_id,
    requestId: row.request_id,
    timestamp: row.timestamp,
    source: (row.source as "promptwall") || "promptwall",
    provider: row.provider,
    model: row.model,
    riskScore: Number(row.risk_score),
    riskLevel: row.risk_level,
    action: row.action,
    decisionReason: row.decision_reason,
    candidates: sanitizedCandidates,
    detectorsTriggered: JSON.parse(row.detectors_triggered) as string[],
    matchedRuleIds: JSON.parse(row.matched_rule_ids) as string[],
    latencyMs: Number(row.latency_ms),
  };
}
