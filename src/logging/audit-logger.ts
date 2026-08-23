/**
 * @file audit-logger.ts
 * @module src/logging
 *
 * SQLite/PostgreSQL implementation of the {@link AuditLogger} interface (M6A).
 *
 * ── Design notes ─────────────────────────────────────────────────────────────
 *
 * - Uses the same Kysely `LogKysely` / `createLogDatabase()` / `migrateLogDatabase()`
 *   infrastructure as the existing `Logger` class, so SQLite ↔ Postgres
 *   switching is handled by config alone.
 *
 * - Constructor accepts an optional injected `db` for testing (same as `Logger`).
 *
 * - `logSecurityEvent()` is the fire-and-forget public helper used in routes.
 *   It MUST NOT block the request path.
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 *
 * `candidates` and `detectors_triggered` are serialised from the
 * {@link CandidateSummary} array produced by `buildSecurityEvent()`.
 * That builder explicitly strips `value`, `normalizedValue`, `location`,
 * `evidence`, and `metadata` from every Candidate before this point.
 * This module never re-reads or re-serialises raw Candidate fields.
 */

import type {
  AuditLogger,
  CandidateSummary,
  PipelineResult,
  SecurityEvent,
} from "@promptwall/engine";
import { buildSecurityEvent } from "@promptwall/engine";
import { type Config, getConfig } from "../config";
import { createLogDatabase, type LogKysely, migrateLogDatabase } from "./db";

// ── SqliteAuditLogger ─────────────────────────────────────────────────────────

/**
 * Production implementation of {@link AuditLogger} backed by Kysely
 * (SQLite in development / Docker; Postgres in production clusters).
 *
 * Use the module-level singleton via {@link getAuditLogger} in production.
 * Inject a fresh instance via the `db` constructor option in tests.
 */
export class SqliteAuditLogger implements AuditLogger {
  private readonly db: LogKysely;
  private readonly ready: Promise<void>;
  private readonly retentionDays: number;

  constructor(options: { config?: Config; db?: LogKysely } = {}) {
    const config = options.config ?? getConfig();
    this.retentionDays = config.logging.retention_days;

    if (options.db) {
      this.db = options.db;
      this.ready = Promise.resolve();
    } else {
      const { db, driver } = createLogDatabase(config);
      this.db = db;
      this.ready = migrateLogDatabase(db, driver);
    }
  }

  /**
   * Persist a {@link SecurityEvent} to the `security_events` table.
   *
   * Never stores raw candidate values — the event's `candidates` array must
   * already be a {@link CandidateSummary}[] (enforced by `buildSecurityEvent`).
   */
  async log(event: SecurityEvent): Promise<void> {
    await this.ready;

    // Serialise JSON columns. Confidence is already rounded to 4dp by buildSecurityEvent.
    const candidatesJson = JSON.stringify(
      event.candidates.map(
        (c: CandidateSummary): Record<string, unknown> => ({
          id: c.id,
          category: c.category,
          subtype: c.subtype,
          severity: c.severity,
          confidence: c.confidence,
          detector: c.detector,
          // Explicitly enumerate fields — do NOT spread c to prevent accidental
          // inclusion of future Candidate fields that may contain raw values.
        }),
      ),
    );

    await this.db
      .insertInto("security_events")
      .values({
        event_id: event.eventId,
        request_id: event.requestId,
        timestamp: event.timestamp,
        source: event.source,
        provider: event.provider,
        model: event.model,
        risk_score: event.riskScore,
        risk_level: event.riskLevel,
        action: event.action,
        decision_reason: event.decisionReason,
        candidates: candidatesJson,
        detectors_triggered: JSON.stringify(event.detectorsTriggered),
        matched_rule_ids: JSON.stringify(event.matchedRuleIds),
        latency_ms: event.latencyMs,
      })
      .execute();
  }

  /**
   * Retrieve recent security events, ordered newest-first.
   *
   * Useful for the audit dashboard and compliance reporting.
   *
   * @param limit  - Maximum rows to return (default 100).
   * @param offset - Pagination offset (default 0).
   */
  async getRecentEvents(limit = 100, offset = 0): Promise<StoredSecurityEvent[]> {
    await this.ready;

    const rows = await this.db
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
      ])
      .orderBy("timestamp", "desc")
      .limit(limit)
      .offset(offset)
      .execute();

    return rows.map((row) => ({
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
      candidates: JSON.parse(row.candidates) as CandidateSummary[],
      detectorsTriggered: JSON.parse(row.detectors_triggered) as string[],
      matchedRuleIds: JSON.parse(row.matched_rule_ids) as string[],
      latencyMs: Number(row.latency_ms),
    }));
  }

  /**
   * Delete events older than `retentionDays`.
   *
   * @param retentionDays - Optional override for retention cutoff days (defaults to config value).
   * @returns Number of rows deleted (0 when retention is disabled).
   */
  async cleanup(retentionDays?: number): Promise<number> {
    await this.ready;

    const days = retentionDays ?? this.retentionDays;
    if (days <= 0) {
      return 0;
    }

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - days);

    const result = await this.db
      .deleteFrom("security_events")
      .where("timestamp", "<", cutoffDate.toISOString())
      .executeTakeFirst();

    return Number(result.numDeletedRows);
  }

  async close(): Promise<void> {
    await this.ready;
    await this.db.destroy();
    if (auditLoggerInstance === this) {
      auditLoggerInstance = null;
    }
  }
}

// ── Stored event DTO (includes DB id) ─────────────────────────────────────────

/** A `SecurityEvent` as retrieved from the database (includes the auto-increment `id`). */
export interface StoredSecurityEvent extends SecurityEvent {
  readonly id: number;
}

// ── Singleton ─────────────────────────────────────────────────────────────────

let auditLoggerInstance: SqliteAuditLogger | null = null;

/**
 * Return the process-wide `SqliteAuditLogger` singleton.
 *
 * Lazily initialised on first call. Uses `getConfig()` for the DB path /
 * driver selection. In tests, prefer constructing a fresh `SqliteAuditLogger`
 * with an injected `db` instead of using this singleton.
 */
export function getAuditLogger(): SqliteAuditLogger {
  if (!auditLoggerInstance) {
    auditLoggerInstance = new SqliteAuditLogger();
  }
  return auditLoggerInstance;
}

// ── Fire-and-forget route helper ──────────────────────────────────────────────

/**
 * Options for {@link logSecurityEvent}.
 */
export interface LogSecurityEventOptions {
  /** Correlation ID from the `x-request-id` header (or generated by middleware). */
  readonly requestId: string;
  /** LLM provider the request targeted. */
  readonly provider: string;
  /** Model name from the request body. */
  readonly model: string;
  /** Milliseconds elapsed between extraction start and `DetectionPipeline.run()` resolving. */
  readonly latencyMs: number;
  /**
   * Optional override logger — pass a fresh `SqliteAuditLogger` in tests to
   * avoid interacting with the global singleton.
   */
  readonly logger?: AuditLogger;
}

/**
 * Build and fire-and-forget a {@link SecurityEvent} from a {@link PipelineResult}.
 *
 * This MUST be called immediately after `DetectionPipeline.run()` resolves and
 * before any HTTP response or provider call, to guarantee the correct audit
 * ordering defined in M6A.
 *
 * Errors are caught and logged to `console.error`; they never bubble up to the
 * request handler.
 *
 * @example
 * ```ts
 * pipelineResult = await detectionPipeline.run(detectionReq);
 * logSecurityEvent(pipelineResult, { requestId, provider: selectedProvider,
 *   model: request.model ?? "unknown", latencyMs: detectionMs });
 * if (pipelineResult.policyDecision.action === "block") { ... }
 * ```
 */
export function logSecurityEvent(
  pipelineResult: PipelineResult,
  opts: LogSecurityEventOptions,
): void {
  try {
    const event = buildSecurityEvent(pipelineResult, {
      requestId: opts.requestId,
      provider: opts.provider,
      model: opts.model,
      latencyMs: opts.latencyMs,
    });

    const logger = opts.logger ?? getAuditLogger();

    void logger.log(event).catch((error) => {
      console.error("[AuditLogger] Failed to persist security event:", error);
    });
  } catch (error) {
    console.error("[AuditLogger] Failed to build security event:", error);
  }
}
