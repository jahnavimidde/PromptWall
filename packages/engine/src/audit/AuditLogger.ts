/**
 * @file AuditLogger.ts
 * @module @promptwall/engine/audit
 *
 * Defines the AuditLogger interface — the contract that all audit log
 * implementations must satisfy.
 *
 * Concrete implementations:
 *   - SQLiteAuditLogger  (src/logging/audit-logger.ts) — production default
 *   - PostgresAuditLogger — same class, different Kysely dialect (future)
 *   - CloudAuditLogger  — forwards to GCP Logging / AWS CloudTrail (future)
 *
 * This interface lives in the engine package so that the engine can declare
 * its dependency without coupling to any specific storage technology.
 * Implementations import @promptwall/engine; the engine never imports back.
 */

import type { SecurityEvent } from "./SecurityEvent";

// ── AuditLogger ───────────────────────────────────────────────────────────────

/**
 * Contract for audit log backends.
 *
 * Implementations MUST:
 *   - Be idempotent for the same `eventId` (best-effort; not a hard guarantee).
 *   - Never throw synchronously — wrap all errors internally and log/emit them.
 *   - Never include raw candidate values in storage.
 *
 * Callers SHOULD:
 *   - Invoke `log()` as fire-and-forget (`void logger.log(event).catch(...)`)
 *     to avoid blocking the request path.
 */
export interface AuditLogger {
  /**
   * Persist a {@link SecurityEvent} to the backing store.
   *
   * @param event - The audit record to store. Must satisfy the security
   *   invariant: `event.candidates` must never contain raw matched values.
   * @returns A promise that resolves when the event has been durably written,
   *   or rejects if the underlying store is unavailable.
   */
  log(event: SecurityEvent): Promise<void>;
}
