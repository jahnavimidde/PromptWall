/**
 * @file RiskScoringContext.ts
 * @module @promptwall/engine/risk
 *
 * Defines RiskScoringContext — optional caller-supplied context passed to
 * {@link RiskEngine.assess} alongside the candidate list.
 *
 * The context is extensible by design: future milestones can enrich it with
 * user identity, tenant policy hints, or historical risk signals without
 * changing the RiskEngine interface.
 *
 * No external dependencies are introduced here.
 */

import type { DetectionRequest } from "../detector/DetectionRequest";

// ── RiskScoringContext ────────────────────────────────────────────────────────

/**
 * Optional context supplied to {@link RiskEngine.assess} for contextual risk
 * adjustment and audit-trail enrichment.
 *
 * All fields are optional. `RiskEngine` functions correctly with no context
 * at all — context only enables future extensions without interface changes.
 *
 * @example Passing the originating request:
 * ```ts
 * const assessment = engine.assess(candidates, { request });
 * ```
 *
 * @example Passing arbitrary metadata for audit:
 * ```ts
 * const assessment = engine.assess(candidates, {
 *   request,
 *   metadata: { userId: "usr-42", tenantId: "acme-corp", requestId: "req-001" },
 * });
 * ```
 */
export interface RiskScoringContext {
  /**
   * The originating {@link DetectionRequest} that produced the candidates.
   *
   * Future extensions may use content length, MIME type, or language to
   * adjust risk weighting (e.g. higher sensitivity for `application/json`).
   * Currently stored in the context but not used in scoring calculations.
   */
  readonly request?: DetectionRequest;

  /**
   * Caller-supplied key-value metadata for context enrichment and audit logging.
   *
   * Examples of useful metadata:
   * - `{ userId: "usr-42" }` — for per-user audit trails
   * - `{ tenantId: "acme" }` — for multi-tenant policy differentiation
   * - `{ requestId: "req-001" }` — for distributed tracing correlation
   *
   * The RiskEngine does not read or validate this field; it is preserved for
   * downstream consumers (PolicyEngine, audit logger).
   */
  readonly metadata?: Readonly<Record<string, unknown>>;
}
