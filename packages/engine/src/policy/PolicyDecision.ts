/**
 * @file PolicyDecision.ts
 * @module @promptwall/engine/policy
 *
 * Defines PolicyDecision — the immutable output of {@link PolicyEngine.decide}.
 *
 * A PolicyDecision carries the enforcement action, the reason it was chosen,
 * traceability fields (matched rule IDs, candidate IDs), and the risk scores
 * that drove the decision. It does NOT carry raw candidate values — secret
 * exposure via audit logs or decision payloads is explicitly prevented.
 *
 * ── Downstream responsibilities ───────────────────────────────────────────────
 *
 * The PolicyDecision specifies WHAT to do. HOW to do it belongs downstream:
 *
 * | Action | Downstream responsibility                                       |
 * |--------|----------------------------------------------------------------|
 * | allow  | Forward the original request to the LLM provider unchanged.    |
 * | mask   | Redact candidate values before forwarding (Masking layer).     |
 * | block  | Return an error or empty response; do not forward the request. |
 *
 * The PolicyEngine never performs masking or blocking itself.
 */

import type { PolicyAction } from "./PolicyAction";
import type { RiskLevel } from "../risk/RiskLevel";

// ── PolicyDecision ────────────────────────────────────────────────────────────

/**
 * The complete, immutable output of {@link PolicyEngine.decide}.
 *
 * ## Security invariant
 *
 * `reason` MUST NOT contain raw candidate values (secrets, PII, tokens).
 * The PolicyEngine is responsible for enforcing this in its `reason`
 * construction. Callers must not inject raw values into `metadata` either.
 *
 * @example
 * ```ts
 * const decision: PolicyDecision = {
 *   action: "block",
 *   reason: "Critical credential detected — request blocked to prevent exposure.",
 *   matchedRuleIds: ["block-critical-secret", "block-critical-risk"],
 *   riskScore: 91.4,
 *   riskLevel: "critical",
 *   candidateIds: ["550e8400-e29b-41d4-a716-446655440000"],
 *   metadata: { requestId: "req-001", tenantId: "acme-corp" },
 * };
 * ```
 */
export interface PolicyDecision {
  /**
   * The enforcement action to apply.
   * Downstream layers are responsible for actually enforcing this action.
   * @see {@link PolicyAction}
   */
  readonly action: PolicyAction;

  /**
   * Human-readable explanation of why this action was chosen.
   *
   * Suitable for:
   * - Audit logs
   * - User-facing error messages (when `action === "block"`)
   * - PolicyEngine explanation dashboards
   *
   * MUST NOT contain raw candidate values (secrets, tokens, PII).
   * Reference candidates by ID or category only.
   */
  readonly reason: string;

  /**
   * IDs of all {@link PolicyRule}s that matched during evaluation.
   * The winning rule (lowest priority number among matches) is always first.
   * Empty only when no rules matched and the default action was applied.
   *
   * Useful for:
   * - Audit trails ("which rules fired?")
   * - Rule effectiveness analytics
   * - Debugging unexpected decisions
   */
  readonly matchedRuleIds: readonly string[];

  /**
   * The aggregated risk score from {@link RiskAssessment.score} (0–100).
   * Carried forward from the risk layer for downstream audit and logging.
   */
  readonly riskScore: number;

  /**
   * The categorical risk level from {@link RiskAssessment.level}.
   * Carried forward from the risk layer for downstream audit and logging.
   */
  readonly riskLevel: RiskLevel;

  /**
   * IDs of all candidates that were assessed by the PolicyEngine.
   * Matches {@link RiskAssessment.candidateIds}.
   * Empty when no candidates were assessed.
   */
  readonly candidateIds: readonly string[];

  /**
   * Optional caller-supplied or engine-generated metadata for correlation.
   *
   * Examples:
   * - `{ requestId: "req-001" }` — distributed tracing
   * - `{ tenantId: "acme-corp" }` — multi-tenant audit
   * - `{ engineVersion: "2.0" }` — version pinning for replay
   *
   * MUST NOT contain raw candidate values. The PolicyEngine does not
   * populate this field itself — it is reserved for callers or middleware.
   */
  readonly metadata?: Readonly<Record<string, unknown>>;
}
