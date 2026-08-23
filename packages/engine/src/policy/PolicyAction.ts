/**
 * @file PolicyAction.ts
 * @module @promptwall/engine/policy
 *
 * Defines PolicyAction — the set of security enforcement actions that the
 * PolicyEngine may issue for a given risk assessment.
 *
 * The three-valued taxonomy is deliberately minimal:
 *
 * | Action | Semantics                                                         |
 * |--------|-------------------------------------------------------------------|
 * | allow  | Content is safe to forward to the LLM provider as-is.            |
 * | mask   | Sensitive candidates must be redacted before forwarding.          |
 * | block  | Request must not be forwarded; return an error or empty response. |
 *
 * The PolicyEngine produces this action. Enforcement (actual masking logic,
 * HTTP error responses) is the responsibility of downstream layers.
 *
 * This type must NOT be used inside RiskEngine — risk assessment and policy
 * decisions are separate pipeline stages.
 */

// ── PolicyAction ──────────────────────────────────────────────────────────────

/**
 * The security enforcement action issued by the {@link PolicyEngine}.
 *
 * Resolution order (highest precedence first):
 *   block → mask → allow
 *
 * When multiple rules match, the winning rule is determined by priority, not
 * by action precedence. See {@link PolicyEngine} for the rule evaluation order.
 */
export type PolicyAction = "allow" | "mask" | "block";

// ── Action precedence ─────────────────────────────────────────────────────────

/**
 * Numeric precedence for each {@link PolicyAction}.
 * Higher value → higher precedence.
 *
 * | Action | Precedence |
 * |--------|-----------|
 * | allow  | 0         |
 * | mask   | 1         |
 * | block  | 2         |
 *
 * @internal Used by callers that need to compare action severity, e.g. for
 * merging multiple decisions from independent sub-engines in future milestones.
 */
export const ACTION_PRECEDENCE: Readonly<Record<PolicyAction, number>> = {
  allow: 0,
  mask: 1,
  block: 2,
} as const;

/**
 * Return the higher-precedence action of two candidates.
 * Deterministic: for equal precedence, returns `a`.
 *
 * @internal Utility for callers that need action-level conflict resolution
 * independent of rule priority. PolicyEngine itself uses priority-order, not
 * this function, for its primary conflict resolution.
 */
export function highestPrecedenceAction(
  a: PolicyAction,
  b: PolicyAction,
): PolicyAction {
  return ACTION_PRECEDENCE[b] > ACTION_PRECEDENCE[a] ? b : a;
}
