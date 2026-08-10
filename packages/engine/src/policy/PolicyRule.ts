/**
 * @file PolicyRule.ts
 * @module @promptwall/engine/policy
 *
 * Defines PolicyRule — a single declarative matching rule that the
 * {@link PolicyEngine} evaluates against a {@link RiskAssessment} and the
 * resolved {@link Candidate}s to produce a {@link PolicyDecision}.
 *
 * ── Matching semantics ────────────────────────────────────────────────────────
 *
 * A rule matches when ALL of its specified conditions are satisfied
 * simultaneously. Absent conditions (undefined fields) are always satisfied —
 * they act as wildcards, not as "must be absent" guards.
 *
 * Condition fields:
 *   category       — matches if any candidate has this category
 *   subtype        — matches if any candidate has this subtype (exact string)
 *   severity       — matches if any candidate has this severity
 *   riskLevel      — matches if the assessment's level equals this value
 *   minRiskScore   — matches if the assessment's score ≥ this value
 *
 * A rule with NO condition fields is a catch-all that matches every request.
 *
 * ── Priority and conflict resolution ─────────────────────────────────────────
 *
 * `priority` is a non-negative integer. Lower values run first; for equal
 * priority values, specificity then stable ID are used as tiebreakers.
 *
 * The `id`s of all matching rules are recorded in {@link PolicyDecision.matchedRuleIds}
 * for audit trail purposes.
 *
 * ── Extension ────────────────────────────────────────────────────────────────
 *
 * Additional match conditions (e.g. `userId`, `tenantId`, `requestPath`) can
 * be added as optional fields in a future milestone without breaking existing
 * rules. Absent fields always default to wildcard (always match) semantics.
 */

import type { CandidateCategory, Severity } from "../candidate/Candidate";
import type { PolicyAction } from "./PolicyAction";
import type { RiskLevel } from "../risk/RiskLevel";

// ── PolicyRule ────────────────────────────────────────────────────────────────

/**
 * A single declarative matching rule evaluated by the {@link PolicyEngine}.
 *
 * All match-condition fields (`category`, `subtype`, `severity`, `riskLevel`,
 * `minRiskScore`) are optional. An absent field is treated as a wildcard —
 * it does not constrain matching. A rule with no condition fields is a
 * catch-all that matches every request.
 *
 * @example Block all critical credentials:
 * ```ts
 * const rule: PolicyRule = {
 *   id: "block-critical-secrets",
 *   priority: 10,
 *   category: "secret",
 *   severity: "critical",
 *   action: "block",
 *   reason: "Critical credential exposure detected — request blocked.",
 * };
 * ```
 *
 * @example Mask PII when risk score ≥ 30:
 * ```ts
 * const rule: PolicyRule = {
 *   id: "mask-pii-medium-risk",
 *   priority: 20,
 *   category: "pii",
 *   minRiskScore: 30,
 *   action: "mask",
 *   reason: "PII detected with medium or higher risk — masking applied.",
 * };
 * ```
 *
 * @example Default allow (catch-all):
 * ```ts
 * const rule: PolicyRule = {
 *   id: "default-allow",
 *   priority: 999,
 *   action: "allow",
 *   reason: "No policy rule triggered — request allowed.",
 * };
 * ```
 */
export interface PolicyRule {
  /**
   * Stable, unique machine identifier for this rule.
   * Used in {@link PolicyDecision.matchedRuleIds} and audit logs.
   * Convention: kebab-case, human-readable.
   * @example "block-critical-secrets", "mask-pii-medium", "default-allow"
   */
  readonly id: string;

  /**
   * Evaluation order hint. Lower values run first.
   * For equal priority values, specificity then stable ID are the tiebreakers.
   *
   * Convention:
   * - 0–9:   Emergency / hard-block rules (always evaluated first)
   * - 10–49: Category-specific action rules
   * - 50–99: Risk-level or score threshold rules
   * - 100+:  Default / catch-all rules
   */
  readonly priority: number;

  // ── Match conditions ───────────────────────────────────────────────────────
  // All fields below are optional. An absent field acts as a wildcard.

  /**
   * Restrict matching to candidates of this {@link CandidateCategory}.
   * The rule matches if ANY candidate in the assessment has this category.
   * Absent → matches all categories.
   */
  readonly category?: CandidateCategory;

  /**
   * Restrict matching to candidates of this exact `subtype` string.
   * The rule matches if ANY candidate in the assessment has this subtype.
   * Absent → matches all subtypes.
   * @example "AWS_ACCESS_KEY", "CREDIT_CARD", "EMAIL_ADDRESS"
   */
  readonly subtype?: string;

  /**
   * Restrict matching to candidates with this {@link Severity} level.
   * The rule matches if ANY candidate in the assessment has this severity.
   * Absent → matches all severity levels.
   */
  readonly severity?: Severity;

  /**
   * Restrict matching to assessments whose `level` equals this {@link RiskLevel}.
   * Applies to the overall assessment level, not individual candidates.
   * Absent → matches all risk levels.
   */
  readonly riskLevel?: RiskLevel;

  /**
   * Restrict matching to assessments whose `score` ≥ this value (inclusive).
   * Value must be in [0, 100].
   * Absent → matches any score (including 0).
   */
  readonly minRiskScore?: number;

  // ── Action ────────────────────────────────────────────────────────────────

  /**
   * The security enforcement action to apply when this rule matches.
   * @see {@link PolicyAction}
   */
  readonly action: PolicyAction;

  /**
   * Human-readable explanation of why this rule triggers this action.
   * Included in {@link PolicyDecision.reason} when this is the winning rule.
   * Must be self-contained for audit logs.
   * MUST NOT reference raw candidate values (secrets, PII, tokens).
   *
   * @example "Critical credential exposure — blocking request."
   * @example "PII detected with risk ≥ 30 — masking applied."
   */
  readonly reason: string;
}
