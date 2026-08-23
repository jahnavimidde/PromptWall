/**
 * @file RiskAssessment.ts
 * @module @promptwall/engine/risk
 *
 * Defines RiskAssessment — the immutable output of {@link RiskEngine.assess}.
 *
 * A RiskAssessment carries the numeric score, the categorical level, the
 * explanatory factors, and a human-readable summary. It does NOT contain
 * ALLOW / MASK / BLOCK decisions — those belong to the PolicyEngine.
 */

import type { RiskFactor } from "./RiskFactor";
import type { RiskLevel } from "./RiskLevel";

// ── RiskAssessment ────────────────────────────────────────────────────────────

/**
 * The complete, immutable output of a {@link RiskEngine} assessment pass.
 *
 * ## Score semantics
 *
 * `score` is in [0, 100] and is produced by the complement-product aggregation
 * formula:
 *
 * ```
 * overallRisk = 100 × (1 − ∏(1 − candidateRisk_i))
 * ```
 *
 * where each `candidateRisk_i` is the per-candidate normalized risk in [0, 1]:
 *
 * ```
 * candidateRisk_i = severityWeight × confidence × evidenceAgreement
 * ```
 *
 * The score is clamped to [0, 100] after aggregation as a safety guard.
 *
 * ## Factor semantics
 *
 * `factors` are EXPLANATORY attribution values. Because the scoring pipeline
 * is multiplicative and non-linear, the sum of `factor.contribution` values
 * does NOT equal `score`. See {@link RiskFactor} for full documentation.
 *
 * @example
 * ```ts
 * const assessment: RiskAssessment = {
 *   score: 91,
 *   level: "critical",
 *   factors: [
 *     {
 *       candidateId: "abc-123",
 *       type: "severity",
 *       contribution: 91,
 *       explanation: "Candidate severity is 'critical' (weight 1.00)",
 *     },
 *   ],
 *   candidateIds: ["abc-123"],
 *   summary: "Critical risk: 1 candidate(s) detected — highest severity: critical.",
 * };
 * ```
 */
export interface RiskAssessment {
  /**
   * Aggregated risk score in [0, 100], clamped.
   *
   * - 0–29:   low
   * - 30–59:  medium
   * - 60–79:  high
   * - 80–100: critical
   *
   * Exact level boundaries are controlled by {@link RiskThresholds} in RiskEngine.
   */
  readonly score: number;

  /** Categorical level derived from `score` using the configured thresholds. */
  readonly level: RiskLevel;

  /**
   * Explanatory factors, one per candidate that contributed to the assessment.
   *
   * Each factor attributes the candidate's influence via a human-readable
   * `explanation` and a proportional `contribution` value. The `contribution`
   * is NOT an additive component of `score` — see {@link RiskFactor}.
   *
   * Empty when no candidates were assessed.
   */
  readonly factors: readonly RiskFactor[];

  /**
   * IDs of all candidates that were assessed.
   * Mirrors the `id` field of each input {@link Candidate}.
   * Empty when no candidates were assessed.
   */
  readonly candidateIds: readonly string[];

  /**
   * Human-readable summary for dashboards, audit logs, and PolicyEngine context.
   *
   * @example "No candidates detected."
   * @example "Critical risk: 2 candidate(s) detected — highest severity: critical."
   * @example "Low risk: 1 candidate(s) detected — highest severity: low."
   */
  readonly summary: string;
}
