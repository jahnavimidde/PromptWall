/**
 * @file RiskFactor.ts
 * @module @promptwall/engine/risk
 *
 * Defines RiskFactor — a single attribution unit that explains WHY a particular
 * candidate raised the overall risk level.
 *
 * ── Attribution vs. decomposition ────────────────────────────────────────────
 *
 * IMPORTANT: `RiskFactor.contribution` is an EXPLANATORY attribution value.
 * It is NOT an additive decomposition of `RiskAssessment.score`.
 *
 * The actual risk calculation uses:
 *   1. A multiplicative per-candidate formula:
 *        candidateRisk = severityWeight × confidence × evidenceAgreement
 *   2. A complement-product aggregation across all candidates:
 *        overallRisk = 100 × (1 − ∏(1 − candidateRisk_i))
 *
 * These are non-linear operations, so `contribution` values do NOT sum to
 * `RiskAssessment.score`. Their purpose is to give PolicyEngine, audit logs,
 * and human reviewers a proportional, human-readable explanation of the
 * dominant signals — nothing more.
 *
 * For the authoritative score, always use `RiskAssessment.score`.
 */

// ── RiskFactorType ────────────────────────────────────────────────────────────

/**
 * Discriminant identifying which aspect of a candidate's profile is being
 * attributed in a {@link RiskFactor}.
 *
 * | Type                  | What it describes                                      |
 * |-----------------------|--------------------------------------------------------|
 * | severity              | The classified severity level of the candidate         |
 * | confidence            | The aggregated detector confidence score               |
 * | evidence              | The number and quality of corroborating evidence items |
 * | context               | Request-level or metadata-level contextual signals     |
 * | detector_reliability  | Reliability weight of the originating detector         |
 *
 * This is an open union (string-extensible): future milestones can introduce
 * new factor types (e.g. `"co_occurrence"`, `"location_overlap"`) without
 * changing the interface or breaking existing consumers.
 */
export type RiskFactorType =
  | "severity"
  | "confidence"
  | "evidence"
  | "context"
  | "detector_reliability"
  // Open union: allows future types without breaking changes.
  // eslint-disable-next-line @typescript-eslint/ban-types
  | (string & {});

// ── RiskFactor ────────────────────────────────────────────────────────────────

/**
 * A single attribution unit explaining why one candidate contributed to risk.
 *
 * ## Attribution semantics
 *
 * `contribution` is a proportional attribution value in [0, 100], scaled to
 * reflect the candidate's relative influence on the overall risk score. It is
 * produced by multiplying the per-candidate normalized risk by 100.
 *
 * Because the actual scoring pipeline uses multiplicative candidate scoring
 * and complement-product global aggregation (both non-linear), the sum of all
 * `contribution` values in a `RiskAssessment` will NOT equal `score`. Do not
 * sum or average factors to reconstruct the score.
 *
 * @example
 * ```ts
 * const factor: RiskFactor = {
 *   candidateId: "abc-123",
 *   type: "severity",
 *   contribution: 70,
 *   explanation: "Candidate severity is 'critical' (weight 1.00)",
 * };
 * ```
 */
export interface RiskFactor {
  /**
   * ID of the {@link Candidate} this factor is attributed to.
   * Matches `Candidate.id` exactly.
   */
  readonly candidateId: string;

  /**
   * The aspect of the candidate being attributed.
   * @see {@link RiskFactorType} for the full list of well-known types.
   */
  readonly type: RiskFactorType;

  /**
   * Proportional attribution weight in [0, 100].
   *
   * Represents the candidate's per-candidate normalized risk scaled to 100.
   * This is an EXPLANATORY value — it is NOT an additive component of
   * `RiskAssessment.score`. See module-level documentation for details.
   */
  readonly contribution: number;

  /**
   * Human-readable explanation of this factor for audit logs and dashboards.
   * Must be self-contained — consumers should not need external context.
   *
   * @example "Critical secret candidate (severity weight 1.00)"
   * @example "High detector confidence: 0.95"
   * @example "3 independent evidence sources (regex, entropy, validator)"
   */
  readonly explanation: string;
}
