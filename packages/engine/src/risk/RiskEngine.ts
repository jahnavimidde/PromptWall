/**
 * @file RiskEngine.ts
 * @module @promptwall/engine/risk
 *
 * Implements the Risk Fusion Engine: transforms a resolved list of
 * {@link Candidate}s into a {@link RiskAssessment} using a transparent,
 * weighted, deterministic risk model.
 *
 * ── Architectural constraints ─────────────────────────────────────────────────
 *
 * - NO knowledge of HTTP, Hono, OpenAI, Gemini, Anthropic, databases, masking,
 *   or policy actions. This engine is a pure function over engine-level types.
 * - NO external dependencies. No ML/LLM calls.
 * - Deterministic: same inputs → same output, independent of time or insertion
 *   order (candidates are sorted by id before processing).
 * - Does NOT make ALLOW / MASK / BLOCK decisions. That belongs to PolicyEngine.
 *
 * ── Risk formula ──────────────────────────────────────────────────────────────
 *
 * STEP 1 — Evidence agreement (per candidate, [0, 1]):
 *
 *   Evidence items are first deduplicated by `id` to prevent double-counting
 *   when the same evidence object is attached more than once.
 *
 *   If the candidate has ≥ 1 unique evidence item:
 *     evidenceAgreement = 1 − ∏(1 − clamp(score_j, 0, 1))
 *
 *   This is the complementary probability that at least one evidence item
 *   fires. Multiple independent sources compound; duplicate IDs are ignored.
 *
 *   If the candidate has 0 evidence items:
 *     evidenceAgreement = candidate.confidence
 *   (detectors that emit no evidence are not unfairly zeroed out)
 *
 * STEP 2 — Per-candidate normalized risk ([0, 1]):
 *
 *   candidateRisk_i = clamp(severityWeight × confidence × evidenceAgreement, 0, 1)
 *
 *   | Factor           | Source                                   |
 *   |------------------|------------------------------------------|
 *   | severityWeight   | Configurable map: severity → [0, 1]      |
 *   | confidence       | candidate.confidence, already in [0, 1]  |
 *   | evidenceAgreement| Computed in Step 1                       |
 *
 * STEP 3 — Global aggregation (complement-product fusion, [0, 100]):
 *
 *   overallRisk = 100 × (1 − ∏(1 − candidateRisk_i))
 *
 *   This is the probabilistic complement product — the probability that at
 *   least one candidate's risk "fires". Properties:
 *   - Bounded by construction: result ∈ [0, 100] for inputs ∈ [0, 1].
 *   - Monotonically increasing: adding candidates never lowers risk.
 *   - Diminishing returns: ten tiny risks cannot pretend to be one critical risk.
 *   - Deterministic and transparent: no hidden weights, no RNG.
 *
 *   The final score is clamped to [0, 100] as a floating-point safety guard.
 *
 * ── RiskFactor.contribution semantics ────────────────────────────────────────
 *
 * IMPORTANT: `RiskFactor.contribution` is an EXPLANATORY attribution value.
 * It is the per-candidate normalized risk scaled to 100, giving a proportional
 * sense of each candidate's individual influence. Because the global aggregation
 * is multiplicative and non-linear, the SUM of `contribution` values does NOT
 * equal `RiskAssessment.score`. Do not treat factors as additive score
 * decomposition. For the authoritative score, always use `RiskAssessment.score`.
 */

import type { Candidate } from "../candidate/Candidate";
import type { Evidence } from "../candidate/Evidence";
import type { Severity } from "../candidate/Candidate";
import type { RiskAssessment } from "./RiskAssessment";
import type { RiskFactor } from "./RiskFactor";
import type { RiskScoringContext } from "./RiskScoringContext";
import {
  DEFAULT_RISK_THRESHOLDS,
  resolveRiskLevel,
  type RiskThresholds,
} from "./RiskLevel";

// ── SeverityWeights ───────────────────────────────────────────────────────────

/**
 * Maps each {@link Severity} level to a numeric weight in [0, 1].
 *
 * Higher weight → larger per-candidate risk contribution.
 * All four severity levels must be specified when providing a full override.
 * Use `Partial<SeverityWeights>` in {@link RiskEngineOptions} to override only
 * selected levels.
 */
export interface SeverityWeights {
  readonly low: number;
  readonly medium: number;
  readonly high: number;
  readonly critical: number;
}

/**
 * Default severity weights aligned with the Milestone 2A specification.
 *
 * | Severity | Weight |
 * |----------|--------|
 * | low      | 0.15   |
 * | medium   | 0.35   |
 * | high     | 0.70   |
 * | critical | 1.00   |
 */
export const DEFAULT_SEVERITY_WEIGHTS: Readonly<SeverityWeights> = {
  low: 0.15,
  medium: 0.35,
  high: 0.70,
  critical: 1.00,
} as const;

// ── RiskEngineOptions ─────────────────────────────────────────────────────────

/**
 * Constructor-level configuration for {@link RiskEngine}.
 * All fields are optional; defaults are used when absent.
 */
export interface RiskEngineOptions {
  /**
   * Custom risk level thresholds.
   * Overrides {@link DEFAULT_RISK_THRESHOLDS} entirely when provided.
   */
  readonly thresholds?: RiskThresholds;

  /**
   * Partial override of the default severity weight map.
   * Only the specified keys are overridden; unspecified keys retain their defaults.
   *
   * @example Override only critical severity:
   * ```ts
   * new RiskEngine({ severityWeights: { critical: 0.9 } })
   * ```
   */
  readonly severityWeights?: Partial<SeverityWeights>;
}

// ── RiskEngine ────────────────────────────────────────────────────────────────

/**
 * Transforms a list of resolved {@link Candidate}s into a {@link RiskAssessment}.
 *
 * The engine is stateless (all state lives in the constructor-resolved options)
 * and deterministic (candidates are sorted by `id` before processing to eliminate
 * insertion-order sensitivity).
 *
 * @example Default configuration:
 * ```ts
 * const engine = new RiskEngine();
 * const assessment = engine.assess(candidates);
 * ```
 *
 * @example Custom severity weights and thresholds:
 * ```ts
 * const engine = new RiskEngine({
 *   severityWeights: { critical: 0.95 },
 *   thresholds: { medium: 25, high: 55, critical: 75 },
 * });
 * ```
 */
export class RiskEngine {
  private readonly weights: Readonly<SeverityWeights>;
  private readonly thresholds: Readonly<RiskThresholds>;

  constructor(options: RiskEngineOptions = {}) {
    // Merge partial weight overrides with defaults
    this.weights = {
      ...DEFAULT_SEVERITY_WEIGHTS,
      ...options.severityWeights,
    };
    this.thresholds = options.thresholds ?? DEFAULT_RISK_THRESHOLDS;
  }

  /**
   * Assess the overall risk of a set of candidates.
   *
   * Processing is always deterministic: candidates are sorted by `id`
   * (ascending lexicographic order) before any computation, so the result
   * is independent of the order in which candidates are passed.
   *
   * @param candidates - Resolved candidates from the ConfidenceEngine.
   *   May be empty; returns a zero-risk assessment in that case.
   * @param context    - Optional scoring context for audit enrichment.
   *   Not used in Milestone 2A scoring calculations; reserved for future use.
   * @returns An immutable {@link RiskAssessment}.
   */
  assess(
    candidates: readonly Candidate[],
    _context?: RiskScoringContext,
  ): RiskAssessment {
    // Empty input → zero-risk baseline
    if (candidates.length === 0) {
      return buildZeroAssessment();
    }

    // Sort by id for determinism (insertion order must not affect the result)
    const sorted = [...candidates].sort((a, b) => a.id.localeCompare(b.id));

    // Compute per-candidate normalized risk and collect factors
    const perCandidateRisks: number[] = [];
    const factors: RiskFactor[] = [];

    for (const candidate of sorted) {
      const candidateRisk = computeCandidateRisk(candidate, this.weights);
      perCandidateRisks.push(candidateRisk);

      // Build a single explanatory factor per candidate (most dominant signal)
      factors.push(buildFactor(candidate, candidateRisk, this.weights));
    }

    // Complement-product global aggregation: 100 × (1 − ∏(1 − risk_i))
    const rawScore = aggregateRisks(perCandidateRisks);

    // Clamp to [0, 100] as a floating-point safety guard
    const score = clamp(rawScore, 0, 100);

    const level = resolveRiskLevel(score, this.thresholds);
    const candidateIds = sorted.map((c) => c.id);

    return {
      score,
      level,
      factors,
      candidateIds,
      summary: buildSummary(score, level, sorted),
    };
  }
}

// ── Private helpers ───────────────────────────────────────────────────────────
// These are module-private pure functions. They are not exported because they
// are implementation details of the formula — callers interact only through
// RiskEngine.assess() and the returned RiskAssessment.

/**
 * Compute the evidence agreement score for a single candidate ([0, 1]).
 *
 * Uses the complement-product formula over unique evidence items:
 *   evidenceAgreement = 1 − ∏(1 − clamp(score_j, 0, 1))
 *
 * Evidence items are deduplicated by `id` to prevent double-counting when the
 * same evidence object appears more than once in the array.
 *
 * Fallback: if no evidence items exist, returns `confidence` so that detectors
 * that don't emit structured evidence are not unfairly zeroed out.
 */
function computeEvidenceAgreement(
  evidence: readonly Evidence[],
  confidence: number,
): number {
  // Deduplicate by id — identical evidence must not be counted twice
  const seen = new Set<string>();
  const unique: Evidence[] = [];
  for (const item of evidence) {
    if (!seen.has(item.id)) {
      seen.add(item.id);
      unique.push(item);
    }
  }

  if (unique.length === 0) {
    // No structured evidence: fall back to candidate confidence
    return clamp(confidence, 0, 1);
  }

  // Complement product: probability that at least one evidence item fires
  let complementProduct = 1;
  for (const item of unique) {
    complementProduct *= 1 - clamp(item.score, 0, 1);
  }
  return 1 - complementProduct;
}

/**
 * Compute the per-candidate normalized risk in [0, 1].
 *
 *   candidateRisk = clamp(severityWeight × confidence × evidenceAgreement, 0, 1)
 */
function computeCandidateRisk(
  candidate: Candidate,
  weights: Readonly<SeverityWeights>,
): number {
  const severityWeight = resolveSeverityWeight(candidate.severity, weights);
  const confidence = clamp(candidate.confidence, 0, 1);
  const evidenceAgreement = computeEvidenceAgreement(
    candidate.evidence,
    confidence,
  );
  return clamp(severityWeight * confidence * evidenceAgreement, 0, 1);
}

/**
 * Aggregate per-candidate normalized risks into a global score using the
 * complement-product formula:
 *
 *   overallRisk = 100 × (1 − ∏(1 − candidateRisk_i))
 *
 * This is the probabilistic "at least one fires" formula. It is bounded,
 * monotonically increasing, and exhibits diminishing returns — properties
 * that make it mathematically appropriate for risk fusion.
 */
function aggregateRisks(risks: readonly number[]): number {
  if (risks.length === 0) return 0;

  let complementProduct = 1;
  for (const r of risks) {
    complementProduct *= 1 - clamp(r, 0, 1);
  }
  return 100 * (1 - complementProduct);
}

/**
 * Build a single {@link RiskFactor} for a candidate.
 *
 * The factor type reflects the most dominant signal:
 * - "severity"   when candidateRisk ≥ 0.5   (severity is the primary driver)
 * - "confidence" when candidateRisk ≥ 0.2   (confidence is the limiting factor)
 * - "evidence"   otherwise                  (evidence quality is the weak link)
 *
 * `contribution` is the per-candidate normalized risk scaled to 100. This is
 * an EXPLANATORY attribution value — not an additive component of the overall
 * score. See module-level documentation for details.
 */
function buildFactor(
  candidate: Candidate,
  candidateRisk: number,
  weights: Readonly<SeverityWeights>,
): RiskFactor {
  const severityWeight = resolveSeverityWeight(candidate.severity, weights);
  const contribution = clamp(candidateRisk * 100, 0, 100);

  // Select the most descriptive factor type based on the dominant signal
  let type: RiskFactor["type"];
  let explanation: string;

  if (candidateRisk >= 0.5) {
    type = "severity";
    explanation =
      `Candidate severity is '${candidate.severity}' (weight ${severityWeight.toFixed(2)}), ` +
      `subtype: ${candidate.subtype}`;
  } else if (candidateRisk >= 0.2) {
    type = "confidence";
    explanation =
      `Detector confidence: ${candidate.confidence.toFixed(3)}, ` +
      `severity '${candidate.severity}' (weight ${severityWeight.toFixed(2)})`;
  } else {
    const uniqueCount = new Set(candidate.evidence.map((e) => e.id)).size;
    type = "evidence";
    explanation =
      `Low combined risk — evidence sources: ${uniqueCount}, ` +
      `confidence: ${candidate.confidence.toFixed(3)}, ` +
      `severity: '${candidate.severity}'`;
  }

  return {
    candidateId: candidate.id,
    type,
    contribution,
    explanation,
  };
}

/**
 * Build a human-readable summary string for a {@link RiskAssessment}.
 */
function buildSummary(
  score: number,
  level: string,
  candidates: readonly Candidate[],
): string {
  const count = candidates.length;
  const highestSeverity = resolveHighestSeverity(candidates);
  const scoreStr = score.toFixed(1);
  return (
    `${capitalize(level)} risk (score: ${scoreStr}): ` +
    `${count} candidate(s) detected — highest severity: ${highestSeverity}.`
  );
}

/**
 * Zero-risk assessment returned when no candidates are assessed.
 */
function buildZeroAssessment(): RiskAssessment {
  return {
    score: 0,
    level: "low",
    factors: [],
    candidateIds: [],
    summary: "No candidates detected.",
  };
}

/**
 * Resolve the numeric weight for a {@link Severity} value.
 */
function resolveSeverityWeight(
  severity: Severity,
  weights: Readonly<SeverityWeights>,
): number {
  switch (severity) {
    case "low":
      return weights.low;
    case "medium":
      return weights.medium;
    case "high":
      return weights.high;
    case "critical":
      return weights.critical;
  }
}

/**
 * Find the highest severity level among a list of candidates.
 * Order: critical > high > medium > low.
 */
function resolveHighestSeverity(candidates: readonly Candidate[]): Severity {
  const order: Record<Severity, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3,
  };
  let best: Severity = "low";
  for (const c of candidates) {
    if ((order[c.severity] ?? 0) > (order[best] ?? 0)) {
      best = c.severity;
    }
  }
  return best;
}

/**
 * Clamp a number to the inclusive range [min, max].
 */
function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Capitalize the first character of a string.
 */
function capitalize(str: string): string {
  if (str.length === 0) return str;
  return str[0]!.toUpperCase() + str.slice(1);
}
