/**
 * @file ConfidenceEngine.ts
 * @module @promptwall/engine/confidence
 *
 * Applies a pluggable {@link ConfidenceScorer} to a collection of candidates,
 * producing updated Candidate objects with recalculated confidence scores.
 *
 * Current behaviour (Milestone 1): identity pass-through. The scorer returns
 * each candidate's existing confidence unchanged.
 *
 * Future milestones will replace the default scorer with weighted evidence
 * aggregation, Bayesian updating, ML-calibrated rescoring, and confidence decay
 * based on location overlap.
 *
 * Design principles:
 * - Immutable update: never mutates input candidates; always spreads into new objects.
 * - Pluggable scorer: swap strategy without changing the engine's callers.
 * - Score clamping: output is always in [0.0, 1.0] regardless of scorer behaviour.
 */

import type { Candidate } from "../candidate/Candidate";
import type { DetectionRequest } from "../detector/DetectionRequest";

// ── ScoringContext ─────────────────────────────────────────────────────────────

/**
 * Contextual information supplied to a {@link ConfidenceScorer} for each
 * scoring call. Enables cross-candidate reasoning (e.g. co-occurrence boosts).
 *
 * Future milestones will enrich this with:
 * - Document-level risk scores
 * - Co-occurrence frequency statistics
 * - Cross-detector agreement/disagreement signals
 * - User-defined risk policies
 */
export interface ScoringContext {
  /** All candidates in scope for this scoring pass (read-only snapshot). */
  readonly allCandidates: readonly Candidate[];
  /** The original detection request that produced these candidates. */
  readonly request: DetectionRequest;
}

// ── ConfidenceScorer ──────────────────────────────────────────────────────────

/**
 * Strategy interface for confidence scoring algorithms.
 *
 * Implement this to plug in custom scoring logic:
 * - Weighted evidence aggregation (use `candidate.evidence` and `confidenceContribution`)
 * - Bayesian updating across multiple detector signals
 * - Risk-calibrated rescoring against a policy
 * - ML-based confidence normalisation
 *
 * Contract:
 * - Must return a number. The engine clamps the result to [0.0, 1.0].
 * - Must not mutate `candidate` or `context`.
 * - Must not throw. Exceptions propagate to the caller.
 *
 * @example Custom weighted scorer (future milestone)
 * ```ts
 * class WeightedEvidenceScorer implements ConfidenceScorer {
 *   score(candidate: Candidate): number {
 *     const items = candidate.evidence.filter(e => e.confidenceContribution !== undefined);
 *     return items.reduce((acc, e) => acc + e.score * (e.confidenceContribution ?? 0), 0);
 *   }
 * }
 * ```
 */
export interface ConfidenceScorer {
  /**
   * Compute a confidence score for a single candidate.
   *
   * @param candidate - The candidate to score. Do not mutate.
   * @param context   - Scoring context for cross-candidate reasoning.
   * @returns         - A confidence value. Will be clamped to [0.0, 1.0] by the engine.
   */
  score(candidate: Candidate, context: ScoringContext): number;
}

// ── PassthroughConfidenceScorer ───────────────────────────────────────────────

/**
 * Identity scorer — returns each candidate's existing confidence unchanged.
 * Shipped as the default until a real scoring strategy is configured.
 */
export class PassthroughConfidenceScorer implements ConfidenceScorer {
  score(candidate: Candidate, _context: ScoringContext): number {
    return candidate.confidence;
  }
}

// ── ConfidenceEngine ──────────────────────────────────────────────────────────

/**
 * Applies a {@link ConfidenceScorer} to a collection of candidates and
 * returns new Candidate objects with updated confidence values.
 *
 * Usage:
 * ```ts
 * const engine = new ConfidenceEngine(); // uses PassthroughConfidenceScorer
 * const scored = engine.apply(rawCandidates, request);
 *
 * // With custom scorer:
 * const engine = new ConfidenceEngine(new WeightedEvidenceScorer());
 * ```
 *
 * Extension points (future milestones):
 * - Multi-pass scoring pipeline (evidence weighting → calibration → normalisation)
 * - Confidence band enforcement (hard floor/ceiling per category or severity)
 * - Confidence decay for candidates with overlapping locations
 */
export class ConfidenceEngine {
  private readonly scorer: ConfidenceScorer;

  constructor(scorer: ConfidenceScorer = new PassthroughConfidenceScorer()) {
    this.scorer = scorer;
  }

  /**
   * Score every candidate and return new Candidate objects with updated confidence.
   *
   * Input is never mutated. Each output object is a shallow spread of the input
   * with only `confidence` replaced by the scorer's result (clamped to [0.0, 1.0]).
   *
   * @param candidates - Candidates to score. Ordering is preserved.
   * @param request    - The originating detection request, passed to the scorer context.
   * @returns New Candidate array with updated confidence values.
   */
  apply(candidates: readonly Candidate[], request: DetectionRequest): Candidate[] {
    const context: ScoringContext = {
      allCandidates: candidates,
      request,
    };

    return candidates.map((candidate) => {
      const rawScore = this.scorer.score(candidate, context);
      return {
        ...candidate,
        confidence: clampScore(rawScore),
      };
    });
  }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/**
 * Clamp a raw scorer output to the valid confidence range [0.0, 1.0].
 * Protects against scorer bugs that return negative or > 1.0 values.
 */
function clampScore(score: number): number {
  return Math.min(1.0, Math.max(0.0, score));
}
