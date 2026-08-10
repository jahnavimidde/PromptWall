/**
 * @file RiskLevel.ts
 * @module @promptwall/engine/risk
 *
 * Defines the RiskLevel discriminated union and the configurable threshold
 * map that maps a numeric risk score [0, 100] to a named level.
 *
 * Thresholds are expressed as the **minimum score** required to reach that
 * level. They are configurable via {@link RiskThresholds} so that operators
 * can tune sensitivity without touching engine code.
 */

// ── RiskLevel ─────────────────────────────────────────────────────────────────

/**
 * Categorical risk classification, ordered from least to most severe.
 *
 * | Level    | Default score range |
 * |----------|---------------------|
 * | low      | 0 – 29              |
 * | medium   | 30 – 59             |
 * | high     | 60 – 79             |
 * | critical | 80 – 100            |
 */
export type RiskLevel = "low" | "medium" | "high" | "critical";

// ── RiskThresholds ─────────────────────────────────────────────────────────────

/**
 * Minimum score (inclusive) required to reach each {@link RiskLevel}.
 *
 * Resolution algorithm:
 *   score ≥ critical  → "critical"
 *   score ≥ high      → "high"
 *   score ≥ medium    → "medium"
 *   otherwise         → "low"
 *
 * All values must satisfy: 0 ≤ medium < high < critical ≤ 100.
 */
export interface RiskThresholds {
  /** Minimum score to classify as "medium". @default 30 */
  readonly medium: number;
  /** Minimum score to classify as "high". @default 60 */
  readonly high: number;
  /** Minimum score to classify as "critical". @default 80 */
  readonly critical: number;
}

/**
 * Default thresholds aligned with the Milestone 2A specification.
 *
 * 0–29   → low
 * 30–59  → medium
 * 60–79  → high
 * 80–100 → critical
 */
export const DEFAULT_RISK_THRESHOLDS: Readonly<RiskThresholds> = {
  medium: 30,
  high: 60,
  critical: 80,
} as const;

// ── Resolver ──────────────────────────────────────────────────────────────────

/**
 * Resolve a numeric score [0, 100] to a {@link RiskLevel} using the supplied
 * (or default) thresholds.
 *
 * The input score is expected to be clamped before this call; this function
 * does not clamp internally so that callers have full observability.
 *
 * @param score      - Numeric risk score in [0, 100].
 * @param thresholds - Threshold configuration (defaults applied if absent).
 * @returns The matching {@link RiskLevel}.
 */
export function resolveRiskLevel(
  score: number,
  thresholds: RiskThresholds = DEFAULT_RISK_THRESHOLDS,
): RiskLevel {
  if (score >= thresholds.critical) return "critical";
  if (score >= thresholds.high) return "high";
  if (score >= thresholds.medium) return "medium";
  return "low";
}
