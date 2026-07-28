/**
 * @file Evidence.ts
 * @module @promptwall/engine/candidate
 *
 * Defines the Evidence model — the atomic unit of detection signal contributed
 * by a single detector component or algorithm.
 *
 * Evidence is immutable by design. Detectors create evidence; they never update it.
 * Aggregation (if needed) produces new Evidence objects.
 */

/**
 * Well-known evidence source identifiers for first-party detectors.
 *
 * The `string & Record<never, never>` intersection preserves autocomplete for
 * the listed literals while allowing arbitrary custom source strings for
 * third-party and enterprise plugin detectors.
 */
export type EvidenceSource =
  | "regex"
  | "gliner"
  | "entropy"
  | "secret_detector"
  | "ocr"
  | "ast"
  | "llm"
  | "validator"
  // Allow arbitrary custom strings without losing autocomplete on the above.
  // eslint-disable-next-line @typescript-eslint/ban-types
  | (string & {});

/**
 * A single piece of evidence contributed by a detector component.
 *
 * Multiple Evidence items accumulate on a {@link Candidate} to form a
 * multi-signal detection. The ConfidenceEngine uses `score` and
 * `confidenceContribution` to compute the candidate's final confidence.
 *
 * @example
 * ```ts
 * const evidence: Evidence = {
 *   id: "550e8400-e29b-41d4-a716-446655440000",
 *   source: "regex",
 *   label: "Matched AWS Access Key pattern",
 *   score: 0.98,
 *   confidenceContribution: 0.6,
 *   detail: "AKIA...",
 * };
 * ```
 */
export interface Evidence {
  /** Unique identifier for this evidence item (UUID v4). */
  readonly id: string;

  /**
   * The algorithm or component that produced this evidence.
   * Use one of the {@link EvidenceSource} literals for first-party detectors,
   * or a namespaced custom string (e.g. `"enterprise.acme-validator"`) for plugins.
   */
  readonly source: EvidenceSource;

  /**
   * Human-readable description of what was observed.
   * @example "Matched AWS Access Key pattern"
   * @example "GLiNER classified as PERSON with 0.94 score"
   * @example "Luhn checksum passed"
   */
  readonly label: string;

  /**
   * Raw confidence score produced by this evidence source (0.0–1.0).
   * Independent of the candidate's aggregated confidence.
   */
  readonly score: number;

  /**
   * Relative weight this evidence item contributes toward the candidate's
   * final confidence score when using weighted aggregation.
   *
   * Convention:
   * - Values across all evidence items for a candidate should sum to 1.0.
   * - When absent, the ConfidenceEngine defaults to equal weighting.
   * - A value of 0.0 means the evidence is informational only.
   *
   * @example 0.6  // regex pattern match carries 60% of confidence weight
   * @example 0.4  // entropy check carries 40% of confidence weight
   */
  readonly confidenceContribution?: number;

  /**
   * Raw matched text, extracted value, or algorithm rationale.
   * Intended for audit logs and human review — never use in security decisions.
   */
  readonly detail?: string;

  /** Evidence-specific key-value metadata for audit and debugging. */
  readonly metadata?: Readonly<Record<string, unknown>>;
}
