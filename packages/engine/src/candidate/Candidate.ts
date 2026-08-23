/**
 * @file Candidate.ts
 * @module @promptwall/engine/candidate
 *
 * Defines the Candidate model — the central output type of the detection framework.
 *
 * A Candidate represents a single detected entity in the source content.
 * It is immutable: detectors create candidates; post-processors (ConfidenceEngine,
 * CandidateGraph) produce new Candidate objects via spread rather than mutation.
 */

import type { Evidence } from "./Evidence";

// ── Location ─────────────────────────────────────────────────────────────────

/**
 * Character-level and structural position of a detected entity within source content.
 *
 * `start` and `end` are character offsets into the flat string content.
 * For structured formats (JSON, XML), `path` provides a dotted accessor.
 */
export interface Location {
  /** Inclusive start offset (0-indexed character position). */
  readonly start: number;
  /** Exclusive end offset (0-indexed character position). */
  readonly end: number;
  /** 1-indexed line number, when the source content has line structure. */
  readonly line?: number;
  /** 0-indexed column offset within the line, when known. */
  readonly column?: number;
  /**
   * Dotted accessor path for structured content.
   * @example "messages[0].content"
   * @example "request.body.user.email"
   */
  readonly path?: string;
}

// ── Enumerations ─────────────────────────────────────────────────────────────

/**
 * High-level detection category. Broad enough to remain stable as detection
 * capabilities expand. Use `subtype` for granular classification.
 */
export type CandidateCategory =
  | "pii" //       Personally Identifiable Information
  | "secret" //    API keys, tokens, passwords, certificates
  | "sensitive" // Confidential but not strictly PII or secret
  | "malicious" // Prompt injection, jailbreak attempts, adversarial inputs
  | "custom"; //   Enterprise plugin categories

/**
 * Risk severity of the detected entity.
 * Assigned by the originating detector; may be adjusted by the risk engine
 * in future milestones.
 */
export type Severity = "low" | "medium" | "high" | "critical";

// ── Candidate ─────────────────────────────────────────────────────────────────

/**
 * A single detected entity with its full provenance chain.
 *
 * Candidates are produced by {@link Detector}s, accumulated in {@link CandidateGraph},
 * and scored by {@link ConfidenceEngine}. Every field is readonly; post-processors
 * use object spread (`{ ...candidate, confidence: newScore }`) for updates.
 *
 * @example
 * ```ts
 * const candidate: Candidate = {
 *   id: "550e8400-e29b-41d4-a716-446655440000",
 *   category: "secret",
 *   subtype: "AWS_ACCESS_KEY",
 *   value: "AKIAIOSFODNN7EXAMPLE",
 *   normalizedValue: "akiaiosfodnn7example",
 *   location: { start: 42, end: 62 },
 *   confidence: 0.97,
 *   severity: "critical",
 *   detector: "aws-key-regex",
 *   evidence: [...],
 *   metadata: { keyPrefix: "AKIA" },
 * };
 * ```
 */
export interface Candidate {
  /** Globally unique identifier (UUID v4). Stable across pipeline stages. */
  readonly id: string;

  /** High-level detection category. */
  readonly category: CandidateCategory;

  /**
   * Fine-grained type within the category.
   * Use SCREAMING_SNAKE_CASE by convention.
   * @example "AWS_ACCESS_KEY", "CREDIT_CARD", "EMAIL_ADDRESS", "PROMPT_INJECTION"
   */
  readonly subtype: string;

  /**
   * Raw matched value exactly as it appears in the source content.
   * Handle with care — this is the sensitive data itself.
   */
  readonly value: string;

  /**
   * Canonical normalized form for deduplication and comparison.
   * Transformation rules are detector-defined (e.g. lowercase, strip whitespace,
   * remove dashes from credit card numbers).
   */
  readonly normalizedValue: string;

  /** Position of the entity within the source content. */
  readonly location: Location;

  /**
   * Aggregated confidence score in [0.0, 1.0].
   * Initially set by the originating detector; updated by {@link ConfidenceEngine}.
   */
  readonly confidence: number;

  /** Risk severity classification. */
  readonly severity: Severity;

  /** `id` of the {@link Detector} that originated this candidate. */
  readonly detector: string;

  /**
   * All evidence items contributing to this candidate.
   * The initial array contains evidence from the originating detector.
   * Evidence aggregation across detectors is handled in future milestones.
   */
  readonly evidence: readonly Evidence[];

  /**
   * Detector-specific key-value metadata for audit and downstream processing.
   * Callers must not mutate this object.
   */
  readonly metadata: Readonly<Record<string, unknown>>;
}
