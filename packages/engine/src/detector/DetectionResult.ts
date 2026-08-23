/**
 * @file DetectionResult.ts
 * @module @promptwall/engine/detector
 *
 * Defines the aggregated output of a full DetectorRegistry detection run.
 *
 * DetectionResult is a value object — fully readonly, no methods. It carries
 * the resolved candidates, timing breakdowns, per-detector statistics, and
 * any non-fatal errors or warnings that occurred during the pipeline.
 */

import type { Candidate } from "../candidate/Candidate";

// ── Supporting types ──────────────────────────────────────────────────────────

/**
 * Execution statistics collected by {@link DetectorRegistry} for a single
 * detector during one detection run.
 */
export interface DetectorStats {
  /** The `id` of the detector this record describes. */
  readonly detectorId: string;
  /** Number of {@link Candidate}s returned by this detector. */
  readonly candidatesFound: number;
  /** Wall-clock time from dispatch to settled result, in milliseconds. */
  readonly executionTimeMs: number;
  /**
   * `true` when the detector exceeded its time budget and was cancelled.
   * Candidates from this detector are excluded from the result set.
   */
  readonly timedOut: boolean;
  /**
   * `true` when the detector threw an unhandled error.
   * The error is captured in {@link DetectionResult.errors}.
   */
  readonly errored: boolean;
}

/**
 * Structured error produced when a detector throws during execution.
 * The registry catches and isolates these — they never propagate to the caller.
 */
export interface DetectionError {
  /** The `id` of the detector that produced this error. */
  readonly detectorId: string;
  /** Human-readable error description. */
  readonly message: string;
  /** The original thrown value, preserved for stack trace access. */
  readonly cause?: unknown;
}

/**
 * Non-fatal advisory emitted during a detection run.
 * Examples: detector skipped due to MIME type mismatch, content truncated.
 */
export interface DetectionWarning {
  /** The `id` of the detector this warning relates to. */
  readonly detectorId: string;
  /** Human-readable warning message. */
  readonly message: string;
}

// ── DetectionResult ───────────────────────────────────────────────────────────

/**
 * The complete, immutable output of {@link DetectorRegistry.detect}.
 *
 * Timing breakdown:
 * ```
 * executionTimeMs
 * └── pipelineExecutionTime   (parallel detector dispatch + settle)
 *     post-processing         (graph resolution + confidence scoring)
 *                              = executionTimeMs − pipelineExecutionTime
 * ```
 */
export interface DetectionResult {
  /**
   * Final resolved candidates after {@link CandidateGraph} processing and
   * {@link ConfidenceEngine} scoring. Ordered by confidence descending.
   */
  readonly candidates: readonly Candidate[];

  /**
   * Total wall-clock time for the entire `detect()` call (ms).
   * Includes detector dispatch, graph resolution, and confidence scoring.
   */
  readonly executionTimeMs: number;

  /**
   * Time spent running detectors in parallel, from first dispatch to last
   * settled result (ms). Excludes post-processing overhead.
   *
   * `executionTimeMs − pipelineExecutionTime` gives the graph + scoring overhead.
   */
  readonly pipelineExecutionTime: number;

  /**
   * Snapshot of the registry's structural version at the moment `detect()` was called.
   * Increments each time a detector is registered or unregistered.
   * Useful for cache invalidation and audit trails.
   */
  readonly registryVersion: number;

  /** Per-detector execution statistics. One entry per supported (non-skipped) detector. */
  readonly detectorStats: readonly DetectorStats[];

  /**
   * Errors captured from detectors that threw during execution.
   * The pipeline continues with remaining detectors — errors never abort the run.
   */
  readonly errors: readonly DetectionError[];

  /**
   * Non-fatal advisories such as skipped detectors or truncated content.
   */
  readonly warnings: readonly DetectionWarning[];
}
