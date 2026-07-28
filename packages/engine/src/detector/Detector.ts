/**
 * @file Detector.ts
 * @module @promptwall/engine/detector
 *
 * Defines the core plugin interface for the detection framework.
 *
 * Every detection algorithm — regex, GLiNER, entropy, OCR, AST, LLM, or custom
 * enterprise plugin — implements this single interface. The registry treats all
 * implementations identically, enabling zero-change extensibility.
 *
 * Implementation contract (enforced by documentation, not types):
 * - `detect()` MUST NOT throw. Catch all internal errors and return `[]`.
 * - `detect()` MUST honour `signal` cancellation at natural yield points.
 * - `detect()` MUST be stateless and safe for concurrent calls.
 * - `supports()` MUST be synchronous, cheap, and side-effect free.
 */

import type { Candidate } from "../candidate/Candidate";
import type { DetectionRequest } from "./DetectionRequest";

// ── DetectorCapabilities ──────────────────────────────────────────────────────

/**
 * Declarative descriptor of what content types a detector can process
 * and what runtime capabilities it exposes.
 *
 * The {@link DetectorRegistry} reads `capabilities` via the `supports()` pre-flight
 * check before dispatching each detector. Detectors that return `false` from
 * `supports()` are skipped and recorded as warnings — they never enter the pipeline.
 *
 * Absence of a constraint (empty array or `undefined`) means the detector accepts
 * all values for that dimension.
 */
export interface DetectorCapabilities {
  /**
   * MIME types this detector can process.
   * An empty array or `undefined` means the detector accepts any MIME type.
   * @example ["text/plain", "application/json"]
   * @example ["image/png", "image/jpeg"]  // for OCR detectors
   */
  readonly supportedMimeTypes?: readonly string[];

  /**
   * Language identifiers (BCP-47 or IANA programming language names) this detector
   * understands. An empty array or `undefined` means the detector is language-agnostic.
   * @example ["en", "fr"]
   * @example ["typescript", "javascript", "python"]
   */
  readonly supportedLanguages?: readonly string[];

  /**
   * Whether this detector can operate on streaming (chunked) content.
   * Streaming support is not used in Milestone 1 but declared here to prevent
   * a future breaking interface change.
   */
  readonly supportsStreaming: boolean;

  /**
   * Whether this detector can process binary-encoded content.
   * Binary detectors must handle base64-encoded input in `content`.
   */
  readonly supportsBinary: boolean;

  /**
   * Execution priority hint for ordered (sequential) execution modes.
   * Lower values signal higher priority (run first). The parallel registry
   * uses this for result ordering in future milestones.
   *
   * Convention:
   * - 0–99:   Critical path (blocking) detectors
   * - 100–199: Standard detectors (default range)
   * - 200+:   Advisory or low-priority detectors
   *
   * @default 100
   */
  readonly priority: number;
}

// ── Detector ─────────────────────────────────────────────────────────────────

/**
 * The core plugin interface every detection algorithm must implement.
 *
 * @example Minimal implementation
 * ```ts
 * class MyDetector implements Detector {
 *   readonly id = "my-detector";
 *   readonly displayName = "My Custom Detector";
 *   readonly version = "1.0.0";
 *   readonly capabilities: DetectorCapabilities = {
 *     supportsStreaming: false,
 *     supportsBinary: false,
 *     priority: 100,
 *   };
 *
 *   supports(request: DetectionRequest): boolean {
 *     return request.mimeType === "text/plain" || !request.mimeType;
 *   }
 *
 *   async detect(request: DetectionRequest, signal?: AbortSignal): Promise<Candidate[]> {
 *     if (signal?.aborted) return [];
 *     // ... detection logic ...
 *     return candidates;
 *   }
 * }
 * ```
 */
export interface Detector {
  /**
   * Stable, unique machine identifier for this detector.
   * Must remain constant across restarts and deployments — used as registry key
   * and in audit logs.
   *
   * Convention: kebab-case, namespaced for plugins.
   * @example "aws-key-regex"
   * @example "gliner-ner-v2"
   * @example "enterprise.acme.credit-card-validator"
   */
  readonly id: string;

  /** Human-readable name for dashboards, logs, and error messages. */
  readonly displayName: string;

  /**
   * Semantic version (SemVer) of this detector implementation.
   * Used in audit trails and canary deployments.
   * @example "1.0.0", "2.3.1-beta"
   */
  readonly version: string;

  /** Declares supported content types and runtime capabilities. */
  readonly capabilities: DetectorCapabilities;

  /**
   * Synchronous pre-flight compatibility check.
   *
   * The registry calls `supports()` before dispatch. Return `false` to opt out
   * of a request without consuming a timeout slot or producing an error.
   *
   * This method must:
   * - Be synchronous (no I/O, no async)
   * - Be cheap (O(1) field comparisons)
   * - Never throw
   *
   * @param request - The incoming detection request to evaluate.
   * @returns `true` if this detector can handle the request; `false` to skip.
   */
  supports(request: DetectionRequest): boolean;

  /**
   * Analyse the request and return zero or more detected candidates.
   *
   * @param request - Immutable detection input. Never mutate this object.
   * @param signal  - Optional AbortSignal for cooperative cancellation.
   *   Detectors should check `signal.aborted` at natural async yield points
   *   and resolve early with `[]` if cancelled. This prevents resource leaks
   *   when the registry's timeout fires.
   *
   * @returns A (possibly empty) array of {@link Candidate}s. Never rejects.
   */
  detect(request: DetectionRequest, signal?: AbortSignal): Promise<Candidate[]>;
}
