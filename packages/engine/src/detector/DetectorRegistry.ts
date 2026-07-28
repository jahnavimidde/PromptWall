/**
 * @file DetectorRegistry.ts
 * @module @promptwall/engine/detector
 *
 * Central orchestrator for plugin-based detection.
 *
 * The registry manages a collection of {@link Detector}s and executes them
 * in parallel for each incoming {@link DetectionRequest}. It guarantees:
 *
 * - **Isolation**: one detector's failure never prevents others from running.
 * - **Timeout**: each detector races against a per-call AbortController.
 * - **Pre-flight**: `supports()` is checked synchronously before dispatch.
 * - **Observability**: per-detector stats, errors, and warnings are always returned.
 *
 * Design: not a singleton. Instantiate one per application boundary, HTTP handler,
 * or test suite. Inject via constructor for testability.
 */

import type { Candidate } from "../candidate/Candidate";
import type { Detector } from "./Detector";
import type { DetectionRequest } from "./DetectionRequest";
import type {
  DetectionError,
  DetectionResult,
  DetectionWarning,
  DetectorStats,
} from "./DetectionResult";

// ── Configuration ─────────────────────────────────────────────────────────────

/**
 * Constructor-level configuration for {@link DetectorRegistry}.
 * All fields are optional; defaults are chosen for a production deployment.
 */
export interface DetectorRegistryOptions {
  /**
   * Default time budget per detector, in milliseconds.
   * A detector that does not resolve within this window is cancelled via
   * AbortSignal and counted as `timedOut` in {@link DetectorStats}.
   * @default 5000
   */
  readonly defaultTimeoutMs?: number;

  /**
   * Starting value for the registry's structural version counter.
   * Useful in tests to assert version increments from a known baseline.
   * @default 1
   */
  readonly initialVersion?: number;
}

/**
 * Per-call options that override constructor defaults for a single `detect()` run.
 */
export interface DetectOptions {
  /**
   * Override the per-detector timeout for this call only (ms).
   * Useful for low-latency paths that need a tighter budget.
   */
  readonly timeoutMs?: number;
}

// ── Internal types ─────────────────────────────────────────────────────────────

/** Return type of the internal per-detector runner. */
interface RunResult {
  readonly candidates: readonly Candidate[];
  readonly executionTimeMs: number;
  readonly timedOut: boolean;
}

// ── DetectorRegistry ──────────────────────────────────────────────────────────

/**
 * Manages registered {@link Detector}s and runs them in parallel.
 *
 * @example
 * ```ts
 * const registry = new DetectorRegistry({ defaultTimeoutMs: 3000 });
 * registry.register(new MyRegexDetector());
 * registry.register(new MyEntropyDetector());
 *
 * const result = await registry.detect({ content: "..." });
 * console.log(result.candidates);
 * ```
 */
export class DetectorRegistry {
  private readonly detectors = new Map<string, Detector>();
  private readonly defaultTimeoutMs: number;
  private version: number;

  constructor(options: DetectorRegistryOptions = {}) {
    this.defaultTimeoutMs = options.defaultTimeoutMs ?? 5_000;
    this.version = options.initialVersion ?? 1;
  }

  // ── Structural operations ──────────────────────────────────────────────────

  /**
   * Register a detector. The detector's `id` must be unique in this registry.
   * Throws synchronously if a detector with the same `id` is already registered.
   * Increments {@link currentVersion}.
   *
   * @throws {Error} If a detector with the same `id` is already registered.
   */
  register(detector: Detector): void {
    if (this.detectors.has(detector.id)) {
      throw new Error(
        `DetectorRegistry: detector "${detector.id}" is already registered. ` +
          `Call unregister("${detector.id}") first if you intend to replace it.`,
      );
    }
    this.detectors.set(detector.id, detector);
    this.version += 1;
  }

  /**
   * Remove a registered detector by its `id`.
   * Throws synchronously if the detector is not registered.
   * Increments {@link currentVersion}.
   *
   * @throws {Error} If no detector with this `id` is registered.
   */
  unregister(id: string): void {
    if (!this.detectors.has(id)) {
      throw new Error(
        `DetectorRegistry: cannot unregister "${id}" — no such detector is registered.`,
      );
    }
    this.detectors.delete(id);
    this.version += 1;
  }

  /** Returns `true` if a detector with this `id` is currently registered. */
  has(id: string): boolean {
    return this.detectors.has(id);
  }

  /**
   * Returns an ordered snapshot of all registered detectors.
   * The array is a copy; mutations do not affect the registry.
   */
  list(): readonly Detector[] {
    return Array.from(this.detectors.values());
  }

  /**
   * Current structural version of this registry.
   * Increments each time a detector is registered or unregistered.
   * Snapshotted into {@link DetectionResult.registryVersion} on each `detect()` call.
   */
  get currentVersion(): number {
    return this.version;
  }

  // ── Detection pipeline ─────────────────────────────────────────────────────

  /**
   * Execute all compatible detectors in parallel and return aggregated results.
   *
   * **Pipeline steps:**
   * 1. **Pre-flight** — call `supports(request)` on every registered detector.
   *    Incompatible detectors are skipped and recorded as {@link DetectionWarning}s.
   * 2. **Dispatch** — run supported detectors concurrently via `Promise.allSettled`.
   *    Each detector races against a per-instance {@link AbortController} timeout.
   * 3. **Collect** — fulfilled results contribute candidates and stats.
   *    Rejected results (errors) are captured in {@link DetectionResult.errors}.
   *    Timed-out detectors are marked `timedOut: true` in stats and excluded from candidates.
   * 4. **Return** — a complete {@link DetectionResult} is always returned, even when
   *    all detectors fail or time out.
   *
   * @param request - The detection input.
   * @param options - Per-call overrides (e.g. tighter timeout).
   */
  async detect(
    request: DetectionRequest,
    options: DetectOptions = {},
  ): Promise<DetectionResult> {
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const registryVersion = this.version;
    const wallStart = Date.now();

    const allDetectors = Array.from(this.detectors.values());

    // Step 1: pre-flight
    const { supported, skipped } = this.partitionBySupport(allDetectors, request);

    const warnings: DetectionWarning[] = skipped.map((d) => ({
      detectorId: d.id,
      message:
        `Detector "${d.displayName}" (${d.id}) was skipped: ` +
        `supports() returned false for this request.`,
    }));

    // Step 2: parallel dispatch
    const pipelineStart = Date.now();
    const settled = await Promise.allSettled(
      supported.map((detector) => this.runWithTimeout(detector, request, timeoutMs)),
    );
    const pipelineExecutionTime = Date.now() - pipelineStart;

    // Step 3: collect — zip settled results with their corresponding detectors
    const allCandidates: Candidate[] = [];
    const detectorStats: DetectorStats[] = [];
    const errors: DetectionError[] = [];

    const pairs = supported.map((detector, i) => ({
      detector,
      // settled.length === supported.length by construction; cast is safe
      outcome: settled[i] as PromiseSettledResult<RunResult>,
    }));

    for (const { detector, outcome } of pairs) {
      if (outcome.status === "fulfilled") {
        const { candidates, executionTimeMs, timedOut } = outcome.value;
        if (!timedOut) {
          allCandidates.push(...candidates);
        }
        detectorStats.push({
          detectorId: detector.id,
          candidatesFound: timedOut ? 0 : candidates.length,
          executionTimeMs,
          timedOut,
          errored: false,
        });
      } else {
        // outcome.status === "rejected" — isolate the error
        const cause: unknown = outcome.reason;
        const message = cause instanceof Error ? cause.message : String(cause);
        errors.push({ detectorId: detector.id, message, cause });
        detectorStats.push({
          detectorId: detector.id,
          candidatesFound: 0,
          executionTimeMs: timeoutMs,
          timedOut: false,
          errored: true,
        });
      }
    }

    return {
      candidates: allCandidates,
      executionTimeMs: Date.now() - wallStart,
      pipelineExecutionTime,
      registryVersion,
      detectorStats,
      errors,
      warnings,
    };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  /**
   * Partition detectors into those that support the request and those that don't.
   * Calls `supports()` synchronously on each detector. Any thrown error from
   * `supports()` is treated as a non-support (detector is skipped with a warning).
   */
  private partitionBySupport(
    detectors: Detector[],
    request: DetectionRequest,
  ): { supported: Detector[]; skipped: Detector[] } {
    const supported: Detector[] = [];
    const skipped: Detector[] = [];

    for (const d of detectors) {
      let doesSupport: boolean;
      try {
        doesSupport = d.supports(request);
      } catch {
        // supports() must not throw, but we protect the registry regardless
        doesSupport = false;
      }
      (doesSupport ? supported : skipped).push(d);
    }

    return { supported, skipped };
  }

  /**
   * Run a single detector with an AbortController-backed timeout.
   *
   * Returns a fulfilled RunResult in all cases:
   * - Normal completion: `{ candidates, executionTimeMs, timedOut: false }`
   * - Timeout: `{ candidates: [], executionTimeMs, timedOut: true }`
   *
   * Non-timeout errors are re-thrown so `Promise.allSettled` captures them.
   */
  private async runWithTimeout(
    detector: Detector,
    request: DetectionRequest,
    timeoutMs: number,
  ): Promise<RunResult> {
    const controller = new AbortController();
    const start = Date.now();
    let timeoutId: ReturnType<typeof setTimeout> | undefined;

    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(() => {
        controller.abort();
        reject(new DetectorTimeoutError(detector.id, timeoutMs));
      }, timeoutMs);
    });

    try {
      const candidates = await Promise.race([
        detector.detect(request, controller.signal),
        timeoutPromise,
      ]);
      return { candidates, executionTimeMs: Date.now() - start, timedOut: false };
    } catch (err) {
      if (err instanceof DetectorTimeoutError) {
        // Timeout: return a safe result, do not throw
        return { candidates: [], executionTimeMs: Date.now() - start, timedOut: true };
      }
      // Detector-thrown error: re-throw so allSettled records it as rejected
      throw err;
    } finally {
      // Always clean up: cancel the timeout timer and signal the detector
      clearTimeout(timeoutId);
      controller.abort();
    }
  }
}

// ── Errors ────────────────────────────────────────────────────────────────────

/**
 * Thrown internally by the registry when a detector exceeds its time budget.
 * Never escapes the registry — caught in `runWithTimeout` and converted to stats.
 */
export class DetectorTimeoutError extends Error {
  /** The `id` of the detector that timed out. */
  readonly detectorId: string;
  /** The timeout duration that was exceeded (ms). */
  readonly timeoutMs: number;

  constructor(detectorId: string, timeoutMs: number) {
    super(`Detector "${detectorId}" exceeded its ${timeoutMs}ms time budget.`);
    this.name = "DetectorTimeoutError";
    this.detectorId = detectorId;
    this.timeoutMs = timeoutMs;
  }
}
