/**
 * @file HangingDetector.ts
 * @module @promptwall/engine/testing
 *
 * A {@link Detector} that never resolves unless its AbortSignal fires.
 * Used to verify the registry's timeout and cancellation behaviour.
 *
 * When the registry's per-detector timeout expires, it aborts the signal,
 * which causes this detector to resolve with `[]`. The registry then marks
 * the detector as `timedOut: true` in {@link DetectorStats}.
 *
 * Do NOT use in production.
 */

import type { Candidate } from "../candidate/Candidate";
import type { Detector, DetectorCapabilities } from "../detector/Detector";
import type { DetectionRequest } from "../detector/DetectionRequest";

/**
 * Simulates a detector that hangs indefinitely (e.g. a stalled HTTP call).
 *
 * Cooperates with the AbortSignal — when the registry cancels it, the promise
 * resolves immediately with an empty array, allowing the test to complete in a
 * bounded time (timeout + epsilon).
 *
 * @example Verify timeout isolation
 * ```ts
 * const registry = new DetectorRegistry({ defaultTimeoutMs: 50 });
 * registry.register(new HangingDetector());
 * registry.register(new DummyDetector());
 *
 * const result = await registry.detect({ content: "..." });
 * const hangStats = result.detectorStats.find(s => s.detectorId === "hanging-detector");
 * expect(hangStats?.timedOut).toBe(true);
 * expect(result.candidates.length).toBeGreaterThan(0); // DummyDetector still ran
 * ```
 */
export class HangingDetector implements Detector {
  readonly id: string;
  readonly displayName: string;
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 999,
  };

  /**
   * @param id - Stable detector id. Override to register multiple instances.
   */
  constructor(id = "hanging-detector") {
    this.id = id;
    this.displayName = `Hanging Detector [${id}]`;
  }

  supports(_request: DetectionRequest): boolean {
    return true;
  }

  /**
   * Blocks indefinitely until `signal` is aborted, then resolves with `[]`.
   * If no signal is provided, the promise never resolves — use only in tests
   * where the registry always supplies a signal.
   */
  async detect(
    _request: DetectionRequest,
    signal?: AbortSignal,
  ): Promise<Candidate[]> {
    if (signal?.aborted) {
      return [];
    }

    return new Promise<Candidate[]>((resolve) => {
      if (signal) {
        signal.addEventListener("abort", () => resolve([]), { once: true });
      }
      // Without a signal, this promise never settles.
      // The registry always provides a signal, so this is safe in practice.
    });
  }
}
