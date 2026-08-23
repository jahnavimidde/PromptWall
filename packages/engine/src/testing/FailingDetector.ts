/**
 * @file FailingDetector.ts
 * @module @promptwall/engine/testing
 *
 * A {@link Detector} that always throws during `detect()`.
 * Used to verify the registry's error isolation guarantee — a failing detector
 * must never prevent other detectors from completing.
 *
 * Do NOT use in production.
 */

import type { Candidate } from "../candidate/Candidate";
import type { Detector, DetectorCapabilities } from "../detector/Detector";
import type { DetectionRequest } from "../detector/DetectionRequest";

/**
 * Simulates a detector with a catastrophic internal failure (e.g. unhandled
 * exception, corrupt model, failed dependency).
 *
 * The registry catches the thrown error via `Promise.allSettled`, records it in
 * {@link DetectionResult.errors}, and continues with remaining detectors.
 *
 * @example Verify error isolation
 * ```ts
 * const registry = new DetectorRegistry();
 * registry.register(new FailingDetector());
 * registry.register(new DummyDetector());
 *
 * const result = await registry.detect({ content: "..." });
 * expect(result.errors).toHaveLength(1);
 * expect(result.errors[0]?.detectorId).toBe("failing-detector");
 * expect(result.candidates.length).toBeGreaterThan(0); // DummyDetector still ran
 * ```
 */
export class FailingDetector implements Detector {
  readonly id: string;
  readonly displayName: string;
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 999,
  };

  private readonly errorMessage: string;

  /**
   * @param id           - Stable detector id. Override to register multiple instances.
   * @param errorMessage - The message of the error that will be thrown.
   */
  constructor(
    id = "failing-detector",
    errorMessage = "Simulated detector failure",
  ) {
    this.id = id;
    this.displayName = `Failing Detector [${id}]`;
    this.errorMessage = errorMessage;
  }

  supports(_request: DetectionRequest): boolean {
    return true;
  }

  /**
   * Always throws. Violates the Detector contract intentionally to test isolation.
   */
  async detect(
    _request: DetectionRequest,
    _signal?: AbortSignal,
  ): Promise<Candidate[]> {
    throw new Error(this.errorMessage);
  }
}
