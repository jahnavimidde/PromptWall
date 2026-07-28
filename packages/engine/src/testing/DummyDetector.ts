/**
 * @file DummyDetector.ts
 * @module @promptwall/engine/testing
 *
 * A minimal {@link Detector} implementation for framework testing and compilation
 * verification. Returns one synthetic {@link Candidate} per call.
 *
 * Do NOT use in production.
 */

import type { Candidate } from "../candidate/Candidate";
import type { Detector, DetectorCapabilities } from "../detector/Detector";
import type { DetectionRequest } from "../detector/DetectionRequest";

/**
 * Returns a single synthetic candidate for every request it supports.
 * Used to verify the end-to-end pipeline (registry → graph → confidence engine)
 * without any real detection logic.
 *
 * @example
 * ```ts
 * const registry = new DetectorRegistry();
 * registry.register(new DummyDetector());
 * const result = await registry.detect({ content: "hello world" });
 * // result.candidates.length === 1
 * ```
 */
export class DummyDetector implements Detector {
  readonly id = "dummy-detector";
  readonly displayName = "Dummy Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 999,
  };

  /** Accepts all requests. */
  supports(_request: DetectionRequest): boolean {
    return true;
  }

  async detect(
    request: DetectionRequest,
    signal?: AbortSignal,
  ): Promise<Candidate[]> {
    if (signal?.aborted) {
      return [];
    }

    const snippet = request.content.slice(0, 20);
    const end = Math.min(20, request.content.length);

    const candidate: Candidate = {
      id: crypto.randomUUID(),
      category: "custom",
      subtype: "DUMMY_DETECTION",
      value: snippet,
      normalizedValue: snippet.toLowerCase().trim(),
      location: { start: 0, end },
      confidence: 0.5,
      severity: "low",
      detector: this.id,
      evidence: [
        {
          id: crypto.randomUUID(),
          source: "validator",
          label: "Synthetic evidence — framework compilation test",
          score: 0.5,
          confidenceContribution: 1.0,
          detail: "Produced by DummyDetector for testing purposes only",
          metadata: { synthetic: true },
        },
      ],
      metadata: { synthetic: true, contentLength: request.content.length },
    };

    return [candidate];
  }
}
