/**
 * @file SemanticInjectionDetector.ts
 * @module @promptwall/engine/detectors/injection
 *
 * Transformer-based semantic detector for prompt injection, indirect instruction
 * extraction, and jailbreak attempts. Adapter calling the Python detector service.
 */

import type { Candidate } from "../../candidate/Candidate";
import type { Evidence } from "../../candidate/Evidence";
import type { DetectionRequest } from "../../detector/DetectionRequest";
import type { Detector, DetectorCapabilities } from "../../detector/Detector";

export interface SemanticInjectionDetectorOptions {
  readonly serviceUrl?: string | undefined;
  readonly timeoutMs?: number | undefined;
}

interface InjectionResponse {
  readonly score: number;
  readonly label: string;
  readonly intent: string;
}

export class SemanticInjectionDetector implements Detector {
  readonly id = "semantic-injection-detector";
  readonly displayName = "Semantic Injection Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 6,
  };

  private readonly serviceUrl: string;
  private readonly timeoutMs: number;

  constructor(options: SemanticInjectionDetectorOptions = {}) {
    this.serviceUrl = options.serviceUrl ?? "http://localhost:5002";
    this.timeoutMs = options.timeoutMs ?? 3000;
  }

  supports(request: DetectionRequest): boolean {
    return typeof request.content === "string" && request.content.length > 0;
  }

  async detect(
    request: DetectionRequest,
    signal?: AbortSignal,
  ): Promise<Candidate[]> {
    if (signal?.aborted || !request.content) {
      return [];
    }

    try {
      const endpoint = `${this.serviceUrl}/analyze/injection`;
      const requestPayload = { text: request.content };

      const controller = new AbortController();
      const onAbort = () => controller.abort();
      if (signal) {
        signal.addEventListener("abort", onAbort, { once: true });
      }

      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      let response: Response;
      try {
        response = await fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(requestPayload),
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeoutId);
        if (signal) {
          signal.removeEventListener("abort", onAbort);
        }
      }

      if (!response.ok) {
        return [];
      }

      const data = (await response.json()) as InjectionResponse;
      if (typeof data?.score !== "number") {
        return [];
      }

      const score = data.score;

      // Threshold check: score < 0.85 -> no candidate
      if (score < 0.85) {
        return [];
      }

      const severity = "high";

      const evidence: Evidence = {
        id: crypto.randomUUID(),
        source: "semantic-classifier",
        label: "Semantic prompt injection classifier",
        score,
        confidenceContribution: 1.0,
        detail: `Semantic injection classifier score: ${score.toFixed(4)}`,
        metadata: {
          classifierLabel: data.label ?? "INJECTION",
          classifierIntent: data.intent ?? "PROMPT_INJECTION",
        },
      };

      const matchedText = request.content;

      return [
        {
          id: crypto.randomUUID(),
          category: "malicious",
          subtype: "PROMPT_INJECTION",
          value: matchedText,
          normalizedValue: matchedText.toLowerCase().trim(),
          location: { start: 0, end: matchedText.length },
          confidence: score,
          severity,
          detector: this.id,
          evidence: [evidence],
          metadata: {
            classifierScore: score,
            classifierLabel: data.label ?? "INJECTION",
          },
        },
      ];
    } catch {
      // Safe fallback on network failure, timeout, or malformed JSON
      return [];
    }
  }
}
