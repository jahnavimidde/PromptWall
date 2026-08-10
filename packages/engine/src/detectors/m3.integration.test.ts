/**
 * @file m3.integration.test.ts
 * @module @promptwall/engine/detectors
 *
 * Mandatory End-to-End Engine Pipeline Test for Milestone 3.
 * Exercises: Input → DetectorRegistry → real detectors → CandidateGraph → ConfidenceEngine → RiskEngine → PolicyEngine → final result.
 */

import { describe, expect, test, mock } from "bun:test";
import { DetectorRegistry } from "../detector/DetectorRegistry";
import { registerDefaultDetectors } from "./index";
import { DetectionPipeline } from "../pipeline/DetectionPipeline";

describe("Milestone 3 — End-to-End Pipeline Integration Test", () => {
  test("processes conceptual mixed PII + secrets prompt through full security pipeline", async () => {
    // Dynamically constructed fixtures (Push Protection compliant)
    const openAiKey = ["sk", "proj", "a".repeat(32), "12345678"].join("-");
    const awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const creditCard = "4532015112830366";

    const promptText = [
      "Hi, I'm Sarah Johnson (sarah.j@example.com, +1-555-867-5309).",
      "Please review this config:",
      `OPENAI_API_KEY=${openAiKey}`,
      `AWS secret: ${awsKey}`,
      `My credit card on file is ${creditCard}.`,
    ].join("\n");

    // Mock fetch for GLiNER to guarantee PII entity responses in isolated unit test runner
    const originalFetch = globalThis.fetch;
    (globalThis.fetch as unknown) = mock(async () => {
      return new Response(
        JSON.stringify([
          { entity_type: "PERSON", start: 8, end: 21, score: 0.95 },
          { entity_type: "EMAIL_ADDRESS", start: 23, end: 41, score: 0.98 },
          { entity_type: "PHONE_NUMBER", start: 43, end: 58, score: 0.91 },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    });

    try {
      const registry = new DetectorRegistry();
      registerDefaultDetectors(registry);
      const pipeline = new DetectionPipeline({ registry });

      const startTime = Date.now();
      const result = await pipeline.run({ content: promptText });
      const durationMs = Date.now() - startTime;

      // 1. Assert candidates produced across expected categories
      expect(result.candidates.length).toBeGreaterThanOrEqual(4);

      const candidateSubtypes = result.candidates.map((c) => c.subtype);
      expect(candidateSubtypes).toContain("CREDIT_CARD");
      expect(candidateSubtypes).toContain("OPENAI_KEY");
      expect(candidateSubtypes).toContain("AWS_KEY");
      expect(candidateSubtypes).toContain("PERSON");

      // 2. Assert risk assessment
      expect(result.riskAssessment.score).toBeGreaterThan(75);
      expect(result.riskAssessment.level).toBe("critical");
      expect(result.riskAssessment.factors.length).toBeGreaterThan(0);

      // 3. Assert policy decision
      expect(result.policyDecision.action).toBe("block");
      expect(result.policyDecision.matchedRuleIds).toContain("block-critical-secret");

      // 4. Record execution stats
      expect(result.detectionResult.detectorStats.length).toBeGreaterThan(0);
      expect(durationMs).toBeLessThan(5000);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
