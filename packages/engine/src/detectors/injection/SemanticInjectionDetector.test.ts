/**
 * @file SemanticInjectionDetector.test.ts
 * @module @promptwall/engine/detectors/injection
 *
 * Unit tests for SemanticInjectionDetector.
 */

import { describe, expect, test, afterEach } from "bun:test";
import { SemanticInjectionDetector } from "./SemanticInjectionDetector";

describe("SemanticInjectionDetector", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  test("A. score below 0.85 (e.g. 0.84) emits no candidate", async () => {
    (globalThis.fetch as unknown) = async () =>
      Response.json({ score: 0.84, label: "SAFE", intent: "PROMPT_INJECTION" });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "borderline prompt" });

    expect(candidates).toHaveLength(0);
  });

  test("B. score exactly 0.85 emits candidate with severity high", async () => {
    (globalThis.fetch as unknown) = async () =>
      Response.json({ score: 0.85, label: "INJECTION", intent: "PROMPT_INJECTION" });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "boundary high prompt" });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.severity).toBe("high");
    expect(candidates[0]!.confidence).toBe(0.85);
  });

  test("C. score 0.95 emits candidate with severity high (never critical alone)", async () => {
    (globalThis.fetch as unknown) = async () =>
      Response.json({ score: 0.95, label: "INJECTION", intent: "PROMPT_INJECTION" });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "test injection prompt" });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.severity).toBe("high");
    expect(candidates[0]!.confidence).toBe(0.95);
    expect(candidates[0]!.category).toBe("malicious");
    expect(candidates[0]!.subtype).toBe("PROMPT_INJECTION");
  });

  test("D. score 0.999 emits candidate with severity high", async () => {
    (globalThis.fetch as unknown) = async () =>
      Response.json({ score: 0.999, label: "INJECTION", intent: "PROMPT_INJECTION" });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "high score injection" });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.severity).toBe("high");
    expect(candidates[0]!.confidence).toBe(0.999);
  });

  test("E. Python service returns malformed JSON -> fails safely", async () => {
    (globalThis.fetch as unknown) = async () =>
      new Response("invalid json text {{{", { status: 200 });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "test prompt" });

    expect(candidates).toHaveLength(0);
  });

  test("F. Python service returns HTTP 500 -> fails safely", async () => {
    (globalThis.fetch as unknown) = async () =>
      new Response("Internal Error", { status: 500 });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "test prompt" });

    expect(candidates).toHaveLength(0);
  });

  test("G. fetch throws / network failure -> fails safely", async () => {
    (globalThis.fetch as unknown) = async () => {
      throw new Error("Network offline");
    };

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "test prompt" });

    expect(candidates).toHaveLength(0);
  });

  test("H. verify no raw prompt is inserted into evidence detail", async () => {
    const rawSecretPrompt = "SECRET_PROMPT_CONTENT_TO_BE_PROTECTED";
    (globalThis.fetch as unknown) = async () =>
      Response.json({ score: 0.99, label: "INJECTION", intent: "PROMPT_INJECTION" });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: rawSecretPrompt });

    expect(candidates).toHaveLength(1);
    const detail = candidates[0]!.evidence[0]!.detail;
    expect(detail).not.toContain(rawSecretPrompt);
    expect(detail).toContain("Semantic injection classifier score: 0.9900");
  });

  test("I. verify subtype is PROMPT_INJECTION", async () => {
    (globalThis.fetch as unknown) = async () =>
      Response.json({ score: 0.92, label: "INJECTION", intent: "PROMPT_INJECTION" });

    const detector = new SemanticInjectionDetector();
    const candidates = await detector.detect({ content: "another prompt" });

    expect(candidates).toHaveLength(1);
    expect(candidates[0]!.subtype).toBe("PROMPT_INJECTION");
    expect(candidates[0]!.category).toBe("malicious");
    expect(candidates[0]!.detector).toBe("semantic-injection-detector");
  });
});
