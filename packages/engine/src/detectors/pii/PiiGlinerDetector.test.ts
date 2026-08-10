/**
 * @file PiiGlinerDetector.test.ts
 * @module @promptwall/engine/detectors/pii
 *
 * Unit tests for PiiGlinerDetector adapter.
 */

import { describe, expect, test, mock } from "bun:test";
import { PiiGlinerDetector } from "./PiiGlinerDetector";

describe("PiiGlinerDetector", () => {
  test("translates returned GLiNER entities into Candidates", async () => {
    const detector = new PiiGlinerDetector({ serviceUrl: "http://mock-gliner:7080" });

    // Mock global fetch
    const originalFetch = globalThis.fetch;
    (globalThis.fetch as unknown) = mock(async () => {
      return new Response(
        JSON.stringify([
          { entity_type: "PERSON", start: 8, end: 21, score: 0.95 },
          { entity_type: "EMAIL_ADDRESS", start: 23, end: 42, score: 0.98 },
        ]),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    });

    try {
      const text = "Hi, I'm Sarah Johnson (sarah.j@example.com)";
      const candidates = await detector.detect({ content: text });

      expect(candidates).toHaveLength(2);

      const person = candidates.find((c) => c.subtype === "PERSON");
      expect(person).toBeDefined();
      expect(person?.value).toBe("Sarah Johnson");
      expect(person?.category).toBe("pii");
      expect(person?.confidence).toBe(0.95);

      const email = candidates.find((c) => c.subtype === "EMAIL_ADDRESS");
      expect(email).toBeDefined();
      expect(email?.value).toBe("sarah.j@example.com");
      expect(email?.category).toBe("pii");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("handles service connection failure gracefully without throwing", async () => {
    const detector = new PiiGlinerDetector({ serviceUrl: "http://localhost:99999" });

    const originalFetch = globalThis.fetch;
    (globalThis.fetch as unknown) = mock(async () => {
      throw new Error("Failed to connect");
    });

    try {
      const candidates = await detector.detect({ content: "John Doe" });
      expect(candidates).toEqual([]);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
