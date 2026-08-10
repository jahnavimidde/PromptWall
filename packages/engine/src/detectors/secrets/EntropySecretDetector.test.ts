/**
 * @file EntropySecretDetector.test.ts
 * @module @promptwall/engine/detectors/secrets
 *
 * Unit tests for EntropySecretDetector.
 */

import { describe, expect, test } from "bun:test";
import { EntropySecretDetector, calculateShannonEntropy } from "./EntropySecretDetector";

describe("EntropySecretDetector", () => {
  const detector = new EntropySecretDetector();

  test("calculates Shannon entropy correctly", () => {
    // Single repeating char -> 0 entropy
    expect(calculateShannonEntropy("AAAAAAA")).toBe(0);
    // 2 unique chars equal split -> 1.0 bit
    expect(calculateShannonEntropy("ABABABAB")).toBe(1);
    expect(calculateShannonEntropy("")).toBe(0);
  });

  test("detects high entropy credential-like string", async () => {
    // High entropy random string with mixed classes
    const highEntropy = "xK9#mQ2$vL8!pZ5@wR1*tY7&";
    const content = `secret_key = "${highEntropy}"`;

    const candidates = await detector.detect({ content });
    expect(candidates.length).toBeGreaterThan(0);
    expect(candidates[0]?.subtype).toBe("HIGH_ENTROPY_SECRET");
    expect(candidates[0]?.category).toBe("secret");
  });

  test("rejects normal English text", async () => {
    const text = "This is a completely normal English paragraph that should not trigger entropy secret detection.";
    const candidates = await detector.detect({ content: text });
    expect(candidates).toHaveLength(0);
  });

  test("rejects low entropy repeated characters", async () => {
    const text = "aaaaaaaaaaaaaaaaaaaaaaaaa BBBBBBBBBBBBBBBBBBBBBBBBB 1111111111111111111111111";
    const candidates = await detector.detect({ content: text });
    expect(candidates).toHaveLength(0);
  });

  test("rejects UUID strings", async () => {
    const uuid = "123e4567-e89b-12d3-a456-426614174000";
    const candidates = await detector.detect({ content: `id: ${uuid}` });
    expect(candidates).toHaveLength(0);
  });

  test("rejects short random strings under 20 chars", async () => {
    const shortRandom = "aB3!xK9#";
    const candidates = await detector.detect({ content: `pass: ${shortRandom}` });
    expect(candidates).toHaveLength(0);
  });

  test("is deterministic across calls", async () => {
    const highEntropy = "xK9#mQ2$vL8!pZ5@wR1*tY7&";
    const req = { content: `token = ${highEntropy}` };

    const first = await detector.detect(req);
    const second = await detector.detect(req);

    expect(first.length).toBe(second.length);
    expect(first[0]?.value).toBe(second[0]?.value);
    expect(first[0]?.confidence).toBe(second[0]?.confidence);
  });
});
