/**
 * @file CreditCardDetector.test.ts
 * @module @promptwall/engine/detectors/pii
 *
 * Unit tests for CreditCardDetector.
 */

import { describe, expect, test } from "bun:test";
import { CreditCardDetector, isValidLuhn } from "./CreditCardDetector";

describe("CreditCardDetector", () => {
  const detector = new CreditCardDetector();

  test("Luhn algorithm validator works correctly", () => {
    // Valid Luhn numbers (standard test card numbers)
    expect(isValidLuhn("4532015112830366")).toBe(true);
    expect(isValidLuhn("4532 0151 1283 0366".replace(/\s/g, ""))).toBe(true);

    // Invalid Luhn numbers
    expect(isValidLuhn("4532015112830367")).toBe(false);
    expect(isValidLuhn("1234567890123456")).toBe(false);
    expect(isValidLuhn("abc")).toBe(false);
  });

  test("detects valid Visa credit card", async () => {
    const validCard = "4532015112830366";
    const content = `Payment card: ${validCard}`;

    const candidates = await detector.detect({ content });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.subtype).toBe("CREDIT_CARD");
    expect(candidates[0]?.category).toBe("pii");
    expect(candidates[0]?.severity).toBe("critical");
    expect(candidates[0]?.normalizedValue).toBe(validCard);
  });

  test("detects formatted credit card with hyphens", async () => {
    const formattedCard = "4532-0151-1283-0366";
    const content = `Card: ${formattedCard}`;

    const candidates = await detector.detect({ content });
    expect(candidates).toHaveLength(1);
    expect(candidates[0]?.value).toBe(formattedCard);
    expect(candidates[0]?.normalizedValue).toBe("4532015112830366");
  });

  test("rejects card number with invalid Luhn checksum", async () => {
    const invalidCard = "4532015112830367";
    const content = `Card: ${invalidCard}`;

    const candidates = await detector.detect({ content });
    expect(candidates).toHaveLength(0);
  });

  test("rejects short digit sequences", async () => {
    const shortDigits = "1234567890";
    const candidates = await detector.detect({ content: `Phone: ${shortDigits}` });
    expect(candidates).toHaveLength(0);
  });
});
