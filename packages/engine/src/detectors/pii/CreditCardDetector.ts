/**
 * @file CreditCardDetector.ts
 * @module @promptwall/engine/detectors/pii
 *
 * Deterministic Credit Card Detector using pattern matching and Luhn checksum validation.
 * Rejects numbers that fail the Luhn algorithm.
 */

import type { Candidate } from "../../candidate/Candidate";
import type { Evidence } from "../../candidate/Evidence";
import type { DetectionRequest } from "../../detector/DetectionRequest";
import type { Detector, DetectorCapabilities } from "../../detector/Detector";

export class CreditCardDetector implements Detector {
  readonly id = "credit-card-detector";
  readonly displayName = "Credit Card Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 15,
  };

  supports(request: DetectionRequest): boolean {
    return typeof request.content === "string" && request.content.length > 0;
  }

  async detect(
    request: DetectionRequest,
    signal?: AbortSignal
  ): Promise<Candidate[]> {
    if (signal?.aborted || !request.content) {
      return [];
    }

    try {
      const candidates: Candidate[] = [];
      const text = request.content;

      // 13-19 digit credit card candidate pattern (with optional spaces or hyphens)
      const ccRegex = /(?<!\d)(?:\d[ -]?){13,19}(?!\d)/g;
      let match: RegExpExecArray | null;

      while ((match = ccRegex.exec(text)) !== null) {
        if (signal?.aborted) break;

        const rawMatch = match[0];
        const digitsOnly = rawMatch.replace(/[ -]/g, "");

        if (digitsOnly.length >= 13 && digitsOnly.length <= 19 && isValidLuhn(digitsOnly)) {
          const start = match.index;
          const end = start + rawMatch.length;

          const evidence: Evidence = {
            id: crypto.randomUUID(),
            source: "validator",
            label: "Credit Card number with valid Luhn checksum",
            score: 0.99,
            confidenceContribution: 1.0,
            detail: "Luhn checksum passed",
          };

          candidates.push({
            id: crypto.randomUUID(),
            category: "pii",
            subtype: "CREDIT_CARD",
            value: rawMatch,
            normalizedValue: digitsOnly,
            location: { start, end },
            confidence: 0.99,
            severity: "critical",
            detector: this.id,
            evidence: [evidence],
            metadata: {
              digitCount: digitsOnly.length,
              luhnValid: true,
            },
          });
        }
      }

      return candidates;
    } catch {
      return [];
    }
  }
}

/**
 * Validates a string of digits using Luhn algorithm (mod 10).
 */
export function isValidLuhn(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;

  let sum = 0;
  let shouldDouble = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let digit = parseInt(digits.charAt(i), 10);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}
