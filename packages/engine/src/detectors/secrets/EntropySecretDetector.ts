/**
 * @file EntropySecretDetector.ts
 * @module @promptwall/engine/detectors/secrets
 *
 * Detects high-entropy credential-like strings using Shannon entropy calculation
 * combined with structural heuristics to suppress false positives (UUIDs, plain text, etc.).
 */

import type { Candidate } from "../../candidate/Candidate";
import type { Evidence } from "../../candidate/Evidence";
import type { DetectionRequest } from "../../detector/DetectionRequest";
import type { Detector, DetectorCapabilities } from "../../detector/Detector";

export class EntropySecretDetector implements Detector {
  readonly id = "entropy-secret-detector";
  readonly displayName = "Entropy Secret Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 20,
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

      // Extract non-whitespace token candidates of length >= 20
      const tokenRegex = /[a-zA-Z0-9_\-\.\/\+\=\!@#\$%\^&\*]{20,}/g;
      let match: RegExpExecArray | null;

      while ((match = tokenRegex.exec(text)) !== null) {
        if (signal?.aborted) break;

        const token = match[0];
        const start = match.index;
        const end = start + token.length;

        if (this.isCredentialCandidate(token, text, start)) {
          const entropy = calculateShannonEntropy(token);

          // Threshold: 3.5 bits/char minimum for high-entropy secrets
          if (entropy >= 3.5) {
            const evidence: Evidence = {
              id: crypto.randomUUID(),
              source: "entropy",
              label: `High entropy token detected (${entropy.toFixed(2)} bits/char)`,
              score: 0.85,
              confidenceContribution: 1.0,
              detail: `Shannon entropy score: ${entropy.toFixed(2)}`,
              metadata: {
                entropy,
                tokenLength: token.length,
              },
            };

            candidates.push({
              id: crypto.randomUUID(),
              category: "secret",
              subtype: "HIGH_ENTROPY_SECRET",
              value: token,
              normalizedValue: token,
              location: { start, end },
              confidence: 0.85,
              severity: "high",
              detector: this.id,
              evidence: [evidence],
              metadata: {
                entropy,
                length: token.length,
              },
            });
          }
        }
      }

      return candidates;
    } catch {
      return [];
    }
  }

  private isCredentialCandidate(token: string, fullText: string, start: number): boolean {
    // 1. Must be at least 20 chars
    if (token.length < 20) return false;

    // 2. Reject if preceded by http://, https://, or ://
    const contextBefore = fullText.slice(Math.max(0, start - 10), start);
    if (/:\/\/$|http$|https$/i.test(contextBefore)) {
      return false;
    }

    // 3. Reject URL/domain paths (containing slashes and common domain extensions or API paths)
    if (token.includes("/") && (/\.(?:com|org|net|io|gov|edu|co)\b/i.test(token) || /\bapi\b|\bv\d\b/i.test(token))) {
      return false;
    }

    // 4. Reject UUID patterns: e.g. 8-4-4-4-12 hex
    const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
    if (uuidRegex.test(token)) return false;

    // 5. Reject pure hex strings (git commit hashes, SHA1, SHA256, hex IDs) to prevent false positives on normal hex
    const isPureHex = /^[0-9a-fA-F]+$/.test(token);
    if (isPureHex) return false;

    // 6. Reject URLs starting with http/https/www
    if (token.startsWith("http://") || token.startsWith("https://") || token.startsWith("www.")) {
      return false;
    }

    // 7. Must have character diversity (at least 2 different character classes: lower, upper, digit, symbol)
    let charClasses = 0;
    if (/[a-z]/.test(token)) charClasses++;
    if (/[A-Z]/.test(token)) charClasses++;
    if (/[0-9]/.test(token)) charClasses++;
    if (/[_\-\.\/\+\=\!@#\$%\^&\*]/.test(token)) charClasses++;

    if (charClasses < 2) return false;

    // 8. Reject repeated character sequences (low diversity)
    const uniqueChars = new Set(token).size;
    if (uniqueChars < 8) return false;

    return true;
  }
}

/**
 * Calculate Shannon Entropy in bits per character.
 * H = - Σ (p_i * log2(p_i))
 */
export function calculateShannonEntropy(str: string): number {
  if (!str) return 0;

  const len = str.length;
  const frequencies = new Map<string, number>();

  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}
