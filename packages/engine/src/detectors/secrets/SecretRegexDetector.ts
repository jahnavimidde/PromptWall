/**
 * @file SecretRegexDetector.ts
 * @module @promptwall/engine/detectors/secrets
 *
 * Implements deterministic regex pattern matching for well-known API keys,
 * tokens, credentials, and private key headers.
 */

import type { Candidate, Severity } from "../../candidate/Candidate";
import type { Evidence } from "../../candidate/Evidence";
import type { DetectionRequest } from "../../detector/DetectionRequest";
import type { Detector, DetectorCapabilities } from "../../detector/Detector";

interface SecretPattern {
  readonly subtype: string;
  readonly patternString: string;
  readonly flags: string;
  readonly severity: Severity;
  readonly label: string;
}

const SECRET_PATTERNS: readonly SecretPattern[] = [
  {
    subtype: "AWS_KEY",
    patternString: "AKIA[0-9A-Z]{16}",
    flags: "g",
    severity: "critical",
    label: "AWS Access Key ID pattern",
  },
  {
    subtype: "ANTHROPIC_KEY",
    patternString: "sk-ant-[a-zA-Z0-9_-]{20,}",
    flags: "g",
    severity: "critical",
    label: "Anthropic API Key pattern",
  },
  {
    subtype: "OPENAI_KEY",
    patternString: "sk-(?!ant-)[a-zA-Z0-9_-]{20,}",
    flags: "g",
    severity: "critical",
    label: "OpenAI API Key pattern",
  },
  {
    subtype: "STRIPE_KEY",
    patternString: "sk_(?:live|test)_[0-9a-zA-Z]{24,}",
    flags: "g",
    severity: "critical",
    label: "Stripe Secret Key pattern",
  },
  {
    subtype: "GITHUB_TOKEN",
    patternString: "gh[pousr]_[a-zA-Z0-9]{36,}",
    flags: "g",
    severity: "critical",
    label: "GitHub Personal Access / OAuth Token pattern",
  },
  {
    subtype: "JWT",
    patternString: "eyJ[a-zA-Z0-9_-]{10,}\\.eyJ[a-zA-Z0-9_-]{10,}\\.[a-zA-Z0-9_-]{10,}",
    flags: "g",
    severity: "high",
    label: "JSON Web Token (JWT) pattern",
  },
  {
    subtype: "BEARER_TOKEN",
    patternString: "Bearer\\s+[a-zA-Z0-9._-]{20,}",
    flags: "gi",
    severity: "high",
    label: "HTTP Bearer Authorization Token pattern",
  },
  {
    subtype: "PRIVATE_KEY",
    patternString: "-----BEGIN (?:[A-Z0-9 -]+)?KEY-----[\\s\\S]*?-----END (?:[A-Z0-9 -]+)?KEY-----",
    flags: "g",
    severity: "critical",
    label: "PEM/OpenSSH Private Key header pattern",
  },
];

export class SecretRegexDetector implements Detector {
  readonly id = "secret-regex-detector";
  readonly displayName = "Secret Regex Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 10,
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

      for (const pattern of SECRET_PATTERNS) {
        if (signal?.aborted) break;

        // Instantiate local RegExp per detect call to ensure thread-safety and prevent lastIndex pollution
        const regex = new RegExp(pattern.patternString, pattern.flags);
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
          if (signal?.aborted) break;

          const matchedValue = match[0];
          const start = match.index;
          const end = start + matchedValue.length;

          // Prevent infinite loops on zero-length matches
          if (matchedValue.length === 0) {
            regex.lastIndex++;
            continue;
          }

          const evidence: Evidence = {
            id: crypto.randomUUID(),
            source: "regex",
            label: pattern.label,
            score: 0.98,
            confidenceContribution: 1.0,
            detail: `Matched regex rule for ${pattern.subtype}`,
          };

          candidates.push({
            id: crypto.randomUUID(),
            category: "secret",
            subtype: pattern.subtype,
            value: matchedValue,
            normalizedValue: matchedValue.trim(),
            location: { start, end },
            confidence: 0.98,
            severity: pattern.severity,
            detector: this.id,
            evidence: [evidence],
            metadata: {
              patternLabel: pattern.label,
              matchLength: matchedValue.length,
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
