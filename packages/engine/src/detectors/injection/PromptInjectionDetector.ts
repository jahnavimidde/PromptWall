/**
 * @file PromptInjectionDetector.ts
 * @module @promptwall/engine/detectors/injection
 *
 * Deterministic baseline detector for prompt injection and instruction override attempts.
 * Uses pattern matching on normalized text.
 */

import type { Candidate } from "../../candidate/Candidate";
import type { Evidence } from "../../candidate/Evidence";
import type { DetectionRequest } from "../../detector/DetectionRequest";
import type { Detector, DetectorCapabilities } from "../../detector/Detector";

interface InjectionPattern {
  readonly label: string;
  readonly patternString: string;
  readonly flags: string;
  readonly score: number;
}

const INJECTION_PATTERNS: readonly InjectionPattern[] = [
  {
    label: "Ignore previous instructions attempt",
    patternString: "ignore\\s+(?:all\\s+)?(?:previous|prior)\\s+(?:instructions|prompts|directions|rules)",
    flags: "gi",
    score: 0.95,
  },
  {
    label: "Disregard previous instructions attempt",
    patternString: "disregard\\s+(?:all\\s+)?(?:previous|prior)\\s+(?:instructions|prompts|directions|rules)",
    flags: "gi",
    score: 0.95,
  },
  {
    label: "System prompt extraction attempt",
    patternString: "(?:reveal|show|display|print|output|repeat|give)(?:\\s+me)?\\s+(?:your\\s+)?(?:system\\s+prompt|hidden\\s+instructions|developer\\s+message|initial\\s+prompt)",
    flags: "gi",
    score: 0.9,
  },
  {
    label: "Developer message extraction attempt",
    patternString: "(?:what\\s+are|tell\\s+me)\\s+(?:your\\s+)?(?:system\\s+instructions|hidden\\s+prompts|developer\\s+rules)",
    flags: "gi",
    score: 0.85,
  },
  {
    label: "Jailbreak instruction override attempt",
    patternString: "(?:bypass|override|disable|ignore)\\s+(?:all\\s+)?(?:safety|security|policy|system)\\s+(?:rules|policies|filters|guidelines)",
    flags: "gi",
    score: 0.95,
  },
  {
    label: "Persona override attempt",
    patternString: "(?:you\\s+are\\s+now|pretend\\s+you\\s+are|act\\s+as\\s+if\\s+you\\s+have\\s+no\\s+restrictions)",
    flags: "gi",
    score: 0.8,
  },
];

export class PromptInjectionDetector implements Detector {
  readonly id = "prompt-injection-detector";
  readonly displayName = "Prompt Injection Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 5,
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

      for (const pattern of INJECTION_PATTERNS) {
        if (signal?.aborted) break;

        const regex = new RegExp(pattern.patternString, pattern.flags);
        let match: RegExpExecArray | null;

        while ((match = regex.exec(text)) !== null) {
          if (signal?.aborted) break;

          const matchedValue = match[0];
          const start = match.index;
          const end = start + matchedValue.length;

          if (matchedValue.length === 0) {
            regex.lastIndex++;
            continue;
          }

          const evidence: Evidence = {
            id: crypto.randomUUID(),
            source: "validator",
            label: pattern.label,
            score: pattern.score,
            confidenceContribution: 1.0,
            detail: `Matched prompt injection pattern: "${matchedValue}"`,
          };

          candidates.push({
            id: crypto.randomUUID(),
            category: "malicious",
            subtype: "PROMPT_INJECTION",
            value: matchedValue,
            normalizedValue: matchedValue.toLowerCase().trim(),
            location: { start, end },
            confidence: pattern.score,
            severity: "critical",
            detector: this.id,
            evidence: [evidence],
            metadata: {
              patternLabel: pattern.label,
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
