/**
 * @file PiiGlinerDetector.ts
 * @module @promptwall/engine/detectors/pii
 *
 * Clean detector adapter around the existing Python GLiNER detector service.
 * Translates returned entities into Candidate objects while maintaining
 * dependency-light pure TypeScript engine design.
 */

import type { Candidate, CandidateCategory, Severity } from "../../candidate/Candidate";
import type { Evidence } from "../../candidate/Evidence";
import type { DetectionRequest } from "../../detector/DetectionRequest";
import type { Detector, DetectorCapabilities } from "../../detector/Detector";

export interface PiiGlinerDetectorOptions {
  readonly serviceUrl?: string;
  readonly timeoutMs?: number;
  readonly scoreThreshold?: number;
}

interface GlinerEntity {
  entity_type: string;
  start: number;
  end: number;
  score: number;
}

export class PiiGlinerDetector implements Detector {
  readonly id = "pii-gliner-detector";
  readonly displayName = "PII GLiNER Detector";
  readonly version = "1.0.0";

  readonly capabilities: DetectorCapabilities = {
    supportsStreaming: false,
    supportsBinary: false,
    priority: 30,
  };

  private readonly serviceUrl: string;
  private readonly timeoutMs: number;
  private readonly scoreThreshold: number;

  constructor(options: PiiGlinerDetectorOptions = {}) {
    this.serviceUrl = options.serviceUrl ?? "http://localhost:7080";
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.scoreThreshold = options.scoreThreshold ?? 0.5;
  }

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
      const endpoint = `${this.serviceUrl}/analyze`;
      const requestPayload = {
        text: request.content,
        score_threshold: this.scoreThreshold,
      };

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

      const entities = (await response.json()) as GlinerEntity[];
      if (!Array.isArray(entities)) {
        return [];
      }

      return entities.map((ent) => this.translateEntity(ent, request.content));
    } catch {
      // Return empty candidate list on connection error or timeout to adhere to Detector contract
      return [];
    }
  }

  private translateEntity(ent: GlinerEntity, content: string): Candidate {
    const rawValue = content.slice(ent.start, ent.end);
    const subtype = normalizeSubtype(ent.entity_type);
    const category = getCategoryForSubtype(subtype);
    const severity = getSeverityForSubtype(subtype);

    const evidence: Evidence = {
      id: crypto.randomUUID(),
      source: "gliner",
      label: `GLiNER model classified entity as ${ent.entity_type}`,
      score: ent.score,
      confidenceContribution: 1.0,
      detail: `Model entity: ${ent.entity_type}, confidence: ${ent.score.toFixed(4)}`,
      metadata: {
        glinerEntityType: ent.entity_type,
        glinerScore: ent.score,
      },
    };

    return {
      id: crypto.randomUUID(),
      category,
      subtype,
      value: rawValue,
      normalizedValue: rawValue.trim(),
      location: { start: ent.start, end: ent.end },
      confidence: ent.score,
      severity,
      detector: this.id,
      evidence: [evidence],
      metadata: {
        entityType: ent.entity_type,
        modelScore: ent.score,
      },
    };
  }
}

function normalizeSubtype(glinerType: string): string {
  switch (glinerType.toUpperCase()) {
    case "PERSON":
      return "PERSON";
    case "EMAIL_ADDRESS":
    case "EMAIL":
      return "EMAIL_ADDRESS";
    case "PHONE_NUMBER":
    case "PHONE":
      return "PHONE_NUMBER";
    case "LOCATION":
    case "ADDRESS":
      return "LOCATION";
    case "ORGANIZATION":
    case "ORG":
      return "ORGANIZATION";
    case "CREDIT_CARD":
      return "CREDIT_CARD";
    case "IBAN_CODE":
    case "IBAN":
      return "IBAN_CODE";
    case "IP_ADDRESS":
      return "IP_ADDRESS";
    case "VAT_CODE":
      return "VAT_CODE";
    default:
      return glinerType.toUpperCase();
  }
}

function getCategoryForSubtype(subtype: string): CandidateCategory {
  if (subtype === "CREDIT_CARD" || subtype === "IBAN_CODE") {
    return "pii";
  }
  return "pii";
}

function getSeverityForSubtype(subtype: string): Severity {
  switch (subtype) {
    case "CREDIT_CARD":
    case "IBAN_CODE":
      return "critical";
    case "PERSON":
    case "EMAIL_ADDRESS":
    case "PHONE_NUMBER":
      return "high";
    case "LOCATION":
    case "ORGANIZATION":
    case "VAT_CODE":
    case "IP_ADDRESS":
      return "medium";
    default:
      return "low";
  }
}
