export const DEMO_HEADER = "X-PromptWall-Demo";
export const DEMO_SECRET_HEADER = "X-PromptWall-Demo-Secret";

// ─── Timing breakdown ────────────────────────────────────────────────────────

export interface DebugTimings {
  /** Time spent on secrets regex/pattern detection (ms) */
  secretsMs: number;
  /** Time spent on GLiNER PII detection (ms) */
  piiMs: number;
  /** Time spent at the upstream LLM provider (ms) */
  providerMs: number;
  /** Time spent restoring placeholders in the response (ms) */
  restoreMs: number;
  /** Total wall-clock time from request received to response ready (ms) */
  totalMs: number;
}

// ─── Policy decisions ────────────────────────────────────────────────────────

export type PolicyDecision = "ALLOWED" | "BLOCKED" | "ROUTED_LOCAL";

// ─── Core envelope ───────────────────────────────────────────────────────────

export interface DebugInfo {
  /** Unique request identifier – matches the X-Request-ID header and dashboard log */
  requestId: string;

  /** Provider name used for this request (e.g. "openai", "anthropic") */
  provider: string;

  /** The raw user prompt before any detection or masking */
  originalPrompt: string;

  /**
   * The prompt after masking PII and secrets with placeholders.
   * Equal to originalPrompt when nothing was detected.
   */
  maskedPrompt: string;

  /** Unique PII entity types detected (e.g. ["EMAIL_ADDRESS", "PERSON"]) */
  piiEntities: string[];

  /** Secret types detected (e.g. ["JWT_TOKEN", "API_KEY_SK"]) */
  secretTypes: string[];

  /** Policy outcome for this request */
  policyDecision: PolicyDecision;

  /** Total PII + secrets scan time (ms) */
  scanTimeMs: number;

  /** Number of placeholder substitutions made (0 if no masking occurred) */
  maskCount: number;

  /** Whether the response contained placeholders that were restored */
  responsesRestored: boolean;

  /** Granular timing breakdown */
  timings: DebugTimings;
}

// ─── Response envelope ───────────────────────────────────────────────────────

/**
 * Debug envelope returned by provider routes when `X-PromptWall-Demo: true`
 * is present in the request.
 *
 * `response` is the normal provider response object (fully restored, identical
 * to what a regular client would receive). `debug` is the sidecar metadata.
 */
export interface DebugEnvelope<TResponse = unknown> {
  response: TResponse;
  debug: DebugInfo;
}
