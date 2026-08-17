/**
 * @file policy-simulator.ts
 * @module src/routes
 *
 * Policy Simulation endpoint (M8A).
 *
 * Allows ADMIN and SECURITY_ANALYST users to evaluate sample content against
 * the current active database policies WITHOUT:
 *   - forwarding content to any LLM provider
 *   - modifying security_policies or policy versions
 *   - modifying the submitted content
 *
 * Route:  POST /api/policies/simulate
 *
 * ── Security invariants ────────────────────────────────────────────────────────
 *
 * The response NEVER includes:
 *   - raw matched values    (Candidate.value)
 *   - normalized values     (Candidate.normalizedValue)
 *   - character locations   (Candidate.location)
 *   - evidence details      (Candidate.evidence)
 *   - raw candidate metadata (Candidate.metadata)
 *   - provider response data
 *
 * Only safe classification metadata is returned:
 *   action | riskLevel | riskScore | decisionReason |
 *   detectorsTriggered | candidate summaries (id, category, subtype, severity, confidence, detector)
 *
 * ── Pipeline ──────────────────────────────────────────────────────────────────
 *
 * Request body
 *   ↓
 * DetectionPipeline (injected with current PolicyEngine from DB / DEFAULT_POLICY_RULES)
 *   ↓
 * active policies from PolicyStore / runtime
 *   ↓
 * RiskEngine
 *   ↓
 * PolicyEngine
 *   ↓
 * SimulationResult (sanitised — no raw values)
 */

import { zValidator } from "@hono/zod-validator";
import { Hono } from "hono";
import { z } from "zod";
import { authMiddleware, requireRole } from "../auth/middleware";
import { DetectionPipeline } from "@promptwall/engine";
import type { CandidateSummary } from "@promptwall/engine";
import type { Candidate } from "@promptwall/engine";
import { getPolicyEngine } from "../policy/runtime";
import type { PolicyStore } from "../policy/policy-store";

export const simulatorRoutes = new Hono();

// ── RBAC: ADMIN and SECURITY_ANALYST only ─────────────────────────────────────

simulatorRoutes.use("*", authMiddleware, requireRole(["ADMIN", "SECURITY_ANALYST"]));

// ── Validation Schema ─────────────────────────────────────────────────────────

const SimulateRequestSchema = z.object({
  /** The content to evaluate — treated as read-only; never forwarded to any LLM. */
  content: z.string().min(1, "content is required"),
  /** Optional IANA MIME type (e.g. \"text/plain\", \"application/json\"). */
  mimeType: z.string().optional(),
  /** Optional model name — recorded for audit context only, not used for routing. */
  model: z.string().optional(),
  /** Optional provider name — recorded for audit context only, not used for routing. */
  provider: z.string().optional(),
});

// ── Response type (safe projection only) ─────────────────────────────────────

/**
 * Safe simulation result.
 *
 * All fields are safe for broad access:
 *   - NO raw matched text
 *   - NO character offsets
 *   - NO evidence detail strings
 *   - NO raw detector metadata
 */
export interface SimulationResult {
  /** Policy enforcement action that would be applied. */
  readonly action: string;
  /** Categorical risk level ("low" | "medium" | "high" | "critical"). */
  readonly riskLevel: string;
  /** Numeric risk score in [0, 100]. */
  readonly riskScore: number;
  /** Human-readable explanation of the policy decision (never contains raw values). */
  readonly decisionReason: string;
  /** IDs of detectors that contributed at least one candidate. */
  readonly detectorsTriggered: readonly string[];
  /** Safe candidate summaries — no raw values, locations, or evidence. */
  readonly candidates: readonly CandidateSummary[];
}

/**
 * Project a raw {@link Candidate} to a safe {@link CandidateSummary}.
 *
 * Explicitly drops: value, normalizedValue, location, evidence, metadata.
 */
function toSafeSummary(c: Candidate): CandidateSummary {
  return {
    id: c.id,
    category: c.category,
    subtype: c.subtype,
    severity: c.severity,
    confidence: Math.round(c.confidence * 10_000) / 10_000,
    detector: c.detector,
  };
}

// ── Handler ───────────────────────────────────────────────────────────────────

/**
 * POST /api/policies/simulate
 *
 * Evaluates sample content against the current active policies without
 * forwarding the content to any LLM provider and without modifying the database.
 *
 * @example Request
 * ```json
 * {
 *   "content": "My AWS key is AKIAIOSFODNN7EXAMPLE and my secret is wJalrXUtnFEMI",
 *   "mimeType": "text/plain",
 *   "model": "gpt-4o",
 *   "provider": "openai"
 * }
 * ```
 *
 * @example Response
 * ```json
 * {
 *   "simulation": {
 *     "action": "block",
 *     "riskLevel": "critical",
 *     "riskScore": 91.4,
 *     "decisionReason": "Critical credential detected — request blocked to prevent exposure.",
 *     "detectorsTriggered": ["secret-regex-detector"],
 *     "candidates": [
 *       {
 *         "id": "...",
 *         "category": "secret",
 *         "subtype": "AWS_ACCESS_KEY",
 *         "severity": "critical",
 *         "confidence": 0.99,
 *         "detector": "secret-regex-detector"
 *       }
 *     ]
 *   }
 * }
 * ```
 */
simulatorRoutes.post(
  "/simulate",
  zValidator("json", SimulateRequestSchema),
  async (c) => {
    const input = c.req.valid("json");

    // Obtain the current live PolicyEngine (reads from DB, falls back to defaults).
    // Accept optional custom store injected via context for testability.
    const customStore = c.get("_testPolicyStore" as never) as PolicyStore | undefined;
    const policyEngine = await getPolicyEngine(customStore);

    // Build a DetectionPipeline injecting the current policy engine.
    // No provider is involved — the pipeline is purely local.
    const pipeline = new DetectionPipeline({ policyEngine });

    // Run detection. Never forwards to a provider; never mutates input.
    const result = await pipeline.run({
      content: input.content,
      mimeType: input.mimeType,
    });

    // Project to safe summaries — strips value, normalizedValue, location,
    // evidence, and metadata from each candidate.
    const candidateSummaries = result.candidates.map(toSafeSummary);
    const detectorsTriggered = [...new Set(candidateSummaries.map((cs) => cs.detector))];

    const simulation: SimulationResult = {
      action: result.policyDecision.action,
      riskLevel: result.policyDecision.riskLevel,
      riskScore: result.policyDecision.riskScore,
      decisionReason: result.policyDecision.reason,
      detectorsTriggered,
      candidates: candidateSummaries,
    };

    return c.json({ simulation });
  },
);
