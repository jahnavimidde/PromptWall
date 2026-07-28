/**
 * @file index.ts
 * @module @promptwall/engine
 *
 * Public API barrel for the PromptWall Core Detection Framework.
 *
 * Import order reflects the dependency graph (leaves first):
 *   Evidence → Candidate → DetectionRequest → DetectionResult
 *   → Detector → DetectorRegistry → CandidateGraph → ConfidenceEngine
 */

// ── candidate/ ────────────────────────────────────────────────────────────────
export type { Evidence, EvidenceSource } from "./candidate/Evidence";
export type {
  Candidate,
  CandidateCategory,
  Location,
  Severity,
} from "./candidate/Candidate";

// ── detector/ ─────────────────────────────────────────────────────────────────
export type { DetectionRequest } from "./detector/DetectionRequest";
export type {
  DetectionResult,
  DetectionError,
  DetectionWarning,
  DetectorStats,
} from "./detector/DetectionResult";
export type { Detector, DetectorCapabilities } from "./detector/Detector";
export {
  DetectorRegistry,
  DetectorTimeoutError,
} from "./detector/DetectorRegistry";
export type {
  DetectorRegistryOptions,
  DetectOptions,
} from "./detector/DetectorRegistry";

// ── graph/ ────────────────────────────────────────────────────────────────────
export { CandidateGraph, PassthroughGraphResolver } from "./graph/CandidateGraph";
export type { GraphResolver, CandidateNode } from "./graph/CandidateGraph";

// ── confidence/ ───────────────────────────────────────────────────────────────
export {
  ConfidenceEngine,
  PassthroughConfidenceScorer,
} from "./confidence/ConfidenceEngine";
export type {
  ConfidenceScorer,
  ScoringContext,
} from "./confidence/ConfidenceEngine";

// ── testing/ ──────────────────────────────────────────────────────────────────
// Re-exported here for convenience. For production bundles, prefer the
// sub-path import: import { DummyDetector } from "@promptwall/engine/testing"
export { DummyDetector } from "./testing/DummyDetector";
export { HangingDetector } from "./testing/HangingDetector";
export { FailingDetector } from "./testing/FailingDetector";
