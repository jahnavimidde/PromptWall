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

// ── risk/ ─────────────────────────────────────────────────────────────────────
export type { RiskLevel, RiskThresholds } from "./risk/RiskLevel";
export { DEFAULT_RISK_THRESHOLDS, resolveRiskLevel } from "./risk/RiskLevel";
export type { RiskFactorType, RiskFactor } from "./risk/RiskFactor";
export type { RiskAssessment } from "./risk/RiskAssessment";
export type { RiskScoringContext } from "./risk/RiskScoringContext";
export {
  RiskEngine,
  DEFAULT_SEVERITY_WEIGHTS,
} from "./risk/RiskEngine";
export type { RiskEngineOptions, SeverityWeights } from "./risk/RiskEngine";

// ── policy/ ───────────────────────────────────────────────────────────────────
export type { PolicyAction } from "./policy/PolicyAction";
export { ACTION_PRECEDENCE, highestPrecedenceAction } from "./policy/PolicyAction";
export type { PolicyRule } from "./policy/PolicyRule";
export type { PolicyDecision } from "./policy/PolicyDecision";
export {
  PolicyEngine,
  DEFAULT_POLICY_RULES,
} from "./policy/PolicyEngine";
export type { PolicyEngineOptions } from "./policy/PolicyEngine";

// ── detectors/ ────────────────────────────────────────────────────────────────
export {
  SecretRegexDetector,
  EntropySecretDetector,
  calculateShannonEntropy,
  CreditCardDetector,
  isValidLuhn,
  PiiGlinerDetector,
  PromptInjectionDetector,
  createDefaultDetectors,
  registerDefaultDetectors,
} from "./detectors";
export type { PiiGlinerDetectorOptions } from "./detectors";

// ── graph/ resolvers ──────────────────────────────────────────────────────────
export { OverlapMergingResolver } from "./graph/OverlapMergingResolver";

// ── pipeline/ ─────────────────────────────────────────────────────────────────
export { DetectionPipeline } from "./pipeline/DetectionPipeline";
export type {
  DetectionPipelineOptions,
  PipelineResult,
} from "./pipeline/DetectionPipeline";


