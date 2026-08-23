/**
 * @file DetectionPipeline.ts
 * @module @promptwall/engine/pipeline
 *
 * Orchestrates the full security detection pipeline:
 *
 * Detection (DetectorRegistry)
 *   ↓
 * CandidateGraph (with OverlapMergingResolver)
 *   ↓
 * ConfidenceEngine
 *   ↓
 * RiskEngine
 *   ↓
 * PolicyEngine
 *   ↓
 * PipelineResult { candidates, riskAssessment, policyDecision, detectionResult }
 *
 * Completely independent of HTTP or network providers.
 */

import type { Candidate } from "../candidate/Candidate";
import type { DetectionRequest } from "../detector/DetectionRequest";
import type { DetectionResult } from "../detector/DetectionResult";
import { DetectorRegistry } from "../detector/DetectorRegistry";
import { CandidateGraph } from "../graph/CandidateGraph";
import { OverlapMergingResolver } from "../graph/OverlapMergingResolver";
import { ConfidenceEngine } from "../confidence/ConfidenceEngine";
import { RiskEngine } from "../risk/RiskEngine";
import type { RiskAssessment } from "../risk/RiskAssessment";
import { PolicyEngine } from "../policy/PolicyEngine";
import type { PolicyDecision } from "../policy/PolicyDecision";
import { registerDefaultDetectors } from "../detectors";

export interface DetectionPipelineOptions {
  readonly registry?: DetectorRegistry;
  readonly confidenceEngine?: ConfidenceEngine;
  readonly riskEngine?: RiskEngine;
  readonly policyEngine?: PolicyEngine;
}

export interface PipelineResult {
  readonly candidates: readonly Candidate[];
  readonly riskAssessment: RiskAssessment;
  readonly policyDecision: PolicyDecision;
  readonly detectionResult: DetectionResult;
}

export class DetectionPipeline {
  private readonly registry: DetectorRegistry;
  private readonly confidenceEngine: ConfidenceEngine;
  private readonly riskEngine: RiskEngine;
  private readonly policyEngine: PolicyEngine;

  constructor(options: DetectionPipelineOptions = {}) {
    if (options.registry) {
      this.registry = options.registry;
    } else {
      this.registry = new DetectorRegistry();
      registerDefaultDetectors(this.registry);
    }

    this.confidenceEngine = options.confidenceEngine ?? new ConfidenceEngine();
    this.riskEngine = options.riskEngine ?? new RiskEngine();
    this.policyEngine = options.policyEngine ?? new PolicyEngine();
  }

  async run(request: DetectionRequest): Promise<PipelineResult> {
    // 1. Detection via DetectorRegistry
    const detectionResult = await this.registry.detect(request);

    // 2. CandidateGraph with OverlapMergingResolver deduplication
    const graph = new CandidateGraph(new OverlapMergingResolver());
    const mergedCandidates = graph.merge(detectionResult.candidates);

    // 3. ConfidenceEngine scoring
    const scoredCandidates = this.confidenceEngine.apply(mergedCandidates, request);

    // 4. RiskEngine assessment
    const riskAssessment = this.riskEngine.assess(scoredCandidates);

    // 5. PolicyEngine decision
    const policyDecision = this.policyEngine.decide(scoredCandidates, riskAssessment);

    return {
      candidates: scoredCandidates,
      riskAssessment,
      policyDecision,
      detectionResult,
    };
  }
}
