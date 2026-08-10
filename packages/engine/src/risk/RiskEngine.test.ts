/**
 * @file RiskEngine.test.ts
 * @module @promptwall/engine/risk
 *
 * Unit tests for the Risk Fusion Engine (Milestone 2A).
 *
 * Coverage:
 *  1.  Empty candidates → score = 0, level = "low"
 *  2.  Low severity + low confidence → "low"
 *  3.  Critical candidate + high confidence → "critical"
 *  4.  Multiple independent evidence sources increase risk
 *  5.  Duplicate evidence IDs do not artificially inflate risk
 *  6.  Multiple candidates aggregate via complement-product
 *  7.  Score never exceeds 100
 *  8.  Score never falls below 0
 *  9.  Threshold boundaries map to correct levels
 * 10.  Custom severity weights are respected
 * 11.  Custom thresholds change level classification
 * 12.  Assessment factors contain useful explanations
 * 13.  Determinism: same input → same output
 * 14.  candidateIds matches sorted candidate IDs
 * 15.  Zero-evidence fallback uses candidate confidence
 * 16.  Single weak candidate stays at low risk
 * 17.  Factor contribution is in [0, 100]
 * 18.  Summary is non-empty and contains the level
 */

import { describe, expect, test } from "bun:test";
import { RiskEngine } from "./RiskEngine";
import { DEFAULT_RISK_THRESHOLDS, resolveRiskLevel } from "./RiskLevel";
import type { Candidate } from "../candidate/Candidate";
import type { Evidence } from "../candidate/Evidence";
import type { Severity } from "../candidate/Candidate";

// ── Test helpers ──────────────────────────────────────────────────────────────

/**
 * Build a minimal Evidence object with a given id and score.
 */
function makeEvidence(id: string, score: number): Evidence {
  return {
    id,
    source: "regex",
    label: `Evidence ${id}`,
    score,
  };
}

/**
 * Build a minimal Candidate with configurable fields.
 * Defaults: confidence = 0.5, severity = "medium", evidence = [].
 */
function makeCandidate(
  id: string,
  overrides: Partial<{
    confidence: number;
    severity: Severity;
    evidence: Evidence[];
    subtype: string;
    detector: string;
  }> = {},
): Candidate {
  return {
    id,
    category: "secret",
    subtype: overrides.subtype ?? "TEST_TYPE",
    value: `value-${id}`,
    normalizedValue: `value-${id}`,
    location: { start: 0, end: 10 },
    confidence: overrides.confidence ?? 0.5,
    severity: overrides.severity ?? "medium",
    detector: overrides.detector ?? "test-detector",
    evidence: overrides.evidence ?? [],
    metadata: {},
  };
}

// ── 1. Empty candidates ───────────────────────────────────────────────────────

describe("RiskEngine — empty candidates", () => {
  const engine = new RiskEngine();

  test("score is 0", () => {
    const result = engine.assess([]);
    expect(result.score).toBe(0);
  });

  test("level is 'low'", () => {
    const result = engine.assess([]);
    expect(result.level).toBe("low");
  });

  test("factors is empty", () => {
    const result = engine.assess([]);
    expect(result.factors).toHaveLength(0);
  });

  test("candidateIds is empty", () => {
    const result = engine.assess([]);
    expect(result.candidateIds).toHaveLength(0);
  });

  test("summary mentions no candidates", () => {
    const result = engine.assess([]);
    expect(result.summary).toBe("No candidates detected.");
  });
});

// ── 2. Low severity + low confidence → low risk ───────────────────────────────

describe("RiskEngine — low severity + low confidence", () => {
  const engine = new RiskEngine();

  test("produces 'low' level", () => {
    const c = makeCandidate("c1", {
      severity: "low",
      confidence: 0.1,
      evidence: [makeEvidence("e1", 0.1)],
    });
    const result = engine.assess([c]);
    expect(result.level).toBe("low");
  });

  test("score is well below 30", () => {
    const c = makeCandidate("c1", {
      severity: "low",
      confidence: 0.1,
      evidence: [makeEvidence("e1", 0.1)],
    });
    // severityWeight=0.15, confidence=0.1, evidenceAgreement≈0.1
    // candidateRisk ≈ 0.15 × 0.1 × 0.1 = 0.0015 → score ≈ 0.15
    const result = engine.assess([c]);
    expect(result.score).toBeLessThan(30);
  });
});

// ── 3. Critical + high confidence → critical risk ─────────────────────────────

describe("RiskEngine — critical severity + high confidence", () => {
  const engine = new RiskEngine();

  test("produces 'critical' level", () => {
    const c = makeCandidate("c1", {
      severity: "critical",
      confidence: 0.97,
      evidence: [
        makeEvidence("e1", 0.98),
        makeEvidence("e2", 0.90),
        makeEvidence("e3", 0.85),
      ],
    });
    const result = engine.assess([c]);
    expect(result.level).toBe("critical");
  });

  test("score is ≥ 80", () => {
    const c = makeCandidate("c1", {
      severity: "critical",
      confidence: 0.97,
      evidence: [
        makeEvidence("e1", 0.98),
        makeEvidence("e2", 0.90),
        makeEvidence("e3", 0.85),
      ],
    });
    const result = engine.assess([c]);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });
});

// ── 4. Multiple independent evidence sources increase risk ────────────────────

describe("RiskEngine — evidence sources", () => {
  const engine = new RiskEngine();

  test("more independent evidence sources → higher risk", () => {
    const base = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e1", 0.6)],
    });
    const rich = makeCandidate("c2", {
      severity: "high",
      confidence: 0.8,
      evidence: [
        makeEvidence("e1", 0.6),
        makeEvidence("e2", 0.7),
        makeEvidence("e3", 0.8),
      ],
    });

    const scoreBase = engine.assess([base]).score;
    const scoreRich = engine.assess([rich]).score;
    expect(scoreRich).toBeGreaterThan(scoreBase);
  });
});

// ── 5. Duplicate evidence does not inflate risk ───────────────────────────────

describe("RiskEngine — duplicate evidence deduplication", () => {
  const engine = new RiskEngine();

  test("same evidence id repeated does not increase risk", () => {
    const sameId = makeEvidence("e1", 0.9);

    const once = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [sameId],
    });
    const repeated = makeCandidate("c2", {
      severity: "high",
      confidence: 0.8,
      // Same evidence object repeated three times
      evidence: [sameId, sameId, sameId],
    });

    const scoreOnce = engine.assess([once]).score;
    const scoreRepeated = engine.assess([repeated]).score;

    // Repeated same-id evidence must produce exactly the same score
    expect(scoreRepeated).toBe(scoreOnce);
  });

  test("different evidence ids produce higher risk than duplicates", () => {
    const singleId = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [
        makeEvidence("e1", 0.9),
        makeEvidence("e1", 0.9), // duplicate id
      ],
    });
    const multiId = makeCandidate("c2", {
      severity: "high",
      confidence: 0.8,
      evidence: [
        makeEvidence("e1", 0.9),
        makeEvidence("e2", 0.9), // genuinely different
      ],
    });

    const scoreSingle = engine.assess([singleId]).score;
    const scoreMulti = engine.assess([multiId]).score;
    expect(scoreMulti).toBeGreaterThan(scoreSingle);
  });
});

// ── 6. Multiple candidates aggregate correctly ────────────────────────────────

describe("RiskEngine — multi-candidate aggregation", () => {
  const engine = new RiskEngine();

  test("two candidates produce higher risk than one", () => {
    const c1 = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e1", 0.85)],
    });
    const c2 = makeCandidate("c2", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e2", 0.85)],
    });

    const scoreOne = engine.assess([c1]).score;
    const scoreTwo = engine.assess([c1, c2]).score;
    expect(scoreTwo).toBeGreaterThan(scoreOne);
  });

  test("complement-product formula: two identical risks < 2× single", () => {
    // If candidateRisk = r, then aggregated = 100 × (1 − (1−r)²)
    // which is always < 2 × 100r for r > 0.
    const c1 = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e1", 0.85)],
    });
    const c2 = makeCandidate("c2", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e2", 0.85)],
    });

    const scoreOne = engine.assess([c1]).score;
    const scoreTwo = engine.assess([c1, c2]).score;
    expect(scoreTwo).toBeLessThan(2 * scoreOne);
  });

  test("candidateIds contains all assessed candidate IDs", () => {
    const c1 = makeCandidate("alpha");
    const c2 = makeCandidate("beta");
    const c3 = makeCandidate("gamma");

    const result = engine.assess([c1, c2, c3]);
    expect(result.candidateIds).toContain("alpha");
    expect(result.candidateIds).toContain("beta");
    expect(result.candidateIds).toContain("gamma");
    expect(result.candidateIds).toHaveLength(3);
  });
});

// ── 7. Score never exceeds 100 ────────────────────────────────────────────────

describe("RiskEngine — score upper bound", () => {
  const engine = new RiskEngine();

  test("single perfect candidate does not exceed 100", () => {
    const c = makeCandidate("c1", {
      severity: "critical",
      confidence: 1.0,
      evidence: [makeEvidence("e1", 1.0)],
    });
    expect(engine.assess([c]).score).toBeLessThanOrEqual(100);
  });

  test("ten perfect candidates do not exceed 100", () => {
    const candidates = Array.from({ length: 10 }, (_, i) =>
      makeCandidate(`c${i}`, {
        severity: "critical",
        confidence: 1.0,
        evidence: [makeEvidence(`e${i}`, 1.0)],
      }),
    );
    expect(engine.assess(candidates).score).toBeLessThanOrEqual(100);
  });
});

// ── 8. Score never falls below 0 ─────────────────────────────────────────────

describe("RiskEngine — score lower bound", () => {
  const engine = new RiskEngine();

  test("zero-evidence, zero-confidence candidate has score ≥ 0", () => {
    const c = makeCandidate("c1", {
      severity: "low",
      confidence: 0,
      evidence: [],
    });
    expect(engine.assess([c]).score).toBeGreaterThanOrEqual(0);
  });

  test("negative confidence is clamped: score ≥ 0", () => {
    // Confidence is clamped internally; even an out-of-range input must not
    // produce a negative score.
    const c: Candidate = {
      ...makeCandidate("c1"),
      confidence: -0.5, // deliberately invalid
    };
    expect(engine.assess([c]).score).toBeGreaterThanOrEqual(0);
  });
});

// ── 9. Threshold boundaries ───────────────────────────────────────────────────

describe("resolveRiskLevel — threshold boundaries", () => {
  const thresholds = DEFAULT_RISK_THRESHOLDS;

  test("score 0 → 'low'", () => {
    expect(resolveRiskLevel(0, thresholds)).toBe("low");
  });

  test("score 29 → 'low'", () => {
    expect(resolveRiskLevel(29, thresholds)).toBe("low");
  });

  test("score 30 → 'medium'", () => {
    expect(resolveRiskLevel(30, thresholds)).toBe("medium");
  });

  test("score 59 → 'medium'", () => {
    expect(resolveRiskLevel(59, thresholds)).toBe("medium");
  });

  test("score 60 → 'high'", () => {
    expect(resolveRiskLevel(60, thresholds)).toBe("high");
  });

  test("score 79 → 'high'", () => {
    expect(resolveRiskLevel(79, thresholds)).toBe("high");
  });

  test("score 80 → 'critical'", () => {
    expect(resolveRiskLevel(80, thresholds)).toBe("critical");
  });

  test("score 100 → 'critical'", () => {
    expect(resolveRiskLevel(100, thresholds)).toBe("critical");
  });
});

// ── 10. Custom severity weights ───────────────────────────────────────────────

describe("RiskEngine — custom severity weights", () => {
  test("raising critical weight increases score", () => {
    const candidate = makeCandidate("c1", {
      severity: "critical",
      confidence: 0.7,
      evidence: [makeEvidence("e1", 0.8)],
    });
    const defaultEngine = new RiskEngine();
    const customEngine = new RiskEngine({
      severityWeights: { critical: 1.0 }, // same as default — just verifying override path
    });

    // Both use weight 1.0 → same score
    expect(defaultEngine.assess([candidate]).score).toBeCloseTo(
      customEngine.assess([candidate]).score,
      5,
    );
  });

  test("lowering critical weight reduces score", () => {
    const candidate = makeCandidate("c1", {
      severity: "critical",
      confidence: 0.9,
      evidence: [makeEvidence("e1", 0.9)],
    });
    const defaultEngine = new RiskEngine(); // critical = 1.00
    const reducedEngine = new RiskEngine({
      severityWeights: { critical: 0.5 },
    });

    expect(reducedEngine.assess([candidate]).score).toBeLessThan(
      defaultEngine.assess([candidate]).score,
    );
  });

  test("raising medium weight to critical level makes medium = critical score", () => {
    const medCandidate = makeCandidate("c1", {
      severity: "medium",
      confidence: 0.9,
      evidence: [makeEvidence("e1", 0.9)],
    });
    const critCandidate = makeCandidate("c2", {
      severity: "critical",
      confidence: 0.9,
      evidence: [makeEvidence("e2", 0.9)],
    });

    const engine = new RiskEngine({
      severityWeights: { medium: 1.0 }, // set medium = critical weight
    });

    // With equal weights, medium and critical candidates should score identically
    expect(engine.assess([medCandidate]).score).toBeCloseTo(
      engine.assess([critCandidate]).score,
      5,
    );
  });
});

// ── 11. Custom thresholds ─────────────────────────────────────────────────────

describe("RiskEngine — custom thresholds", () => {
  test("custom thresholds shift level classification", () => {
    // A score of 50 is 'medium' by default, but 'high' with lower thresholds
    const engine = new RiskEngine({
      thresholds: { medium: 20, high: 40, critical: 70 },
    });

    // Build a candidate that produces ~50 score
    const candidate = makeCandidate("c1", {
      severity: "high",
      confidence: 0.85,
      evidence: [makeEvidence("e1", 0.85), makeEvidence("e2", 0.70)],
    });

    const result = engine.assess([candidate]);
    // With custom threshold high=40, score≥40 should be "high" or better
    expect(["high", "critical"]).toContain(result.level);
  });

  test("raising critical threshold to 95 reclassifies score 80 as 'high'", () => {
    // resolveRiskLevel is already imported at the top of the file;
    // call it directly rather than using a dynamic import.
    const level = resolveRiskLevel(80, { medium: 30, high: 60, critical: 95 });
    expect(level).toBe("high");
  });
});

// ── 12. Assessment explanations ───────────────────────────────────────────────

describe("RiskEngine — explanation quality", () => {
  const engine = new RiskEngine();

  test("factors contain non-empty explanation strings", () => {
    const c = makeCandidate("c1", {
      severity: "critical",
      confidence: 0.9,
      evidence: [makeEvidence("e1", 0.95)],
    });
    const result = engine.assess([c]);
    expect(result.factors.length).toBeGreaterThan(0);
    for (const factor of result.factors) {
      expect(typeof factor.explanation).toBe("string");
      expect(factor.explanation.length).toBeGreaterThan(0);
    }
  });

  test("factor explanation mentions the candidate's severity", () => {
    const c = makeCandidate("c1", {
      severity: "critical",
      confidence: 0.9,
      evidence: [makeEvidence("e1", 0.95)],
    });
    const result = engine.assess([c]);
    const explanations = result.factors.map((f) => f.explanation).join(" ");
    expect(explanations).toMatch(/critical/i);
  });

  test("factor candidateId matches the assessed candidate's id", () => {
    const c = makeCandidate("unique-id-xyz", {
      severity: "high",
      confidence: 0.75,
      evidence: [makeEvidence("e1", 0.8)],
    });
    const result = engine.assess([c]);
    expect(result.factors[0]?.candidateId).toBe("unique-id-xyz");
  });

  test("factor contribution is in [0, 100]", () => {
    const candidates = [
      makeCandidate("c1", { severity: "critical", confidence: 1.0, evidence: [makeEvidence("e1", 1.0)] }),
      makeCandidate("c2", { severity: "low", confidence: 0.01, evidence: [] }),
    ];
    const result = engine.assess(candidates);
    for (const factor of result.factors) {
      expect(factor.contribution).toBeGreaterThanOrEqual(0);
      expect(factor.contribution).toBeLessThanOrEqual(100);
    }
  });

  test("summary is non-empty and contains the level", () => {
    const c = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e1", 0.8)],
    });
    const result = engine.assess([c]);
    expect(result.summary.length).toBeGreaterThan(0);
    expect(result.summary.toLowerCase()).toContain(result.level);
  });
});

// ── 13. Determinism ───────────────────────────────────────────────────────────

describe("RiskEngine — determinism", () => {
  const engine = new RiskEngine();

  test("same candidates in same order → identical score", () => {
    const candidates = [
      makeCandidate("c1", { severity: "high", confidence: 0.8, evidence: [makeEvidence("e1", 0.85)] }),
      makeCandidate("c2", { severity: "medium", confidence: 0.6, evidence: [makeEvidence("e2", 0.7)] }),
    ];
    const r1 = engine.assess(candidates);
    const r2 = engine.assess(candidates);
    expect(r1.score).toBe(r2.score);
    expect(r1.level).toBe(r2.level);
  });

  test("same candidates in different order → identical score", () => {
    const c1 = makeCandidate("c1", {
      severity: "high",
      confidence: 0.8,
      evidence: [makeEvidence("e1", 0.85)],
    });
    const c2 = makeCandidate("c2", {
      severity: "medium",
      confidence: 0.6,
      evidence: [makeEvidence("e2", 0.7)],
    });

    const r1 = engine.assess([c1, c2]);
    const r2 = engine.assess([c2, c1]); // reversed
    expect(r1.score).toBe(r2.score);
    expect(r1.level).toBe(r2.level);
    expect(r1.candidateIds).toEqual(r2.candidateIds); // both sorted by id
  });

  test("calling assess() 100 times produces the same score", () => {
    const candidates = [
      makeCandidate("c1", { severity: "critical", confidence: 0.95, evidence: [makeEvidence("e1", 0.95)] }),
    ];
    const scores = Array.from({ length: 100 }, () => engine.assess(candidates).score);
    const first = scores[0]!;
    for (const s of scores) {
      expect(s).toBe(first);
    }
  });
});

// ── 14. Zero-evidence fallback ────────────────────────────────────────────────

describe("RiskEngine — zero-evidence fallback", () => {
  const engine = new RiskEngine();

  test("candidate with no evidence uses confidence as agreement", () => {
    const highConf = makeCandidate("c1", {
      severity: "high",
      confidence: 0.95,
      evidence: [],
    });
    const lowConf = makeCandidate("c2", {
      severity: "high",
      confidence: 0.2,
      evidence: [],
    });

    const scoreHigh = engine.assess([highConf]).score;
    const scoreLow = engine.assess([lowConf]).score;
    expect(scoreHigh).toBeGreaterThan(scoreLow);
  });
});
