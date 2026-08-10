/**
 * @file PolicyEngine.test.ts
 * @module @promptwall/engine/policy
 *
 * Unit tests for the Policy Decision Engine (Milestone 2B).
 *
 * These are UNIT TESTS for PolicyEngine logic.
 * They are NOT the PromptWall security benchmark.
 *
 * Coverage (all 23 required scenarios + additional edge cases):
 *  1.  Empty candidates + low risk → allow
 *  2.  Low-risk PII → allow
 *  3.  Medium-risk candidate → mask
 *  4.  High-risk candidate → mask
 *  5.  Critical-risk candidate → block
 *  6.  Critical secret → block
 *  7.  High severity secret → mask
 *  8.  Rule matching by category
 *  9.  Rule matching by subtype
 * 10.  Rule matching by severity
 * 11.  Rule matching by risk level
 * 12.  Rule matching by minimum risk score
 * 13.  Multiple conditions require ALL conditions (AND semantics)
 * 14.  Higher-priority rule wins (first-match-wins)
 * 15.  More specific rule wins when priorities are equal
 * 16.  Stable deterministic ID tiebreaker
 * 17.  Multiple matched rules are recorded in matchedRuleIds
 * 18.  Default action when no rule matches
 * 19.  Same input produces identical decision (determinism)
 * 20.  Raw candidate secret values never appear in reason
 * 21.  Decision contains risk score and risk level
 * 22.  Decision contains candidate IDs
 * 23.  Decision contains matched rule IDs
 * 24.  (edge) catch-all rule (no conditions) always matches
 * 25.  (edge) minRiskScore boundary: score exactly equals threshold
 * 26.  (edge) minRiskScore boundary: score one below threshold
 * 27.  (edge) empty rule set → defaultAction
 * 28.  (edge) defaultAction override works
 * 29.  (edge) candidate with multiple categories only needs one to match
 * 30.  (edge) sorting: 5 rules with same priority resolved deterministically
 */

import { describe, expect, test } from "bun:test";
import {
  PolicyEngine,
  DEFAULT_POLICY_RULES,
} from "./PolicyEngine";
import type { PolicyRule } from "./PolicyRule";
import type { PolicyDecision } from "./PolicyDecision";
import type { PolicyAction } from "./PolicyAction";
import type { Candidate } from "../candidate/Candidate";
import type { CandidateCategory, Severity } from "../candidate/Candidate";
import type { RiskAssessment } from "../risk/RiskAssessment";
import type { RiskLevel } from "../risk/RiskLevel";

// ── Test helpers ──────────────────────────────────────────────────────────────

/**
 * Build a minimal RiskAssessment for testing.
 * Only score and level are meaningful for PolicyEngine evaluation.
 */
function makeAssessment(
  score: number,
  level: RiskLevel,
  candidateIds: string[] = [],
): RiskAssessment {
  return {
    score,
    level,
    factors: [],
    candidateIds,
    summary: `Test assessment: ${level} (${score})`,
  };
}

/**
 * Build a minimal Candidate for testing.
 * Raw `value` is intentionally set to a secret-like string in some tests
 * to verify it is never surfaced in the decision reason.
 */
function makeCandidate(
  id: string,
  overrides: Partial<{
    category: CandidateCategory;
    subtype: string;
    severity: Severity;
    value: string;
  }> = {},
): Candidate {
  return {
    id,
    category: overrides.category ?? "custom",
    subtype: overrides.subtype ?? "TEST_TYPE",
    value: overrides.value ?? `value-${id}`,
    normalizedValue: `value-${id}`,
    location: { start: 0, end: 10 },
    confidence: 0.8,
    severity: overrides.severity ?? "low",
    detector: "test-detector",
    evidence: [],
    metadata: {},
  };
}

/** Build a simple custom rule. */
function makeRule(
  id: string,
  priority: number,
  action: PolicyAction,
  conditions: Partial<Omit<PolicyRule, "id" | "priority" | "action" | "reason">> = {},
): PolicyRule {
  return {
    id,
    priority,
    action,
    reason: `Rule '${id}' triggered — action: ${action}.`,
    ...conditions,
  };
}

// ── 1. Empty candidates + low risk → allow ───────────────────────────────────

describe("PolicyEngine — empty candidates + low risk", () => {
  const engine = new PolicyEngine();

  test("returns allow for empty candidates + score 0 / level low", () => {
    const decision = engine.decide([], makeAssessment(0, "low"));
    expect(decision.action).toBe("allow");
  });

  test("level is preserved in decision", () => {
    const decision = engine.decide([], makeAssessment(0, "low"));
    expect(decision.riskLevel).toBe("low");
  });

  test("score is preserved in decision", () => {
    const decision = engine.decide([], makeAssessment(0, "low"));
    expect(decision.riskScore).toBe(0);
  });

  test("candidateIds is empty", () => {
    const decision = engine.decide([], makeAssessment(0, "low", []));
    expect(decision.candidateIds).toHaveLength(0);
  });
});

// ── 2. Low-risk PII → allow ──────────────────────────────────────────────────

describe("PolicyEngine — low-risk PII", () => {
  const engine = new PolicyEngine();

  test("PII with low risk score → allow", () => {
    const c = makeCandidate("c1", { category: "pii", severity: "low" });
    const decision = engine.decide([c], makeAssessment(10, "low", ["c1"]));
    expect(decision.action).toBe("allow");
  });
});

// ── 3. Medium-risk candidate → mask ──────────────────────────────────────────

describe("PolicyEngine — medium risk → mask", () => {
  const engine = new PolicyEngine();

  test("assessment with medium level → mask", () => {
    const c = makeCandidate("c1", { category: "pii", severity: "medium" });
    const decision = engine.decide([c], makeAssessment(40, "medium", ["c1"]));
    expect(decision.action).toBe("mask");
  });
});

// ── 4. High-risk candidate → mask ────────────────────────────────────────────

describe("PolicyEngine — high risk → mask", () => {
  const engine = new PolicyEngine();

  test("assessment with high level → mask", () => {
    const c = makeCandidate("c1", { category: "pii", severity: "high" });
    const decision = engine.decide([c], makeAssessment(65, "high", ["c1"]));
    expect(decision.action).toBe("mask");
  });
});

// ── 5. Critical-risk candidate → block ───────────────────────────────────────

describe("PolicyEngine — critical risk → block", () => {
  const engine = new PolicyEngine();

  test("assessment with critical level → block", () => {
    const c = makeCandidate("c1", { category: "pii", severity: "medium" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    expect(decision.action).toBe("block");
  });
});

// ── 6. Critical secret → block ───────────────────────────────────────────────

describe("PolicyEngine — critical secret → block", () => {
  const engine = new PolicyEngine();

  test("critical severity secret candidate → block", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "critical" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    expect(decision.action).toBe("block");
  });

  test("winning rule is block-critical-secret (higher priority than block-critical-risk)", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "critical" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    // block-critical-secret has priority 10, block-critical-risk has priority 30
    expect(decision.matchedRuleIds[0]).toBe("block-critical-secret");
  });
});

// ── 7. High severity secret → mask ───────────────────────────────────────────

describe("PolicyEngine — high severity secret → mask", () => {
  const engine = new PolicyEngine();

  test("high severity secret with medium risk → mask (rule wins over risk level)", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "high" });
    // Assessment is only medium risk — but mask-high-secret fires on the candidate
    const decision = engine.decide([c], makeAssessment(40, "medium", ["c1"]));
    expect(decision.action).toBe("mask");
  });

  test("winning rule is mask-high-secret", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "high" });
    const decision = engine.decide([c], makeAssessment(40, "medium", ["c1"]));
    expect(decision.matchedRuleIds[0]).toBe("mask-high-secret");
  });
});

// ── 8. Rule matching by category ─────────────────────────────────────────────

describe("PolicyEngine — rule matching by category", () => {
  test("rule with category=malicious matches malicious candidate", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("block-malicious", 1, "block", { category: "malicious" })],
    });
    const c = makeCandidate("c1", { category: "malicious" });
    const decision = engine.decide([c], makeAssessment(50, "medium", ["c1"]));
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds).toContain("block-malicious");
  });

  test("rule with category=pii does NOT match secret candidate", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("mask-pii", 1, "mask", { category: "pii" }),
        makeRule("default-allow", 999, "allow"),
      ],
    });
    const c = makeCandidate("c1", { category: "secret" });
    const decision = engine.decide([c], makeAssessment(20, "low", ["c1"]));
    expect(decision.action).toBe("allow");
    expect(decision.matchedRuleIds).not.toContain("mask-pii");
  });
});

// ── 9. Rule matching by subtype ───────────────────────────────────────────────

describe("PolicyEngine — rule matching by subtype", () => {
  test("rule with subtype=AWS_ACCESS_KEY matches candidate with that subtype", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("block-aws", 1, "block", { subtype: "AWS_ACCESS_KEY" })],
    });
    const c = makeCandidate("c1", {
      category: "secret",
      subtype: "AWS_ACCESS_KEY",
      severity: "critical",
    });
    const decision = engine.decide([c], makeAssessment(90, "critical", ["c1"]));
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds).toContain("block-aws");
  });

  test("rule does NOT match a different subtype", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("block-aws", 1, "block", { subtype: "AWS_ACCESS_KEY" }),
        makeRule("allow-all", 999, "allow"),
      ],
    });
    const c = makeCandidate("c1", {
      category: "secret",
      subtype: "GITHUB_TOKEN",
    });
    const decision = engine.decide([c], makeAssessment(20, "low", ["c1"]));
    expect(decision.action).toBe("allow");
    expect(decision.matchedRuleIds).not.toContain("block-aws");
  });
});

// ── 10. Rule matching by severity ────────────────────────────────────────────

describe("PolicyEngine — rule matching by severity", () => {
  test("rule with severity=high matches candidate with high severity", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("mask-high-sev", 1, "mask", { severity: "high" })],
    });
    const c = makeCandidate("c1", { category: "pii", severity: "high" });
    const decision = engine.decide([c], makeAssessment(30, "medium", ["c1"]));
    expect(decision.action).toBe("mask");
    expect(decision.matchedRuleIds).toContain("mask-high-sev");
  });

  test("rule with severity=critical does NOT match medium severity candidate", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("block-critical-sev", 1, "block", { severity: "critical" }),
        makeRule("allow-all", 999, "allow"),
      ],
    });
    const c = makeCandidate("c1", { category: "pii", severity: "medium" });
    const decision = engine.decide([c], makeAssessment(40, "medium", ["c1"]));
    expect(decision.action).toBe("allow");
    expect(decision.matchedRuleIds).not.toContain("block-critical-sev");
  });
});

// ── 11. Rule matching by risk level ──────────────────────────────────────────

describe("PolicyEngine — rule matching by risk level", () => {
  test("rule with riskLevel=medium matches assessment at medium level", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("mask-medium", 1, "mask", { riskLevel: "medium" })],
    });
    const decision = engine.decide([], makeAssessment(40, "medium"));
    expect(decision.action).toBe("mask");
  });

  test("rule with riskLevel=high does NOT match medium assessment", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("block-high", 1, "block", { riskLevel: "high" }),
        makeRule("allow-all", 999, "allow"),
      ],
    });
    const decision = engine.decide([], makeAssessment(40, "medium"));
    expect(decision.action).toBe("allow");
  });
});

// ── 12. Rule matching by minimum risk score ───────────────────────────────────

describe("PolicyEngine — rule matching by minRiskScore", () => {
  test("score exactly at minRiskScore matches (inclusive boundary)", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("mask-at-50", 1, "mask", { minRiskScore: 50 })],
    });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    expect(decision.action).toBe("mask");
  });

  test("score one below minRiskScore does NOT match", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("mask-at-50", 1, "mask", { minRiskScore: 50 }),
        makeRule("allow-all", 999, "allow"),
      ],
    });
    const decision = engine.decide([], makeAssessment(49, "medium"));
    expect(decision.action).toBe("allow");
  });

  test("score above minRiskScore matches", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("mask-at-50", 1, "mask", { minRiskScore: 50 })],
    });
    const decision = engine.decide([], makeAssessment(75, "high"));
    expect(decision.action).toBe("mask");
  });
});

// ── 13. Multiple conditions require ALL conditions ─────────────────────────────

describe("PolicyEngine — AND semantics for multiple conditions", () => {
  const rule = makeRule("block-critical-secret", 1, "block", {
    category: "secret",
    severity: "critical",
  });
  const engine = new PolicyEngine({ rules: [rule, makeRule("allow-all", 999, "allow")] });

  test("both conditions met → rule matches", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "critical" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    expect(decision.action).toBe("block");
  });

  test("category matches but severity does not → rule does NOT match", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "high" });
    const decision = engine.decide([c], makeAssessment(65, "high", ["c1"]));
    expect(decision.action).toBe("allow");
  });

  test("severity matches but category does not → rule does NOT match", () => {
    const c = makeCandidate("c1", { category: "pii", severity: "critical" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    expect(decision.action).toBe("allow");
  });

  test("three-condition AND: all three must match", () => {
    const threeCondRule = makeRule("block-specific", 1, "block", {
      category: "secret",
      severity: "critical",
      riskLevel: "critical",
    });
    const eng = new PolicyEngine({ rules: [threeCondRule, makeRule("allow-all", 999, "allow")] });

    // All three match
    const cAll = makeCandidate("c1", { category: "secret", severity: "critical" });
    expect(eng.decide([cAll], makeAssessment(85, "critical", ["c1"])).action).toBe("block");

    // riskLevel doesn't match
    const cLowRisk = makeCandidate("c2", { category: "secret", severity: "critical" });
    expect(eng.decide([cLowRisk], makeAssessment(10, "low", ["c2"])).action).toBe("allow");
  });
});

// ── 14. Higher-priority rule wins ─────────────────────────────────────────────

describe("PolicyEngine — higher-priority rule wins (first-match-wins)", () => {
  test("priority 10 mask beats priority 20 block", () => {
    // The MASK rule has lower priority number → evaluated first → wins
    const engine = new PolicyEngine({
      rules: [
        makeRule("mask-first", 10, "mask"),     // higher priority (lower number)
        makeRule("block-second", 20, "block"),  // lower priority (higher number)
      ],
    });
    // Both rules are catch-alls (no conditions) — both match
    const decision = engine.decide([], makeAssessment(50, "medium"));
    expect(decision.action).toBe("mask");
    expect(decision.matchedRuleIds[0]).toBe("mask-first");
  });

  test("priority 5 block beats priority 10 allow", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("allow-late", 10, "allow"),
        makeRule("block-early", 5, "block"),
      ],
    });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds[0]).toBe("block-early");
  });
});

// ── 15. More specific rule wins when priorities are equal ─────────────────────

describe("PolicyEngine — specificity tiebreaker", () => {
  test("category-specific rule beats catch-all at equal priority", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("generic-block", 10, "block"),                         // 0 conditions
        makeRule("specific-mask", 10, "mask", { category: "pii" }),    // 1 condition
      ],
    });
    const c = makeCandidate("c1", { category: "pii" });
    const decision = engine.decide([c], makeAssessment(40, "medium", ["c1"]));
    // specific-mask has higher specificity → wins despite same priority
    expect(decision.action).toBe("mask");
    expect(decision.matchedRuleIds[0]).toBe("specific-mask");
  });

  test("two-condition rule beats one-condition rule at equal priority", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("one-cond", 10, "mask", { category: "secret" }),                      // 1 condition
        makeRule("two-cond", 10, "block", { category: "secret", severity: "high" }),   // 2 conditions
      ],
    });
    const c = makeCandidate("c1", { category: "secret", severity: "high" });
    const decision = engine.decide([c], makeAssessment(65, "high", ["c1"]));
    // two-cond is more specific → wins
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds[0]).toBe("two-cond");
  });
});

// ── 16. Stable deterministic ID tiebreaker ────────────────────────────────────

describe("PolicyEngine — deterministic ID tiebreaker", () => {
  test("lexicographically earlier id wins when priority and specificity are equal", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("zzz-allow", 10, "allow"),   // same priority, same specificity (0)
        makeRule("aaa-block", 10, "block"),   // id "aaa-block" < "zzz-allow"
      ],
    });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    // "aaa-block" sorts before "zzz-allow" → wins
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds[0]).toBe("aaa-block");
  });

  test("ordering is stable across many calls", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("mmm-mask", 10, "mask"),
        makeRule("aaa-allow", 10, "allow"),
        makeRule("zzz-block", 10, "block"),
      ],
    });
    const first = engine.decide([], makeAssessment(50, "medium")).action;
    for (let i = 0; i < 20; i++) {
      const d = engine.decide([], makeAssessment(50, "medium"));
      expect(d.action).toBe(first);
    }
  });
});

// ── 17. Multiple matched rules are recorded ───────────────────────────────────

describe("PolicyEngine — multiple matched rules recorded", () => {
  test("all matching rules appear in matchedRuleIds", () => {
    // Use custom engine with two catch-all rules
    const engine = new PolicyEngine({
      rules: [
        makeRule("rule-a", 10, "block"),
        makeRule("rule-b", 20, "mask"),
        makeRule("rule-c", 30, "allow"),
      ],
    });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    // All three are catch-alls → all match
    expect(decision.matchedRuleIds).toContain("rule-a");
    expect(decision.matchedRuleIds).toContain("rule-b");
    expect(decision.matchedRuleIds).toContain("rule-c");
    expect(decision.matchedRuleIds).toHaveLength(3);
  });

  test("winning rule id appears first in matchedRuleIds", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("winner", 5, "block"),
        makeRule("runner-up", 10, "mask"),
      ],
    });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    expect(decision.matchedRuleIds[0]).toBe("winner");
  });

  test("non-matching rules do NOT appear in matchedRuleIds", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("match-pii", 10, "mask", { category: "pii" }),
        makeRule("no-match-secret", 20, "block", { category: "secret" }),
      ],
    });
    const c = makeCandidate("c1", { category: "pii" });
    const decision = engine.decide([c], makeAssessment(40, "medium", ["c1"]));
    expect(decision.matchedRuleIds).toContain("match-pii");
    expect(decision.matchedRuleIds).not.toContain("no-match-secret");
  });

  test("default engine: critical secret matches both block-critical-secret and block-critical-risk", () => {
    const engine = new PolicyEngine();
    const c = makeCandidate("c1", { category: "secret", severity: "critical" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    expect(decision.matchedRuleIds).toContain("block-critical-secret");
    expect(decision.matchedRuleIds).toContain("block-critical-risk");
  });
});

// ── 18. Default action when no rule matches ───────────────────────────────────

describe("PolicyEngine — default action", () => {
  test("empty rule set + defaultAction allow → allow", () => {
    const engine = new PolicyEngine({ rules: [], defaultAction: "allow" });
    const decision = engine.decide([], makeAssessment(85, "critical"));
    expect(decision.action).toBe("allow");
    expect(decision.matchedRuleIds).toHaveLength(0);
  });

  test("empty rule set + defaultAction block → block", () => {
    const engine = new PolicyEngine({ rules: [], defaultAction: "block" });
    const decision = engine.decide([], makeAssessment(85, "critical"));
    expect(decision.action).toBe("block");
  });

  test("no matching rule → default 'allow' applies (built-in default)", () => {
    // Rule requires category=secret, but we send pii
    const engine = new PolicyEngine({
      rules: [makeRule("secret-only", 1, "block", { category: "secret" })],
      defaultAction: "allow",
    });
    const c = makeCandidate("c1", { category: "pii" });
    const decision = engine.decide([c], makeAssessment(85, "critical", ["c1"]));
    expect(decision.action).toBe("allow");
    expect(decision.matchedRuleIds).toHaveLength(0);
  });

  test("default reason is non-empty and references the default action", () => {
    const engine = new PolicyEngine({ rules: [], defaultAction: "mask" });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    expect(decision.reason.toLowerCase()).toContain("mask");
    expect(decision.reason.length).toBeGreaterThan(0);
  });
});

// ── 19. Determinism ───────────────────────────────────────────────────────────

describe("PolicyEngine — determinism", () => {
  const engine = new PolicyEngine();

  test("same input → same decision on repeated calls", () => {
    const c = makeCandidate("c1", { category: "secret", severity: "critical" });
    const assessment = makeAssessment(91, "critical", ["c1"]);
    const first = engine.decide([c], assessment);

    for (let i = 0; i < 20; i++) {
      const d = engine.decide([c], assessment);
      expect(d.action).toBe(first.action);
      expect(d.reason).toBe(first.reason);
      expect(d.matchedRuleIds).toEqual(first.matchedRuleIds);
    }
  });

  test("decision is independent of candidate array order", () => {
    const c1 = makeCandidate("alpha", { category: "secret", severity: "critical" });
    const c2 = makeCandidate("beta", { category: "pii", severity: "low" });
    const assessment = makeAssessment(91, "critical", ["alpha", "beta"]);

    const d1 = engine.decide([c1, c2], assessment);
    const d2 = engine.decide([c2, c1], assessment);
    expect(d1.action).toBe(d2.action);
    expect(d1.reason).toBe(d2.reason);
  });
});

// ── 20. Raw secret values never appear in reason ──────────────────────────────

describe("PolicyEngine — security: no raw values in reason", () => {
  const RAW_SECRET = "AKIAIOSFODNN7EXAMPLE";

  test("reason does not contain the raw candidate value", () => {
    const engine = new PolicyEngine();
    const c = makeCandidate("c1", {
      category: "secret",
      severity: "critical",
      value: RAW_SECRET,
    });
    const decision = engine.decide([c], makeAssessment(91, "critical", ["c1"]));
    expect(decision.reason).not.toContain(RAW_SECRET);
  });

  test("reason does not contain raw value even for custom rules", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("custom", 1, "block", { category: "secret" }),
      ],
    });
    const c = makeCandidate("c1", {
      category: "secret",
      severity: "high",
      value: RAW_SECRET,
    });
    const decision = engine.decide([c], makeAssessment(65, "high", ["c1"]));
    expect(decision.reason).not.toContain(RAW_SECRET);
  });

  test("reason does not contain any candidate value string", () => {
    const engine = new PolicyEngine();
    const secrets = ["password123!", "ghp_ExampleGitHubToken"];
    const candidates = secrets.map((s, i) =>
      makeCandidate(`c${i}`, { category: "secret", severity: "critical", value: s }),
    );
    const decision = engine.decide(candidates, makeAssessment(95, "critical", ["c0", "c1"]));
    for (const s of secrets) {
      expect(decision.reason).not.toContain(s);
    }
  });
});

// ── 21. Decision contains risk score and risk level ───────────────────────────

describe("PolicyEngine — decision carries risk metadata", () => {
  const engine = new PolicyEngine();

  test("riskScore matches assessment score", () => {
    const decision = engine.decide([], makeAssessment(73.5, "high"));
    expect(decision.riskScore).toBe(73.5);
  });

  test("riskLevel matches assessment level", () => {
    const decision = engine.decide([], makeAssessment(73.5, "high"));
    expect(decision.riskLevel).toBe("high");
  });

  test("fractional scores are preserved exactly", () => {
    const decision = engine.decide([], makeAssessment(42.789, "medium"));
    expect(decision.riskScore).toBe(42.789);
  });
});

// ── 22. Decision contains candidate IDs ───────────────────────────────────────

describe("PolicyEngine — decision carries candidate IDs", () => {
  const engine = new PolicyEngine();

  test("candidateIds is taken from assessment.candidateIds", () => {
    const assessment = makeAssessment(40, "medium", ["id-alpha", "id-beta", "id-gamma"]);
    const decision = engine.decide([], assessment);
    expect(decision.candidateIds).toEqual(["id-alpha", "id-beta", "id-gamma"]);
  });

  test("empty candidateIds when assessment has none", () => {
    const decision = engine.decide([], makeAssessment(0, "low", []));
    expect(decision.candidateIds).toHaveLength(0);
  });
});

// ── 23. Decision contains matched rule IDs ────────────────────────────────────

describe("PolicyEngine — decision carries matched rule IDs", () => {
  const engine = new PolicyEngine();

  test("at least one matched rule ID for a critical risk assessment", () => {
    const decision = engine.decide([], makeAssessment(85, "critical"));
    expect(decision.matchedRuleIds.length).toBeGreaterThan(0);
  });

  test("matchedRuleIds contains the winning rule ID", () => {
    const decision = engine.decide([], makeAssessment(85, "critical"));
    expect(decision.matchedRuleIds[0]).toBe("block-critical-risk");
  });
});

// ── 24. Catch-all rule (no conditions) ───────────────────────────────────────

describe("PolicyEngine — catch-all rule", () => {
  test("rule with no conditions matches every request", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("catch-all-block", 1, "block")],
    });
    // No candidates, zero risk — catch-all still matches
    const decision = engine.decide([], makeAssessment(0, "low"));
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds).toContain("catch-all-block");
  });
});

// ── 25–26. minRiskScore boundary ─────────────────────────────────────────────
// (covered in section 12 above, included here for reference completeness)

// ── 27. Empty rule set → defaultAction ───────────────────────────────────────
// (covered in section 18 above)

// ── 28. defaultAction override ───────────────────────────────────────────────
// (covered in section 18 above)

// ── 29. ANY candidate in list satisfies a category condition ─────────────────

describe("PolicyEngine — any-candidate matching for category/subtype/severity", () => {
  test("rule matches if ANY candidate has the required category", () => {
    const engine = new PolicyEngine({
      rules: [makeRule("block-secret", 1, "block", { category: "secret" })],
    });
    const piiCandidate = makeCandidate("c1", { category: "pii" });
    const secretCandidate = makeCandidate("c2", { category: "secret" });
    // Mix of pii + secret → block rule fires because c2 is a secret
    const decision = engine.decide([piiCandidate, secretCandidate], makeAssessment(50, "medium", ["c1", "c2"]));
    expect(decision.action).toBe("block");
  });

  test("rule does NOT match if no candidate has the required category", () => {
    const engine = new PolicyEngine({
      rules: [
        makeRule("block-secret", 1, "block", { category: "secret" }),
        makeRule("allow-all", 999, "allow"),
      ],
    });
    const piiOnly = [makeCandidate("c1", { category: "pii" })];
    const decision = engine.decide(piiOnly, makeAssessment(50, "medium", ["c1"]));
    expect(decision.action).toBe("allow");
  });
});

// ── 30. Five rules with same priority resolved deterministically ──────────────

describe("PolicyEngine — stable multi-rule sort", () => {
  test("five same-priority rules always produce same winner", () => {
    const rules: PolicyRule[] = [
      makeRule("echo", 10, "allow"),
      makeRule("alpha", 10, "block"),
      makeRule("delta", 10, "mask"),
      makeRule("bravo", 10, "allow"),
      makeRule("charlie", 10, "block"),
    ];
    // All catch-alls, same priority (0 conditions each)
    // Sorted by id: alpha < bravo < charlie < delta < echo
    // Winner: alpha → block
    const engine = new PolicyEngine({ rules });
    const decision = engine.decide([], makeAssessment(50, "medium"));
    expect(decision.action).toBe("block");
    expect(decision.matchedRuleIds[0]).toBe("alpha");
  });
});

// ── DEFAULT_POLICY_RULES export ───────────────────────────────────────────────

describe("DEFAULT_POLICY_RULES", () => {
  test("contains 6 rules", () => {
    expect(DEFAULT_POLICY_RULES).toHaveLength(6);
  });

  test("all rule IDs are unique", () => {
    const ids = DEFAULT_POLICY_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("block-critical-secret has lower priority number than block-critical-risk", () => {
    const blockSecret = DEFAULT_POLICY_RULES.find((r) => r.id === "block-critical-secret");
    const blockRisk = DEFAULT_POLICY_RULES.find((r) => r.id === "block-critical-risk");
    expect(blockSecret?.priority).toBeLessThan(blockRisk?.priority ?? Infinity);
  });

  test("allow-low-risk is a catch-all for low risk", () => {
    const rule = DEFAULT_POLICY_RULES.find((r) => r.id === "allow-low-risk");
    expect(rule?.action).toBe("allow");
    expect(rule?.riskLevel).toBe("low");
  });
});
