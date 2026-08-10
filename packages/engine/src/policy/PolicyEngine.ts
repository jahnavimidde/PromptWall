/**
 * @file PolicyEngine.ts
 * @module @promptwall/engine/policy
 *
 * Implements the Policy Decision Engine: converts a {@link RiskAssessment}
 * and resolved {@link Candidate}s into an explicit {@link PolicyDecision}.
 *
 * ── Architectural constraints ─────────────────────────────────────────────────
 *
 * - NO knowledge of HTTP, Hono, OpenAI, Gemini, Anthropic, Ollama, databases,
 *   Docker, or external ML models.
 * - NO runtime dependencies. Pure engine-level types only.
 * - Deterministic: same input → same output, regardless of call order or time.
 * - Does NOT perform masking or blocking. That is the downstream layer's job.
 * - Does NOT expose raw candidate values in the decision reason.
 *
 * ── Rule matching algorithm ───────────────────────────────────────────────────
 *
 * Rules are sorted once at construction time using a three-level key:
 *
 *   1. priority ASC      — lower number = evaluated first (higher priority)
 *   2. specificity DESC  — more condition fields = more specific = evaluated first
 *   3. id ASC            — lexicographic stable tiebreaker
 *
 * For each call to `decide()`:
 *
 *   1. Walk the sorted rules in order.
 *   2. A rule matches when ALL of its specified conditions are satisfied:
 *        - category     → ANY candidate has this category
 *        - subtype      → ANY candidate has this subtype
 *        - severity     → ANY candidate has this severity
 *        - riskLevel    → assessment.level === rule.riskLevel
 *        - minRiskScore → assessment.score >= rule.minRiskScore
 *      Absent conditions are wildcards (always satisfied).
 *   3. Collect ALL matching rules → their IDs go into matchedRuleIds.
 *   4. The FIRST matching rule (by sort order) determines action + reason.
 *      ("higher-priority rule wins")
 *   5. If NO rule matches → use defaultAction + a generic reason.
 *
 * ── Conflict resolution ───────────────────────────────────────────────────────
 *
 * Conflicts are resolved by sort order priority:
 *
 *   "If a higher-priority rule says MASK and a lower-priority rule says BLOCK,
 *    the higher-priority rule determines the final action."
 *
 * This is a FIRST-MATCH-WINS strategy, not an action-precedence strategy.
 * Operators control conflict resolution by assigning explicit priority numbers.
 * The engine records all matched rule IDs for full audit transparency.
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 *
 * Raw candidate values (secrets, tokens, PII) are NEVER included in the
 * decision reason. The reason references categories, severity levels, and
 * rule IDs — never the actual content of a candidate.
 */

import type { Candidate } from "../candidate/Candidate";
import type { RiskAssessment } from "../risk/RiskAssessment";
import type { PolicyDecision } from "./PolicyDecision";
import type { PolicyRule } from "./PolicyRule";
import type { PolicyAction } from "./PolicyAction";

// ── Default policy rules ──────────────────────────────────────────────────────

/**
 * Safe built-in policy rules applied when no custom rules are provided.
 *
 * Priority assignment:
 * - 10: Critical secret → block (most specific, highest urgency)
 * - 20: High secret → mask
 * - 30: Critical risk level → block
 * - 40: High risk level → mask
 * - 50: Medium risk level → mask
 * - 100: Low risk level → allow (catch-all fallback)
 *
 * Rule evaluation order within each priority level: specificity then id.
 * These rules cover the full RiskLevel spectrum and common secret severities.
 */
export const DEFAULT_POLICY_RULES: readonly PolicyRule[] = [
  {
    id: "block-critical-secret",
    priority: 10,
    category: "secret",
    severity: "critical",
    action: "block",
    reason:
      "Critical credential detected — request blocked to prevent exposure.",
  },
  {
    id: "mask-high-secret",
    priority: 20,
    category: "secret",
    severity: "high",
    action: "mask",
    reason:
      "High-severity credential detected — sensitive values will be masked.",
  },
  {
    id: "block-critical-risk",
    priority: 30,
    riskLevel: "critical",
    action: "block",
    reason: "Critical overall risk level — request blocked.",
  },
  {
    id: "mask-high-risk",
    priority: 40,
    riskLevel: "high",
    action: "mask",
    reason: "High overall risk level — sensitive values will be masked.",
  },
  {
    id: "mask-medium-risk",
    priority: 50,
    riskLevel: "medium",
    action: "mask",
    reason: "Medium overall risk level — sensitive values will be masked.",
  },
  {
    id: "allow-low-risk",
    priority: 100,
    riskLevel: "low",
    action: "allow",
    reason: "Low overall risk level — request allowed.",
  },
] as const;

// ── PolicyEngineOptions ───────────────────────────────────────────────────────

/**
 * Constructor-level configuration for {@link PolicyEngine}.
 * All fields are optional; safe defaults apply when absent.
 */
export interface PolicyEngineOptions {
  /**
   * Custom rule set. Replaces — does not extend — the default rules.
   * To extend the defaults, spread {@link DEFAULT_POLICY_RULES} alongside
   * your custom rules:
   *
   * ```ts
   * new PolicyEngine({
   *   rules: [...DEFAULT_POLICY_RULES, myCustomRule],
   * });
   * ```
   *
   * Rules are sorted at construction time; insertion order does not affect
   * evaluation order.
   *
   * Defaults to {@link DEFAULT_POLICY_RULES} when absent.
   */
  readonly rules?: readonly PolicyRule[];

  /**
   * Action to apply when no rule matches.
   * @default "allow"
   */
  readonly defaultAction?: PolicyAction;
}

// ── PolicyEngine ──────────────────────────────────────────────────────────────

/**
 * Converts a {@link RiskAssessment} and resolved {@link Candidate}s into a
 * {@link PolicyDecision} using a declarative, priority-ordered rule set.
 *
 * @example Default configuration (recommended for most deployments):
 * ```ts
 * const engine = new PolicyEngine();
 * const decision = engine.decide(candidates, assessment);
 * ```
 *
 * @example Custom rules with a safe default:
 * ```ts
 * const engine = new PolicyEngine({
 *   rules: [
 *     { id: "block-all", priority: 999, action: "block", reason: "All requests blocked." },
 *   ],
 *   defaultAction: "block",
 * });
 * ```
 *
 * @example Extending the default rule set:
 * ```ts
 * const engine = new PolicyEngine({
 *   rules: [
 *     ...DEFAULT_POLICY_RULES,
 *     {
 *       id: "block-aws-keys",
 *       priority: 5,
 *       subtype: "AWS_ACCESS_KEY",
 *       action: "block",
 *       reason: "AWS access key detected — request blocked.",
 *     },
 *   ],
 * });
 * ```
 */
export class PolicyEngine {
  /**
   * Rules sorted at construction time.
   * Sort key: priority ASC → specificity DESC → id ASC.
   * Immutable after construction — `decide()` reads it without mutation.
   */
  private readonly sortedRules: readonly PolicyRule[];
  private readonly defaultAction: PolicyAction;

  constructor(options: PolicyEngineOptions = {}) {
    const rules = options.rules ?? DEFAULT_POLICY_RULES;
    this.sortedRules = sortRules(rules);
    this.defaultAction = options.defaultAction ?? "allow";
  }

  /**
   * Evaluate the rule set against the candidates and assessment, returning
   * a deterministic {@link PolicyDecision}.
   *
   * Processing steps:
   *   1. Walk sorted rules; collect all that match.
   *   2. Winning rule = first in sorted order (highest-priority match).
   *   3. Remaining matches recorded in matchedRuleIds for audit.
   *   4. If no rules match, apply defaultAction.
   *
   * @param candidates - Resolved candidates from ConfidenceEngine.
   *   Used to evaluate category, subtype, and severity conditions.
   * @param assessment - RiskAssessment from RiskEngine.
   *   Used to evaluate riskLevel and minRiskScore conditions.
   * @returns An immutable {@link PolicyDecision}.
   */
  decide(
    candidates: readonly Candidate[],
    assessment: RiskAssessment,
  ): PolicyDecision {
    // Collect all matching rules (preserving sorted order)
    const matched: PolicyRule[] = [];
    for (const rule of this.sortedRules) {
      if (ruleMatches(rule, candidates, assessment)) {
        matched.push(rule);
      }
    }

    // Winning rule: first in sorted order = highest-priority match
    const winner = matched[0];

    const action: PolicyAction = winner?.action ?? this.defaultAction;
    const reason: string = winner?.reason ?? buildDefaultReason(this.defaultAction, assessment);
    const matchedRuleIds: readonly string[] = matched.map((r) => r.id);

    return {
      action,
      reason,
      matchedRuleIds,
      riskScore: assessment.score,
      riskLevel: assessment.level,
      candidateIds: assessment.candidateIds,
    };
  }
}

// ── Private helpers ───────────────────────────────────────────────────────────

/**
 * Sort a rule set by the three-level key:
 *   1. priority ASC  (lower number = higher priority)
 *   2. specificity DESC (more conditions = more specific = higher priority)
 *   3. id ASC  (lexicographic stable tiebreaker)
 *
 * Returns a new array; the input is not mutated.
 */
function sortRules(rules: readonly PolicyRule[]): PolicyRule[] {
  return [...rules].sort((a, b) => {
    // 1. Priority: ascending (lower number runs first)
    if (a.priority !== b.priority) {
      return a.priority - b.priority;
    }
    // 2. Specificity: descending (more conditions = more specific = runs first)
    const specDiff = ruleSpecificity(b) - ruleSpecificity(a);
    if (specDiff !== 0) {
      return specDiff;
    }
    // 3. Stable lexicographic tiebreaker
    return a.id.localeCompare(b.id);
  });
}

/**
 * Count the number of defined optional condition fields on a rule.
 * Used to rank rules by specificity (more conditions = more specific).
 *
 * Counted fields: category, subtype, severity, riskLevel, minRiskScore
 */
function ruleSpecificity(rule: PolicyRule): number {
  let count = 0;
  if (rule.category !== undefined) count++;
  if (rule.subtype !== undefined) count++;
  if (rule.severity !== undefined) count++;
  if (rule.riskLevel !== undefined) count++;
  if (rule.minRiskScore !== undefined) count++;
  return count;
}

/**
 * Test whether a single rule matches the given candidates and assessment.
 *
 * All specified conditions must be satisfied (AND semantics).
 * Absent conditions are wildcards — they are always satisfied.
 *
 * Candidate conditions (category, subtype, severity) match if ANY candidate
 * in the list satisfies the condition.
 *
 * Assessment conditions (riskLevel, minRiskScore) are evaluated against the
 * assessment directly.
 */
function ruleMatches(
  rule: PolicyRule,
  candidates: readonly Candidate[],
  assessment: RiskAssessment,
): boolean {
  // category: any candidate must have this category
  if (rule.category !== undefined) {
    if (!candidates.some((c) => c.category === rule.category)) return false;
  }

  // subtype: any candidate must have this subtype (exact match)
  if (rule.subtype !== undefined) {
    if (!candidates.some((c) => c.subtype === rule.subtype)) return false;
  }

  // severity: any candidate must have this severity
  if (rule.severity !== undefined) {
    if (!candidates.some((c) => c.severity === rule.severity)) return false;
  }

  // riskLevel: assessment level must equal the rule's required level
  if (rule.riskLevel !== undefined) {
    if (assessment.level !== rule.riskLevel) return false;
  }

  // minRiskScore: assessment score must be >= the rule's minimum
  if (rule.minRiskScore !== undefined) {
    if (assessment.score < rule.minRiskScore) return false;
  }

  return true;
}

/**
 * Build a generic reason string when no rule matched.
 * Never references raw candidate values.
 */
function buildDefaultReason(
  defaultAction: PolicyAction,
  assessment: RiskAssessment,
): string {
  return (
    `No policy rule matched — default action '${defaultAction}' applied. ` +
    `Risk: ${assessment.level} (score: ${assessment.score.toFixed(1)}).`
  );
}
