/**
 * @file adapter.ts
 * @module src/policy
 *
 * Policy Adapter Layer (M7A).
 * Converts database StoredPolicy objects into engine PolicyRule[] without
 * modifying @promptwall/engine.
 */

import type { PolicyRule } from "@promptwall/engine";
import type { StoredPolicy } from "./policy-store";

/**
 * Map a single StoredPolicy to a engine PolicyRule.
 */
export function toPolicyRule(policy: StoredPolicy): PolicyRule {
  const cond = policy.conditions ?? {};
  return {
    id: policy.id,
    priority: policy.priority,
    action: policy.action,
    reason: policy.reason ?? `Dynamic policy '${policy.name}' matched`,
    category: cond.category,
    subtype: cond.subtype,
    severity: cond.severity,
    riskLevel: cond.riskLevel,
    minRiskScore: cond.minRiskScore,
  };
}

/**
 * Map a list of StoredPolicy objects to engine PolicyRule[].
 */
export function toPolicyRules(policies: readonly StoredPolicy[]): PolicyRule[] {
  return policies.filter((p) => p.enabled).map(toPolicyRule);
}
