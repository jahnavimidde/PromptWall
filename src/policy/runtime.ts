/**
 * @file runtime.ts
 * @module src/policy
 *
 * Cached Policy Engine Runtime (M7A).
 * Maintains a high-performance in-memory PolicyEngine instance initialized
 * from database policies, with cache invalidation after policy mutations.
 */

import { DEFAULT_POLICY_RULES, PolicyEngine } from "@promptwall/engine";
import { PolicyStore } from "./policy-store";

let cachedEngine: PolicyEngine | null = null;
let defaultStoreInstance: PolicyStore | null = null;

function getStore(customStore?: PolicyStore): PolicyStore {
  if (customStore) return customStore;
  if (!defaultStoreInstance) {
    defaultStoreInstance = new PolicyStore();
  }
  return defaultStoreInstance;
}

/**
 * Get the cached PolicyEngine instance.
 * Re-instantiates from database rules on cache miss, falling back to
 * DEFAULT_POLICY_RULES if no active database policies exist.
 */
export async function getPolicyEngine(customStore?: PolicyStore): Promise<PolicyEngine> {
  if (cachedEngine) {
    return cachedEngine;
  }

  const store = getStore(customStore);
  const activeRules = await store.getActivePolicyRules();

  const rulesToUse = activeRules.length > 0 ? activeRules : DEFAULT_POLICY_RULES;
  cachedEngine = new PolicyEngine({ rules: rulesToUse });

  return cachedEngine;
}

/**
 * Invalidate the in-memory policy engine cache.
 * Call this immediately after any policy creation, update, deletion, or status toggle.
 */
export function invalidatePolicyCache(): void {
  cachedEngine = null;
}
