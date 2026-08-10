/**
 * @file index.ts
 * @module @promptwall/engine/detectors
 *
 * Registration helper and exports for production default security detectors.
 */

import { SecretRegexDetector } from "./secrets/SecretRegexDetector";
import { EntropySecretDetector } from "./secrets/EntropySecretDetector";
import { CreditCardDetector } from "./pii/CreditCardDetector";
import { PiiGlinerDetector } from "./pii/PiiGlinerDetector";
import { PromptInjectionDetector } from "./injection/PromptInjectionDetector";
import type { Detector } from "../detector/Detector";
import type { DetectorRegistry } from "../detector/DetectorRegistry";

export { SecretRegexDetector } from "./secrets/SecretRegexDetector";
export { EntropySecretDetector, calculateShannonEntropy } from "./secrets/EntropySecretDetector";
export { CreditCardDetector, isValidLuhn } from "./pii/CreditCardDetector";
export { PiiGlinerDetector } from "./pii/PiiGlinerDetector";
export type { PiiGlinerDetectorOptions } from "./pii/PiiGlinerDetector";
export { PromptInjectionDetector } from "./injection/PromptInjectionDetector";

/**
 * Instantiate the default production detector set.
 * Note: DummyDetector is explicitly excluded from production default set.
 */
export function createDefaultDetectors(): Detector[] {
  return [
    new PromptInjectionDetector(),
    new SecretRegexDetector(),
    new EntropySecretDetector(),
    new CreditCardDetector(),
    new PiiGlinerDetector(),
  ];
}

/**
 * Register all default production detectors into an existing DetectorRegistry.
 */
export function registerDefaultDetectors(registry: DetectorRegistry): void {
  for (const detector of createDefaultDetectors()) {
    if (!registry.has(detector.id)) {
      registry.register(detector);
    }
  }
}
