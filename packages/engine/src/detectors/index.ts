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
import { SemanticInjectionDetector } from "./injection/SemanticInjectionDetector";
import type { Detector } from "../detector/Detector";
import type { DetectorRegistry } from "../detector/DetectorRegistry";

export { SecretRegexDetector } from "./secrets/SecretRegexDetector";
export { EntropySecretDetector, calculateShannonEntropy } from "./secrets/EntropySecretDetector";
export { CreditCardDetector, isValidLuhn } from "./pii/CreditCardDetector";
export { PiiGlinerDetector } from "./pii/PiiGlinerDetector";
export type { PiiGlinerDetectorOptions } from "./pii/PiiGlinerDetector";
export { PromptInjectionDetector } from "./injection/PromptInjectionDetector";
export { SemanticInjectionDetector } from "./injection/SemanticInjectionDetector";
export type { SemanticInjectionDetectorOptions } from "./injection/SemanticInjectionDetector";

export interface DefaultDetectorsOptions {
  readonly serviceUrl?: string | undefined;
}

/**
 * Instantiate the default production detector set.
 * Note: DummyDetector is explicitly excluded from production default set.
 */
export function createDefaultDetectors(options: DefaultDetectorsOptions = {}): Detector[] {
  return [
    new PromptInjectionDetector(),
    new SecretRegexDetector(),
    new EntropySecretDetector(),
    new CreditCardDetector(),
    new PiiGlinerDetector({ serviceUrl: options.serviceUrl }),
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
