/**
 * @file index.ts
 * @module @promptwall/engine/audit
 *
 * Barrel for the audit logging types exported by the engine package.
 */

export type { CandidateSummary, SecurityEvent } from "./SecurityEvent";
export { buildSecurityEvent } from "./SecurityEvent";
export type { AuditLogger } from "./AuditLogger";
