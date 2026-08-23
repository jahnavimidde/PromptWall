/**
 * @file audit-export.ts
 * @module src/logging
 *
 * Compliance audit exporter for CSV and JSON format exports (M6B).
 *
 * ── Security invariant ────────────────────────────────────────────────────────
 * Exports contain strictly sanitized classification metadata.
 * Raw values, raw secrets, PII strings, character locations, evidence details,
 * and raw prompt text are NEVER exported.
 */

import type { StoredSecurityEvent } from "./audit-logger";

export interface AuditExportOptions {
  readonly format: "csv" | "json";
  readonly filename?: string;
}

/**
 * Format a collection of `StoredSecurityEvent` records into JSON string.
 */
export function exportSecurityEventsAsJSON(events: readonly StoredSecurityEvent[]): string {
  const sanitizedEvents = events.map((e) => ({
    eventId: e.eventId,
    requestId: e.requestId,
    timestamp: e.timestamp,
    source: e.source,
    provider: e.provider,
    model: e.model,
    action: e.action,
    riskLevel: e.riskLevel,
    riskScore: e.riskScore,
    decisionReason: e.decisionReason,
    matchedRuleIds: e.matchedRuleIds,
    detectorsTriggered: e.detectorsTriggered,
    candidates: e.candidates.map((c) => ({
      id: c.id,
      category: c.category,
      subtype: c.subtype,
      severity: c.severity,
      confidence: c.confidence,
      detector: c.detector,
    })),
    latencyMs: e.latencyMs,
  }));

  return JSON.stringify(sanitizedEvents, null, 2);
}

/**
 * Format a collection of `StoredSecurityEvent` records into CSV format string.
 */
export function exportSecurityEventsAsCSV(events: readonly StoredSecurityEvent[]): string {
  const headers = [
    "eventId",
    "requestId",
    "timestamp",
    "provider",
    "model",
    "action",
    "riskLevel",
    "riskScore",
    "decisionReason",
    "detectorsTriggered",
    "candidateSubtypes",
    "latencyMs",
  ];

  const escapeCSV = (val: unknown): string => {
    if (val === null || val === undefined) return '""';
    const str = String(val);
    if (str.includes(",") || str.includes('"') || str.includes("\n")) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return `"${str}"`;
  };

  const rows = events.map((e) => {
    const detectors = e.detectorsTriggered.join("; ");
    const subtypes = e.candidates.map((c) => `${c.category}:${c.subtype}`).join("; ");

    return [
      escapeCSV(e.eventId),
      escapeCSV(e.requestId),
      escapeCSV(e.timestamp),
      escapeCSV(e.provider),
      escapeCSV(e.model),
      escapeCSV(e.action),
      escapeCSV(e.riskLevel),
      escapeCSV(e.riskScore),
      escapeCSV(e.decisionReason),
      escapeCSV(detectors),
      escapeCSV(subtypes),
      escapeCSV(e.latencyMs),
    ].join(",");
  });

  return [headers.join(","), ...rows].join("\n");
}
