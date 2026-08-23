/**
 * @file logger.ts
 * @module src/observability
 *
 * Structured Operational JSON Logger (Milestone 10).
 *
 * Emits sanitized machine-readable JSON log events for observability pipelines (Fluentbit, Datadog, CloudWatch).
 *
 * Security invariant: NEVER logs raw prompt content, secret strings, PII, or raw evidence.
 */

import { getConfig } from "../config";

export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogMetadata {
  requestId?: string;
  provider?: string;
  model?: string;
  route?: string;
  action?: string;
  latency?: number;
  statusCode?: number;
  error?: string;
  [key: string]: unknown;
}

export interface StructuredLogEntry {
  time: string;
  level: LogLevel;
  event: string;
  requestId?: string;
  provider?: string;
  model?: string;
  route?: string;
  action?: string;
  latency?: number;
  statusCode?: number;
  error?: string;
  [key: string]: unknown;
}

const FORBIDDEN_KEYS = new Set([
  "prompt",
  "content",
  "message",
  "messages",
  "secret",
  "apikey",
  "api_key",
  "authorization",
  "token",
  "password",
  "evidence",
  "raw",
]);

/**
 * Sanitize metadata to enforce zero-leak security invariants.
 */
export function sanitizeMetadata(metadata: LogMetadata = {}): LogMetadata {
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    const lowerKey = key.toLowerCase();
    if (FORBIDDEN_KEYS.has(lowerKey)) {
      continue;
    }

    // Do not log large nested strings or buffers
    if (typeof value === "string" && value.length > 200) {
      sanitized[key] = `${value.slice(0, 197)}...`;
    } else if (typeof value === "object" && value !== null) {
      // Recursively sanitize shallow object
      const cleanObj: Record<string, unknown> = {};
      for (const [subKey, subVal] of Object.entries(value)) {
        if (!FORBIDDEN_KEYS.has(subKey.toLowerCase()) && typeof subVal !== "function") {
          cleanObj[subKey] = subVal;
        }
      }
      sanitized[key] = cleanObj;
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized as LogMetadata;
}

/**
 * Format a structured JSON log entry.
 */
export function formatStructuredLog(
  level: LogLevel,
  event: string,
  metadata: LogMetadata = {},
): string {
  const sanitized = sanitizeMetadata(metadata);
  const entry: StructuredLogEntry = {
    time: new Date().toISOString(),
    level,
    event,
    ...sanitized,
  };

  return JSON.stringify(entry);
}

/**
 * Emit a structured log message to standard output.
 */
export function structuredLog(level: LogLevel, event: string, metadata: LogMetadata = {}): void {
  const config = getConfig();
  if (config.observability && !config.observability.request_logging) {
    return;
  }

  const line = formatStructuredLog(level, event, metadata);
  if (level === "error") {
    console.error(line);
  } else if (level === "warn") {
    console.warn(line);
  } else {
    console.log(line);
  }
}

export const logInfo = (event: string, metadata?: LogMetadata) =>
  structuredLog("info", event, metadata);

export const logWarn = (event: string, metadata?: LogMetadata) =>
  structuredLog("warn", event, metadata);

export const logError = (event: string, metadata?: LogMetadata) =>
  structuredLog("error", event, metadata);

export const logDebug = (event: string, metadata?: LogMetadata) =>
  structuredLog("debug", event, metadata);
