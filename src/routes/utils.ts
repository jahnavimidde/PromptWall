import type { Context } from "hono";
import { getConfig } from "../config";
import type { RequestLogData, RequestProvider, RequestSource } from "../logging/logger";
import { logRequest } from "../logging/logger";
import type { PIIDetectResult } from "../pii/request";
import { ProviderError } from "../providers/errors";
import type { SecretsProcessResult } from "../secrets/request";

// ============================================================================
// Error Response Types & Formatting
// ============================================================================

export interface OpenAIErrorResponse {
  error: {
    message: string;
    type: "invalid_request_error" | "server_error";
    param: null;
    code: string | null;
  };
}

export interface AnthropicErrorResponse {
  type: "error";
  error: {
    type: "invalid_request_error" | "server_error";
    message: string;
  };
}

export const errorFormats = {
  openai: {
    error(
      message: string,
      type: "invalid_request_error" | "server_error",
      code?: string,
    ): OpenAIErrorResponse {
      return {
        error: {
          message,
          type,
          param: null,
          code: code ?? null,
        },
      };
    },
  },

  anthropic: {
    error(message: string, type: "invalid_request_error" | "server_error"): AnthropicErrorResponse {
      return {
        type: "error",
        error: {
          type,
          message,
        },
      };
    },
  },
};

// ============================================================================
// Response Headers
// ============================================================================

export interface PIIHeaderData {
  hasPII: boolean;
}

export interface SecretsHeaderData {
  detected: boolean;
  types: string[];
  masked: boolean;
}

export function setResponseHeaders(
  c: Context,
  mode: string,
  provider: string,
  pii: PIIHeaderData,
  secrets?: SecretsHeaderData,
): void {
  c.header("X-PasteGuard-Mode", mode);
  c.header("X-PasteGuard-Provider", provider);
  c.header("X-PasteGuard-PII-Detected", pii.hasPII.toString());

  if (mode === "mask" && pii.hasPII) {
    c.header("X-PasteGuard-PII-Masked", "true");
  }
  if (secrets?.detected) {
    c.header("X-PasteGuard-Secrets-Detected", "true");
    c.header("X-PasteGuard-Secrets-Types", secrets.types.join(","));
  }
  if (secrets?.masked) {
    c.header("X-PasteGuard-Secrets-Masked", "true");
  }
}

export function setBlockedHeaders(c: Context, secretTypes: string[]): void {
  c.header("X-PasteGuard-Secrets-Detected", "true");
  c.header("X-PasteGuard-Secrets-Types", secretTypes.join(","));
}

export function setStreamingHeaders(c: Context): void {
  c.header("Content-Type", "text/event-stream");
  c.header("Cache-Control", "no-cache");
  c.header("Connection", "keep-alive");
}

// ============================================================================
// Logging Helpers
// ============================================================================

export interface PIILogData {
  hasPII: boolean;
  entityTypes: string[];
  scanTimeMs: number;
}

export interface SecretsLogData {
  detected?: boolean;
  types?: string[];
  masked: boolean;
}

export function toPIILogData(piiResult: PIIDetectResult): PIILogData {
  return {
    hasPII: piiResult.hasPII,
    entityTypes: [...new Set(piiResult.detection.allEntities.map((e) => e.entity_type))],
    scanTimeMs: piiResult.detection.scanTimeMs,
  };
}

export function toPIIHeaderData(piiResult: PIIDetectResult): PIIHeaderData {
  return {
    hasPII: piiResult.hasPII,
  };
}

export function toSecretsLogData<T>(
  secretsResult: SecretsProcessResult<T>,
): SecretsLogData | undefined {
  if (!secretsResult.detection) return undefined;
  return {
    detected: secretsResult.detection.detected,
    types: secretsResult.detection.matches.map((m) => m.type),
    masked: secretsResult.masked,
  };
}

export function toSecretsHeaderData<T>(
  secretsResult: SecretsProcessResult<T>,
): SecretsHeaderData | undefined {
  if (!secretsResult.detection?.detected) return undefined;
  return {
    detected: true,
    types: secretsResult.detection.matches.map((m) => m.type),
    masked: secretsResult.masked,
  };
}

/** Actual LLM providers that can be routed to and can fail. Derived from RequestProvider (DB schema). */
export type ProviderId = Exclude<RequestProvider, "api">;

/** All provider values that may appear in logs, including the internal API category. */
export type LogProviderId = RequestProvider;

export interface CreateLogDataOptions {
  provider: LogProviderId;
  source?: RequestSource;
  model: string;
  startTime: number;
  pii?: PIILogData;
  secrets?: SecretsLogData;
  maskedContent?: string;
  statusCode?: number;
  errorMessage?: string;
}

export function createLogData(options: CreateLogDataOptions): RequestLogData {
  const config = getConfig();
  const { provider, model, startTime, pii, secrets, maskedContent, statusCode, errorMessage } =
    options;

  return {
    timestamp: new Date().toISOString(),
    mode: config.mode,
    provider,
    source: options.source,
    model: model || "unknown",
    piiDetected: pii?.hasPII ?? false,
    entities: pii?.entityTypes ?? [],
    latencyMs: Date.now() - startTime,
    scanTimeMs: pii?.scanTimeMs ?? 0,
    maskedContent,
    secretsDetected: secrets?.detected,
    secretsMasked: secrets?.masked,
    secretsTypes: secrets?.types,
    statusCode,
    errorMessage,
  };
}

// ============================================================================
// Provider Error Handling
// ============================================================================

export interface ProviderErrorContext {
  provider: ProviderId;
  model: string;
  startTime: number;
  pii?: PIILogData;
  secrets?: SecretsLogData;
  maskedContent?: string;
  userAgent: string | null;
}

export function handleProviderError(
  c: Context,
  error: unknown,
  ctx: ProviderErrorContext,
  formatError: (message: string) => object,
): Response {
  console.error(`${ctx.provider} request error:`, error);

  if (error instanceof ProviderError) {
    logRequest(
      createLogData({
        provider: ctx.provider,
        model: ctx.model,
        startTime: ctx.startTime,
        pii: ctx.pii,
        secrets: ctx.secrets,
        maskedContent: ctx.maskedContent,
        statusCode: error.status,
        errorMessage: error.errorMessage,
      }),
      ctx.userAgent,
    );

    return new Response(error.body, {
      status: error.status,
      headers: c.res.headers,
    });
  }

  const message = error instanceof Error ? error.message : "Unknown error";
  const errorMessage = `Provider error: ${message}`;

  logRequest(
    createLogData({
      provider: ctx.provider,
      model: ctx.model,
      startTime: ctx.startTime,
      pii: ctx.pii,
      secrets: ctx.secrets,
      maskedContent: ctx.maskedContent,
      statusCode: 502,
      errorMessage,
    }),
    ctx.userAgent,
  );

  return c.json(formatError(errorMessage), 502);
}

// ============================================================================
// Query Credential Stripping
// ============================================================================

/**
 * Gateway credential query-parameter names.
 *
 * These parameters are accepted by {@link extractGatewayCredential} for
 * authentication and MUST be removed from the upstream URL before proxying.
 * Forwarding them would expose PromptWall credentials in upstream server logs,
 * CDN access logs, HTTP Referer headers, and browser history.
 *
 * Only authentication-specific names are listed here. Provider-specific
 * parameters (e.g. `provider`, `stream`, `limit`) are never touched.
 */
const CREDENTIAL_QUERY_PARAMS = new Set(["api_key", "token"]);

/**
 * Strip gateway credential parameters from a raw query string.
 *
 * Uses `URLSearchParams` for safe, RFC-3986-compliant parsing so that:
 * - URL-encoded characters in values are decoded and re-encoded correctly.
 * - Repeated parameter names are each removed independently.
 * - Unrelated parameters (e.g. `provider=openai&limit=10`) are preserved in order.
 * - No naive string replacement is used.
 *
 * @param rawQuery - The raw query portion of the URL, with or without a leading `?`.
 * @returns A sanitized query string WITHOUT a leading `?`.
 *          Returns an empty string when no non-credential parameters remain.
 *
 * @example
 * stripCredentialParams("?api_key=pw_live_xxx&provider=openai&token=jwt")
 * // => "provider=openai"
 *
 * stripCredentialParams("?provider=openai&limit=10")
 * // => "provider=openai&limit=10"
 *
 * stripCredentialParams("")
 * // => ""
 */
export function stripCredentialParams(rawQuery: string): string {
  if (!rawQuery) return "";
  const qs = rawQuery.startsWith("?") ? rawQuery.slice(1) : rawQuery;
  if (!qs) return "";
  const params = new URLSearchParams(qs);
  for (const key of CREDENTIAL_QUERY_PARAMS) {
    params.delete(key);
  }
  return params.toString();
}

/**
 * Build a sanitized upstream URL by appending a credential-free query string.
 *
 * Adds the leading `?` only when non-credential parameters remain after stripping.
 * Credential parameters are stripped via {@link stripCredentialParams}.
 *
 * @param base     - The base URL (path, no query string).
 * @param rawQuery - The raw query string from the incoming request (with or without `?`).
 * @returns The base URL with a clean, credential-free query string appended.
 */
export function buildSanitizedUrl(base: string, rawQuery: string): string {
  const clean = stripCredentialParams(rawQuery);
  return clean ? `${base}?${clean}` : base;
}
