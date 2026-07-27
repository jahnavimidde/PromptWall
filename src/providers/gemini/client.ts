import { type GeminiProviderConfig, getConfig } from "../../config";
import { ProviderError } from "../errors";
import type { GeminiGenerateContentRequest, GeminiGenerateContentResponse } from "./types";

export { ProviderError } from "../errors";

/**
 * Result from Gemini provider call
 */
export type GeminiProviderResult =
  | {
      isStreaming: true;
      response: ReadableStream<Uint8Array>;
      model: string;
    }
  | {
      isStreaming: false;
      response: GeminiGenerateContentResponse;
      model: string;
    };

/**
 * Execute Gemini REST API call
 */
export async function callGemini(
  request: GeminiGenerateContentRequest,
  config: GeminiProviderConfig,
  authHeader?: string,
): Promise<GeminiProviderResult> {
  const model = request.model || config.model || "gemini-1.5-flash";
  const isStreaming = request.stream ?? false;

  const baseUrl = config.base_url.replace(/\/$/, "");
  const action = isStreaming ? "streamGenerateContent?alt=sse" : "generateContent";
  let endpoint = `${baseUrl}/models/${model}:${action}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  // Gemini REST API authentication: always use x-goog-api-key header.
  // Google does NOT accept "Authorization: Bearer <api-key>" for API-key auth;
  // that format is only for OAuth2 tokens. Sending a Bearer header with a plain
  // API key is what caused the 403 "unregistered callers" error.
  //
  // Priority: client-supplied authHeader > config.api_key fallback
  if (authHeader) {
    // Strip the "Bearer " prefix if the client forwarded it that way — the raw
    // string after "Bearer " is the API key, not an OAuth token.
    const rawKey = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    headers["x-goog-api-key"] = rawKey;
  } else if (config.api_key) {
    headers["x-goog-api-key"] = config.api_key;
  }

  const hasKey = Boolean(headers["x-goog-api-key"]);
  console.log(
    `[Gemini] endpoint=${endpoint} auth=x-goog-api-key key_loaded=${hasKey} ` +
      `key_preview=${hasKey ? `${headers["x-goog-api-key"].slice(0, 6)}…` : "none"}`,
  );

  // Omit helper fields that shouldn't be in Gemini payload
  const { model: _, stream: __, ...geminiPayload } = request;

  const timeoutMs = getConfig().server.request_timeout * 1000;
  const response = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(geminiPayload),
    signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
  });

  if (!response.ok) {
    throw new ProviderError(response.status, response.statusText, await response.text());
  }

  if (isStreaming) {
    if (!response.body) {
      throw new Error("No response body for streaming Gemini request");
    }
    return { response: response.body, isStreaming: true, model };
  }

  const jsonResponse = (await response.json()) as GeminiGenerateContentResponse;
  return { response: jsonResponse, isStreaming: false, model };
}

/**
 * Get Gemini provider metadata info
 */
export function getGeminiInfo(config: GeminiProviderConfig): { baseUrl: string } {
  return {
    baseUrl: config.base_url,
  };
}
