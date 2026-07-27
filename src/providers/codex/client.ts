import { type CodexProviderConfig, getConfig } from "../../config";
import { ProviderError } from "../errors";
import type { CodexRequest, CodexResponse } from "./types";

export type CodexResult =
  | {
      isStreaming: true;
      response: ReadableStream<Uint8Array>;
      model: string;
    }
  | {
      isStreaming: false;
      response: CodexResponse;
      model: string;
    };

/**
 * Executes post request to Codex responses API.
 */
export async function callCodex(
  request: CodexRequest,
  config: CodexProviderConfig,
  clientHeaders?: Record<string, string>,
): Promise<CodexResult> {
  const baseUrl = config.base_url.replace(/\/$/, "");
  const endpoint = `${baseUrl}/responses`;
  const timeoutMs = getConfig().server.request_timeout * 1000;

  // Filter out headers that could conflict
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (clientHeaders) {
    for (const [key, value] of Object.entries(clientHeaders)) {
      const lower = key.toLowerCase();
      if (lower === "host" || lower === "content-length" || lower === "content-type") continue;
      headers[key] = value;
    }
  }

  const response = await fetch(endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify(request),
    signal: timeoutMs > 0 ? AbortSignal.timeout(timeoutMs) : undefined,
  });

  if (!response.ok) {
    throw new ProviderError(response.status, response.statusText, await response.text());
  }

  const contentType = response.headers.get("content-type") || "";
  const isStreaming = (request.stream ?? false) || contentType.includes("text/event-stream");
  const model = request.model || config.model || "codex";

  if (isStreaming) {
    if (!response.body) {
      throw new Error("No response body for streaming request");
    }
    return { response: response.body, isStreaming: true, model };
  }

  const jsonResponse = (await response.json()) as CodexResponse;
  return { response: jsonResponse, isStreaming: false, model };
}

export function getCodexInfo(config: CodexProviderConfig): { baseUrl: string } {
  return {
    baseUrl: config.base_url,
  };
}
