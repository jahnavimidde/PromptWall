import type { LLMRequest, LLMResponse, ProxyAdapter } from "../types";
import type { CodexRequest, CodexResponse } from "./types";

const NORMALIZED_RESPONSE_FIELDS = ["object", "choices", "created"] as const;

/**
 * Codex Adapter translating between PromptWall LLMRequest and Codex custom API.
 */
export class CodexAdapter implements ProxyAdapter<CodexResponse> {
  toProviderRequest(request: LLMRequest): CodexRequest {
    const { model, messages, stream, instructions, input, ...rest } = request;

    const codexReq: CodexRequest = {
      ...rest,
      model,
      stream,
    };

    if (instructions !== undefined) {
      codexReq.instructions = instructions;
    }
    if (input !== undefined) {
      codexReq.input = input;
    }

    // Fallback mapping if standard messages array is provided
    if (messages && Array.isArray(messages) && instructions === undefined && input === undefined) {
      const systemMessage = messages.find((m) => m.role === "system");
      if (systemMessage) {
        codexReq.instructions = systemMessage.content;
      }
      const otherMessages = messages.filter((m) => m.role !== "system");
      if (otherMessages.length === 1 && otherMessages[0].role === "user") {
        codexReq.input = otherMessages[0].content;
      } else if (otherMessages.length > 0) {
        codexReq.input = otherMessages;
      }
    }

    return codexReq;
  }

  fromProviderResponse(response: CodexResponse): LLMResponse {
    if (!response) {
      return response as unknown as LLMResponse;
    }

    const outputText = response.output_text || response.output || response.text || "";

    return {
      ...response,
      // Preserve provider fields exactly. Proxy responses must not expose
      // normalization-only defaults that were absent from the upstream body.
      id: response.id as string | undefined,
      object: "chat.completion",
      model: response.model as string | undefined,
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: outputText,
          },
          finish_reason: "stop",
        },
      ],
    };
  }

  toProxyResponse(response: LLMResponse): CodexResponse {
    const proxyResponse = { ...response } as Record<string, unknown>;
    for (const field of NORMALIZED_RESPONSE_FIELDS) {
      delete proxyResponse[field];
    }
    return proxyResponse as CodexResponse;
  }
}

export const codexAdapter = new CodexAdapter();
