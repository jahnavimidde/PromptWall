import type { LLMRequest, LLMResponse, ProxyAdapter } from "../types";
import type { AnthropicMessage, AnthropicRequest, AnthropicResponse, ContentBlock } from "./types";

const NORMALIZED_RESPONSE_FIELDS = ["object", "choices", "created"] as const;

/**
 * Anthropic Adapter
 * Handles translation between PromptWall generic format and Anthropic Messages API schema.
 */
export class AnthropicAdapter implements ProxyAdapter<AnthropicResponse> {
  /**
   * Convert generic PromptWall LLMRequest into AnthropicRequest
   */
  toProviderRequest(request: LLMRequest): AnthropicRequest {
    const { model, messages, temperature, top_p, max_tokens, stream, system, ...rest } = request;

    const anthropicMessages: AnthropicMessage[] = [];
    let systemPrompt: AnthropicRequest["system"] = typeof system === "string" ? system : undefined;

    for (const msg of messages ?? []) {
      const { role, content, ...msgRest } = msg;

      if (role === "system") {
        if (!systemPrompt) {
          systemPrompt = content as AnthropicRequest["system"];
        }
        continue;
      }

      anthropicMessages.push({
        ...msgRest,
        role: role as AnthropicMessage["role"],
        content: content as AnthropicMessage["content"],
      });
    }

    const anthropicRequest: AnthropicRequest = {
      ...rest,
      model: model || "claude-3-5-sonnet-20241022",
      messages: anthropicMessages.length > 0 ? anthropicMessages : [{ role: "user", content: "" }],
      max_tokens: max_tokens || 4096,
      temperature,
      top_p,
      stream,
    };

    if (systemPrompt) {
      anthropicRequest.system = systemPrompt;
    }

    return anthropicRequest;
  }

  /**
   * Convert AnthropicResponse into generic PromptWall LLMResponse
   */
  fromProviderResponse(response: AnthropicResponse): LLMResponse {
    if (!response) {
      return response as unknown as LLMResponse;
    }

    const contentText = Array.isArray(response.content)
      ? response.content
          .map((block: ContentBlock) => (block.type === "text" ? block.text : ""))
          .join("")
      : String(response.content || "");

    return {
      ...response,
      id: response.id,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: response.model,
      choices: [
        {
          index: 0,
          message: {
            role: response.role || "assistant",
            content: contentText,
          },
          finish_reason: response.stop_reason || "stop",
        },
      ],
      usage: response.usage
        ? {
            prompt_tokens: response.usage.input_tokens,
            completion_tokens: response.usage.output_tokens,
            total_tokens: response.usage.input_tokens + response.usage.output_tokens,
          }
        : undefined,
    };
  }

  toProxyResponse(response: LLMResponse): AnthropicResponse {
    const proxyResponse = { ...response } as Record<string, unknown>;
    for (const field of NORMALIZED_RESPONSE_FIELDS) {
      delete proxyResponse[field];
    }

    const usage = response.usage;
    if (
      usage &&
      typeof usage.prompt_tokens === "number" &&
      typeof usage.completion_tokens === "number"
    ) {
      proxyResponse.usage = {
        input_tokens: usage.prompt_tokens,
        output_tokens: usage.completion_tokens,
      };
    }

    return proxyResponse as AnthropicResponse;
  }
}

export const anthropicAdapter = new AnthropicAdapter();
