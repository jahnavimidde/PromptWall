import type { LLMRequest, LLMResponse, ProviderAdapter } from "../types";
import type { OpenAIMessage, OpenAIRequest, OpenAIResponse } from "./types";

/**
 * OpenAI Adapter
 * Handles translation between PromptWall generic format and OpenAI API schema.
 */
export class OpenAIAdapter implements ProviderAdapter<OpenAIRequest, OpenAIResponse> {
  /**
   * Convert generic PromptWall LLMRequest into OpenAIRequest
   */
  toProviderRequest(request: LLMRequest): OpenAIRequest {
    const { model, messages, temperature, top_p, max_tokens, stream, ...rest } = request;

    const openAIMessages: OpenAIMessage[] = (messages ?? []).map((msg) => {
      const { role, content, ...msgRest } = msg;
      return {
        ...msgRest,
        role: role as OpenAIMessage["role"],
        content: content as OpenAIMessage["content"],
      };
    });

    const openAIRequest: OpenAIRequest = {
      ...rest,
      model,
      messages: openAIMessages,
      temperature,
      top_p,
      max_tokens,
      stream,
    };

    return openAIRequest;
  }

  /**
   * Convert OpenAIResponse into generic PromptWall LLMResponse
   */
  fromProviderResponse(response: OpenAIResponse): LLMResponse {
    if (!response) {
      return response as unknown as LLMResponse;
    }

    const genericChoices = response.choices?.map((choice) => {
      if (!choice.message) {
        return { index: choice.index, finish_reason: choice.finish_reason };
      }
      const { role, content, ...msgRest } = choice.message;
      return {
        index: choice.index,
        message: {
          ...msgRest,
          role,
          content,
        },
        finish_reason: choice.finish_reason,
      };
    });

    return {
      ...response,
      id: response.id,
      object: response.object,
      created: response.created,
      model: response.model,
      choices: genericChoices,
      usage: response.usage,
    };
  }
}

export const openAIAdapter = new OpenAIAdapter();
