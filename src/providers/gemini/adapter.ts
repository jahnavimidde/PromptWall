import type { LLMRequest, LLMResponse, LLMResponseChoice, ProviderAdapter } from "../types";
import type {
  GeminiContent,
  GeminiGenerateContentRequest,
  GeminiGenerateContentResponse,
  GeminiGenerationConfig,
  GeminiPart,
  GeminiSystemInstruction,
} from "./types";

/**
 * Gemini Adapter
 * Translates between PromptWall generic LLM representation and Gemini REST API schema.
 */
export class GeminiAdapter
  implements ProviderAdapter<GeminiGenerateContentRequest, GeminiGenerateContentResponse>
{
  /**
   * Convert generic PromptWall LLMRequest into GeminiGenerateContentRequest
   */
  toProviderRequest(request: LLMRequest): GeminiGenerateContentRequest {
    const { model, messages, temperature, top_p, max_tokens, stream, stop, tools, ...rest } =
      request;

    const contents: GeminiContent[] = [];
    let systemInstruction: GeminiSystemInstruction | undefined;

    for (const msg of messages ?? []) {
      const { role, content, ...msgRest } = msg;

      // System prompt mapping
      if (role === "system" || role === "developer") {
        const textStr = typeof content === "string" ? content : JSON.stringify(content);
        if (textStr) {
          systemInstruction = {
            parts: [{ text: textStr }],
          };
        }
        continue;
      }

      // Convert roles: assistant -> model, user -> user
      const geminiRole = role === "assistant" ? "model" : "user";
      const parts: GeminiPart[] = [];

      if (typeof content === "string") {
        parts.push({ text: content });
      } else if (Array.isArray(content)) {
        for (const item of content) {
          if (typeof item === "string") {
            parts.push({ text: item });
          } else if (item && typeof item === "object") {
            const itemObj = item as Record<string, unknown>;
            if (itemObj.type === "text" && typeof itemObj.text === "string") {
              parts.push({ text: itemObj.text });
            } else if (itemObj.type === "image_url" && itemObj.image_url) {
              // Extract base64 image data if present
              const imgObj = itemObj.image_url as { url?: string };
              if (imgObj.url?.startsWith("data:")) {
                const match = imgObj.url.match(/^data:([^;]+);base64,(.+)$/);
                if (match) {
                  parts.push({
                    inlineData: {
                      mimeType: match[1],
                      data: match[2],
                    },
                  });
                }
              }
            } else if (itemObj.text && typeof itemObj.text === "string") {
              parts.push({ text: itemObj.text });
            } else {
              parts.push(itemObj as GeminiPart);
            }
          }
        }
      } else if (content) {
        parts.push({ text: String(content) });
      }

      contents.push({
        ...msgRest,
        role: geminiRole,
        parts: parts.length > 0 ? parts : [{ text: "" }],
      });
    }

    const generationConfig: GeminiGenerationConfig = {};
    if (temperature !== undefined) generationConfig.temperature = temperature;
    if (top_p !== undefined) generationConfig.topP = top_p;
    if (max_tokens !== undefined) generationConfig.maxOutputTokens = max_tokens;
    if (stop !== undefined) {
      generationConfig.stopSequences = Array.isArray(stop) ? stop : [String(stop)];
    }

    const geminiRequest: GeminiGenerateContentRequest = {
      ...rest,
      model,
      stream,
      contents,
    };

    if (systemInstruction) {
      geminiRequest.systemInstruction = systemInstruction;
    }

    if (Object.keys(generationConfig).length > 0) {
      geminiRequest.generationConfig = generationConfig;
    }

    if (tools) {
      geminiRequest.tools = tools as unknown[];
    }

    return geminiRequest;
  }

  /**
   * Convert GeminiGenerateContentResponse into generic PromptWall LLMResponse
   */
  fromProviderResponse(response: GeminiGenerateContentResponse): LLMResponse {
    if (!response) {
      return response as unknown as LLMResponse;
    }

    const genericChoices: LLMResponseChoice[] = (response.candidates || []).map(
      (candidate, idx) => {
        const parts = candidate.content?.parts || [];
        const textContent = parts.map((p) => p.text || "").join("");
        const finishReason = candidate.finishReason ? candidate.finishReason.toLowerCase() : "stop";

        return {
          index: candidate.index ?? idx,
          message: {
            role: candidate.content?.role === "model" ? "assistant" : "user",
            content: textContent,
          },
          finish_reason: finishReason,
        };
      },
    );

    const usage = response.usageMetadata
      ? {
          prompt_tokens: response.usageMetadata.promptTokenCount,
          completion_tokens: response.usageMetadata.candidatesTokenCount,
          total_tokens: response.usageMetadata.totalTokenCount,
        }
      : undefined;

    return {
      ...response,
      id: response.modelVersion ? `gemini-${response.modelVersion}` : undefined,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: response.modelVersion || "gemini",
      choices: genericChoices,
      usage,
    };
  }
}

export const geminiAdapter = new GeminiAdapter();
