import { getConfig } from "../../config";
import { providerRegistry } from "../registry";
import type {
  LLMCompleteOptions,
  LLMCompletionResult,
  LLMProvider,
  LLMRequest,
  ProviderInfo,
} from "../types";
import { openAIAdapter } from "./adapter";
import { callOpenAI, getOpenAIInfo } from "./client";
import type { OpenAIResponse } from "./types";

/**
 * OpenAI provider orchestrator implementing LLMProvider
 */
export class OpenAIProvider implements LLMProvider {
  readonly id = "openai";
  readonly name = "OpenAI";

  async complete(request: LLMRequest, options?: LLMCompleteOptions): Promise<LLMCompletionResult> {
    const config = getConfig();

    // 1. Map generic request to provider-specific request format via adapter
    const providerRequest = openAIAdapter.toProviderRequest(request);

    // 2. Call client with provider request
    const result = await callOpenAI(providerRequest, config.providers.openai, options?.authHeader);

    // 3. Handle streaming vs non-streaming response mapping
    if (result.isStreaming) {
      return {
        isStreaming: true,
        response: result.response,
        model: result.model,
      };
    }

    // Map provider response to generic response format via adapter
    const genericResponse = openAIAdapter.fromProviderResponse(result.response as OpenAIResponse);

    return {
      isStreaming: false,
      response: genericResponse,
      model: result.model,
    };
  }

  info(): ProviderInfo {
    const config = getConfig();
    const info = getOpenAIInfo(config.providers.openai);
    return {
      id: this.id,
      displayName: "OpenAI",
      vendor: "openai",
      deploymentType: "cloud",
      supportsStreaming: true,
      supportsVision: true,
      supportsTools: true,
      supportsEmbeddings: true,
      baseUrl: info.baseUrl,
      defaultModel: config.providers.openai.model || "gpt-4o",
      capabilities: {
        supportsStreaming: true,
        supportsVision: true,
        supportsTools: true,
        supportsFunctionCalling: true,
        supportsJSONMode: true,
        supportsSystemInstruction: true,
        supportsEmbeddings: true,
        supportsAudio: true,
        supportsReasoning: true,
        supportsThinking: false,
        supportsSafetySettings: false,
        supportsImages: true,
        supportsVideo: false,
        supportsBatch: true,
        supportsCaching: false,
        supportsFineTuning: true,
        supportsLocalExecution: false,
      },
    };
  }
}

// Register provider factory for lazy initialization
providerRegistry.registerFactory("openai", () => new OpenAIProvider());
