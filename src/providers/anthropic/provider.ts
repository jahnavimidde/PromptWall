import { getConfig } from "../../config";
import { providerRegistry } from "../registry";
import type {
  LLMCompleteOptions,
  LLMCompletionResult,
  LLMProvider,
  LLMRequest,
  ProviderInfo,
} from "../types";
import { anthropicAdapter } from "./adapter";
import { type AnthropicClientHeaders, callAnthropic, getAnthropicInfo } from "./client";
import type { AnthropicResponse } from "./types";

/**
 * Anthropic provider orchestrator implementing LLMProvider
 */
export class AnthropicProvider implements LLMProvider {
  readonly id = "anthropic";
  readonly name = "Anthropic";

  async complete(request: LLMRequest, options?: LLMCompleteOptions): Promise<LLMCompletionResult> {
    const config = getConfig();

    // 1. Map generic request to provider-specific request format via adapter
    const providerRequest = anthropicAdapter.toProviderRequest(request);

    // 2. Map headers from options
    const clientHeaders: AnthropicClientHeaders = {
      apiKey: options?.apiKey as string | undefined,
      authorization: options?.authHeader || (options?.authorization as string | undefined),
      beta: options?.beta as string | undefined,
    };

    // 3. Call client with provider request
    const result = await callAnthropic(providerRequest, config.providers.anthropic, clientHeaders);

    // 4. Handle streaming vs non-streaming response mapping
    if (result.isStreaming) {
      return {
        isStreaming: true,
        response: result.response,
        model: result.model,
      };
    }

    // Map provider response to generic response format via adapter
    const genericResponse = anthropicAdapter.fromProviderResponse(
      result.response as AnthropicResponse,
    );

    return {
      isStreaming: false,
      response: genericResponse,
      model: result.model,
    };
  }

  info(): ProviderInfo {
    const config = getConfig();
    const info = getAnthropicInfo(config.providers.anthropic);
    return {
      id: this.id,
      displayName: "Anthropic",
      vendor: "anthropic",
      deploymentType: "cloud",
      supportsStreaming: true,
      supportsVision: true,
      supportsTools: true,
      supportsEmbeddings: false,
      baseUrl: info.baseUrl,
      defaultModel: config.providers.anthropic.model || "claude-3-5-sonnet-20241022",
      capabilities: {
        supportsStreaming: true,
        supportsVision: true,
        supportsTools: true,
        supportsFunctionCalling: true,
        supportsJSONMode: false,
        supportsSystemInstruction: true,
        supportsEmbeddings: false,
        supportsAudio: false,
        supportsReasoning: false,
        supportsThinking: false,
        supportsSafetySettings: false,
        supportsImages: true,
        supportsVideo: false,
        supportsBatch: true,
        supportsCaching: true,
        supportsFineTuning: false,
        supportsLocalExecution: false,
      },
    };
  }
}

// Register provider factory for lazy initialization
providerRegistry.registerFactory("anthropic", () => new AnthropicProvider());
