import { getConfig } from "../../config";
import { providerRegistry } from "../registry";
import type {
  LLMCompleteOptions,
  LLMCompletionResult,
  LLMProvider,
  LLMRequest,
  ProviderInfo,
} from "../types";
import { geminiAdapter } from "./adapter";
import { callGemini, getGeminiInfo } from "./client";
import type { GeminiGenerateContentResponse } from "./types";

/**
 * Gemini Provider Orchestrator
 */
export class GeminiProvider implements LLMProvider {
  readonly id = "gemini";
  readonly name = "Gemini";

  async complete(request: LLMRequest, options?: LLMCompleteOptions): Promise<LLMCompletionResult> {
    const config = getConfig();

    // 1. Translate generic LLMRequest -> Gemini request via adapter
    const providerRequest = geminiAdapter.toProviderRequest(request);

    // 2. Execute call with client
    const result = await callGemini(providerRequest, config.providers.gemini, options?.authHeader);

    // 3. Handle streaming vs non-streaming responses
    if (result.isStreaming) {
      return {
        isStreaming: true,
        response: result.response,
        model: result.model,
      };
    }

    // 4. Translate Gemini response -> generic LLMResponse via adapter
    const genericResponse = geminiAdapter.fromProviderResponse(
      result.response as GeminiGenerateContentResponse,
    );

    return {
      isStreaming: false,
      response: genericResponse,
      model: result.model,
    };
  }

  info(): ProviderInfo {
    const config = getConfig();
    const info = getGeminiInfo(config.providers.gemini);
    return {
      id: this.id,
      displayName: "Google Gemini",
      vendor: "google",
      deploymentType: "cloud",
      supportsStreaming: true,
      supportsVision: true,
      supportsTools: true,
      supportsEmbeddings: false,
      baseUrl: info.baseUrl,
      defaultModel: config.providers.gemini.model || "gemini-1.5-flash",
      capabilities: {
        supportsStreaming: true,
        supportsVision: true,
        supportsTools: true,
        supportsFunctionCalling: true,
        supportsJSONMode: true,
        supportsSystemInstruction: true,
        supportsEmbeddings: false,
        supportsAudio: true,
        supportsReasoning: true,
        supportsThinking: true,
        supportsSafetySettings: true,
        supportsImages: true,
        supportsVideo: true,
        supportsBatch: true,
        supportsCaching: true,
        supportsFineTuning: true,
        supportsLocalExecution: false,
      },
    };
  }
}

// Register factory in lazy ProviderRegistry
providerRegistry.registerFactory("gemini", () => new GeminiProvider());
