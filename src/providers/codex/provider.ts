import { getConfig } from "../../config";
import { providerRegistry } from "../registry";
import type {
  LLMCompleteOptions,
  LLMCompletionResult,
  LLMProvider,
  LLMRequest,
  ProviderInfo,
} from "../types";
import { codexAdapter } from "./adapter";
import { callCodex, getCodexInfo } from "./client";
import type { CodexResponse } from "./types";

/**
 * Codex provider orchestrator implementing LLMProvider
 */
export class CodexProvider implements LLMProvider {
  readonly id = "codex";
  readonly name = "Codex";

  async complete(request: LLMRequest, options?: LLMCompleteOptions): Promise<LLMCompletionResult> {
    const config = getConfig();

    // 1. Map generic request to provider-specific request format via adapter
    const providerRequest = codexAdapter.toProviderRequest(request);

    // 2. Extract client headers from options
    const clientHeaders = (options?.headers as Record<string, string> | undefined) || {};
    if (options?.authHeader) {
      clientHeaders.Authorization = options.authHeader;
    }

    // 3. Call client with provider request
    const result = await callCodex(providerRequest, config.providers.codex, clientHeaders);

    // 4. Handle streaming vs non-streaming response mapping
    if (result.isStreaming) {
      return {
        isStreaming: true,
        response: result.response,
        model: result.model,
      };
    }

    // Map provider response to generic response format via adapter
    const genericResponse = codexAdapter.fromProviderResponse(result.response as CodexResponse);

    return {
      isStreaming: false,
      response: genericResponse,
      model: result.model,
    };
  }

  info(): ProviderInfo {
    const config = getConfig();
    const info = getCodexInfo(config.providers.codex);
    return {
      id: this.id,
      displayName: "Codex",
      vendor: "openai", // Codex runs on OpenAI models or is compatible
      deploymentType: "cloud",
      supportsStreaming: true,
      supportsVision: false,
      supportsTools: false,
      supportsEmbeddings: false,
      baseUrl: info.baseUrl,
      defaultModel: config.providers.codex.model || "codex",
      capabilities: {
        supportsStreaming: true,
        supportsVision: false,
        supportsTools: false,
        supportsFunctionCalling: false,
        supportsJSONMode: false,
        supportsSystemInstruction: true,
        supportsEmbeddings: false,
        supportsAudio: false,
        supportsReasoning: false,
        supportsThinking: false,
        supportsSafetySettings: false,
        supportsImages: false,
        supportsVideo: false,
        supportsBatch: false,
        supportsCaching: false,
        supportsFineTuning: false,
        supportsLocalExecution: false,
      },
    };
  }
}

// Register provider factory for lazy initialization
providerRegistry.registerFactory("codex", () => new CodexProvider());
