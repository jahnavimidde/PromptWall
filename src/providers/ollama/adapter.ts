import type { LLMRequest, LLMResponse, ProviderAdapter } from "../types";

/**
 * Ollama Provider Adapter (Placeholder)
 * Will translate between PromptWall generic format and Ollama API format
 */
export class OllamaAdapter implements ProviderAdapter<unknown, unknown> {
  toProviderRequest(_request: LLMRequest): unknown {
    // TODO: Implement Ollama request translation
    throw new Error("OllamaAdapter.toProviderRequest is not implemented yet.");
  }

  fromProviderResponse(_response: unknown): LLMResponse {
    // TODO: Implement Ollama response translation
    throw new Error("OllamaAdapter.fromProviderResponse is not implemented yet.");
  }
}

export const ollamaAdapter = new OllamaAdapter();
