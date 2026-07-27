/**
 * Unified types and interface for LLM Providers
 */

export interface ChatMessage {
  role: string;
  content?: string | unknown;
  [key: string]: unknown;
}

export interface LLMRequest {
  model?: string;
  messages?: ChatMessage[];
  temperature?: number;
  top_p?: number;
  max_tokens?: number;
  stream?: boolean;
  [key: string]: unknown;
}

export interface LLMResponseChoice {
  index?: number;
  message?: ChatMessage;
  finish_reason?: string | null;
}

export interface LLMResponseUsage {
  prompt_tokens?: number;
  completion_tokens?: number;
  total_tokens?: number;
}

export interface LLMResponse {
  id?: string;
  object?: string;
  created?: number;
  model?: string;
  choices?: LLMResponseChoice[];
  usage?: LLMResponseUsage;
  [key: string]: unknown;
}

export type LLMCompletionResult =
  | {
      isStreaming: true;
      response: ReadableStream<Uint8Array>;
      model: string;
    }
  | {
      isStreaming: false;
      response: unknown;
      model: string;
    };

export interface LLMCompleteOptions {
  authHeader?: string;
  [key: string]: unknown;
}

export interface ProviderCapabilities {
  supportsStreaming: boolean;
  supportsVision: boolean;
  supportsTools: boolean;
  supportsFunctionCalling: boolean;
  supportsJSONMode: boolean;
  supportsSystemInstruction: boolean;
  supportsEmbeddings: boolean;
  supportsAudio: boolean;
  supportsReasoning: boolean;
  supportsThinking: boolean;
  supportsSafetySettings: boolean;
  supportsImages: boolean;
  supportsVideo: boolean;
  supportsBatch: boolean;
  supportsCaching: boolean;
  supportsFineTuning: boolean;
  supportsLocalExecution: boolean;
}

export interface ProviderInfo {
  id: string;
  displayName: string;
  vendor: string;
  deploymentType: "cloud" | "local" | "custom" | string;
  supportsStreaming: boolean;
  supportsVision: boolean;
  supportsTools: boolean;
  supportsEmbeddings: boolean;
  baseUrl?: string;
  defaultModel?: string;
  capabilities: ProviderCapabilities;
  [key: string]: unknown;
}

export interface LLMProvider {
  readonly id: string;
  readonly name: string;
  complete(request: LLMRequest, options?: LLMCompleteOptions): Promise<LLMCompletionResult>;
  info(): ProviderInfo;
}

export interface ProviderAdapter<TProviderRequest = unknown, TProviderResponse = unknown> {
  toProviderRequest(request: LLMRequest): TProviderRequest;
  fromProviderResponse(response: TProviderResponse): LLMResponse;
}

/** Reverse mapping for HTTP proxy routes that must return provider-native JSON. */
export interface ProxyAdapter<TProviderResponse = unknown>
  extends ProviderAdapter<unknown, TProviderResponse> {
  toProxyResponse(response: LLMResponse): TProviderResponse;
}
