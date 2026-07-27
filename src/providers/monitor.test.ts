import { describe, expect, test } from "bun:test";
import { providerMonitor } from "./monitor";
import type { LLMProvider, ProviderCapabilities, ProviderInfo } from "./types";

const testCapabilities: ProviderCapabilities = {
  supportsStreaming: true,
  supportsVision: false,
  supportsTools: false,
  supportsFunctionCalling: false,
  supportsJSONMode: false,
  supportsSystemInstruction: false,
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
  supportsLocalExecution: true,
};

class TestProvider implements LLMProvider {
  readonly id = "test";
  readonly name = "Test Provider";

  async complete() {
    return { isStreaming: false as const, response: {}, model: "test" };
  }

  info(): ProviderInfo {
    return {
      id: "test",
      displayName: "Test Provider",
      vendor: "test",
      deploymentType: "local",
      supportsStreaming: true,
      supportsVision: false,
      supportsTools: false,
      supportsEmbeddings: false,
      capabilities: testCapabilities,
    };
  }
}

describe("ProviderMonitor", () => {
  test("returns true if provider has no baseUrl", async () => {
    const provider = new TestProvider();
    const isHealthy = await providerMonitor.checkProviderHealth(provider);
    expect(isHealthy).toBe(true);
  });
});
