import { beforeEach, describe, expect, test } from "bun:test";
import { providerRegistry } from "./registry";
import type { LLMProvider, ProviderCapabilities, ProviderInfo } from "./types";

const mockCapabilities: ProviderCapabilities = {
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
  supportsLocalExecution: false,
};

class MockProvider implements LLMProvider {
  constructor(
    public readonly id: string,
    public readonly name: string,
  ) {}

  async complete() {
    return {
      isStreaming: false as const,
      response: { id: "test" },
      model: "mock-model",
    };
  }

  info(): ProviderInfo {
    return {
      id: this.id,
      displayName: this.name,
      vendor: "mock",
      deploymentType: "custom",
      supportsStreaming: true,
      supportsVision: false,
      supportsTools: false,
      supportsEmbeddings: false,
      capabilities: mockCapabilities,
    };
  }
}

describe("ProviderRegistry", () => {
  beforeEach(() => {
    providerRegistry.clear();
  });

  test("registers and retrieves a provider instance", () => {
    const mock = new MockProvider("test-provider", "Test Provider");
    providerRegistry.register(mock);

    expect(providerRegistry.has("test-provider")).toBe(true);
    expect(providerRegistry.get("test-provider")).toBe(mock);
  });

  test("supports lazy factory registration", () => {
    let factoryCalled = 0;
    providerRegistry.registerFactory("lazy-provider", () => {
      factoryCalled++;
      return new MockProvider("lazy-provider", "Lazy Provider");
    });

    expect(providerRegistry.has("lazy-provider")).toBe(true);
    expect(factoryCalled).toBe(0);

    const provider = providerRegistry.get("lazy-provider");
    expect(factoryCalled).toBe(1);
    expect(provider?.id).toBe("lazy-provider");

    // Second retrieval uses cached instance
    const providerAgain = providerRegistry.get("lazy-provider");
    expect(factoryCalled).toBe(1);
    expect(providerAgain).toBe(provider);
  });

  test("getAll returns all instances including uninstantiated factories", () => {
    const directMock = new MockProvider("direct", "Direct Provider");
    providerRegistry.register(directMock);

    providerRegistry.registerFactory("lazy", () => new MockProvider("lazy", "Lazy Provider"));

    const all = providerRegistry.getAll();
    expect(all).toHaveLength(2);
    expect(all.map((p) => p.id)).toContain("direct");
    expect(all.map((p) => p.id)).toContain("lazy");
  });

  test("clear resets providers and factories", () => {
    providerRegistry.register(new MockProvider("test", "Test"));
    providerRegistry.registerFactory("lazy", () => new MockProvider("lazy", "Lazy"));

    providerRegistry.clear();

    expect(providerRegistry.has("test")).toBe(false);
    expect(providerRegistry.has("lazy")).toBe(false);
    expect(providerRegistry.get("test")).toBeUndefined();
    expect(providerRegistry.getAll()).toHaveLength(0);
  });
});
