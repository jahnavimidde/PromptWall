import { describe, expect, test } from "bun:test";
import { providerRegistry } from "../registry";
import { AnthropicProvider } from "./provider";

describe("AnthropicProvider", () => {
  test("registers itself with providerRegistry via factory", () => {
    const provider = providerRegistry.get("anthropic");
    expect(provider).toBeDefined();
    expect(provider?.id).toBe("anthropic");
  });

  test("provides correct metadata from info()", () => {
    const provider = new AnthropicProvider();
    const info = provider.info();

    expect(info.id).toBe("anthropic");
    expect(info.displayName).toBe("Anthropic");
    expect(info.vendor).toBe("anthropic");
    expect(info.deploymentType).toBe("cloud");
    expect(info.supportsStreaming).toBe(true);
    expect(info.supportsVision).toBe(true);
    expect(info.supportsTools).toBe(true);
    expect(info.supportsEmbeddings).toBe(false);
    expect(typeof info.baseUrl).toBe("string");
    expect(info.capabilities).toBeDefined();
    expect(info.capabilities.supportsCaching).toBe(true);
  });
});
