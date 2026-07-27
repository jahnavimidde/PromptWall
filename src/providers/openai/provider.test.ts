import { describe, expect, test } from "bun:test";
import { providerRegistry } from "../registry";
import { OpenAIProvider } from "./provider";

describe("OpenAIProvider", () => {
  test("registers itself with providerRegistry via factory", () => {
    const provider = providerRegistry.get("openai");
    expect(provider).toBeDefined();
    expect(provider?.id).toBe("openai");
  });

  test("provides correct metadata from info()", () => {
    const provider = new OpenAIProvider();
    const info = provider.info();

    expect(info.id).toBe("openai");
    expect(info.displayName).toBe("OpenAI");
    expect(info.vendor).toBe("openai");
    expect(info.deploymentType).toBe("cloud");
    expect(info.supportsStreaming).toBe(true);
    expect(info.supportsVision).toBe(true);
    expect(info.supportsTools).toBe(true);
    expect(info.supportsEmbeddings).toBe(true);
    expect(typeof info.baseUrl).toBe("string");
  });
});
