import { describe, expect, test } from "bun:test";
import { providerRegistry } from "../registry";
import { CodexProvider } from "./provider";

describe("CodexProvider", () => {
  test("registers itself with providerRegistry via factory", () => {
    const provider = providerRegistry.get("codex");
    expect(provider).toBeDefined();
    expect(provider?.id).toBe("codex");
  });

  test("provides correct metadata from info()", () => {
    const provider = new CodexProvider();
    const info = provider.info();

    expect(info.id).toBe("codex");
    expect(info.displayName).toBe("Codex");
    expect(info.vendor).toBe("openai");
    expect(info.deploymentType).toBe("cloud");
    expect(info.supportsStreaming).toBe(true);
    expect(info.supportsVision).toBe(false);
    expect(info.supportsTools).toBe(false);
    expect(info.supportsEmbeddings).toBe(false);
    expect(typeof info.baseUrl).toBe("string");
    expect(info.capabilities).toBeDefined();
    expect(info.capabilities.supportsSystemInstruction).toBe(true);
  });
});
