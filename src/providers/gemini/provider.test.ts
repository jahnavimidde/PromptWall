import { describe, expect, test } from "bun:test";
import { providerRegistry } from "../registry";
import "./provider"; // Ensures GeminiProvider self-registers with providerRegistry

describe("GeminiProvider", () => {
  test("registers itself with providerRegistry via factory", () => {
    expect(providerRegistry.has("gemini")).toBe(true);

    const provider = providerRegistry.get("gemini");
    expect(provider).toBeDefined();
    expect(provider?.id).toBe("gemini");
    expect(provider?.name).toBe("Gemini");
  });

  test("provides correct metadata from info()", () => {
    const provider = providerRegistry.get("gemini");
    const info = provider?.info();

    expect(info).toBeDefined();
    expect(info?.id).toBe("gemini");
    expect(info?.displayName).toBe("Google Gemini");
    expect(info?.vendor).toBe("google");
    expect(info?.supportsStreaming).toBe(true);
    expect(info?.supportsVision).toBe(true);
    expect(info?.supportsTools).toBe(true);
  });
});
