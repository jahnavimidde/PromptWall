import { describe, expect, test } from "bun:test";
import type { LLMRequest } from "../types";
import { codexAdapter } from "./adapter";
import type { CodexResponse } from "./types";

describe("CodexAdapter", () => {
  test("translates generic LLMRequest (with instructions and input) to CodexRequest", () => {
    const genericRequest: LLMRequest = {
      model: "codex",
      instructions: "Be concise.",
      input: "Hello world",
      stream: false,
    };

    const codexRequest = codexAdapter.toProviderRequest(genericRequest);

    expect(codexRequest.model).toBe("codex");
    expect(codexRequest.instructions).toBe("Be concise.");
    expect(codexRequest.input).toBe("Hello world");
    expect(codexRequest.stream).toBe(false);
  });

  test("translates generic LLMRequest (with messages) to CodexRequest using fallback mapping", () => {
    const genericRequest: LLMRequest = {
      model: "codex",
      messages: [
        { role: "system", content: "System instructions" },
        { role: "user", content: "User prompt" },
      ],
      stream: false,
    };

    const codexRequest = codexAdapter.toProviderRequest(genericRequest);

    expect(codexRequest.model).toBe("codex");
    expect(codexRequest.instructions).toBe("System instructions");
    expect(codexRequest.input).toBe("User prompt");
    expect(codexRequest.stream).toBe(false);
  });

  test("translates CodexResponse to generic LLMResponse", () => {
    const codexResponse: CodexResponse = {
      id: "resp_123",
      output_text: "Hello, this is Codex.",
      model: "codex-gpt4",
    };

    const genericResponse = codexAdapter.fromProviderResponse(codexResponse);

    expect(genericResponse.id).toBe("resp_123");
    expect(genericResponse.model).toBe("codex-gpt4");
    expect(genericResponse.choices).toHaveLength(1);
    expect(genericResponse.choices?.[0].message).toEqual({
      role: "assistant",
      content: "Hello, this is Codex.",
    });
  });

  test("strips normalized fields in toProxyResponse", () => {
    const normalized = codexAdapter.fromProviderResponse({
      output: [{ content: [{ type: "output_text", text: "hello" }] }],
      model: "codex-gpt4",
    } as CodexResponse);

    expect(normalized.choices).toBeDefined();
    expect(codexAdapter.toProxyResponse(normalized)).toEqual({
      output: [{ content: [{ type: "output_text", text: "hello" }] }],
      model: "codex-gpt4",
    });
  });
});
