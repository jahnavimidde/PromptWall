import { describe, expect, test } from "bun:test";
import type { LLMRequest, LLMResponse } from "../types";
import { openAIAdapter } from "./adapter";
import type { OpenAIResponse } from "./types";

describe("OpenAIAdapter", () => {
  test("translates generic LLMRequest to OpenAIRequest", () => {
    const genericRequest: LLMRequest = {
      model: "gpt-4o",
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Hello world" },
      ],
      temperature: 0.7,
      stream: false,
    };

    const openAIRequest = openAIAdapter.toProviderRequest(genericRequest);

    expect(openAIRequest.model).toBe("gpt-4o");
    expect(openAIRequest.messages).toHaveLength(2);
    expect(openAIRequest.messages[0]).toEqual({
      role: "system",
      content: "You are a helpful assistant.",
    });
    expect(openAIRequest.temperature).toBe(0.7);
    expect(openAIRequest.stream).toBe(false);
  });

  test("translates OpenAIResponse to generic LLMResponse", () => {
    const openAIResponse: OpenAIResponse = {
      id: "chatcmpl-123",
      object: "chat.completion",
      created: 1677652288,
      model: "gpt-4o",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: "Hello! How can I help you?",
          },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: 9,
        completion_tokens: 12,
        total_tokens: 21,
      },
    };

    const genericResponse = openAIAdapter.fromProviderResponse(openAIResponse);

    expect(genericResponse.id).toBe("chatcmpl-123");
    expect(genericResponse.model).toBe("gpt-4o");
    expect(genericResponse.choices).toHaveLength(1);
    expect(genericResponse.choices?.[0].message).toEqual({
      role: "assistant",
      content: "Hello! How can I help you?",
    });
    expect(genericResponse.usage?.total_tokens).toBe(21);
  });

  test("performs full round-trip mapping integrity check", () => {
    const inputRequest: LLMRequest = {
      model: "gpt-4o",
      messages: [{ role: "user", content: "Test prompt" }],
    };

    const mappedRequest = openAIAdapter.toProviderRequest(inputRequest);

    const simulatedResponse: OpenAIResponse = {
      id: "chatcmpl-roundtrip",
      object: "chat.completion",
      created: 12345678,
      model: mappedRequest.model || "gpt-4o",
      choices: [
        {
          index: 0,
          message: {
            role: "assistant",
            content: `Response for: ${mappedRequest.messages[0].content}`,
          },
          finish_reason: "stop",
        },
      ],
    };

    const genericResponse: LLMResponse = openAIAdapter.fromProviderResponse(simulatedResponse);

    expect(genericResponse.id).toBe("chatcmpl-roundtrip");
    expect(genericResponse.choices?.[0].message?.content).toBe("Response for: Test prompt");
  });
});
