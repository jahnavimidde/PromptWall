import { describe, expect, test } from "bun:test";
import type { LLMRequest, LLMResponse } from "../types";
import { anthropicAdapter } from "./adapter";
import type { AnthropicResponse } from "./types";

describe("AnthropicAdapter", () => {
  test("translates generic LLMRequest to AnthropicRequest", () => {
    const genericRequest: LLMRequest = {
      model: "claude-3-5-sonnet-20241022",
      messages: [
        { role: "system", content: "You are a helpful assistant." },
        { role: "user", content: "Hello world" },
      ],
      temperature: 0.7,
      stream: false,
    };

    const anthropicRequest = anthropicAdapter.toProviderRequest(genericRequest);

    expect(anthropicRequest.model).toBe("claude-3-5-sonnet-20241022");
    expect(anthropicRequest.system).toBe("You are a helpful assistant.");
    expect(anthropicRequest.messages).toHaveLength(1);
    expect(anthropicRequest.messages[0]).toEqual({
      role: "user",
      content: "Hello world",
    });
    expect(anthropicRequest.temperature).toBe(0.7);
    expect(anthropicRequest.stream).toBe(false);
  });

  test("translates AnthropicResponse to generic LLMResponse", () => {
    const anthropicResponse: AnthropicResponse = {
      id: "msg_123",
      type: "message",
      role: "assistant",
      model: "claude-3-5-sonnet-20241022",
      content: [
        {
          type: "text",
          text: "Hello! How can I help you?",
        },
      ],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: {
        input_tokens: 9,
        output_tokens: 12,
      },
    };

    const genericResponse = anthropicAdapter.fromProviderResponse(anthropicResponse);

    expect(genericResponse.id).toBe("msg_123");
    expect(genericResponse.model).toBe("claude-3-5-sonnet-20241022");
    expect(genericResponse.choices).toHaveLength(1);
    expect(genericResponse.choices?.[0].message).toEqual({
      role: "assistant",
      content: "Hello! How can I help you?",
    });
    expect(genericResponse.usage?.total_tokens).toBe(21);
    expect(genericResponse.choices?.[0].finish_reason).toBe("end_turn");
  });

  test("performs full round-trip mapping integrity check", () => {
    const inputRequest: LLMRequest = {
      model: "claude-3-5-sonnet-20241022",
      messages: [{ role: "user", content: "Test prompt" }],
    };

    const mappedRequest = anthropicAdapter.toProviderRequest(inputRequest);

    const simulatedResponse: AnthropicResponse = {
      id: "msg_roundtrip",
      type: "message",
      role: "assistant",
      model: mappedRequest.model,
      content: [
        {
          type: "text",
          text: `Response for: ${mappedRequest.messages[0].content}`,
        },
      ],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: {
        input_tokens: 10,
        output_tokens: 15,
      },
    };

    const genericResponse: LLMResponse = anthropicAdapter.fromProviderResponse(simulatedResponse);

    expect(genericResponse.id).toBe("msg_roundtrip");
    expect(genericResponse.choices?.[0].message?.content).toBe("Response for: Test prompt");
  });

  test("strips normalized fields in toProxyResponse", () => {
    const normalized = anthropicAdapter.fromProviderResponse({
      id: "msg_123",
      type: "message",
      role: "assistant",
      model: "claude-3-haiku-20240307",
      content: [{ type: "text", text: "hello" }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 5, output_tokens: 3 },
    } as AnthropicResponse);

    expect(normalized.choices).toBeDefined();
    expect(anthropicAdapter.toProxyResponse(normalized)).toEqual({
      id: "msg_123",
      type: "message",
      role: "assistant",
      model: "claude-3-haiku-20240307",
      content: [{ type: "text", text: "hello" }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 5, output_tokens: 3 },
    });
  });
});
