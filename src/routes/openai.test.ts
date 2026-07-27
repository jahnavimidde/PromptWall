import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { DEFAULT_PROVIDER, OpenAIRequestSchema } from "../providers/openai/types";
import { openaiRoutes } from "./openai";

const app = new Hono();
app.route("/openai", openaiRoutes);

describe("POST /openai/v1/chat/completions", () => {
  test("returns 400 for missing messages", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({}),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("invalid_request_error");
  });

  test("returns 400 for invalid message format", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        messages: [{ invalid: "format" }],
      }),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(400);
  });

  test("returns 400 for invalid role", async () => {
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({
        model: "gpt-5.2",
        messages: [{ role: "invalid", content: "test" }],
      }),
      headers: { "Content-Type": "application/json" },
    });

    expect(res.status).toBe(400);
  });
});

describe("Zod schema preserves unknown fields", () => {
  const base = {
    model: "gpt-4o",
    messages: [{ role: "user", content: "Hello" }],
  };

  test("preserves name field on message", () => {
    const input = {
      ...base,
      messages: [{ role: "user", content: "Hello", name: "test_user" }],
    };

    const result = OpenAIRequestSchema.parse(input);

    // biome-ignore lint/suspicious/noExplicitAny: testing unknown field preservation
    expect((result.messages[0] as any).name).toBe("test_user");
  });

  test("preserves tool_calls on assistant message", () => {
    const input = {
      ...base,
      messages: [
        {
          role: "assistant",
          content: null,
          tool_calls: [
            {
              id: "call_123",
              type: "function",
              function: { name: "get_weather", arguments: "{}" },
            },
          ],
        },
      ],
    };

    const result = OpenAIRequestSchema.parse(input);

    // biome-ignore lint/suspicious/noExplicitAny: testing unknown field preservation
    expect((result.messages[0] as any).tool_calls).toHaveLength(1);
    // biome-ignore lint/suspicious/noExplicitAny: testing unknown field preservation
    expect((result.messages[0] as any).tool_calls[0].id).toBe("call_123");
  });

  test("preserves audio content part fields", () => {
    const input = {
      ...base,
      messages: [
        {
          role: "user",
          content: [{ type: "input_audio", input_audio: { data: "base64...", format: "wav" } }],
        },
      ],
    };

    const result = OpenAIRequestSchema.parse(input);

    // biome-ignore lint/suspicious/noExplicitAny: testing unknown field preservation
    const part = (result.messages[0].content as any[])[0];
    expect(part.type).toBe("input_audio");
    expect(part.input_audio.format).toBe("wav");
  });

  test("preserves unknown top-level fields", () => {
    const input = { ...base, custom_field: "preserved" };

    const result = OpenAIRequestSchema.parse(input);

    // biome-ignore lint/suspicious/noExplicitAny: testing unknown field preservation
    expect((result as any).custom_field).toBe("preserved");
  });

  test("parses and preserves the provider field", () => {
    const input = { ...base, provider: "gemini" };

    const result = OpenAIRequestSchema.parse(input);

    expect(result.provider).toBe("gemini");
  });

  test("provider field is optional - defaults to undefined when omitted", () => {
    const result = OpenAIRequestSchema.parse(base);

    expect(result.provider).toBeUndefined();
  });

  test("DEFAULT_PROVIDER is 'gemini'", () => {
    expect(DEFAULT_PROVIDER).toBe("gemini");
  });
});

