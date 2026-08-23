import { afterEach, beforeEach, describe, expect, mock, test } from "bun:test";
import { Hono } from "hono";
import { getConfig } from "../config";
import { DEMO_HEADER, DEMO_SECRET_HEADER } from "../debug/types";
import { type PIIDetectionResult } from "../pii/detect";

const mockAnalyzeRequest = mock<() => Promise<PIIDetectionResult>>(() =>
  Promise.resolve({
    hasPII: false,
    spanEntities: [],
    allEntities: [],
    scanTimeMs: 0,
  }),
);
const mockLogRequest = mock(() => {});

// Only mock getPIIDetector; preserve real exports for filterAllowlistedEntities and PIIDetector
mock.module("../pii/detect", () => {
  const actual = require("../pii/detect");
  return {
    ...actual, // Re-export all real exports (filterAllowlistedEntities, PIIDetector, etc.)
    getPIIDetector: () => ({
      analyzeRequest: mockAnalyzeRequest,
      detectPII: mock(() => Promise.resolve([])),
      healthCheck: mock(() => Promise.resolve(true)),
    }),
  };
});

mock.module("../logging/logger", () => ({
  logRequest: mockLogRequest,
}));

// Import routes after setting up mock modules
const { openaiRoutes } = await import("./openai");
const { anthropicRoutes } = await import("./anthropic");

const app = new Hono();
app.route("/openai", openaiRoutes);
app.route("/anthropic", anthropicRoutes);

const originalFetch = globalThis.fetch;
const config = getConfig();
const originalMode = config.mode;
const originalSecretsAction = config.secrets_detection.action;

beforeEach(() => {
  // Mock standard NODE_ENV and host so isDemoEnabled allows it
  process.env.NODE_ENV = "development";
  delete process.env.PROMPTWALL_DEMO_SECRET;
  mockLogRequest.mockClear();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  config.mode = originalMode;
  config.secrets_detection.action = originalSecretsAction;
  mockAnalyzeRequest.mockResolvedValue({
    hasPII: false,
    spanEntities: [],
    allEntities: [],
    scanTimeMs: 0,
  });
});

describe("Demo mode integration tests", () => {
  test("OpenAI normal mode returns a raw JSON response (unchanged)", async () => {
    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) => {
      return Response.json({
        id: "chatcmpl_123",
        object: "chat.completion",
        created: 1677652288,
        model: "gpt-4o",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "Normal OpenAI reply" },
            finish_reason: "stop",
          },
        ],
      });
    }) as unknown as typeof fetch;

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        provider: "openai",
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.debug).toBeUndefined();
    expect(body.choices[0].message.content).toBe("Normal OpenAI reply");
    expect(mockLogRequest).toHaveBeenCalledTimes(1);
  });

  test("OpenAI demo mode returns a debug envelope and logs exactly once", async () => {
    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) => {
      return Response.json({
        id: "chatcmpl_123",
        object: "chat.completion",
        created: 1677652288,
        model: "gpt-4o",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "Normal OpenAI reply" },
            finish_reason: "stop",
          },
        ],
      });
    }) as unknown as typeof fetch;

    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [DEMO_HEADER]: "true",
      },
      body: JSON.stringify({
        provider: "openai",
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.debug).toBeDefined();
    expect(body.debug.provider).toBe("openai");
    expect(body.debug.originalPrompt).toBe("Hello");
    expect(body.debug.maskedPrompt).toBe("Hello");
    expect(body.response.choices[0].message.content).toBe("Normal OpenAI reply");
    expect(mockLogRequest).toHaveBeenCalledTimes(1);
  });

  test("Anthropic normal mode returns a raw JSON response (unchanged)", async () => {
    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) => {
      return Response.json({
        id: "msg_123",
        type: "message",
        role: "assistant",
        model: "claude-3-haiku-20240307",
        content: [{ type: "text", text: "Normal Anthropic reply" }],
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: { input_tokens: 10, output_tokens: 5 },
      });
    }) as unknown as typeof fetch;

    const res = await app.request("/anthropic/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "test-key",
      },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 100,
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.debug).toBeUndefined();
    expect(body.content[0].text).toBe("Normal Anthropic reply");
    expect(mockLogRequest).toHaveBeenCalledTimes(1);
  });

  test("Anthropic demo mode returns a debug envelope and logs exactly once", async () => {
    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) => {
      return Response.json({
        id: "msg_123",
        type: "message",
        role: "assistant",
        model: "claude-3-haiku-20240307",
        content: [{ type: "text", text: "Normal Anthropic reply" }],
        stop_reason: "end_turn",
        stop_sequence: null,
        usage: { input_tokens: 10, output_tokens: 5 },
      });
    }) as unknown as typeof fetch;

    const res = await app.request("/anthropic/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "test-key",
        [DEMO_HEADER]: "true",
      },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 100,
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.debug).toBeDefined();
    expect(body.debug.provider).toBe("anthropic");
    expect(body.debug.originalPrompt).toBe("Hello");
    expect(body.debug.maskedPrompt).toBe("Hello");
    expect(body.response.content[0].text).toBe("Normal Anthropic reply");
    expect(mockLogRequest).toHaveBeenCalledTimes(1);
  });

  test("demo secret check secures the endpoint in production-like environment", async () => {
    process.env.NODE_ENV = "production";
    process.env.PROMPTWALL_DEMO_SECRET = "production-super-secret";

    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) => {
      return Response.json({
        id: "chatcmpl_123",
        object: "chat.completion",
        created: 1677652288,
        model: "gpt-4o",
        choices: [
          {
            index: 0,
            message: { role: "assistant", content: "Normal OpenAI reply" },
            finish_reason: "stop",
          },
        ],
      });
    }) as unknown as typeof fetch;

    // Call without secret header should fall back to normal mode (no envelope)
    const resNoSecret = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [DEMO_HEADER]: "true",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    const bodyNoSecret = await resNoSecret.json();
    expect(bodyNoSecret.debug).toBeUndefined();

    // Call with correct secret header should return debug envelope
    const resWithSecret = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        [DEMO_HEADER]: "true",
        [DEMO_SECRET_HEADER]: "production-super-secret",
      },
      body: JSON.stringify({
        model: "gpt-4o",
        messages: [{ role: "user", content: "Hello" }],
      }),
    });

    const bodyWithSecret = await resWithSecret.json();
    expect(bodyWithSecret.debug).toBeDefined();
  });
});
