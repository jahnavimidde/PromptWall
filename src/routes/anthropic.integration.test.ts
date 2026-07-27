import { afterEach, describe, expect, mock, test } from "bun:test";
import { Hono } from "hono";
import { getConfig } from "../config";
import { filterAllowlistedEntities, type PIIDetectionResult, PIIDetector } from "../pii/detect";

const mockAnalyzeRequest = mock<() => Promise<PIIDetectionResult>>(() =>
  Promise.resolve({
    hasPII: false,
    spanEntities: [],
    allEntities: [],
    scanTimeMs: 0,
  }),
);
const mockLogRequest = mock(() => {});

mock.module("../pii/detect", () => ({
  PIIDetector,
  filterAllowlistedEntities,
  getPIIDetector: () => ({
    analyzeRequest: mockAnalyzeRequest,
    detectPII: mock(() => Promise.resolve([])),
    healthCheck: mock(() => Promise.resolve(true)),
  }),
}));

mock.module("../logging/logger", () => ({
  logRequest: mockLogRequest,
}));

const { anthropicRoutes } = await import("./anthropic");

const app = new Hono();
app.route("/anthropic", anthropicRoutes);

const originalFetch = globalThis.fetch;
const config = getConfig();
const originalMode = config.mode;
const originalSecretsAction = config.secrets_detection.action;

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
  mockLogRequest.mockClear();
});

describe("Anthropic route integration", () => {
  test("masks PII before forwarding to Anthropic", async () => {
    mockAnalyzeRequest.mockResolvedValueOnce({
      hasPII: true,
      spanEntities: [[{ entity_type: "EMAIL_ADDRESS", start: 6, end: 22, score: 0.99 }]],
      allEntities: [{ entity_type: "EMAIL_ADDRESS", start: 6, end: 22, score: 0.99 }],
      scanTimeMs: 2,
    });

    let upstreamBody: Record<string, unknown> | undefined;
    globalThis.fetch = (async (_input: string | URL | Request, init?: RequestInit) => {
      upstreamBody = JSON.parse(String(init?.body));
      return Response.json({
        id: "msg_test",
        type: "message",
        role: "assistant",
        model: "claude-3-haiku-20240307",
        content: [{ type: "text", text: "Reply [[EMAIL_ADDRESS_1]]" }],
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
        messages: [{ role: "user", content: "Email john@example.com" }],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("X-PasteGuard-Provider")).toBe("anthropic");
    expect(res.headers.get("X-PasteGuard-PII-Masked")).toBe("true");
    expect((upstreamBody?.messages as Array<{ content: string }>)[0].content).toBe(
      "Email [[EMAIL_ADDRESS_1]]",
    );
    expect(await res.json()).toEqual({
      id: "msg_test",
      type: "message",
      role: "assistant",
      model: "claude-3-haiku-20240307",
      content: [{ type: "text", text: "Reply john@example.com" }],
      stop_reason: "end_turn",
      stop_sequence: null,
      usage: { input_tokens: 10, output_tokens: 5 },
    });
  });

  test("unmasks streaming text deltas", async () => {
    mockAnalyzeRequest.mockResolvedValueOnce({
      hasPII: true,
      spanEntities: [[{ entity_type: "EMAIL_ADDRESS", start: 6, end: 22, score: 0.99 }]],
      allEntities: [{ entity_type: "EMAIL_ADDRESS", start: 6, end: 22, score: 0.99 }],
      scanTimeMs: 2,
    });

    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) =>
      Promise.resolve(
        new Response(
          'event: content_block_delta\ndata: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Email [[EMAIL_ADDRESS_1]]"}}\n\n',
          {
            status: 200,
            headers: { "Content-Type": "text/event-stream" },
          },
        ),
      )) as unknown as typeof fetch;

    const res = await app.request("/anthropic/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": "test-key",
      },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 100,
        stream: true,
        messages: [{ role: "user", content: "Email john@example.com" }],
      }),
    });

    expect(res.status).toBe(200);
    expect(res.headers.get("Content-Type")).toContain("text/event-stream");
    const text = await res.text();
    expect(text).toContain("Email john@example.com");
    expect(text).not.toContain("[[EMAIL_ADDRESS_1]]");
  });

  test("blocks requests when secrets are detected", async () => {
    config.secrets_detection.action = "block";
    const secret =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtest\n-----END RSA PRIVATE KEY-----";
    let fetchCalled = false;
    globalThis.fetch = (async () => {
      fetchCalled = true;
      return new Response("unexpected");
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
        messages: [{ role: "user", content: `Key ${secret}` }],
      }),
    });

    expect(res.status).toBe(400);
    expect(fetchCalled).toBe(false);
    expect(res.headers.get("X-PasteGuard-Secrets-Detected")).toBe("true");
    const body = (await res.json()) as { error: { type: string } };
    expect(body.error.type).toBe("invalid_request_error");
  });

  test("returns 503 when PII detection is unavailable", async () => {
    mockAnalyzeRequest.mockRejectedValueOnce(new Error("detector offline"));
    let fetchCalled = false;
    globalThis.fetch = (async () => {
      fetchCalled = true;
      return new Response("unexpected");
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

    expect(res.status).toBe(503);
    expect(fetchCalled).toBe(false);
    expect(mockLogRequest).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 503 }), null);
  });

  test("returns 502 when Anthropic upstream fails", async () => {
    globalThis.fetch = (async () =>
      Promise.resolve(
        new Response(JSON.stringify({ error: { message: "upstream failed" } }), { status: 502 }),
      )) as unknown as typeof fetch;

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

    expect(res.status).toBe(502);
    expect(mockLogRequest).toHaveBeenCalledWith(expect.objectContaining({ statusCode: 502 }), null);
  });
});
