import { describe, expect, test } from "bun:test";
import { callCodex } from "./client";

describe("callCodex", () => {
  test("treats text/event-stream responses as streaming even without request.stream", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) =>
      Promise.resolve(
        new Response("data: {}\n\n", {
          status: 200,
          headers: { "Content-Type": "text/event-stream" },
        }),
      )) as typeof fetch;

    try {
      const result = await callCodex(
        { model: "gpt-5.5", input: "hello" },
        { enabled: true, base_url: "https://codex.example", model: "codex" },
      );

      expect(result.isStreaming).toBe(true);
      expect(result.response).toBeInstanceOf(ReadableStream);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("parses JSON when response is not event-stream and stream is false", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (_input: string | URL | Request, _init?: RequestInit) =>
      Promise.resolve(
        Response.json({
          output: [{ content: [{ type: "output_text", text: "ok" }] }],
        }),
      )) as typeof fetch;

    try {
      const result = await callCodex(
        { model: "gpt-5.5", input: "hello" },
        { enabled: true, base_url: "https://codex.example", model: "codex" },
      );

      expect(result.isStreaming).toBe(false);
      expect(result.response).toEqual({
        output: [{ content: [{ type: "output_text", text: "ok" }] }],
      });
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
