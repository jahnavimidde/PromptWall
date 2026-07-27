import { describe, expect, test } from "bun:test";
import type { LLMRequest } from "../types";
import { GeminiAdapter } from "./adapter";
import type { GeminiGenerateContentResponse } from "./types";

describe("GeminiAdapter", () => {
  const adapter = new GeminiAdapter();

  test("translates generic LLMRequest to GeminiGenerateContentRequest", () => {
    const request: LLMRequest = {
      model: "gemini-1.5-flash",
      temperature: 0.7,
      top_p: 0.9,
      max_tokens: 500,
      messages: [
        { role: "system", content: "You are a helpful security assistant." },
        { role: "user", content: "Hello Gemini!" },
        { role: "assistant", content: "Hello! How can I assist you?" },
      ],
    };

    const geminiReq = adapter.toProviderRequest(request);

    expect(geminiReq.model).toBe("gemini-1.5-flash");
    expect(geminiReq.systemInstruction).toBeDefined();
    expect(geminiReq.systemInstruction?.parts[0].text).toBe(
      "You are a helpful security assistant.",
    );
    expect(geminiReq.contents).toHaveLength(2);
    expect(geminiReq.contents[0].role).toBe("user");
    expect(geminiReq.contents[0].parts[0].text).toBe("Hello Gemini!");
    expect(geminiReq.contents[1].role).toBe("model");
    expect(geminiReq.contents[1].parts[0].text).toBe("Hello! How can I assist you?");
    expect(geminiReq.generationConfig?.temperature).toBe(0.7);
    expect(geminiReq.generationConfig?.topP).toBe(0.9);
    expect(geminiReq.generationConfig?.maxOutputTokens).toBe(500);
  });

  test("translates GeminiGenerateContentResponse to generic LLMResponse", () => {
    const geminiResp: GeminiGenerateContentResponse = {
      modelVersion: "1.5-flash",
      candidates: [
        {
          index: 0,
          finishReason: "STOP",
          content: {
            role: "model",
            parts: [{ text: "PromptWall protection active." }],
          },
        },
      ],
      usageMetadata: {
        promptTokenCount: 15,
        candidatesTokenCount: 25,
        totalTokenCount: 40,
      },
    };

    const genericResp = adapter.fromProviderResponse(geminiResp);

    expect(genericResp.model).toBe("1.5-flash");
    expect(genericResp.choices).toHaveLength(1);
    expect(genericResp.choices?.[0].message?.role).toBe("assistant");
    expect(genericResp.choices?.[0].message?.content).toBe("PromptWall protection active.");
    expect(genericResp.choices?.[0].finish_reason).toBe("stop");
    expect(genericResp.usage?.prompt_tokens).toBe(15);
    expect(genericResp.usage?.completion_tokens).toBe(25);
    expect(genericResp.usage?.total_tokens).toBe(40);
  });

  test("handles multimodal data and empty parts gracefully", () => {
    const request: LLMRequest = {
      model: "gemini-1.5-pro",
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: "Analyze this image" },
            {
              type: "image_url",
              image_url: { url: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA" },
            },
          ],
        },
      ],
    };

    const geminiReq = adapter.toProviderRequest(request);

    expect(geminiReq.contents).toHaveLength(1);
    expect(geminiReq.contents[0].parts).toHaveLength(2);
    expect(geminiReq.contents[0].parts[0].text).toBe("Analyze this image");
    expect(geminiReq.contents[0].parts[1].inlineData).toBeDefined();
    expect(geminiReq.contents[0].parts[1].inlineData?.mimeType).toBe("image/png");
    expect(geminiReq.contents[0].parts[1].inlineData?.data).toBe("iVBORw0KGgoAAAANSUhEUgAA");
  });
});
