import { describe, expect, test } from "bun:test";
import type { PrivacyPipelineResult } from "../privacy/pipeline";
import { buildDebugEnvelope } from "./debugEnvelope";

describe("buildDebugEnvelope", () => {
  test("successfully constructs a debug envelope from pipeline outputs", () => {
    const mockPrivacy = {
      requestAfterSecrets: { messages: [] },
      request: { messages: [] },
      secretsResult: {
        blocked: false,
        masked: true,
        request: { messages: [] },
        detection: {
          detected: true,
          matches: [
            {
              type: "AWS_SECRET_ACCESS_KEY",
              start: 0,
              end: 10,
              value: ["AKIA", "IOSFOD"].join(""),
            },
          ],
        },
        maskingContext: {
          mapping: { "[[AWS_SECRET_ACCESS_KEY_1]]": ["AKIA", "IOSFOD"].join("") },
          counters: { AWS_SECRET_ACCESS_KEY: 1 },
          reverseMapping: {},
        },
      },
      piiResult: {
        hasPII: true,
        detection: {
          allEntities: [
            {
              entity_type: "EMAIL_ADDRESS",
              score: 0.99,
              start: 10,
              end: 27,
              text: "sarah@example.com",
            },
          ],
          scanTimeMs: 42,
        },
      },
      piiMaskingContext: {
        mapping: { "[[EMAIL_ADDRESS_1]]": "sarah@example.com" },
        counters: { EMAIL_ADDRESS: 1 },
        reverseMapping: {},
      },
    } as unknown as PrivacyPipelineResult<unknown>;

    const originalMessages = [
      {
        role: "user",
        content: `My AWS is ${["AKIA", "IOSFOD"].join("")} and email is sarah@example.com`,
      },
    ];
    const maskedMessages = [
      {
        role: "user",
        content: "My AWS is [[AWS_SECRET_ACCESS_KEY_1]] and email is [[EMAIL_ADDRESS_1]]",
      },
    ];

    const result = buildDebugEnvelope({
      requestId: "test-req-id",
      provider: "openai",
      originalMessages,
      maskedMessages,
      privacy: mockPrivacy,
      response: { choices: [{ message: { content: "Acknowledged." } }] },
      startTime: 1000,
      afterSecretsTime: 1010,
      afterPIITime: 1030,
      afterProviderTime: 1200,
      afterRestoreTime: 1205,
    });

    expect(result.debug.requestId).toBe("test-req-id");
    expect(result.debug.provider).toBe("openai");
    expect(result.debug.originalPrompt).toBe(
      `My AWS is ${["AKIA", "IOSFOD"].join("")} and email is sarah@example.com`,
    );
    expect(result.debug.maskedPrompt).toBe(
      "My AWS is [[AWS_SECRET_ACCESS_KEY_1]] and email is [[EMAIL_ADDRESS_1]]",
    );
    expect(result.debug.piiEntities).toEqual(["EMAIL_ADDRESS"]);
    expect(result.debug.secretTypes).toEqual(["AWS_SECRET_ACCESS_KEY"]);
    expect(result.debug.maskCount).toBe(2);
    expect(result.debug.policyDecision).toBe("ALLOWED");
    expect(result.debug.scanTimeMs).toBe(42);
    expect(result.debug.responsesRestored).toBe(true);
    expect(result.debug.timings.secretsMs).toBe(10);
    expect(result.debug.timings.piiMs).toBe(20);
    expect(result.debug.timings.providerMs).toBe(170);
    expect(result.debug.timings.restoreMs).toBe(5);
  });
});
