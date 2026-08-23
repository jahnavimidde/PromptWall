/**
 * @file SecretRegexDetector.test.ts
 * @module @promptwall/engine/detectors/secrets
 *
 * Unit tests for SecretRegexDetector.
 * NOTE: All secret test fixtures are constructed dynamically at runtime to prevent GitHub Push Protection triggers.
 */

import { describe, expect, test } from "bun:test";
import { SecretRegexDetector } from "./SecretRegexDetector";

describe("SecretRegexDetector", () => {
  const detector = new SecretRegexDetector();

  test("detects AWS Access Key", async () => {
    const awsKey = ["AKIA", "IOSFODNN7EXAMPLE"].join("");
    const content = `Header\nAWS key: ${awsKey}\nFooter`;
    const candidates = await detector.detect({ content });

    expect(candidates.length).toBeGreaterThan(0);
    const awsCand = candidates.find((c) => c.subtype === "AWS_KEY");
    expect(awsCand).toBeDefined();
    expect(awsCand?.category).toBe("secret");
    expect(awsCand?.severity).toBe("critical");
    expect(awsCand?.value).toBe(awsKey);
  });

  test("detects OpenAI API key", async () => {
    const openAiKey = ["sk", "proj", "a".repeat(30), "12345678"].join("-");
    const content = `export OPENAI_KEY=${openAiKey}`;
    const candidates = await detector.detect({ content });

    const cand = candidates.find((c) => c.subtype === "OPENAI_KEY");
    expect(cand).toBeDefined();
    expect(cand?.category).toBe("secret");
    expect(cand?.severity).toBe("critical");
  });

  test("detects Anthropic API key", async () => {
    const antKey = ["sk", "ant", "api03", "b".repeat(30)].join("-");
    const content = `const client = new Anthropic({ apiKey: "${antKey}" });`;
    const candidates = await detector.detect({ content });

    const cand = candidates.find((c) => c.subtype === "ANTHROPIC_KEY");
    expect(cand).toBeDefined();
    expect(cand?.category).toBe("secret");
  });

  test("detects GitHub token", async () => {
    const ghToken = ["ghp", "1234567890abcdefghijklmnopqrstuvwxyz"].join("_");
    const content = `Authorization: token ${ghToken}`;
    const candidates = await detector.detect({ content });

    const cand = candidates.find((c) => c.subtype === "GITHUB_TOKEN");
    expect(cand).toBeDefined();
    expect(cand?.category).toBe("secret");
  });

  test("detects JWT token", async () => {
    const header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    const payload = "eyJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9";
    const signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    const jwt = `${header}.${payload}.${signature}`;

    const candidates = await detector.detect({ content: `Bearer ${jwt}` });
    const jwtCand = candidates.find((c) => c.subtype === "JWT");
    expect(jwtCand).toBeDefined();
    expect(jwtCand?.category).toBe("secret");
  });

  test("detects Bearer token", async () => {
    const bearer = `Bearer ${"x".repeat(45)}`;
    const candidates = await detector.detect({ content: `Authorization: ${bearer}` });
    const bCand = candidates.find((c) => c.subtype === "BEARER_TOKEN");
    expect(bCand).toBeDefined();
  });

  test("detects Private Key header", async () => {
    const keyPart1 = "-----BEGIN RSA ";
    const keyPart2 = "PRIVATE KEY-----\nfakekey\n-----END RSA PRIVATE KEY-----";
    const pemKey = `${keyPart1}${keyPart2}`;

    const candidates = await detector.detect({ content: pemKey });
    const pkCand = candidates.find((c) => c.subtype === "PRIVATE_KEY");
    expect(pkCand).toBeDefined();
    expect(pkCand?.severity).toBe("critical");
  });

  test("returns empty array for clean content", async () => {
    const candidates = await detector.detect({ content: "Hello world, this prompt is clean!" });
    expect(candidates).toHaveLength(0);
  });
});
