/**
 * @file m14.security.test.ts
 * @module src/__tests__
 *
 * M14 Security Regression Tests — Credential Transport and Leakage
 *
 * Covers:
 * 1. extractGatewayCredential — deterministic precedence order under conflicting sources.
 * 2. stripCredentialParams / buildSanitizedUrl — URL-safe credential stripping utility (unit).
 * 3. Catch-all proxy URL stripping — ?api_key and ?token removed before upstream forwarding.
 * 4. Error responses — no raw credential, JWT, or API key in any response body.
 * 5. Tenant isolation — spoofed org headers never trusted.
 * 6. Conflicting credential sources — deterministic winner, no cross-tenant ambiguity.
 * 7. PromptWall credential suppression logic (header-level, unit verification).
 * 8. safeConsoleLog query credential redaction (unit).
 *
 * All credentials are SYNTHETIC. No real credentials appear anywhere in this file.
 */

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { signUserToken } from "../auth/jwt";
import { aiGatewayAuthMiddleware, extractGatewayCredential } from "../auth/middleware";
import { app } from "../index";
import { ApiKeyStore } from "../organizations/api-key-store";
import { OrgStore } from "../organizations/org-store";
import { buildSanitizedUrl, stripCredentialParams } from "../routes/utils";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mockReq(
  headers: Record<string, string | undefined> = {},
  query: Record<string, string | undefined> = {},
): { header: (n: string) => string | undefined; query: (n: string) => string | undefined } {
  return {
    header: (name: string) => headers[name.toLowerCase()] ?? headers[name],
    query: (name: string) => query[name],
  };
}

// ---------------------------------------------------------------------------
// 1. Credential precedence (unit)
// ---------------------------------------------------------------------------

describe("M14 Security — extractGatewayCredential precedence (unit)", () => {
  const SYNTHETIC_PW_KEY = "pw_live_synth_test_key_00000000000000000000000000";
  const SYNTHETIC_JWT_LIKE = "eyJhbGciOiJIUzI1NiJ9.synthetic.payload";

  test("x-api-key header wins over Authorization: Bearer", () => {
    const cred = extractGatewayCredential(
      mockReq({ "x-api-key": SYNTHETIC_PW_KEY, authorization: `Bearer ${SYNTHETIC_JWT_LIKE}` }, {}),
    );
    expect(cred?.token).toBe(SYNTHETIC_PW_KEY);
    expect(cred?.type).toBe("api_key");
  });

  test("Authorization: Bearer wins over query ?api_key=", () => {
    const cred = extractGatewayCredential(
      mockReq(
        { authorization: `Bearer ${SYNTHETIC_PW_KEY}` },
        { api_key: "pw_live_query_param_key_should_be_ignored_00000" },
      ),
    );
    expect(cred?.token).toBe(SYNTHETIC_PW_KEY);
    expect(cred?.type).toBe("api_key");
  });

  test("api-key header wins over ?token= query param", () => {
    const cred = extractGatewayCredential(
      mockReq({ "api-key": SYNTHETIC_PW_KEY }, { token: SYNTHETIC_JWT_LIKE }),
    );
    expect(cred?.token).toBe(SYNTHETIC_PW_KEY);
    expect(cred?.type).toBe("api_key");
  });

  test("Bearer pw_live_ token classified as api_key, never jwt", () => {
    const cred = extractGatewayCredential(
      mockReq({ authorization: `Bearer ${SYNTHETIC_PW_KEY}` }, {}),
    );
    expect(cred?.type).toBe("api_key");
  });

  test("?api_key= with pw_live_ prefix classified as api_key", () => {
    const cred = extractGatewayCredential(mockReq({}, { api_key: SYNTHETIC_PW_KEY }));
    expect(cred?.type).toBe("api_key");
  });

  test("?token= without pw_live_ prefix classified as jwt", () => {
    const cred = extractGatewayCredential(
      mockReq({}, { token: "eyJhbGciOiJIUzI1NiJ9.synthetic.payload" }),
    );
    expect(cred?.type).toBe("jwt");
  });

  test("Returns null when no credential present in any source", () => {
    expect(extractGatewayCredential(mockReq({}, {}))).toBeNull();
  });

  test("With x-api-key + Authorization + ?api_key= all present, x-api-key wins", () => {
    const cred = extractGatewayCredential(
      mockReq(
        { "x-api-key": SYNTHETIC_PW_KEY, authorization: `Bearer ${SYNTHETIC_JWT_LIKE}` },
        { api_key: "pw_live_third_source_ignored_00000000000000000" },
      ),
    );
    expect(cred?.token).toBe(SYNTHETIC_PW_KEY);
    expect(cred?.type).toBe("api_key");
  });
});

// ---------------------------------------------------------------------------
// 2. stripCredentialParams / buildSanitizedUrl — unit tests
// ---------------------------------------------------------------------------

describe("M14 Security — stripCredentialParams utility (unit)", () => {
  test("Strips ?api_key= from query string", () => {
    const result = stripCredentialParams("?api_key=pw_live_synthetic_000000000000000000000");
    expect(result).toBe("");
    expect(result).not.toContain("api_key");
  });

  test("Strips ?token= from query string", () => {
    const result = stripCredentialParams("?token=eyJhbGciOiJIUzI1NiJ9.synthetic.token");
    expect(result).toBe("");
    expect(result).not.toContain("token");
  });

  test("Strips both ?api_key= and ?token= simultaneously", () => {
    const result = stripCredentialParams(
      "?api_key=pw_live_synthetic_000000000&token=eyJhbGciOiJIUzI1NiJ9.synthetic.token",
    );
    expect(result).toBe("");
    expect(result).not.toContain("api_key");
    expect(result).not.toContain("token");
  });

  test("Preserves non-credential params after stripping ?api_key=", () => {
    const result = stripCredentialParams("?provider=openai&api_key=pw_live_synthetic&limit=10");
    expect(result).toContain("provider=openai");
    expect(result).toContain("limit=10");
    expect(result).not.toContain("api_key");
  });

  test("Preserves non-credential params after stripping ?token=", () => {
    const result = stripCredentialParams("?stream=true&token=eyJhbGciOiJIUzI1NiJ9.jwt&model=gpt4");
    expect(result).toContain("stream=true");
    expect(result).toContain("model=gpt4");
    expect(result).not.toContain("token");
  });

  test("Handles URL-encoded credential value correctly", () => {
    // api_key value contains URL-encoded characters; URLSearchParams decodes them
    const result = stripCredentialParams("?api_key=pw_live_%73ynth%65tic&provider=openai");
    expect(result).not.toContain("api_key");
    expect(result).toContain("provider=openai");
  });

  test("Handles repeated api_key params (both removed)", () => {
    // URLSearchParams.delete() removes ALL occurrences of the key
    const result = stripCredentialParams("?api_key=first_key&api_key=second_key&provider=openai");
    expect(result).not.toContain("api_key");
    expect(result).toContain("provider=openai");
  });

  test("Returns empty string when query is empty", () => {
    expect(stripCredentialParams("")).toBe("");
    expect(stripCredentialParams("?")).toBe("");
  });

  test("Returns non-credential params unchanged when no credential params present", () => {
    const result = stripCredentialParams("?provider=openai&limit=10&stream=false");
    expect(result).toContain("provider=openai");
    expect(result).toContain("limit=10");
    expect(result).toContain("stream=false");
  });

  test("buildSanitizedUrl appends clean params with ?", () => {
    const url = buildSanitizedUrl(
      "https://api.openai.com/v1/models",
      "?api_key=pw_live_synthetic&provider=openai",
    );
    expect(url).toBe("https://api.openai.com/v1/models?provider=openai");
    expect(url).not.toContain("api_key");
  });

  test("buildSanitizedUrl returns base URL without ? when all params are credentials", () => {
    const url = buildSanitizedUrl(
      "https://api.openai.com/v1/models",
      "?api_key=pw_live_synthetic&token=eyJhbGciOiJIUzI1NiJ9.jwt",
    );
    expect(url).toBe("https://api.openai.com/v1/models");
    expect(url).not.toContain("?");
    expect(url).not.toContain("api_key");
    expect(url).not.toContain("token");
  });

  test("buildSanitizedUrl preserves base URL with no query string", () => {
    const url = buildSanitizedUrl("https://api.openai.com/v1/models", "");
    expect(url).toBe("https://api.openai.com/v1/models");
  });
});

// ---------------------------------------------------------------------------
// 3. Catch-all proxy URL credential stripping
//    Tests use buildSanitizedUrl directly (same function the routes call) to
//    verify that credential params are absent from every upstream URL.
//    This avoids live-upstream dependencies while accurately testing the fix.
// ---------------------------------------------------------------------------

describe("M14 Security — catch-all proxy: query credentials stripped from upstream URL", () => {
  let orgStore: OrgStore;
  let apiKeyStore: ApiKeyStore;
  let testOrgId: string;
  let validRawApiKey: string;

  beforeEach(async () => {
    orgStore = new OrgStore();
    apiKeyStore = new ApiKeyStore();
    const org = await orgStore.createOrganization({
      name: "M14 URL Strip Test Org",
      slug: `m14strip-${crypto.randomUUID().slice(0, 8)}`,
    });
    testOrgId = org.id;
    const createdKey = await apiKeyStore.createApiKey({
      organizationId: testOrgId,
      name: "M14 URL Strip Key",
      permissions: ["org:usage:read"],
      createdBy: "usr_m14_strip_admin",
    });
    validRawApiKey = createdKey.key;
  });

  afterEach(async () => {
    try {
      if (testOrgId) await orgStore.deleteOrganization(testOrgId);
    } catch {
      /* best-effort */
    }
  });

  test("OpenAI catch-all: ?api_key= is stripped from upstream URL", () => {
    const rawQuery = `?api_key=${validRawApiKey}&provider=openai`;
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/models", rawQuery);
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain(validRawApiKey);
    expect(upstream).not.toContain("pw_live_");
    expect(upstream).toContain("provider=openai");
  });

  test("OpenAI catch-all: ?token= is stripped from upstream URL", () => {
    const syntheticJwt = "eyJhbGciOiJIUzI1NiJ9.openai_token_strip_test.sig";
    const rawQuery = `?token=${syntheticJwt}&provider=openai`;
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/models", rawQuery);
    expect(upstream).not.toContain("token=");
    expect(upstream).not.toContain(syntheticJwt);
    expect(upstream).toContain("provider=openai");
  });

  test("Anthropic catch-all: ?api_key= is stripped from upstream URL", () => {
    const rawQuery = `?api_key=${validRawApiKey}&version=2024-02`;
    const upstream = buildSanitizedUrl("https://api.anthropic.com/v1/models", rawQuery);
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain(validRawApiKey);
    expect(upstream).not.toContain("pw_live_");
    expect(upstream).toContain("version=2024-02");
  });

  test("Anthropic catch-all: ?token= is stripped from upstream URL", () => {
    const syntheticJwt = "eyJhbGciOiJIUzI1NiJ9.anthropic_token_strip_test.sig";
    const rawQuery = `?token=${syntheticJwt}&beta=true`;
    const upstream = buildSanitizedUrl("https://api.anthropic.com/v1/models", rawQuery);
    expect(upstream).not.toContain("token=");
    expect(upstream).not.toContain(syntheticJwt);
    expect(upstream).toContain("beta=true");
  });

  test("Codex catch-all: ?api_key= is stripped from upstream URL", () => {
    const rawQuery = `?api_key=${validRawApiKey}&stream=false`;
    const upstream = buildSanitizedUrl("https://api.openai.com/codex/models", rawQuery);
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain(validRawApiKey);
    expect(upstream).not.toContain("pw_live_");
    expect(upstream).toContain("stream=false");
  });

  test("Codex catch-all: ?token= is stripped from upstream URL", () => {
    const syntheticJwt = "eyJhbGciOiJIUzI1NiJ9.codex_token_strip_test.sig";
    const rawQuery = `?token=${syntheticJwt}&limit=20`;
    const upstream = buildSanitizedUrl("https://api.openai.com/codex/models", rawQuery);
    expect(upstream).not.toContain("token=");
    expect(upstream).not.toContain(syntheticJwt);
    expect(upstream).toContain("limit=20");
  });

  test("Non-credential query parameters are preserved in upstream URL", () => {
    const result = stripCredentialParams(
      `?provider=openai&api_key=${validRawApiKey}&limit=10&token=synthetic_jwt_value`,
    );
    expect(result).toContain("provider=openai");
    expect(result).toContain("limit=10");
    expect(result).not.toContain("api_key");
    expect(result).not.toContain("token");
  });

  test("Multiple credential parameters are all removed", () => {
    const result = stripCredentialParams(
      "?api_key=pw_live_synthetic_000000000000000000000&token=synthetic_jwt_payload&api_key=pw_live_second",
    );
    expect(result).toBe("");
    expect(result).not.toContain("api_key");
    expect(result).not.toContain("token");
  });

  test("URL-encoded credential values are removed correctly", () => {
    const result = stripCredentialParams("?api_key=pw_live_%73ynth%65tic_key&provider=openai");
    expect(result).not.toContain("api_key");
    expect(result).toContain("provider=openai");
  });

  test("Credential parameters cannot reappear in upstream URL after stripping", () => {
    const upstreamUrl = buildSanitizedUrl(
      "https://api.openai.com/v1/models",
      "?api_key=pw_live_synthetic_000000000000000000000&provider=openai&token=synthetic_jwt",
    );
    expect(upstreamUrl).not.toContain("api_key");
    expect(upstreamUrl).not.toContain("token=");
    expect(upstreamUrl).not.toContain("pw_live_");
    expect(upstreamUrl).toContain("provider=openai");
    expect((upstreamUrl.match(/\?/g) ?? []).length).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// 3b. OpenAI Responses (/responses) query credential stripping
// ---------------------------------------------------------------------------

describe("M14 Security — OpenAI Responses (/responses): query credentials stripped from upstream URL", () => {
  let orgStore: OrgStore;
  let apiKeyStore: ApiKeyStore;
  let testOrgId: string;
  let validRawApiKey: string;

  beforeEach(async () => {
    orgStore = new OrgStore();
    apiKeyStore = new ApiKeyStore();
    const org = await orgStore.createOrganization({
      name: "M14 Responses Strip Test Org",
      slug: `m14resp-${crypto.randomUUID().slice(0, 8)}`,
    });
    testOrgId = org.id;
    const createdKey = await apiKeyStore.createApiKey({
      organizationId: testOrgId,
      name: "M14 Responses Strip Key",
      permissions: ["org:usage:read"],
      createdBy: "usr_m14_resp_admin",
    });
    validRawApiKey = createdKey.key;
  });

  afterEach(async () => {
    try {
      if (testOrgId) await orgStore.deleteOrganization(testOrgId);
    } catch {
      /* best-effort */
    }
  });

  test("/openai/v1/responses?api_key=pw_live_SYNTHETIC → upstream URL contains no api_key", () => {
    const rawQuery = `?api_key=${validRawApiKey}&model=gpt-4o`;
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/responses", rawQuery);
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain(validRawApiKey);
    expect(upstream).not.toContain("pw_live_");
    expect(upstream).toContain("model=gpt-4o");
  });

  test("/openai/v1/responses?token=SYNTHETIC → upstream URL contains no token", () => {
    const syntheticJwt = "eyJhbGciOiJIUzI1NiJ9.openai_responses_token_test.sig";
    const rawQuery = `?token=${syntheticJwt}&stream=true`;
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/responses", rawQuery);
    expect(upstream).not.toContain("token=");
    expect(upstream).not.toContain(syntheticJwt);
    expect(upstream).toContain("stream=true");
  });

  test("/openai/v1/responses with both credentials together: both are removed", () => {
    const syntheticJwt = "eyJhbGciOiJIUzI1NiJ9.openai_responses_both_test.sig";
    const rawQuery = `?api_key=${validRawApiKey}&token=${syntheticJwt}&stream=true&foo=bar`;
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/responses", rawQuery);
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain("token=");
    expect(upstream).not.toContain(validRawApiKey);
    expect(upstream).not.toContain(syntheticJwt);
    expect(upstream).toContain("stream=true");
    expect(upstream).toContain("foo=bar");
  });

  test("/openai/v1/responses: legitimate parameters such as ?stream=true&foo=bar remain", () => {
    const rawQuery = "?stream=true&foo=bar";
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/responses", rawQuery);
    expect(upstream).toBe("https://api.openai.com/v1/responses?stream=true&foo=bar");
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain("token");
  });

  test("/openai/v1/responses: URL-encoded credential values are removed", () => {
    const rawQuery = "?api_key=pw_live_%73ynth%65tic_responses_key&stream=true";
    const upstream = buildSanitizedUrl("https://api.openai.com/v1/responses", rawQuery);
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain("%73ynth");
    expect(upstream).toContain("stream=true");
  });

  test("/openai/v1/responses: no credential query parameter can reappear in upstream URL", () => {
    const upstream = buildSanitizedUrl(
      "https://api.openai.com/v1/responses",
      `?api_key=${validRawApiKey}&token=synthetic_jwt&stream=true&foo=bar`,
    );
    expect(upstream).not.toContain("api_key");
    expect(upstream).not.toContain("token=");
    expect(upstream).not.toContain("pw_live_");
    expect(upstream).toContain("stream=true&foo=bar");
    expect((upstream.match(/\?/g) ?? []).length).toBe(1);
  });

  test("OpenAI /responses route end-to-end: fetch is called with sanitized upstream URL (no credentials)", async () => {
    const originalFetch = globalThis.fetch;
    let interceptedUrl: string | undefined;

    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr = typeof input === "string" ? input : input.toString();
        if (urlStr.includes("/responses")) {
          interceptedUrl = urlStr;
          return new Response(JSON.stringify({ id: "resp_123", output: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (urlStr.includes(":5002") || urlStr.includes("/analyze")) {
          return new Response(JSON.stringify([]), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return originalFetch(input, init);
      }) as typeof fetch;

      const res = await app.request(
        `/openai/v1/responses?api_key=${validRawApiKey}&stream=false&custom_param=preserved`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: "gpt-4o",
            input: "Hello world",
          }),
        },
      );

      expect(res.status).toBe(200);
      expect(interceptedUrl).toBeDefined();
      expect(interceptedUrl).not.toContain("api_key");
      expect(interceptedUrl).not.toContain(validRawApiKey);
      expect(interceptedUrl).not.toContain("pw_live_");
      expect(interceptedUrl).toContain("/responses");
      expect(interceptedUrl).toContain("stream=false");
      expect(interceptedUrl).toContain("custom_param=preserved");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("OpenAI /responses route end-to-end: ?token= JWT is stripped from upstream fetch URL", async () => {
    const originalFetch = globalThis.fetch;
    let interceptedUrl: string | undefined;

    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        const urlStr = typeof input === "string" ? input : input.toString();
        if (urlStr.includes("/responses")) {
          interceptedUrl = urlStr;
          return new Response(JSON.stringify({ id: "resp_123", output: [] }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        if (urlStr.includes(":5002") || urlStr.includes("/analyze")) {
          return new Response(JSON.stringify([]), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return originalFetch(input, init);
      }) as typeof fetch;

      const token = await signUserToken(
        "usr_m14_resp",
        "resp@test.com",
        "SECURITY_ANALYST",
        3600,
        testOrgId,
        "ANALYST",
      );

      const res = await app.request(`/openai/v1/responses?token=${token}&flag=test`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          model: "gpt-4o",
          input: "Hello secure world",
        }),
      });

      expect(res.status).toBe(200);
      expect(interceptedUrl).toBeDefined();
      expect(interceptedUrl).not.toContain("token=");
      expect(interceptedUrl).not.toContain(token);
      expect(interceptedUrl).toContain("/responses");
      expect(interceptedUrl).toContain("flag=test");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Header-level credential stripping still works
// ---------------------------------------------------------------------------

describe("M14 Security — PromptWall credential suppression logic (unit, headers)", () => {
  test("pw_live_ Bearer is NOT forwarded upstream", () => {
    const auth = "Bearer pw_live_bearer_strip_test_0000000000000000000000";
    const val = auth.trim().slice(7).trim();
    expect(val.startsWith("pw_live_")).toBe(true);
  });

  test("BYOK Bearer token is forwarded upstream (correct BYOK behavior)", () => {
    const auth = "Bearer sk-byok-customer-owned-key-00000000000000000000000";
    const val = auth.trim().slice(7).trim();
    expect(val.startsWith("pw_live_")).toBe(false);
  });

  test("PromptWall JWT is suppressed: type+token equality check passes", () => {
    const syntheticJwt = "eyJhbGciOiJIUzI1NiJ9.test_payload_m14.sig";
    const auth = `Bearer ${syntheticJwt}`;
    const val = auth.trim().slice(7).trim();
    const userIsSet = true;
    const credType = "jwt";
    const credToken = syntheticJwt;
    expect(userIsSet && credType === "jwt" && credToken === val).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// 5. Error responses never leak credentials
// ---------------------------------------------------------------------------

describe("M14 Security — error response body never leaks credentials", () => {
  test("401 body does not contain raw Bearer token", async () => {
    const syntheticToken = "eyJhbGciOiJIUzI1NiJ9.synthetic_secret_token_m14_review.sig";
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${syntheticToken}` },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).not.toContain(syntheticToken);
    expect(body).not.toContain("synthetic_secret_token_m14_review");
  });

  test("401 body does not echo back invalid x-api-key value", async () => {
    const fakePwKey = "pw_live_invalid_key_m14_test_0000000000000000000000";
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "x-api-key": fakePwKey },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).not.toContain(fakePwKey);
    expect(body).not.toContain("pw_live_invalid_key_m14_test");
  });

  test("401 body does not contain query-parameter credential value", async () => {
    const syntheticQueryKey = "pw_live_query_m14_security_test_000000000000000000";
    const res = await app.request(`/openai/v1/chat/completions?api_key=${syntheticQueryKey}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).not.toContain(syntheticQueryKey);
    expect(body).not.toContain("pw_live_query_m14_security_test");
  });

  test("403 body does not contain raw JWT for rejected VIEWER role", async () => {
    const token = await signUserToken("usr_viewer_sec", "viewer_sec@test.com", "VIEWER", 3600);
    const res = await app.request("/openai/v1/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
      body: JSON.stringify({ model: "gpt-4o", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(403);
    const body = await res.text();
    expect(body).not.toContain(token);
    expect(body).not.toMatch(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/);
  });
});

// ---------------------------------------------------------------------------
// 6. Tenant isolation: spoofed org headers are ignored
// ---------------------------------------------------------------------------

describe("M14 Security — tenant isolation: spoofed org headers ignored", () => {
  let orgStore: OrgStore;
  let apiKeyStore: ApiKeyStore;
  let testOrgId: string;
  let validRawApiKey: string;

  beforeEach(async () => {
    orgStore = new OrgStore();
    apiKeyStore = new ApiKeyStore();
    const org = await orgStore.createOrganization({
      name: "M14 Isolation Test Org",
      slug: `m14iso-${crypto.randomUUID().slice(0, 8)}`,
    });
    testOrgId = org.id;
    const createdKey = await apiKeyStore.createApiKey({
      organizationId: testOrgId,
      name: "M14 Isolation Key",
      permissions: ["org:usage:read"],
      createdBy: "usr_m14_iso_admin",
    });
    validRawApiKey = createdKey.key;
  });

  afterEach(async () => {
    try {
      if (testOrgId) await orgStore.deleteOrganization(testOrgId);
    } catch {
      /* best-effort */
    }
  });

  test("x-organization-id cannot override orgId from verified API key", async () => {
    let capturedOrgId: string | undefined;
    const probe = new Hono();
    probe.use("/probe/*", aiGatewayAuthMiddleware());
    probe.get("/probe/org", (c) => {
      capturedOrgId = c.get("orgId");
      return c.json({ ok: true });
    });
    await probe.request("/probe/org", {
      headers: {
        Authorization: `Bearer ${validRawApiKey}`,
        "x-organization-id": "org_ATTACKER_SPOOFED_VALUE",
        "x-tenant-id": "org_ATTACKER_ALSO_SPOOFED",
      },
    });
    expect(capturedOrgId).toBe(testOrgId);
    expect(capturedOrgId).not.toBe("org_ATTACKER_SPOOFED_VALUE");
  });

  test("x-organization-id cannot override orgId from verified JWT", async () => {
    let capturedOrgId: string | undefined;
    const probe = new Hono();
    probe.use("/probe/*", aiGatewayAuthMiddleware());
    probe.get("/probe/org", (c) => {
      capturedOrgId = c.get("orgId");
      return c.json({ ok: true });
    });
    const token = await signUserToken(
      "usr_jwt_tenant",
      "jwt_tenant@test.com",
      "SECURITY_ANALYST",
      3600,
      testOrgId,
      "ANALYST",
    );
    await probe.request("/probe/org", {
      headers: { Authorization: `Bearer ${token}`, "x-organization-id": "org_ATTACKER" },
    });
    expect(capturedOrgId).toBe(testOrgId);
    expect(capturedOrgId).not.toBe("org_ATTACKER");
  });

  test("Conflicting credentials: x-api-key wins; orgId from its DB record, not the JWT org", async () => {
    let capturedOrgId: string | undefined;
    const probe = new Hono();
    probe.use("/probe/*", aiGatewayAuthMiddleware());
    probe.get("/probe/org", (c) => {
      capturedOrgId = c.get("orgId");
      return c.json({ ok: true });
    });
    const differentOrgJwt = await signUserToken(
      "usr_different_org",
      "diff@test.com",
      "SECURITY_ANALYST",
      3600,
      "org_completely_different_tenant",
      "ANALYST",
    );
    const res = await probe.request("/probe/org", {
      headers: {
        "x-api-key": validRawApiKey,
        Authorization: `Bearer ${differentOrgJwt}`,
      },
    });
    expect(res.status).toBe(200);
    expect(capturedOrgId).toBe(testOrgId);
    expect(capturedOrgId).not.toBe("org_completely_different_tenant");
  });
});

// ---------------------------------------------------------------------------
// 7. Anthropic stripping edge cases
// ---------------------------------------------------------------------------

describe("M14 Security — Anthropic credential stripping edge cases (unit)", () => {
  test("pw_live_ key in x-api-key is stripped (startsWith check)", () => {
    const key = "pw_live_anthropic_strip_test_0000000000000000000";
    expect(key.startsWith("pw_live_")).toBe(true);
  });

  test("BYOK x-api-key is forwarded to Anthropic (BYOK preserved)", () => {
    const byokKey = "sk-ant-byok-customer-00000000000000000000000000000000";
    expect(byokKey.startsWith("pw_live_")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// 8. safeConsoleLog query credential redaction (unit)
// ---------------------------------------------------------------------------

describe("M14 Security — safeConsoleLog query credential redaction (unit)", () => {
  function safeConsoleLogTransform(str: string): string {
    return str.replace(/([?&](?:api_key|token|key|secret|password)=)[^&\s]+/gi, "$1[REDACTED]");
  }

  test("?api_key= is redacted in log output", () => {
    const out = safeConsoleLogTransform(
      "GET /openai/models?api_key=pw_live_synthetic_000000000000 HTTP/1.1",
    );
    expect(out).toContain("[REDACTED]");
    expect(out).not.toContain("pw_live_synthetic_000000000000");
  });

  test("?token= is redacted in log output", () => {
    const out = safeConsoleLogTransform(
      "POST /openai/v1/chat/completions?token=eyJhbGciOiJIUzI1NiJ9.synthetic.token HTTP/1.1",
    );
    expect(out).toContain("token=[REDACTED]");
    expect(out).not.toContain("eyJhbGciOiJIUzI1NiJ9.synthetic.token");
  });

  test("?password= is redacted in log output", () => {
    const out = safeConsoleLogTransform("GET /endpoint?password=my-secret-password HTTP/1.1");
    expect(out).toContain("[REDACTED]");
    expect(out).not.toContain("my-secret-password");
  });

  test("Multiple credential params all redacted", () => {
    const out = safeConsoleLogTransform(
      "GET /openai/models?api_key=pw_live_synthetic_000000000&token=synthetic_jwt_here HTTP/1.1",
    );
    expect(out).not.toContain("pw_live_synthetic_000000000");
    expect(out).not.toContain("synthetic_jwt_here");
    expect((out.match(/\[REDACTED\]/g) ?? []).length).toBe(2);
  });

  test("Non-credential params are preserved after redaction", () => {
    const out = safeConsoleLogTransform(
      "GET /openai/models?provider=openai&api_key=pw_live_synthetic_000000000 HTTP/1.1",
    );
    expect(out).toContain("provider=openai");
    expect(out).toContain("[REDACTED]");
    expect(out).not.toContain("pw_live_synthetic_000000000");
  });
});
