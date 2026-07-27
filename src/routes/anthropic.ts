import { zValidator } from "@hono/zod-validator";
import type { Context } from "hono";
import { Hono } from "hono";
import { getConfig } from "../config";
import { buildDebugEnvelope, isDemoEnabled } from "../debug/debugEnvelope";
import { formatMaskedRequestForLog } from "../logging/log-content";
import { logRequest } from "../logging/logger";
import type { PlaceholderContext } from "../masking/context";
import { anthropicExtractor } from "../masking/extractors/anthropic";
import { restoreResponse } from "../masking/restorer";
import type { PIIDetectResult } from "../pii/request";
import {
  PrivacyPipelineDetectionError,
  type PrivacyPipelineResult,
  processPrivacyPipeline,
} from "../privacy/pipeline";
import "../providers/anthropic/provider";
import { anthropicAdapter } from "../providers/anthropic/adapter";
import { createAnthropicUnmaskingStream } from "../providers/anthropic/stream-transformer";
import { type AnthropicRequest, AnthropicRequestSchema } from "../providers/anthropic/types";
import { callLocalAnthropic } from "../providers/local";
import { providerRegistry } from "../providers/registry";
import type { LLMRequest, LLMResponse } from "../providers/types";
import type { SecretsProcessResult } from "../secrets/request";
import {
  createLogData,
  errorFormats,
  handleProviderError,
  setBlockedHeaders,
  setResponseHeaders,
  setStreamingHeaders,
  toPIIHeaderData,
  toPIILogData,
  toSecretsHeaderData,
  toSecretsLogData,
} from "./utils";

export const anthropicRoutes = new Hono();

anthropicRoutes.post(
  "/v1/messages",
  zValidator("json", AnthropicRequestSchema, (result, c) => {
    if (!result.success) {
      return c.json(
        errorFormats.anthropic.error(
          `Invalid request body: ${result.error.message}`,
          "invalid_request_error",
        ),
        400,
      );
    }
  }),
  async (c) => {
    const startTime = Date.now();
    const request = c.req.valid("json") as AnthropicRequest;
    const config = getConfig();

    // Route mode requires local provider
    if (config.mode === "route" && !config.local) {
      return respondError(c, "Route mode requires local provider configuration.", 400);
    }

    // route_local secrets action requires local provider
    if (
      config.secrets_detection.enabled &&
      config.secrets_detection.action === "route_local" &&
      !config.local
    ) {
      return respondError(
        c,
        "secrets_detection.action 'route_local' requires local provider.",
        400,
      );
    }

    // Check if Anthropic provider is configured (required for mask mode, optional for route mode)
    if (config.mode === "mask" && !config.providers.anthropic) {
      return respondError(
        c,
        "Anthropic provider not configured. Add providers.anthropic to config.yaml.",
        400,
      );
    }

    const isDemoMode = isDemoEnabled(c);
    const requestId = c.req.header("x-request-id") ?? crypto.randomUUID();

    let privacy: PrivacyPipelineResult<AnthropicRequest>;
    let afterSecretsTime = 0;
    let afterPIITime = 0;
    try {
      privacy = await processPrivacyPipeline(request, config, anthropicExtractor);
      if (isDemoMode) {
        afterPIITime = Date.now();
        afterSecretsTime = afterPIITime - (privacy.piiResult?.detection.scanTimeMs ?? 0);
      }
    } catch (error) {
      if (error instanceof PrivacyPipelineDetectionError) {
        console.error("PII detection error:", error.cause ?? error);
        return respondDetectionError(
          c,
          error.request as AnthropicRequest,
          error.secretsResult as SecretsProcessResult<AnthropicRequest>,
          startTime,
        );
      }
      throw error;
    }

    const { secretsResult, piiResult } = privacy;
    if (secretsResult.blocked) {
      return respondBlocked(c, request, secretsResult, startTime);
    }

    if (!piiResult) {
      throw new Error("PII detection result missing from privacy pipeline");
    }

    const shouldRouteToLocal =
      config.mode === "route" &&
      (piiResult.hasPII ||
        (secretsResult.detection?.detected && config.secrets_detection.action === "route_local"));

    if (shouldRouteToLocal) {
      return sendToLocal(c, request, {
        request: privacy.requestAfterSecrets,
        startTime,
        piiResult,
        secretsResult,
      });
    }

    const maskedContent =
      piiResult.hasPII || secretsResult.masked ? formatRequestForLog(privacy.request) : undefined;

    return sendToAnthropic(c, privacy.request, {
      startTime,
      piiResult,
      piiMaskingContext: privacy.piiMaskingContext,
      secretsResult,
      maskedContent,
      isDemoMode,
      requestId,
      afterSecretsTime,
      afterPIITime,
      privacy,
      originalRequest: request,
    });
  },
);

anthropicRoutes.all("/*", async (c) => {
  const config = getConfig();

  if (!config.providers.anthropic) {
    return respondError(
      c,
      "Anthropic provider not configured. Add providers.anthropic to config.yaml.",
      400,
    );
  }

  const { proxy } = await import("hono/proxy");
  const baseUrl = config.providers.anthropic.base_url || "https://api.anthropic.com";
  const path = c.req.path.replace(/^\/anthropic/, "");
  const query = c.req.url.includes("?") ? c.req.url.slice(c.req.url.indexOf("?")) : "";

  return proxy(`${baseUrl}${path}${query}`, {
    ...c.req,
    headers: {
      ...c.req.header(),
      "X-Forwarded-Host": c.req.header("host"),
      host: undefined,
    },
  });
});

// --- Types ---

interface SendOptions {
  startTime: number;
  piiResult: PIIDetectResult;
  piiMaskingContext?: PlaceholderContext;
  secretsResult: SecretsProcessResult<AnthropicRequest>;
  maskedContent?: string;
  isDemoMode?: boolean;
  requestId?: string;
  afterSecretsTime?: number;
  afterPIITime?: number;
  privacy?: PrivacyPipelineResult<AnthropicRequest>;
  originalRequest?: AnthropicRequest;
}

interface LocalOptions {
  request: AnthropicRequest;
  startTime: number;
  piiResult: PIIDetectResult;
  secretsResult: SecretsProcessResult<AnthropicRequest>;
}

// --- Helpers ---

function formatRequestForLog(request: AnthropicRequest): string | undefined {
  const config = getConfig();
  return formatMaskedRequestForLog(request, anthropicExtractor, config);
}

// --- Response handlers ---

function respondError(c: Context, message: string, status: number) {
  return c.json(
    errorFormats.anthropic.error(message, status >= 500 ? "server_error" : "invalid_request_error"),
    status as 400 | 500 | 502 | 503,
  );
}

function respondBlocked(
  c: Context,
  request: AnthropicRequest,
  secretsResult: SecretsProcessResult<AnthropicRequest>,
  startTime: number,
) {
  const secretTypes = secretsResult.blockedTypes ?? [];

  setBlockedHeaders(c, secretTypes);

  logRequest(
    createLogData({
      provider: "anthropic",
      model: request.model,
      startTime,
      secrets: { detected: true, types: secretTypes, masked: false },
      statusCode: 400,
      errorMessage: `Request blocked: detected secret material (${secretTypes.join(",")})`,
    }),
    c.req.header("User-Agent") || null,
  );

  return c.json(
    errorFormats.anthropic.error(
      `Request blocked: detected secret material (${secretTypes.join(",")}). Remove secrets and retry.`,
      "invalid_request_error",
    ),
    400,
  );
}

function respondDetectionError(
  c: Context,
  request: AnthropicRequest,
  secretsResult: SecretsProcessResult<AnthropicRequest>,
  startTime: number,
) {
  logRequest(
    createLogData({
      provider: "anthropic",
      model: request.model,
      startTime,
      secrets: toSecretsLogData(secretsResult),
      statusCode: 503,
      errorMessage: "PII detection service unavailable",
    }),
    c.req.header("User-Agent") || null,
  );

  return respondError(c, "PII detection service unavailable", 503);
}

// --- Provider handlers ---

async function sendToLocal(c: Context, originalRequest: AnthropicRequest, opts: LocalOptions) {
  const config = getConfig();
  const { request, piiResult, secretsResult, startTime } = opts;

  if (!config.local) {
    throw new Error("Local provider not configured");
  }

  const maskedContent =
    piiResult.hasPII || secretsResult.masked ? formatRequestForLog(request) : undefined;

  setResponseHeaders(
    c,
    config.mode,
    "local",
    toPIIHeaderData(piiResult),
    toSecretsHeaderData(secretsResult),
  );

  try {
    const result = await callLocalAnthropic(request, config.local);

    logRequest(
      createLogData({
        provider: "local",
        model: result.model || originalRequest.model,
        startTime,
        pii: toPIILogData(piiResult),
        secrets: toSecretsLogData(secretsResult),
        maskedContent,
      }),
      c.req.header("User-Agent") || null,
    );

    if (result.isStreaming) {
      setStreamingHeaders(c);
      return c.body(result.response as ReadableStream);
    }

    return c.json(result.response);
  } catch (error) {
    return handleProviderError(
      c,
      error,
      {
        provider: "local",
        model: originalRequest.model,
        startTime,
        pii: toPIILogData(piiResult),
        secrets: toSecretsLogData(secretsResult),
        maskedContent,
        userAgent: c.req.header("User-Agent") || null,
      },
      (msg) => errorFormats.anthropic.error(msg, "server_error"),
    );
  }
}

async function sendToAnthropic(c: Context, request: AnthropicRequest, opts: SendOptions) {
  const config = getConfig();
  const {
    startTime,
    piiResult,
    piiMaskingContext,
    secretsResult,
    maskedContent,
    isDemoMode = false,
    requestId = "",
    afterSecretsTime = 0,
    afterPIITime = 0,
    privacy,
    originalRequest,
  } = opts;

  setResponseHeaders(
    c,
    config.mode,
    "anthropic",
    toPIIHeaderData(piiResult),
    toSecretsHeaderData(secretsResult),
  );

  const clientHeaders = {
    apiKey: c.req.header("x-api-key"),
    authorization: c.req.header("Authorization"),
    beta: c.req.header("anthropic-beta"),
  };

  try {
    const provider = providerRegistry.get("anthropic");
    if (!provider) {
      throw new Error("Anthropic provider not registered");
    }

    const result = await provider.complete(request as LLMRequest, {
      apiKey: clientHeaders.apiKey,
      authHeader: clientHeaders.authorization,
      beta: clientHeaders.beta,
    });
    const afterProviderTime = isDemoMode ? Date.now() : 0;

    logRequest(
      createLogData({
        provider: "anthropic",
        model: result.model || request.model,
        startTime,
        pii: toPIILogData(piiResult),
        secrets: toSecretsLogData(secretsResult),
        maskedContent,
      }),
      c.req.header("User-Agent") || null,
    );

    if (result.isStreaming) {
      // Streaming not supported in demo mode
      return respondStreaming(c, result.response, piiMaskingContext, secretsResult.maskingContext);
    }

    const restoredResponse = buildRestoredJson(
      result.response as LLMResponse,
      piiMaskingContext,
      secretsResult.maskingContext,
    );
    const afterRestoreTime = isDemoMode ? Date.now() : 0;

    if (isDemoMode && privacy && originalRequest) {
      const envelope = buildDebugEnvelope({
        requestId,
        provider: "anthropic",
        originalMessages: originalRequest.messages as Array<{ role: string; content: unknown }>,
        maskedMessages: request.messages as Array<{ role: string; content: unknown }>,
        privacy,
        response: restoredResponse,
        startTime,
        afterSecretsTime,
        afterPIITime,
        afterProviderTime,
        afterRestoreTime,
      });
      return c.json(envelope);
    }

    return c.json(restoredResponse);
  } catch (error) {
    return handleProviderError(
      c,
      error,
      {
        provider: "anthropic",
        model: request.model,
        startTime,
        pii: toPIILogData(piiResult),
        secrets: toSecretsLogData(secretsResult),
        maskedContent,
        userAgent: c.req.header("User-Agent") || null,
      },
      (msg) => errorFormats.anthropic.error(msg, "server_error"),
    );
  }
}

// --- Response formatters ---

function respondStreaming(
  c: Context,
  stream: ReadableStream<Uint8Array>,
  piiMaskingContext: PlaceholderContext | undefined,
  secretsContext: PlaceholderContext | undefined,
) {
  const config = getConfig();
  setStreamingHeaders(c);

  if (piiMaskingContext || secretsContext) {
    const unmaskingStream = createAnthropicUnmaskingStream(
      stream,
      piiMaskingContext,
      config.masking,
      secretsContext,
    );
    return c.body(unmaskingStream);
  }

  return c.body(stream);
}

function buildRestoredJson(
  response: LLMResponse,
  piiMaskingContext: PlaceholderContext | undefined,
  secretsContext: PlaceholderContext | undefined,
): LLMResponse {
  const config = getConfig();
  const proxyResponse = anthropicAdapter.toProxyResponse(response);
  return restoreResponse(proxyResponse, anthropicExtractor, config.masking, {
    piiContext: piiMaskingContext,
    secretsContext,
  }) as LLMResponse;
}
