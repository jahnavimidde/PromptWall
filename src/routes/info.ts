import { Hono } from "hono";
import pkg from "../../package.json";
import { getConfig } from "../config";
import { getAnthropicInfo } from "../providers/anthropic/client";
import { getGeminiInfo } from "../providers/gemini/client";
import { getLocalInfo } from "../providers/local";
import "../providers/gemini/provider";
import "../providers/openai/provider";
import { providerRegistry } from "../providers/registry";

export const infoRoutes = new Hono();

infoRoutes.get("/info", (c) => {
  const config = getConfig();
  const openAIProvider = providerRegistry.get("openai");
  const openAIBaseUrl =
    (openAIProvider?.info().baseUrl as string) ?? config.providers.openai.base_url;

  const providers = {
    gemini: {
      base_url: getGeminiInfo(config.providers.gemini).baseUrl,
      default: true,
    },
    openai: {
      base_url: openAIBaseUrl,
    },
    anthropic: {
      base_url: getAnthropicInfo(config.providers.anthropic).baseUrl,
    },
    codex: {
      base_url: config.providers.codex.base_url,
    },
  };

  const info: Record<string, unknown> = {
    name: "PromptWall",
    version: pkg.version,
    description: "Enterprise AI Security Gateway",
    mode: config.mode,
    providers,
    pii_detection: {
      phone_regions: config.pii_detection.phone_regions,
      detector_timeout: config.pii_detection.detector_timeout,
      score_threshold: config.pii_detection.score_threshold,
      entities: config.pii_detection.entities,
    },
    secrets_detection: {
      enabled: config.secrets_detection.enabled,
      action: config.secrets_detection.action,
      entities: config.secrets_detection.entities,
      max_scan_chars: config.secrets_detection.max_scan_chars,
      log_detected_types: config.secrets_detection.log_detected_types,
    },
    logging: {
      retention_days: config.logging.retention_days,
      log_masked_content: config.logging.log_masked_content,
    },
  };

  if (config.mode === "route" && config.local) {
    const localInfo = getLocalInfo(config.local);
    info.local = {
      type: localInfo.type,
      base_url: localInfo.baseUrl,
    };
  }

  if (config.mode === "mask") {
    info.masking = {
      show_markers: config.masking.show_markers,
    };
  }

  return c.json(info);
});
