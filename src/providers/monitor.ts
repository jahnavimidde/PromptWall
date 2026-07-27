import { getConfig } from "../config";
import { HEALTH_CHECK_TIMEOUT_MS } from "../constants/timeouts";
import type { LLMProvider } from "./types";

/**
 * Monitor for tracking provider health, availability, and stats
 */
export class ProviderMonitor {
  /**
   * Check if a provider endpoint is healthy and reachable
   */
  async checkProviderHealth(provider: LLMProvider): Promise<boolean> {
    const info = provider.info();
    if (!info.baseUrl) return true;

    try {
      const baseUrl = (info.baseUrl as string).replace(/\/$/, "");
      const endpoint = `${baseUrl}/models`;
      const config = getConfig();
      const headers: Record<string, string> = {};

      if (info.id === "openai" && config.providers.openai.api_key) {
        headers.Authorization = `Bearer ${config.providers.openai.api_key}`;
      }

      const response = await fetch(endpoint, {
        method: "GET",
        headers,
        signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT_MS),
      });

      return response.ok;
    } catch {
      return false;
    }
  }
}

export const providerMonitor = new ProviderMonitor();
