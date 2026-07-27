import type { LLMProvider } from "./types";

export type ProviderFactory = () => LLMProvider;

/**
 * Registry for managing LLM providers and provider factories (lazy initialization)
 */
export class ProviderRegistry {
  private static instance: ProviderRegistry;
  private providers = new Map<string, LLMProvider>();
  private factories = new Map<string, ProviderFactory>();

  public static getInstance(): ProviderRegistry {
    if (!ProviderRegistry.instance) {
      ProviderRegistry.instance = new ProviderRegistry();
    }
    return ProviderRegistry.instance;
  }

  /**
   * Register a provider instance directly
   */
  public register(provider: LLMProvider): void {
    this.providers.set(provider.id, provider);
  }

  /**
   * Register a provider factory for lazy initialization
   */
  public registerFactory(id: string, factory: ProviderFactory): void {
    this.factories.set(id, factory);
  }

  /**
   * Get provider by id (instantiating via factory lazily if needed)
   */
  public get(id: string): LLMProvider | undefined {
    if (this.providers.has(id)) {
      return this.providers.get(id);
    }
    const factory = this.factories.get(id);
    if (factory) {
      const provider = factory();
      this.providers.set(id, provider);
      return provider;
    }
    return undefined;
  }

  /**
   * Check if a provider or provider factory is registered
   */
  public has(id: string): boolean {
    return this.providers.has(id) || this.factories.has(id);
  }

  /**
   * Get all provider instances (instantiating any uninstantiated factory providers)
   */
  public getAll(): LLMProvider[] {
    for (const [id, factory] of this.factories.entries()) {
      if (!this.providers.has(id)) {
        this.providers.set(id, factory());
      }
    }
    return Array.from(this.providers.values());
  }

  /**
   * Clear all registered providers and factories (useful for testing)
   */
  public clear(): void {
    this.providers.clear();
    this.factories.clear();
  }
}

export const providerRegistry = ProviderRegistry.getInstance();
