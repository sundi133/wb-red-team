import OpenAI from "openai";
import type { Config } from "./types.js";

export interface ChatMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface ChatOptions {
  model: string;
  messages: ChatMessage[];
  temperature?: number;
  maxTokens?: number;
}

export interface LlmProvider {
  chat(options: ChatOptions): Promise<string>;
}

// ── OpenAI Provider ──

class OpenAIProvider implements LlmProvider {
  private client: OpenAI;

  constructor() {
    this.client = new OpenAI();
  }

  async chat(options: ChatOptions): Promise<string> {
    const response = await this.client.chat.completions.create({
      model: options.model,
      messages: options.messages,
      temperature: options.temperature ?? 0,
      max_tokens: options.maxTokens ?? 4096,
    });
    return response.choices[0]?.message?.content?.trim() ?? "";
  }
}

// ── Anthropic Provider (uses fetch directly to avoid extra dependency) ──

class AnthropicProvider implements LlmProvider {
  private apiKey: string;

  constructor() {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key)
      throw new Error(
        "ANTHROPIC_API_KEY environment variable is required for anthropic provider",
      );
    this.apiKey = key;
  }

  async chat(options: ChatOptions): Promise<string> {
    // Separate system message from user/assistant messages
    const systemMsg = options.messages.find((m) => m.role === "system");
    const nonSystemMsgs = options.messages.filter((m) => m.role !== "system");

    const body: Record<string, unknown> = {
      model: options.model,
      max_tokens: options.maxTokens ?? 4096,
      temperature: options.temperature ?? 0,
      messages: nonSystemMsgs.map((m) => ({
        role: m.role,
        content: m.content,
      })),
    };
    if (systemMsg) {
      body.system = systemMsg.content;
    }

    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": this.apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const err = await response.text();
      throw new Error(`Anthropic API error ${response.status}: ${err}`);
    }

    const data = (await response.json()) as {
      content: { type: string; text: string }[];
    };
    const textBlock = data.content.find((b) => b.type === "text");
    return textBlock?.text?.trim() ?? "";
  }
}

// ── OpenRouter Provider (OpenAI-compatible API) ──

class OpenRouterProvider implements LlmProvider {
  private client: OpenAI;

  constructor() {
    const key = process.env.OPENROUTER_API_KEY;
    if (!key)
      throw new Error(
        "OPENROUTER_API_KEY environment variable is required for openrouter provider",
      );
    this.client = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey: key,
    });
  }

  async chat(options: ChatOptions): Promise<string> {
    const response = await this.client.chat.completions.create({
      model: options.model,
      messages: options.messages,
      temperature: options.temperature ?? 0,
      max_tokens: options.maxTokens ?? 4096,
    });
    return response.choices[0]?.message?.content?.trim() ?? "";
  }
}

// ── Retry wrapper ──

function isRetryableError(e: unknown): boolean {
  if (e instanceof Error) {
    const msg = e.message.toLowerCase();
    // Rate limits, server errors, timeouts, network failures
    return (
      msg.includes("429") ||
      msg.includes("500") ||
      msg.includes("502") ||
      msg.includes("503") ||
      msg.includes("529") ||
      msg.includes("timeout") ||
      msg.includes("econnreset") ||
      msg.includes("econnrefused") ||
      msg.includes("fetch failed") ||
      msg.includes("network")
    );
  }
  return false;
}

class RetryingProvider implements LlmProvider {
  constructor(
    private inner: LlmProvider,
    private retryAttempts: number,
    private retryDelayMs: number,
  ) {}

  async chat(options: ChatOptions): Promise<string> {
    let lastError: Error | undefined;

    for (let attempt = 0; attempt <= this.retryAttempts; attempt++) {
      try {
        return await this.inner.chat(options);
      } catch (e) {
        lastError = e as Error;
        if (!isRetryableError(e) || attempt === this.retryAttempts) {
          throw lastError;
        }
        const delay = this.retryDelayMs * Math.pow(2, attempt);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }

    throw lastError!;
  }
}

// ── Factory ──

let cachedProvider: LlmProvider | null = null;
let cachedProviderName: string | null = null;
let cachedRetryAttempts: number | null = null;
let cachedRetryDelayMs: number | null = null;

export function getLlmProvider(config: Config): LlmProvider {
  const providerName = config.attackConfig.llmProvider;
  const retryAttempts = config.attackConfig.retryAttempts ?? 3;
  const retryDelayMs = config.attackConfig.retryDelayMs ?? 500;

  if (
    cachedProvider &&
    cachedProviderName === providerName &&
    cachedRetryAttempts === retryAttempts &&
    cachedRetryDelayMs === retryDelayMs
  ) {
    return cachedProvider;
  }

  let inner: LlmProvider;
  switch (providerName) {
    case "openai":
      inner = new OpenAIProvider();
      break;
    case "anthropic":
      inner = new AnthropicProvider();
      break;
    case "openrouter":
      inner = new OpenRouterProvider();
      break;
    default:
      throw new Error(
        `Unknown LLM provider: "${providerName}". Use "openai", "anthropic", or "openrouter".`,
      );
  }

  cachedProvider = new RetryingProvider(inner, retryAttempts, retryDelayMs);
  cachedProviderName = providerName;
  cachedRetryAttempts = retryAttempts;
  cachedRetryDelayMs = retryDelayMs;
  return cachedProvider;
}
