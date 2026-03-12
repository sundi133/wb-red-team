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

// ── Factory ──

let cachedProvider: LlmProvider | null = null;
let cachedProviderName: string | null = null;

export function getLlmProvider(config: Config): LlmProvider {
  const providerName = config.attackConfig.llmProvider;

  if (cachedProvider && cachedProviderName === providerName) {
    return cachedProvider;
  }

  switch (providerName) {
    case "openai":
      cachedProvider = new OpenAIProvider();
      break;
    case "anthropic":
      cachedProvider = new AnthropicProvider();
      break;
    case "openrouter":
      cachedProvider = new OpenRouterProvider();
      break;
    default:
      throw new Error(
        `Unknown LLM provider: "${providerName}". Use "openai", "anthropic", or "openrouter".`,
      );
  }

  cachedProviderName = providerName;
  return cachedProvider;
}
