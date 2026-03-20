import OpenAI from "openai";
import type { ChatCompletionCreateParamsNonStreaming } from "openai/resources/chat/completions";
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
  /** Request JSON output from the model (OpenAI/OpenRouter only). */
  responseFormat?: "json_object";
}

export interface LlmProvider {
  chat(options: ChatOptions): Promise<string>;
}

type TokenLimitField = "max_tokens" | "max_completion_tokens";

function prefersMaxCompletionTokens(model: string): boolean {
  return /(^|\/)(gpt-5|o1|o3|o4)(?:$|[-/])/i.test(model);
}

function buildOpenAIChatRequest(
  options: ChatOptions,
  tokenLimitField: TokenLimitField,
): ChatCompletionCreateParamsNonStreaming {
  return {
    model: options.model,
    messages: options.messages,
    temperature: options.temperature ?? 0,
    [tokenLimitField]: options.maxTokens ?? 4096,
    ...(options.responseFormat
      ? { response_format: { type: options.responseFormat } }
      : {}),
  };
}

function shouldRetryWithAlternateTokenField(error: unknown): boolean {
  if (!(error instanceof OpenAI.BadRequestError)) {
    return false;
  }

  const message = error.message.toLowerCase();
  return (
    error.param === "max_tokens" ||
    error.param === "max_completion_tokens" ||
    (message.includes("unsupported parameter") &&
      (message.includes("max_tokens") ||
        message.includes("max_completion_tokens")))
  );
}

async function createOpenAICompatibleChatCompletion(
  client: OpenAI,
  options: ChatOptions,
): Promise<string> {
  const initialTokenLimitField: TokenLimitField = prefersMaxCompletionTokens(
    options.model,
  )
    ? "max_completion_tokens"
    : "max_tokens";

  try {
    const response = await client.chat.completions.create(
      buildOpenAIChatRequest(options, initialTokenLimitField),
    );
    return response.choices[0]?.message?.content?.trim() ?? "";
  } catch (error) {
    if (!shouldRetryWithAlternateTokenField(error)) {
      throw error;
    }

    const fallbackTokenLimitField: TokenLimitField =
      initialTokenLimitField === "max_tokens"
        ? "max_completion_tokens"
        : "max_tokens";
    const response = await client.chat.completions.create(
      buildOpenAIChatRequest(options, fallbackTokenLimitField),
    );
    return response.choices[0]?.message?.content?.trim() ?? "";
  }
}

// ── OpenAI Provider ──

class OpenAIProvider implements LlmProvider {
  private client: OpenAI;

  constructor() {
    this.client = new OpenAI();
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(this.client, options);
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

    const MAX_RETRIES = 4;
    const RETRY_DELAYS_MS = [5000, 15000, 30000, 60000];

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      let response: Response;
      try {
        response = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": this.apiKey,
            "anthropic-version": "2023-06-01",
          },
          body: JSON.stringify(body),
        });
      } catch (fetchErr) {
        if (attempt < MAX_RETRIES) {
          const delayMs = RETRY_DELAYS_MS[attempt];
          console.warn(
            `  [Anthropic] Network error – retrying in ${delayMs / 1000}s (attempt ${attempt + 1}/${MAX_RETRIES}): ${fetchErr instanceof Error ? fetchErr.message : String(fetchErr)}`,
          );
          await new Promise((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
        throw new Error(
          `Anthropic API network error after ${MAX_RETRIES} retries: ${fetchErr instanceof Error ? fetchErr.message : String(fetchErr)}`,
        );
      }

      if (
        response.status === 529 ||
        response.status === 503 ||
        response.status === 429
      ) {
        if (attempt < MAX_RETRIES) {
          const delayMs = RETRY_DELAYS_MS[attempt];
          console.warn(
            `  [Anthropic] ${response.status} – retrying in ${delayMs / 1000}s (attempt ${attempt + 1}/${MAX_RETRIES})...`,
          );
          await new Promise((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
      }

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

    throw new Error(
      "Anthropic API error: max retries exceeded (529 Overloaded)",
    );
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
      defaultHeaders: {
        "HTTP-Referer":
          process.env.OPENROUTER_SITE_URL || "https://github.com/red-team-ai",
        "X-OpenRouter-Title": process.env.OPENROUTER_SITE_NAME || "Red Team AI",
      },
    });
  }

  async chat(options: ChatOptions): Promise<string> {
    return createOpenAICompatibleChatCompletion(this.client, options);
  }
}

// ── Factory ──

const providerCache = new Map<string, LlmProvider>();

function createProvider(name: string): LlmProvider {
  if (providerCache.has(name)) {
    return providerCache.get(name)!;
  }

  let provider: LlmProvider;
  switch (name) {
    case "openai":
      provider = new OpenAIProvider();
      break;
    case "anthropic":
      provider = new AnthropicProvider();
      break;
    case "openrouter":
      provider = new OpenRouterProvider();
      break;
    default:
      throw new Error(
        `Unknown LLM provider: "${name}". Use "openai", "anthropic", or "openrouter".`,
      );
  }

  providerCache.set(name, provider);
  return provider;
}

/** Get the LLM provider for attack generation. */
export function getLlmProvider(config: Config): LlmProvider {
  return createProvider(config.attackConfig.llmProvider);
}

/** Get the LLM provider for the judge. Falls back to the attack provider if judgeProvider is not set. */
export function getJudgeProvider(config: Config): LlmProvider {
  const judgeName =
    config.attackConfig.judgeProvider ?? config.attackConfig.llmProvider;
  return createProvider(judgeName);
}
