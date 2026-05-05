import { readFileSync } from "fs";
import { resolve } from "path";
import type { Config } from "./types.js";

function findDuplicates(values: string[] | undefined): string[] {
  if (!values?.length) return [];
  const counts = new Map<string, number>();
  for (const value of values) {
    counts.set(value, (counts.get(value) ?? 0) + 1);
  }
  return [...counts.entries()]
    .filter(([, count]) => count > 1)
    .map(([value]) => value);
}

function validateAndNormalizeConfig(config: Config): Config {
  config.target.type = config.target.type ?? "http_agent";

  // Validate required fields
  if (config.target.type === "http_agent") {
    if (!config.target?.baseUrl)
      throw new Error("config: target.baseUrl is required");
    if (!config.target?.agentEndpoint)
      throw new Error("config: target.agentEndpoint is required");
    config.target.authEndpoint = config.target.authEndpoint ?? "";
  } else if (config.target.type === "websocket_agent") {
    if (!config.target?.baseUrl)
      throw new Error("config: target.baseUrl is required");
    if (!config.target.websocket?.path) {
      throw new Error(
        'config: target.websocket.path is required when target.type is "websocket_agent"',
      );
    }
    config.target.agentEndpoint = config.target.agentEndpoint ?? "";
    config.target.authEndpoint = config.target.authEndpoint ?? "";
  } else if (config.target.type === "mcp") {
    const mcp = config.target.mcp;
    if (!mcp)
      throw new Error(
        'config: target.mcp is required when target.type is "mcp"',
      );
    if (!mcp.transport) {
      throw new Error(
        'config: target.mcp.transport is required when target.type is "mcp"',
      );
    }
    if (mcp.transport === "stdio" && !mcp.command) {
      throw new Error(
        "config: target.mcp.command is required for stdio MCP targets",
      );
    }
    if (
      (mcp.transport === "sse" || mcp.transport === "streamable_http") &&
      !mcp.url
    ) {
      throw new Error(
        "config: target.mcp.url is required for network MCP targets",
      );
    }
    config.target.baseUrl = config.target.baseUrl ?? "";
    config.target.agentEndpoint = config.target.agentEndpoint ?? "";
    config.target.authEndpoint = config.target.authEndpoint ?? "";
  } else {
    throw new Error(`config: unknown target.type "${config.target.type}"`);
  }
  config.target.applicationDetails = config.target.applicationDetails?.trim();
  if (!config.target.applicationDetails) {
    console.warn(
      "Warning: target.applicationDetails is not set — LLM-generated attacks will be less app-specific",
    );
    config.target.applicationDetails = "";
  }
  if (
    !config.auth?.credentials?.length &&
    !Object.keys(config.auth?.apiKeys ?? {}).length
  ) {
    throw new Error(
      "config: at least one auth method (credentials or apiKeys) is required",
    );
  }
  if (!config.sensitivePatterns?.length) {
    config.sensitivePatterns = [];
    if (config.attackConfig.enableDiscovery) {
      console.log(
        "  sensitivePatterns is empty — discovery round will auto-populate from target reconnaissance",
      );
    } else {
      console.warn(
        "Warning: no sensitivePatterns defined and discovery is disabled — sensitive_data checks will be limited",
      );
    }
  }

  // Defaults
  const defaults = {
    adaptiveRounds: 3,
    maxAttacksPerCategory: 15,
    concurrency: 3,
    delayBetweenRequestsMs: 200,
    llmProvider: "openai",
    llmModel: "gpt-4o",
    enableLlmGeneration: true,
    maxMultiTurnSteps: 8,
    strategiesPerRound: 8,
    requireReviewConfirmation: true,
    enableMultiTurnGeneration: true,
    multiTurnGenerationRate: 0.4,
    enableAdaptiveMultiTurn: true,
    maxAdaptiveTurns: 15,
    appTailoredCustomPromptCount: 0,
  };
  config.attackConfig = { ...defaults, ...config.attackConfig };

  const duplicateCategories = findDuplicates(
    config.attackConfig.enabledCategories,
  );
  if (duplicateCategories.length > 0) {
    throw new Error(
      `config: duplicate enabledCategories: ${duplicateCategories.join(", ")}`,
    );
  }

  const duplicateStrategies = findDuplicates(
    config.attackConfig.enabledStrategies,
  );
  if (duplicateStrategies.length > 0) {
    throw new Error(
      `config: duplicate enabledStrategies: ${duplicateStrategies.join(", ")}`,
    );
  }

  return config;
}

export function loadConfig(configPath?: string): Config {
  const fullPath = resolve(configPath ?? "config.json");
  const raw = readFileSync(fullPath, "utf-8");
  const config: Config = JSON.parse(raw);
  return validateAndNormalizeConfig(config);
}

/** Load and validate a config from a plain object (for API server usage). */
export function loadConfigFromObject(obj: Record<string, unknown>): Config {
  const config = obj as unknown as Config;
  return validateAndNormalizeConfig(config);
}
