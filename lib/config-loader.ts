import { readFileSync } from "fs";
import { resolve } from "path";
import type { Config } from "./types.js";

export function loadConfig(configPath?: string): Config {
  const fullPath = resolve(configPath ?? "config.json");
  const raw = readFileSync(fullPath, "utf-8");
  const config: Config = JSON.parse(raw);

  // Validate required fields
  if (!config.target?.baseUrl) throw new Error("config: target.baseUrl is required");
  if (!config.target?.agentEndpoint) throw new Error("config: target.agentEndpoint is required");
  if (!config.auth?.credentials?.length && !config.auth?.apiKeys) {
    throw new Error("config: at least one auth method (credentials or apiKeys) is required");
  }
  if (!config.sensitivePatterns?.length) {
    console.warn("Warning: no sensitivePatterns defined — sensitive_data checks will be limited");
  }

  // Defaults
  const defaults = {
    adaptiveRounds: 3,
    maxAttacksPerCategory: 15,
    concurrency: 3,
    delayBetweenRequestsMs: 200,
    llmModel: "gpt-4o",
    enableLlmGeneration: true,
  };
  config.attackConfig = { ...defaults, ...config.attackConfig };

  return config;
}
