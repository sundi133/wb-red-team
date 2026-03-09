import { describe, it, expect } from "vitest";
import { loadConfig } from "../lib/config-loader.js";
import { writeFileSync, mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

function writeTestConfig(dir: string, config: Record<string, unknown>): string {
  const path = join(dir, "config.json");
  writeFileSync(path, JSON.stringify(config));
  return path;
}

function makeValidConfig(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    target: { baseUrl: "http://localhost:3000", agentEndpoint: "/api/agent", authEndpoint: "/api/login" },
    auth: {
      methods: ["jwt"],
      jwtSecret: "test-secret",
      credentials: [{ email: "a@b.com", password: "pass", role: "admin" }],
      apiKeys: {},
    },
    requestSchema: { messageField: "message", roleField: "role", apiKeyField: "api_key", guardrailModeField: "guardrail_mode" },
    responseSchema: { responsePath: "response", toolCallsPath: "tool_calls", userInfoPath: "user", guardrailsPath: "guardrails" },
    sensitivePatterns: ["sk-proj-"],
    ...overrides,
  };
}

describe("loadConfig", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), "redteam-test-"));
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("loads a valid config file", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig());
    const config = loadConfig(path);
    expect(config.target.baseUrl).toBe("http://localhost:3000");
    expect(config.target.agentEndpoint).toBe("/api/agent");
  });

  it("applies default attackConfig values", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig());
    const config = loadConfig(path);
    expect(config.attackConfig.adaptiveRounds).toBe(3);
    expect(config.attackConfig.maxAttacksPerCategory).toBe(15);
    expect(config.attackConfig.concurrency).toBe(3);
    expect(config.attackConfig.delayBetweenRequestsMs).toBe(200);
    expect(config.attackConfig.llmModel).toBe("gpt-4o");
    expect(config.attackConfig.enableLlmGeneration).toBe(true);
    expect(config.attackConfig.maxMultiTurnSteps).toBe(8);
  });

  it("allows overriding attackConfig defaults", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig({
      attackConfig: { adaptiveRounds: 5, llmModel: "gpt-4o-mini" },
    }));
    const config = loadConfig(path);
    expect(config.attackConfig.adaptiveRounds).toBe(5);
    expect(config.attackConfig.llmModel).toBe("gpt-4o-mini");
    // Non-overridden fields get defaults
    expect(config.attackConfig.concurrency).toBe(3);
  });

  it("throws on missing baseUrl", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig({
      target: { agentEndpoint: "/api/agent", authEndpoint: "/api/login" },
    }));
    expect(() => loadConfig(path)).toThrow("target.baseUrl is required");
  });

  it("throws on missing agentEndpoint", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig({
      target: { baseUrl: "http://localhost:3000", authEndpoint: "/api/login" },
    }));
    expect(() => loadConfig(path)).toThrow("target.agentEndpoint is required");
  });

  it("throws on missing auth credentials and apiKeys", () => {
    const path = writeTestConfig(tmpDir, makeValidConfig({
      auth: { methods: ["jwt"], jwtSecret: "s", credentials: [], apiKeys: undefined },
    }));
    expect(() => loadConfig(path)).toThrow("at least one auth method");
  });

  it("throws on non-existent config file", () => {
    expect(() => loadConfig("/nonexistent/path/config.json")).toThrow();
  });
});
