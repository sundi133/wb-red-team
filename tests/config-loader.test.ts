import { describe, it, expect, vi } from "vitest";
import { loadConfig } from "../lib/config-loader.js";
import { writeFileSync, mkdtempSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

function writeTestConfig(dir: string, config: Record<string, unknown>): string {
  const path = join(dir, "config.json");
  writeFileSync(path, JSON.stringify(config));
  return path;
}

function makeValidConfig(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    target: {
      baseUrl: "http://localhost:3000",
      agentEndpoint: "/api/agent",
      authEndpoint: "/api/login",
      applicationDetails:
        "Internal support assistant for order lookups and refunds.",
    },
    auth: {
      methods: ["jwt"],
      jwtSecret: "test-secret",
      credentials: [{ email: "a@b.com", password: "pass", role: "admin" }],
      apiKeys: {},
    },
    requestSchema: {
      messageField: "message",
      roleField: "role",
      apiKeyField: "api_key",
      guardrailModeField: "guardrail_mode",
    },
    responseSchema: {
      responsePath: "response",
      toolCallsPath: "tool_calls",
      userInfoPath: "user",
      guardrailsPath: "guardrails",
    },
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
    expect(config.target.type).toBe("http_agent");
    expect(config.target.baseUrl).toBe("http://localhost:3000");
    expect(config.target.agentEndpoint).toBe("/api/agent");
    expect(config.target.applicationDetails).toBe(
      "Internal support assistant for order lookups and refunds.",
    );
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
    expect(config.attackConfig.targetTimeoutMs).toBe(30000);
    expect(config.attackConfig.llmTimeoutMs).toBe(60000);
  });

  it("allows overriding attackConfig defaults", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        attackConfig: { adaptiveRounds: 5, llmModel: "gpt-4o-mini" },
      }),
    );
    const config = loadConfig(path);
    expect(config.attackConfig.adaptiveRounds).toBe(5);
    expect(config.attackConfig.llmModel).toBe("gpt-4o-mini");
    // Non-overridden fields get defaults
    expect(config.attackConfig.concurrency).toBe(3);
  });

  it("throws on duplicate enabled categories", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        attackConfig: {
          enabledCategories: ["prompt_injection", "prompt_injection"],
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("duplicate enabledCategories");
  });

  it("throws on duplicate enabled strategies", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        attackConfig: {
          enabledStrategies: [
            "life_or_death_emergency",
            "life_or_death_emergency",
          ],
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("duplicate enabledStrategies");
  });

  it("preserves target.applicationDetails when provided", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          baseUrl: "http://localhost:3000",
          agentEndpoint: "/api/agent",
          authEndpoint: "/api/login",
          applicationDetails:
            "Customer support AI assistant for refunds and order lookups.",
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.target.applicationDetails).toBe(
      "Customer support AI assistant for refunds and order lookups.",
    );
  });

  it("defaults target.applicationDetails to empty string when omitted", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          baseUrl: "http://localhost:3000",
          agentEndpoint: "/api/agent",
          authEndpoint: "/api/login",
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.target.applicationDetails).toBe("");
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("target.applicationDetails"),
    );
    warn.mockRestore();
  });

  it("loads a valid MCP target config", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          type: "mcp",
          applicationDetails: "MCP security test target",
          mcp: {
            transport: "stdio",
            command: "node",
            args: ["server.js"],
          },
        },
      }),
    );
    const config = loadConfig(path);
    expect(config.target.type).toBe("mcp");
    expect(config.target.mcp?.transport).toBe("stdio");
    expect(config.target.mcp?.command).toBe("node");
    expect(config.target.baseUrl).toBe("");
    expect(config.target.agentEndpoint).toBe("");
  });

  it("throws when MCP target is missing target.mcp", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          type: "mcp",
          applicationDetails: "MCP security test target",
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.mcp is required");
  });

  it("throws when stdio MCP target is missing command", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          type: "mcp",
          applicationDetails: "MCP security test target",
          mcp: {
            transport: "stdio",
          },
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.mcp.command is required");
  });

  it("throws on missing baseUrl", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: { agentEndpoint: "/api/agent", authEndpoint: "/api/login" },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.baseUrl is required");
  });

  it("throws on missing agentEndpoint", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        target: {
          baseUrl: "http://localhost:3000",
          authEndpoint: "/api/login",
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("target.agentEndpoint is required");
  });

  it("throws on missing auth credentials and apiKeys", () => {
    const path = writeTestConfig(
      tmpDir,
      makeValidConfig({
        auth: {
          methods: ["jwt"],
          jwtSecret: "s",
          credentials: [],
          apiKeys: undefined,
        },
      }),
    );
    expect(() => loadConfig(path)).toThrow("at least one auth method");
  });

  it("throws on non-existent config file", () => {
    expect(() => loadConfig("/nonexistent/path/config.json")).toThrow();
  });
});
