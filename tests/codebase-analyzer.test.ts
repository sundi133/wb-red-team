import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Config, CodebaseAnalysis } from "../lib/types.js";

// Mock glob before importing the module under test
vi.mock("glob", () => ({
  glob: vi.fn().mockResolvedValue(["agent.ts", "tools.ts"]),
}));

// Mock fs to return controlled source content
vi.mock("fs", async (importOriginal) => {
  const actual = (await importOriginal()) as Record<string, unknown>;
  return {
    ...actual,
    readFileSync: vi.fn((path: string) => {
      if (path.includes("agent.ts")) {
        return `
import { ChatOpenAI } from "@langchain/openai";
import { tool } from "@langchain/core/tools";

const readFile = tool({ name: "read_file", description: "Read a file from disk" });
const sendEmail = tool({ name: "send_email", description: "Send an email to a user" });
const queryDb = tool({ name: "query_database", description: "Query the SQL database" });
const createGist = tool({ name: "create_gist", description: "Create a GitHub gist" });
`;
      }
      if (path.includes("tools.ts")) {
        return `
const listInbox = tool({ name: "list_inbox", description: "List inbox emails" });
const slackDm = tool({ name: "slack_dm", description: "Send a Slack DM" });
`;
      }
      if (path.includes("package.json")) {
        return JSON.stringify({
          dependencies: { "@langchain/openai": "^0.1.0", "@langchain/core": "^0.2.0" },
        });
      }
      throw new Error("ENOENT");
    }),
  };
});

// Mock llm-provider to return a fake analysis
const mockChat = vi.fn();
vi.mock("../lib/llm-provider.js", () => ({
  getLlmProvider: () => ({ chat: mockChat }),
}));

const baseConfig: Config = {
  target: {
    baseUrl: "http://localhost:3000",
    agentEndpoint: "/api/agent",
    authEndpoint: "/api/auth/login",
  },
  codebasePath: "/fake/path/src",
  codebaseGlob: "**/*.ts",
  auth: {
    methods: ["jwt"],
    jwtSecret: "test-secret",
    credentials: [{ email: "admin@test.com", password: "pass", role: "admin" }],
    apiKeys: { admin: "ak_admin" },
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
  attackConfig: {
    adaptiveRounds: 3,
    maxAttacksPerCategory: 15,
    concurrency: 3,
    delayBetweenRequestsMs: 200,
    llmProvider: "openai",
    llmModel: "gpt-4o",
    enableLlmGeneration: true,
    maxMultiTurnSteps: 8,
  },
};

// Must import after mocks are set up
const { analyzeCodebase } = await import("../lib/codebase-analyzer.js");

describe("analyzeCodebase", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns a valid CodebaseAnalysis with all required fields", async () => {
    mockChat.mockResolvedValueOnce(
      JSON.stringify({
        tools: [
          { name: "read_file", description: "Read a file from disk", parameters: "path: string" },
          { name: "send_email", description: "Send an email to a user", parameters: "to: string, body: string" },
          { name: "query_database", description: "Query the SQL database", parameters: "sql: string" },
          { name: "create_gist", description: "Create a GitHub gist", parameters: "content: string" },
          { name: "list_inbox", description: "List inbox emails", parameters: "" },
          { name: "slack_dm", description: "Send a Slack DM", parameters: "user: string, message: string" },
        ],
        roles: [{ name: "admin", permissions: ["*"] }],
        guardrailPatterns: [],
        sensitiveData: [],
        authMechanisms: ["jwt"],
        knownWeaknesses: ["hardcoded secret"],
        systemPromptHints: [],
      }),
    );

    const result = await analyzeCodebase(baseConfig);

    expect(result).toBeDefined();
    expect(Array.isArray(result.tools)).toBe(true);
    expect(Array.isArray(result.roles)).toBe(true);
    expect(Array.isArray(result.guardrailPatterns)).toBe(true);
    expect(Array.isArray(result.sensitiveData)).toBe(true);
    expect(Array.isArray(result.authMechanisms)).toBe(true);
    expect(Array.isArray(result.knownWeaknesses)).toBe(true);
    expect(Array.isArray(result.systemPromptHints)).toBe(true);
    expect(Array.isArray(result.detectedFrameworks)).toBe(true);
    expect(Array.isArray(result.toolChains)).toBe(true);
  });

  it("detects langchain framework from package deps and imports", async () => {
    mockChat.mockResolvedValueOnce(
      JSON.stringify({
        tools: [],
        roles: [],
        guardrailPatterns: [],
        sensitiveData: [],
        authMechanisms: [],
        knownWeaknesses: [],
        systemPromptHints: [],
      }),
    );

    const result = await analyzeCodebase(baseConfig);

    const langchain = result.detectedFrameworks.find((f) => f.name === "langchain");
    expect(langchain).toBeDefined();
    expect(langchain!.confidence).toBe("high"); // detected via package.json
    expect(langchain!.evidence.length).toBeGreaterThanOrEqual(1);
  });

  it("generates tool chain attack graphs for source→sink pairs", async () => {
    mockChat.mockResolvedValueOnce(
      JSON.stringify({
        tools: [
          { name: "read_file", description: "Read a file from disk", parameters: "path" },
          { name: "send_email", description: "Send an email to a user", parameters: "to, body" },
          { name: "query_database", description: "Query the SQL database", parameters: "sql" },
          { name: "create_gist", description: "Create a GitHub gist", parameters: "content" },
          { name: "list_inbox", description: "List inbox emails", parameters: "" },
          { name: "slack_dm", description: "Send a Slack DM", parameters: "user, msg" },
        ],
        roles: [],
        guardrailPatterns: [],
        sensitiveData: [],
        authMechanisms: [],
        knownWeaknesses: [],
        systemPromptHints: [],
      }),
    );

    const result = await analyzeCodebase(baseConfig);

    expect(result.toolChains.length).toBeGreaterThan(0);

    // read_file (source with "file" = sensitive) → send_email (sink with "email" = external) should be critical
    const criticalChain = result.toolChains.find(
      (c) => c.source === "read_file" && c.sink === "send_email",
    );
    expect(criticalChain).toBeDefined();
    expect(criticalChain!.risk).toBe("critical");

    // query_database (source with "query" = sensitive) → create_gist (sink with "gist" = external) should be critical
    const dbGistChain = result.toolChains.find(
      (c) => c.source === "query_database" && c.sink === "create_gist",
    );
    expect(dbGistChain).toBeDefined();
    expect(dbGistChain!.risk).toBe("critical");

    // list_inbox (source with "inbox" = sensitive) → slack_dm (sink with "slack" = external) should be critical
    const inboxSlackChain = result.toolChains.find(
      (c) => c.source === "list_inbox" && c.sink === "slack_dm",
    );
    expect(inboxSlackChain).toBeDefined();
    expect(inboxSlackChain!.risk).toBe("critical");
  });

  it("handles LLM returning invalid JSON gracefully", async () => {
    mockChat.mockResolvedValueOnce("I'm sorry, I can't help with that.");

    const result = await analyzeCodebase(baseConfig);

    // Should fall back to empty analysis
    expect(result.tools).toEqual([]);
    expect(result.roles).toEqual([]);
    expect(result.knownWeaknesses).toEqual([]);
  });

  it("handles LLM returning JSON wrapped in markdown fences", async () => {
    mockChat.mockResolvedValueOnce(
      "```json\n" +
        JSON.stringify({
          tools: [{ name: "test_tool", description: "A test tool", parameters: "" }],
          roles: [],
          guardrailPatterns: [],
          sensitiveData: [],
          authMechanisms: [],
          knownWeaknesses: [],
          systemPromptHints: [],
        }) +
        "\n```",
    );

    const result = await analyzeCodebase(baseConfig);
    expect(result.tools).toHaveLength(1);
    expect(result.tools[0].name).toBe("test_tool");
  });

  it("normalizes null/missing array fields from LLM response", async () => {
    mockChat.mockResolvedValueOnce(
      JSON.stringify({
        tools: null,
        roles: "not an array",
        guardrailPatterns: undefined,
        sensitiveData: [],
        authMechanisms: [],
        knownWeaknesses: [],
        systemPromptHints: [],
      }),
    );

    const result = await analyzeCodebase(baseConfig);
    expect(Array.isArray(result.tools)).toBe(true);
    expect(Array.isArray(result.roles)).toBe(true);
    expect(Array.isArray(result.guardrailPatterns)).toBe(true);
  });

  it("only includes high and critical risk tool chains (not medium)", async () => {
    mockChat.mockResolvedValueOnce(
      JSON.stringify({
        tools: [
          { name: "search_docs", description: "Search documentation", parameters: "" },
          { name: "create_note", description: "Create a note", parameters: "" },
        ],
        roles: [],
        guardrailPatterns: [],
        sensitiveData: [],
        authMechanisms: [],
        knownWeaknesses: [],
        systemPromptHints: [],
      }),
    );

    const result = await analyzeCodebase(baseConfig);

    // search (source) → create (sink) with neither being sensitive/external = medium → filtered out
    for (const chain of result.toolChains) {
      expect(chain.risk).not.toBe("medium");
    }
  });
});
