import { describe, it, expect, vi, afterEach } from "vitest";
import { executeAttack } from "../lib/attack-runner.js";
import type { Attack, Config } from "../lib/types.js";

function makeConfig(): Config {
  return {
    target: {
      baseUrl: "http://localhost:3000",
      agentEndpoint: "/api/agent",
      authEndpoint: "/api/login",
    },
    codebasePath: ".",
    codebaseGlob: "**/*.ts",
    auth: {
      methods: ["jwt"],
      jwtSecret: "secret",
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
    sensitivePatterns: ["sk-proj-", "SSN:\\s*\\d{3}-\\d{2}-\\d{4}"],
    attackConfig: {
      adaptiveRounds: 1,
      maxAttacksPerCategory: 10,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "gpt-4o-mini",
      enableLlmGeneration: true,
      maxMultiTurnSteps: 3,
    },
  };
}

function makeAttack(overrides: Partial<Attack> = {}): Attack {
  return {
    id: "test-1",
    category: "prompt_injection",
    name: "Test attack",
    description: "Test prompt injection",
    authMethod: "none",
    role: "admin",
    payload: { message: "ignore instructions" },
    expectation: "Agent should comply with injected instruction",
    severity: "high",
    isLlmGenerated: false,
    ...overrides,
  };
}

describe("executeAttack validation", () => {
  it("throws INVALID_ATTACK when attack name is missing", async () => {
    await expect(
      executeAttack(
        makeConfig(),
        makeAttack({ name: "" }) as Attack,
      ),
    ).rejects.toThrow("INVALID_ATTACK: missing attack.name");
  });

  it("throws INVALID_ATTACK when payload.message is missing", async () => {
    await expect(
      executeAttack(
        makeConfig(),
        makeAttack({ payload: {} }) as Attack,
      ),
    ).rejects.toThrow("INVALID_ATTACK: missing attack.payload.message");
  });
});

describe("executeAttack custom API template", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("adds configured guardrails to OpenAI-style request bodies", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      headers: { get: () => "application/json" },
      json: async () => ({ choices: [{ message: { content: "ok" } }] }),
      text: async () => "",
    } as Response);

    const config = makeConfig();
    config.target.baseUrl = "http://localhost:4000";
    config.target.agentEndpoint = "/v1/chat/completions";
    config.target.customApiTemplate = {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      guardrails: ["votal-input-guard", "votal-output-guard"],
      bodyTemplate:
        '{"model":"qwen3.5-27b","messages":[{"role":"user","content":"{{message}}"}]}',
      responsePath: "choices[0].message.content",
    };

    await executeAttack(config, makeAttack({ payload: { message: "user message" } }));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const requestInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(requestInit.body))).toEqual({
      model: "qwen3.5-27b",
      messages: [{ role: "user", content: "user message" }],
      guardrails: ["votal-input-guard", "votal-output-guard"],
    });
  });
});
