import { describe, it, expect, vi, afterEach } from "vitest";
import {
  executeAttack,
  executeMultiTurn,
  normalizeAttackForExecution,
  prepareConversation,
} from "../lib/attack-runner.js";
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
  it("fills safe metadata defaults before execution", () => {
    const normalized = normalizeAttackForExecution(
      makeConfig(),
      makeAttack({
        name: "",
        description: "",
        expectation: "",
        severity: undefined as unknown as Attack["severity"],
      }),
    );

    expect(normalized).toMatchObject({
      name: "Prompt Injection candidate",
      description: "Prompt Injection candidate",
      expectation:
        "Evaluate whether the agent response violates the intended security boundary.",
      severity: "medium",
    });
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

describe("executeMultiTurn validation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("repairs sparse step payloads by preserving the parent message", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      headers: { get: () => "application/json" },
      json: async () => ({ response: "ok" }),
      text: async () => "",
    } as Response);

    const config = makeConfig();
    config.auth.methods = ["none"];
    config.target.baseUrl = "http://localhost:4000";
    config.target.agentEndpoint = "/api/agent";

    const result = await executeMultiTurn(
      config,
      makeAttack({
        payload: { message: "parent message" },
        steps: [
          {
            payload: { role: "admin" } as Attack["payload"],
            expectation: "continue",
          },
        ],
      }),
      async () => ({ verdict: "FAIL", findings: [] }),
    );

    expect(result.results).toHaveLength(2);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const secondBody = JSON.parse(String(fetchMock.mock.calls[1]?.[1]?.body));
    expect(secondBody.message).toBe("parent message");
    expect(secondBody.role).toBe("admin");
  });
});

describe("prepareConversation", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.skipIf(process.platform === "win32")(
    "refreshes pre-auth state for each new conversation when enabled",
    async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      status: 200,
      statusText: "OK",
      json: async () => ({ conversationId: "conv-123" }),
    } as Response);

    const config = makeConfig();
    config.target.refreshPerConversation = true;
    config.target.preAuthCommand = {
      command: "python3 scripts/get_esso_token_mock.py 9245099016",
      outputVar: "E_SSO_TOKEN",
    };
    config.target.setupSteps = [
      {
        name: "Create conversation",
        url: "/start/conversation",
        method: "POST",
        headers: {
          "e-sso-token": "{{var:E_SSO_TOKEN}}",
        },
        body: {
          conversationId: "{{uuid}}",
        },
        extract: {
          conversationId: "conversationId",
        },
      },
    ];

    await prepareConversation(config);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const requestInit = fetchMock.mock.calls[0]?.[1] as RequestInit;
    expect((requestInit.headers as Record<string, string>)["e-sso-token"]).toMatch(
      /^\*MOCK_ESSO\*/,
    );
    },
  );
});
