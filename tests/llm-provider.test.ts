import { beforeEach, describe, expect, it, vi } from "vitest";
import type { Config } from "../lib/types.js";

const { createMock, MockBadRequestError } = vi.hoisted(() => {
  const createMock = vi.fn();

  class MockBadRequestError extends Error {
    param?: string;

    constructor(message: string, param?: string) {
      super(message);
      this.param = param;
    }
  }

  return { createMock, MockBadRequestError };
});

vi.mock("openai", () => ({
  default: class MockOpenAI {
    static BadRequestError = MockBadRequestError;

    chat = {
      completions: {
        create: createMock,
      },
    };
  },
}));

import { getJudgeProvider, getLlmProvider } from "../lib/llm-provider.js";

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
      methods: ["none"],
      jwtSecret: "secret",
      credentials: [],
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
    sensitivePatterns: [],
    attackConfig: {
      adaptiveRounds: 1,
      maxAttacksPerCategory: 1,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "qwen3.5-27b",
      enableLlmGeneration: true,
      maxMultiTurnSteps: 1,
    },
  };
}

describe("llm provider guardrails", () => {
  beforeEach(() => {
    createMock.mockReset();
    createMock.mockResolvedValue({
      choices: [{ message: { content: "ok" } }],
    });
  });

  it("adds llmGuardrails to generation requests when configured", async () => {
    const config = makeConfig();
    config.attackConfig.llmGuardrails = [
      "votal-input-guard",
      "votal-output-guard",
    ];

    await getLlmProvider(config).chat({
      model: "qwen3.5-27b",
      messages: [{ role: "user", content: "user message" }],
    });

    expect(createMock).toHaveBeenCalledTimes(1);
    expect(createMock.mock.calls[0]?.[0]).toMatchObject({
      model: "qwen3.5-27b",
      messages: [{ role: "user", content: "user message" }],
      guardrails: ["votal-input-guard", "votal-output-guard"],
    });
  });

  it("adds judgeGuardrails to judge requests when configured", async () => {
    const config = makeConfig();
    config.attackConfig.judgeProvider = "openai";
    config.attackConfig.judgeModel = "qwen3.5-27b";
    config.attackConfig.judgeGuardrails = ["votal-output-guard"];

    await getJudgeProvider(config).chat({
      model: "qwen3.5-27b",
      messages: [{ role: "user", content: "judge this" }],
    });

    expect(createMock).toHaveBeenCalledTimes(1);
    expect(createMock.mock.calls[0]?.[0]).toMatchObject({
      model: "qwen3.5-27b",
      messages: [{ role: "user", content: "judge this" }],
      guardrails: ["votal-output-guard"],
    });
  });
});
