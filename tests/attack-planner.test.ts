import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  AttackModule,
  CodebaseAnalysis,
  Config,
} from "../lib/types.js";

const { chatMock } = vi.hoisted(() => ({
  chatMock: vi.fn(),
}));

vi.mock("../lib/llm-provider.js", () => ({
  getLlmProvider: () => ({
    chat: chatMock,
  }),
}));

import { planAttacks } from "../lib/attack-planner.js";

function makeConfig(): Config {
  return {
    target: {
      baseUrl: "http://localhost:3000",
      agentEndpoint: "/api/agent",
      authEndpoint: "/api/login",
      applicationDetails: "Internal AI assistant for employee workflows.",
    },
    codebasePath: ".",
    codebaseGlob: "**/*.ts",
    auth: {
      methods: ["none"],
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
    sensitivePatterns: [],
    attackConfig: {
      adaptiveRounds: 2,
      maxAttacksPerCategory: 1,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "gpt-4.1-mini",
      enableLlmGeneration: true,
      includeSeedAttacks: false,
      maxMultiTurnSteps: 1,
      strategiesPerRound: 2,
      attacksPerStrategy: 10,
      enabledStrategies: [
        "life_or_death_emergency",
        "critical_deadline_pressure",
        "personal_distress_moral_dilemma",
      ],
    },
  };
}

const mockAnalysis: CodebaseAnalysis = {
  tools: [],
  roles: [{ name: "admin", permissions: ["*"] }],
  guardrailPatterns: [],
  sensitiveData: [],
  authMechanisms: ["jwt"],
  knownWeaknesses: [],
  systemPromptHints: [],
  detectedFrameworks: [],
  toolChains: [],
};

const mockModule: AttackModule = {
  category: "prompt_injection",
  getSeedAttacks: () => [],
  getGenerationPrompt: () =>
    "Generate realistic prompt injection attacks against the target agent.",
};

describe("planAttacks", () => {
  beforeEach(() => {
    chatMock.mockReset();
    chatMock.mockResolvedValue(
      JSON.stringify([
        {
          id: "",
          category: "prompt_injection",
          name: "Generated attack",
          description: "Generated description",
          authMethod: "none",
          role: "admin",
          payload: { message: "Generated prompt" },
          expectation: "Generated expectation",
          severity: "high",
        },
      ]),
    );
  });

  it("uses attacksPerStrategy for each selected strategy in batch mode", async () => {
    const attacks = await planAttacks(
      makeConfig(),
      mockAnalysis,
      [mockModule],
      [],
      2,
    );

    expect(attacks).toHaveLength(20);
    expect(chatMock).toHaveBeenCalledTimes(20);
    expect(attacks.every((attack) => attack.isLlmGenerated)).toBe(true);
    expect(new Set(attacks.map((attack) => attack.strategyName)).size).toBe(2);
  });

  it("skips seed attacks on round 1 when includeSeedAttacks is false", async () => {
    const config = makeConfig();
    config.attackConfig.includeSeedAttacks = false;

    const attacks = await planAttacks(
      config,
      mockAnalysis,
      [
        {
          ...mockModule,
          getSeedAttacks: () => [
            {
              id: "seed-1",
              category: "prompt_injection",
              name: "Seed attack",
              description: "Seed",
              authMethod: "none",
              role: "admin",
              payload: { message: "seed" },
              expectation: "seed",
              severity: "high",
              isLlmGenerated: false,
            },
          ],
        },
      ],
      [],
      1,
    );

    expect(attacks).toHaveLength(20);
    expect(attacks.every((attack) => attack.isLlmGenerated)).toBe(true);
  });
});
