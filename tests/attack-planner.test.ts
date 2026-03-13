import { describe, it, expect, vi, beforeEach } from "vitest";
import type {
  Config,
  CodebaseAnalysis,
  AttackModule,
  Attack,
  AttackResult,
} from "../lib/types.js";

// Mock llm-provider
const mockChat = vi.fn();
vi.mock("../lib/llm-provider.js", () => ({
  getLlmProvider: () => ({ chat: mockChat }),
}));

// Mock attack-strategies to return deterministic strategies
vi.mock("../lib/attack-strategies.js", () => ({
  ALL_STRATEGIES: [
    {
      id: 0,
      slug: "test_strategy",
      name: "Test Strategy",
      level: 1,
      levelName: "Basic",
      promptModifier: "Use a test approach",
    },
  ],
  sampleStrategies: () => [
    {
      id: 0,
      slug: "test_strategy",
      name: "Test Strategy",
      level: 1,
      levelName: "Basic",
      promptModifier: "Use a test approach",
    },
  ],
}));

const { planAttacks } = await import("../lib/attack-planner.js");

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
    enableLlmGeneration: false,
    maxMultiTurnSteps: 8,
  },
};

const mockAnalysis: CodebaseAnalysis = {
  tools: [
    { name: "read_file", description: "Read a file", parameters: "path: string" },
    { name: "send_email", description: "Send email", parameters: "to, body" },
  ],
  roles: [{ name: "admin", permissions: ["*"] }],
  guardrailPatterns: [],
  sensitiveData: [],
  authMechanisms: ["jwt"],
  knownWeaknesses: [],
  systemPromptHints: [],
  detectedFrameworks: [],
  toolChains: [],
};

function makeSeedAttack(overrides: Partial<Attack> = {}): Attack {
  return {
    id: "test-seed-1",
    category: "auth_bypass",
    name: "Test Seed Attack",
    description: "A test seed attack",
    authMethod: "jwt",
    role: "admin",
    payload: { message: "test message" },
    expectation: "Should bypass auth",
    severity: "high",
    isLlmGenerated: false,
    ...overrides,
  };
}

const mockModule: AttackModule = {
  category: "auth_bypass",
  getSeedAttacks: () => [
    makeSeedAttack({ id: "auth-seed-1", name: "Forged JWT" }),
    makeSeedAttack({ id: "auth-seed-2", name: "Missing Auth", authMethod: "none" }),
  ],
  getGenerationPrompt: () => "Generate auth bypass attacks...",
};

const mockModule2: AttackModule = {
  category: "prompt_injection",
  getSeedAttacks: () => [
    makeSeedAttack({
      id: "pi-seed-1",
      category: "prompt_injection",
      name: "System Prompt Override",
    }),
  ],
  getGenerationPrompt: () => "Generate prompt injection attacks...",
};

describe("planAttacks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("includes seed attacks on round 1 with LLM generation disabled", async () => {
    const attacks = await planAttacks(
      baseConfig,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    expect(attacks).toHaveLength(2);
    expect(attacks[0].id).toBe("auth-seed-1");
    expect(attacks[1].id).toBe("auth-seed-2");
    expect(attacks.every((a) => !a.isLlmGenerated)).toBe(true);
  });

  it("does NOT include seed attacks on round 2+", async () => {
    const attacks = await planAttacks(
      baseConfig,
      mockAnalysis,
      [mockModule],
      [],
      2,
    );

    // With LLM disabled and round > 1, no seed attacks and no generated attacks
    expect(attacks).toHaveLength(0);
  });

  it("collects seed attacks from multiple modules", async () => {
    const attacks = await planAttacks(
      baseConfig,
      mockAnalysis,
      [mockModule, mockModule2],
      [],
      1,
    );

    expect(attacks).toHaveLength(3); // 2 from auth_bypass + 1 from prompt_injection
    const categories = new Set(attacks.map((a) => a.category));
    expect(categories.has("auth_bypass")).toBe(true);
    expect(categories.has("prompt_injection")).toBe(true);
  });

  it("adds LLM-generated attacks when enableLlmGeneration is true", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    // First call: LLM generation for module (round 1)
    // Second call: realism rewrite for seed attacks
    mockChat
      .mockResolvedValueOnce(
        JSON.stringify([
          {
            id: "gen-1",
            category: "auth_bypass",
            name: "Generated Attack",
            description: "LLM-generated attack",
            authMethod: "jwt",
            role: "admin",
            payload: { message: "generated payload" },
            expectation: "bypass auth",
            severity: "critical",
            strategyId: 0,
            strategyName: "Test Strategy",
          },
        ]),
      )
      .mockResolvedValueOnce(
        JSON.stringify([
          { idx: 0, message: "rewritten seed 1" },
          { idx: 1, message: "rewritten seed 2" },
        ]),
      );

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    // 2 seed + 1 generated
    expect(attacks).toHaveLength(3);

    const generated = attacks.filter((a) => a.isLlmGenerated);
    expect(generated).toHaveLength(1);
    expect(generated[0].category).toBe("auth_bypass");
  });

  it("marks all LLM-generated attacks with isLlmGenerated: true", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    mockChat
      .mockResolvedValueOnce(
        JSON.stringify([
          {
            id: "gen-1",
            category: "auth_bypass",
            name: "Gen1",
            description: "test",
            authMethod: "jwt",
            role: "admin",
            payload: { message: "test" },
            expectation: "test",
            severity: "high",
          },
          {
            id: "gen-2",
            category: "auth_bypass",
            name: "Gen2",
            description: "test",
            authMethod: "none",
            role: "viewer",
            payload: { message: "test" },
            expectation: "test",
            severity: "medium",
          },
        ]),
      )
      .mockResolvedValueOnce("[]"); // realism rewrite returns empty

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    const generated = attacks.filter((a) => a.isLlmGenerated);
    expect(generated).toHaveLength(2);
    generated.forEach((a) => expect(a.isLlmGenerated).toBe(true));
  });

  it("handles LLM returning invalid JSON without crashing", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    mockChat
      .mockResolvedValueOnce("I'm sorry, I cannot generate attacks.")
      .mockResolvedValueOnce("[]"); // realism rewrite

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    // Should still have 2 seed attacks even though LLM generation failed
    expect(attacks).toHaveLength(2);
    expect(attacks.every((a) => !a.isLlmGenerated)).toBe(true);
  });

  it("handles LLM throwing an error without crashing", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    mockChat
      .mockRejectedValueOnce(new Error("API rate limit exceeded"))
      .mockResolvedValueOnce("[]"); // realism rewrite

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    // Seeds still present despite LLM error
    expect(attacks).toHaveLength(2);
  });

  it("refines PARTIAL results on round 2+ with LLM generation enabled", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    const previousResults: AttackResult[] = [
      {
        attack: makeSeedAttack({ id: "auth-seed-1", category: "auth_bypass" }),
        verdict: "PARTIAL",
        statusCode: 200,
        responseBody: "partial leak of data",
        responseTimeMs: 150,
        findings: ["Partial data exposure detected"],
        llmReasoning: "Some data was leaked but not all",
      },
    ];

    // First call: LLM generation for the module
    // Second call: refinement of partial attacks
    mockChat
      .mockResolvedValueOnce(JSON.stringify([]))
      .mockResolvedValueOnce(
        JSON.stringify([
          {
            id: "refined-1",
            category: "auth_bypass",
            name: "Refined Attack",
            description: "Improved version of auth-seed-1",
            authMethod: "forged_jwt",
            role: "admin",
            payload: { message: "refined payload" },
            expectation: "full bypass",
            severity: "critical",
            refinedFrom: "auth-seed-1",
          },
        ]),
      );

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      previousResults,
      2,
    );

    // No seeds on round 2, but we get refined attacks
    const refined = attacks.filter((a) => a.refinedFrom);
    expect(refined.length).toBeGreaterThan(0);
    expect(refined[0].refinedFrom).toBe("auth-seed-1");
    expect(refined[0].isLlmGenerated).toBe(true);
  });

  it("handles LLM response wrapped in markdown fences", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    mockChat
      .mockResolvedValueOnce(
        "```json\n" +
          JSON.stringify([
            {
              id: "fenced-1",
              category: "auth_bypass",
              name: "Fenced Attack",
              description: "test",
              authMethod: "jwt",
              role: "admin",
              payload: { message: "test" },
              expectation: "test",
              severity: "high",
            },
          ]) +
          "\n```",
      )
      .mockResolvedValueOnce("[]"); // realism rewrite

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    const generated = attacks.filter((a) => a.isLlmGenerated);
    expect(generated).toHaveLength(1);
    expect(generated[0].id).toBe("fenced-1");
  });

  it("handles LLM refusal with embedded JSON array", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    mockChat
      .mockResolvedValueOnce(
        'I cannot help with attacks, but here is an example: [{"id":"embedded-1","category":"auth_bypass","name":"Embedded","description":"test","authMethod":"jwt","role":"admin","payload":{"message":"test"},"expectation":"test","severity":"high"}]',
      )
      .mockResolvedValueOnce("[]"); // realism rewrite

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      [],
      1,
    );

    const generated = attacks.filter((a) => a.isLlmGenerated);
    expect(generated).toHaveLength(1);
  });

  it("does not refine when there are no PARTIAL results", async () => {
    const configWithLlm = {
      ...baseConfig,
      attackConfig: { ...baseConfig.attackConfig, enableLlmGeneration: true },
    };

    const previousResults: AttackResult[] = [
      {
        attack: makeSeedAttack(),
        verdict: "FAIL",
        statusCode: 403,
        responseBody: "Forbidden",
        responseTimeMs: 50,
        findings: [],
      },
    ];

    mockChat.mockResolvedValueOnce(JSON.stringify([])); // LLM generation

    const attacks = await planAttacks(
      configWithLlm,
      mockAnalysis,
      [mockModule],
      previousResults,
      2,
    );

    // No seeds on round 2, no LLM generation returned, no partials to refine
    expect(attacks).toHaveLength(0);
    // Only 1 call (generation), no refinement call
    expect(mockChat).toHaveBeenCalledTimes(1);
  });
});
