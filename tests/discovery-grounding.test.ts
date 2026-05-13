import { describe, expect, it } from "vitest";
import { mergeDiscoveryIntelIntoAnalysis } from "../lib/run.js";
import { buildTargetGroundingProfile } from "../lib/target-grounding.js";
import type { CodebaseAnalysis, Config } from "../lib/types.js";
import type { DiscoveryIntel } from "../lib/discovery-round.js";

function config(): Config {
  return {
    target: {
      type: "http_agent",
      baseUrl: "http://localhost:3000",
      agentEndpoint: "/api/chat",
      authEndpoint: "",
      applicationDetails: "Support assistant for customer subscription questions.",
    },
    codebaseGlob: "**/*.ts",
    auth: {
      methods: ["none"],
      jwtSecret: "",
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
      responsePath: "content",
      toolCallsPath: "",
      userInfoPath: "",
      guardrailsPath: "",
    },
    sensitivePatterns: [],
    attackConfig: {
      adaptiveRounds: 1,
      maxAttacksPerCategory: 1,
      concurrency: 1,
      delayBetweenRequestsMs: 0,
      llmProvider: "openai",
      llmModel: "gpt-4o-mini",
      enableLlmGeneration: false,
      maxMultiTurnSteps: 3,
    },
  } as Config;
}

function analysis(): CodebaseAnalysis {
  return {
    tools: [],
    roles: [],
    guardrailPatterns: [],
    sensitiveData: [],
    authMechanisms: [],
    knownWeaknesses: [],
    systemPromptHints: [],
    detectedFrameworks: [],
    toolChains: [],
  };
}

function intel(overrides: Partial<DiscoveryIntel>): DiscoveryIntel {
  return {
    discoveredTools: ["database_query", "email"],
    capabilityEvidence: [],
    claimedCapabilities: [],
    refusedCapabilities: [],
    mentionedCapabilities: [],
    discoveredDataStores: [],
    discoveredPatterns: [],
    architectureHints: [],
    guardrailProfile: [],
    weaknesses: [],
    authMechanisms: [],
    sessionArtifacts: [],
    privilegeBoundaries: [],
    integrationPoints: ["Slack"],
    dataFlows: [],
    sensitiveDataClasses: [],
    fileHandlingSurfaces: [],
    inputParsers: [],
    configSources: [],
    secretHandlingLocations: [],
    detectionGaps: [],
    featureFlags: [],
    defaultAssumptions: [],
    unknowns: [],
    targetSurfaces: [],
    attackObjectives: [],
    promptManipulationSurfaces: [],
    jailbreakRiskCategories: [],
    systemPromptExposureSignals: [],
    retrievalAttackSurfaces: [],
    memoryAttackSurfaces: [],
    toolUseAttackSurfaces: [],
    agenticFailureModes: [],
    privacyAndLeakageRisks: [],
    unsafeCapabilityAreas: [],
    deceptionAndManipulationRisks: [],
    boundaryConditions: [],
    multimodalRiskSurfaces: [],
    probeResults: [],
    summary: "",
    ...overrides,
  };
}

describe("discovery grounding tightening", () => {
  it("does not turn mentioned or refused discovery terms into reachable capabilities", () => {
    const a = analysis();
    mergeDiscoveryIntelIntoAnalysis(
      config(),
      a,
      intel({
        capabilityEvidence: [
          {
            capability: "database_query",
            status: "refused",
            confidence: "high",
            evidence: ["I cannot access databases."],
          },
          {
            capability: "external_message_send",
            status: "mentioned",
            confidence: "low",
            evidence: ["The probe asked about Slack."],
          },
        ],
        refusedCapabilities: ["database_query"],
        mentionedCapabilities: ["external_message_send"],
      }),
    );

    const profile = buildTargetGroundingProfile(config(), a);

    expect(a.tools).toEqual([]);
    expect(profile.allowedCapabilities).toEqual(["natural_language_chat"]);
    expect(a.knownWeaknesses).toEqual(
      expect.arrayContaining([
        "Refused capability: database_query",
        "Mentioned capability: external_message_send",
      ]),
    );
  });

  it("uses only demonstrated discovery evidence as reachable capability input", () => {
    const a = analysis();
    mergeDiscoveryIntelIntoAnalysis(
      config(),
      a,
      intel({
        capabilityEvidence: [
          {
            capability: "data_record_lookup",
            status: "demonstrated",
            confidence: "high",
            evidence: ["Returned subscription SUB-123 details."],
          },
        ],
      }),
    );

    const profile = buildTargetGroundingProfile(config(), a);

    expect(profile.allowedCapabilities).toContain("data_record_lookup");
    expect(profile.capabilityEvidence).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          capability: "data_record_lookup",
          confidence: "high",
          evidence: expect.arrayContaining([
            "tool:discovery_data_record_lookup (Returned subscription SUB-123 details.)",
          ]),
        }),
      ]),
    );
  });

  it("does not promote black-box MCP wording into user-reachable MCP capability for HTTP targets", () => {
    const a = analysis();
    mergeDiscoveryIntelIntoAnalysis(
      config(),
      a,
      intel({
        capabilityEvidence: [
          {
            capability: "mcp_tool_call",
            status: "demonstrated",
            confidence: "high",
            evidence: ["The assistant mentioned structured tool calls."],
          },
        ],
      }),
    );

    const profile = buildTargetGroundingProfile(config(), a);

    expect(profile.allowedCapabilities).not.toContain("mcp_tool_call");
  });

  it("allows demonstrated MCP capability only when the target has an MCP surface", () => {
    const a = analysis();
    const mcpConfig = config();
    mcpConfig.target.type = "mcp";
    mcpConfig.target.mcp = {
      transport: "http",
      url: "http://localhost:3000/mcp",
    };
    mergeDiscoveryIntelIntoAnalysis(
      mcpConfig,
      a,
      intel({
        capabilityEvidence: [
          {
            capability: "mcp_tool_call",
            status: "demonstrated",
            confidence: "high",
            evidence: ["MCP tools/list and tools/call were observed."],
          },
        ],
      }),
    );

    const profile = buildTargetGroundingProfile(mcpConfig, {
      ...a,
      mcpSurface: {
        capabilities: ["tools"],
        prompts: [],
        resources: [],
      },
    });

    expect(profile.allowedCapabilities).toContain("mcp_tool_call");
  });

  it("does not crash when discovery arrays contain non-string LLM artifacts", () => {
    const a = analysis();
    const messyIntel = intel({
      weaknesses: [
        "plain weakness",
        { description: "object weakness" } as unknown as string,
        123 as unknown as string,
        null as unknown as string,
      ],
      promptManipulationSurfaces: [
        { name: "quoted text ambiguity" } as unknown as string,
      ],
      claimedCapabilities: [
        "email_drafting",
        { capability: "api_documentation" } as unknown as string,
      ],
    });

    expect(() =>
      mergeDiscoveryIntelIntoAnalysis(config(), a, messyIntel),
    ).not.toThrow();
    expect(a.knownWeaknesses).toEqual(
      expect.arrayContaining([
        "plain weakness",
        "object weakness",
        "123",
        "quoted text ambiguity",
        "Claimed capability: email_drafting",
        "Claimed capability: api_documentation",
      ]),
    );
  });
});
