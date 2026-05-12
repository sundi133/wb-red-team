import { describe, expect, it } from "vitest";
import {
  buildAdaptiveDiscoveryProbes,
  parseDiscoveryJsonResponse,
} from "../lib/discovery-round.js";
import type { DiscoveryIntel } from "../lib/discovery-round.js";

function intel(overrides: Partial<DiscoveryIntel>): DiscoveryIntel {
  return {
    discoveredTools: [],
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
    integrationPoints: [],
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

describe("discovery response parsing", () => {
  it("parses fenced discovery JSON", () => {
    const parsed = parseDiscoveryJsonResponse(`\`\`\`json
{
  "discovered_tools": ["search_records"],
  "capability_evidence": [],
  "summary": "ok"
}
\`\`\``);

    expect(parsed.discovered_tools).toEqual(["search_records"]);
    expect(parsed.summary).toBe("ok");
  });

  it("extracts the JSON object when the model adds surrounding text", () => {
    const parsed = parseDiscoveryJsonResponse(`Here is the analysis:
{
  "discovered_tools": ["lookup_order"],
  "capability_evidence": [],
  "summary": "done"
}
Thanks`);

    expect(parsed.discovered_tools).toEqual(["lookup_order"]);
  });

  it("preserves parse failures for malformed JSON so the caller can repair", () => {
    expect(() =>
      parseDiscoveryJsonResponse('{"discovered_tools": ["lookup_order" "search_order"]}'),
    ).toThrow();
  });
});

describe("adaptive discovery probes", () => {
  it("builds safe follow-up probes for claimed capabilities", () => {
    const probes = buildAdaptiveDiscoveryProbes(
      intel({
        capabilityEvidence: [
          {
            capability: "data_record_lookup",
            status: "claimed",
            confidence: "medium",
            evidence: ["I can search customer records."],
          },
          {
            capability: "email_drafting",
            status: "mentioned",
            confidence: "low",
            evidence: ["Email drafting was mentioned."],
          },
        ],
      }),
    );

    expect(probes.map((probe) => probe.capability)).toEqual([
      "data_record_lookup",
      "email_drafting",
    ]);
    expect(probes[0].probe).toContain("harmless lookup/search");
    expect(probes[1].probe).toContain("without sending");
  });

  it("does not re-probe demonstrated or only-refused capabilities", () => {
    const probes = buildAdaptiveDiscoveryProbes(
      intel({
        discoveredTools: ["search_records"],
        capabilityEvidence: [
          {
            capability: "data_record_lookup",
            status: "demonstrated",
            confidence: "high",
            evidence: ["Tool returned REC-123."],
          },
          {
            capability: "database_query",
            status: "refused",
            confidence: "high",
            evidence: ["I cannot run SQL queries."],
          },
        ],
        summary: "The agent refused raw database query access.",
      }),
    );

    expect(probes.map((probe) => probe.capability)).not.toContain(
      "data_record_lookup",
    );
    expect(probes.map((probe) => probe.capability)).not.toContain(
      "database_query",
    );
  });

  it("derives follow-up probes from discovered tool and integration hints", () => {
    const probes = buildAdaptiveDiscoveryProbes(
      intel({
        discoveredTools: ["create_support_note", "draft_customer_email"],
        integrationPoints: ["Slack notifications"],
      }),
    );

    expect(probes.map((probe) => probe.capability)).toEqual(
      expect.arrayContaining([
        "internal_message_send",
        "email_drafting",
        "external_message_send",
      ]),
    );
  });
});
