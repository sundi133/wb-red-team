/**
 * Extracted red-team run logic — importable by both CLI (red-team.ts) and API server (dashboard/server.ts).
 */

import { loadConfigFromObject } from "./config-loader.js";
import { describeTarget, getTargetAdapter } from "./target-adapter.js";
import { analyzeCodebase } from "./codebase-analyzer.js";
import { planAttacks, refinePartialAttacks } from "./attack-planner.js";
import {
  preAuthenticate,
  executeAttack,
  executeMultiTurn,
  executeAdaptiveMultiTurn,
  executeRapidFire,
  sleep,
} from "./attack-runner.js";
import { analyzeResponse, type AppContext } from "./response-analyzer.js";
import {
  generateReport,
  writeReport,
} from "./report-generator.js";
import { runStaticAnalysis } from "./static-analyzer.js";
import { analyzeRound } from "./round-analyzer.js";
import { generateIdealResponse } from "./ideal-response-generator.js";
import {
  loadCustomAttacksFromConfig,
  mergeCustomAttacksForRound,
} from "./custom-attacks-loader.js";
import { generateAppTailoredCustomAttacks } from "./app-tailored-custom-prompts.js";
import {
  runDiscoveryRound,
  applyDiscoveryIntel,
} from "./discovery-round.js";
import type {
  AttackModule,
  Attack,
  AttackResult,
  AttackCategory,
  CategoryDefenseProfile,
  CodebaseAnalysis,
  Config,
  Report,
  RoundResult,
} from "./types.js";

// Attack module imports
import { authBypassModule } from "../attacks/auth-bypass.js";
import { rbacBypassModule } from "../attacks/rbac-bypass.js";
import { promptInjectionModule } from "../attacks/prompt-injection.js";
import { outputEvasionModule } from "../attacks/output-evasion.js";
import { dataExfiltrationModule } from "../attacks/data-exfiltration.js";
import { rateLimitModule } from "../attacks/rate-limit.js";
import { sensitiveDataModule } from "../attacks/sensitive-data.js";
import { indirectPromptInjectionModule } from "../attacks/indirect-prompt-injection.js";
import { steganographicExfiltrationModule } from "../attacks/steganographic-exfiltration.js";
import { outOfBandExfiltrationModule } from "../attacks/out-of-band-exfiltration.js";
import { trainingDataExtractionModule } from "../attacks/training-data-extraction.js";
import { sideChannelInferenceModule } from "../attacks/side-channel-inference.js";
import { toolMisuseModule } from "../attacks/tool-misuse.js";
import { rogueAgentModule } from "../attacks/rogue-agent.js";
import { goalHijackModule } from "../attacks/goal-hijack.js";
import { identityPrivilegeModule } from "../attacks/identity-privilege.js";
import { unexpectedCodeExecModule } from "../attacks/unexpected-code-exec.js";
import { cascadingFailureModule } from "../attacks/cascading-failure.js";
import { multiAgentDelegationModule } from "../attacks/multi-agent-delegation.js";
import { memoryPoisoningModule } from "../attacks/memory-poisoning.js";
import { toolOutputManipulationModule } from "../attacks/tool-output-manipulation.js";
import { guardrailTimingModule } from "../attacks/guardrail-timing.js";
import { multiTurnEscalationModule } from "../attacks/multi-turn-escalation.js";
import { conversationManipulationModule } from "../attacks/conversation-manipulation.js";
import { contextWindowAttackModule } from "../attacks/context-window-attack.js";
import { slowBurnExfiltrationModule } from "../attacks/slow-burn-exfiltration.js";
import { brandReputationModule } from "../attacks/brand-reputation.js";
import { competitorEndorsementModule } from "../attacks/competitor-endorsement.js";
import { toxicContentModule } from "../attacks/toxic-content.js";
import { misinformationModule } from "../attacks/misinformation.js";
import { piiDisclosureModule } from "../attacks/pii-disclosure.js";
import { regulatoryViolationModule } from "../attacks/regulatory-violation.js";
import { copyrightInfringementModule } from "../attacks/copyright-infringement.js";
import { consentBypassModule } from "../attacks/consent-bypass.js";
import { sessionHijackingModule } from "../attacks/session-hijacking.js";
import { crossTenantAccessModule } from "../attacks/cross-tenant-access.js";
import { apiAbuseModule } from "../attacks/api-abuse.js";
import { supplyChainModule } from "../attacks/supply-chain.js";
import { socialEngineeringModule } from "../attacks/social-engineering.js";
import { harmfulAdviceModule } from "../attacks/harmful-advice.js";
import { biasExploitationModule } from "../attacks/bias-exploitation.js";
import { contentFilterBypassModule } from "../attacks/content-filter-bypass.js";
import { agenticWorkflowBypassModule } from "../attacks/agentic-workflow-bypass.js";
import { toolChainHijackModule } from "../attacks/tool-chain-hijack.js";
import { agentReflectionExploitModule } from "../attacks/agent-reflection-exploit.js";
import { crossSessionInjectionModule } from "../attacks/cross-session-injection.js";
import { drugSynthesisModule } from "../attacks/drug-synthesis.js";
import { weaponsViolenceModule } from "../attacks/weapons-violence.js";
import { financialCrimeModule } from "../attacks/financial-crime.js";
import { cyberCrimeModule } from "../attacks/cyber-crime.js";
import { csamMinorSafetyModule } from "../attacks/csam-minor-safety.js";
import { fakeQuotesMisinfoModule } from "../attacks/fake-quotes-misinfo.js";
import { competitorSabotageModule } from "../attacks/competitor-sabotage.js";
import { defamationHarassmentModule } from "../attacks/defamation-harassment.js";
import { brandImpersonationModule } from "../attacks/brand-impersonation.js";
import { hateSpeechDogwhistleModule } from "../attacks/hate-speech-dogwhistle.js";
import { radicalizationContentModule } from "../attacks/radicalization-content.js";
import { targetedHarassmentModule } from "../attacks/targeted-harassment.js";
import { influenceOperationsModule } from "../attacks/influence-operations.js";
import { psychologicalManipulationModule } from "../attacks/psychological-manipulation.js";
import { deceptiveMisinfoModule } from "../attacks/deceptive-misinfo.js";
import { hallucinationModule } from "../attacks/hallucination.js";
import { overrelianceModule } from "../attacks/overreliance.js";
import { overRefusalModule } from "../attacks/over-refusal.js";
import { ragPoisoningModule } from "../attacks/rag-poisoning.js";
import { ragAttributionModule } from "../attacks/rag-attribution.js";
import { modelExtractionModule } from "../attacks/model-extraction.js";
import { membershipInferenceModule } from "../attacks/membership-inference.js";
import { backdoorTriggerModule } from "../attacks/backdoor-trigger.js";
import { dataPoisoningModule } from "../attacks/data-poisoning.js";
import { gradientLeakageModule } from "../attacks/gradient-leakage.js";
import { modelInversionModule } from "../attacks/model-inversion.js";
import { ragCorpusPoisoningModule } from "../attacks/rag-corpus-poisoning.js";
import { retrievalRankingAttackModule } from "../attacks/retrieval-ranking-attack.js";
import { vectorStoreManipulationModule } from "../attacks/vector-store-manipulation.js";
import { chunkBoundaryInjectionModule } from "../attacks/chunk-boundary-injection.js";
import { embeddingInversionModule } from "../attacks/embedding-inversion.js";
import { structuredOutputInjectionModule } from "../attacks/structured-output-injection.js";
import { generatedCodeRceModule } from "../attacks/generated-code-rce.js";
import { markdownLinkInjectionModule } from "../attacks/markdown-link-injection.js";
import { sycophancyExploitationModule } from "../attacks/sycophancy-exploitation.js";
import { hallucinationInducementModule } from "../attacks/hallucination-inducement.js";
import { formatConfusionAttackModule } from "../attacks/format-confusion-attack.js";
import { modelDosModule } from "../attacks/model-dos.js";
import { tokenFloodingDosModule } from "../attacks/token-flooding-dos.js";
import { infiniteLoopAgentModule } from "../attacks/infinite-loop-agent.js";
import { quotaExhaustionAttackModule } from "../attacks/quota-exhaustion-attack.js";
import { inferenceAttackModule } from "../attacks/inference-attack.js";
import { reIdentificationModule } from "../attacks/re-identification.js";
import { linkageAttackModule } from "../attacks/linkage-attack.js";
import { differentialPrivacyViolationModule } from "../attacks/differential-privacy-violation.js";
import { logicBombConditionalModule } from "../attacks/logic-bomb-conditional.js";
import { agenticLegalCommitmentModule } from "../attacks/agentic-legal-commitment.js";
import { contextualIntegrityViolationModule } from "../attacks/contextual-integrity-violation.js";
import { financialFraudFacilitationModule } from "../attacks/financial-fraud-facilitation.js";
import { gdprErasureBypassModule } from "../attacks/gdpr-erasure-bypass.js";
import { mcpServerCompromiseModule } from "../attacks/mcp-server-compromise.js";
import { pluginManifestSpoofingModule } from "../attacks/plugin-manifest-spoofing.js";
import { sdkDependencyAttackModule } from "../attacks/sdk-dependency-attack.js";
import { fineTuningDataInjectionModule } from "../attacks/fine-tuning-data-injection.js";
import { promptTemplateInjectionModule } from "../attacks/prompt-template-injection.js";
import { debugAccessModule } from "../attacks/debug-access.js";
import { shellInjectionModule } from "../attacks/shell-injection.js";
import { sqlInjectionModule } from "../attacks/sql-injection.js";
import { unauthorizedCommitmentsModule } from "../attacks/unauthorized-commitments.js";
import { offTopicModule } from "../attacks/off-topic.js";
import { divergentRepetitionModule } from "../attacks/divergent-repetition.js";
import { modelFingerprintingModule } from "../attacks/model-fingerprinting.js";
import { specialTokenInjectionModule } from "../attacks/special-token-injection.js";
import { crossLingualAttackModule } from "../attacks/cross-lingual-attack.js";
import { medicalSafetyModule } from "../attacks/medical-safety.js";
import { financialComplianceModule } from "../attacks/financial-compliance.js";
import { pharmacySafetyModule } from "../attacks/pharmacy-safety.js";
import { insuranceComplianceModule } from "../attacks/insurance-compliance.js";
import { ecommerceSecurityModule } from "../attacks/ecommerce-security.js";
import { telecomComplianceModule } from "../attacks/telecom-compliance.js";
import { housingDiscriminationModule } from "../attacks/housing-discrimination.js";
import { ssrfModule } from "../attacks/ssrf.js";
import { pathTraversalModule } from "../attacks/path-traversal.js";
import { insecureOutputHandlingModule } from "../attacks/insecure-output-handling.js";
import { multimodalGhostInjectionModule } from "../attacks/multimodal-ghost-injection.js";
import { graphConsensusPoisoningModule } from "../attacks/graph-consensus-poisoning.js";
import { interAgentProtocolAbuseModule } from "../attacks/inter-agent-protocol-abuse.js";
import { mcpToolNamespaceCollisionModule } from "../attacks/mcp-tool-namespace-collision.js";
import { computerUseInjectionModule } from "../attacks/computer-use-injection.js";
import { streamingVoiceInjectionModule } from "../attacks/streaming-voice-injection.js";
import { crossModalConflictModule } from "../attacks/cross-modal-conflict.js";
import { llmJudgeManipulationModule } from "../attacks/llm-judge-manipulation.js";
import { retrievalTenantBleedModule } from "../attacks/retrieval-tenant-bleed.js";
import { mcpToolMisuseModule } from "../attacks-mcp/mcp-tool-misuse.js";
import { mcpDataExfiltrationModule } from "../attacks-mcp/mcp-data-exfiltration.js";
import { mcpIndirectPromptInjectionModule } from "../attacks-mcp/mcp-indirect-prompt-injection.js";
import { mcpPathTraversalModule } from "../attacks-mcp/mcp-path-traversal.js";
import { mcpSsrfModule } from "../attacks-mcp/mcp-ssrf.js";
import { mcpCrossTenantAccessModule } from "../attacks-mcp/mcp-cross-tenant-access.js";
import { mcpDebugAccessModule } from "../attacks-mcp/mcp-debug-access.js";
import { apiSpecificAttackModule } from "../attacks/api-specific-attack.js";
import { sandboxEscapeModule } from "../attacks/sandbox-escape.js";
import { toolPermissionEscalationModule } from "../attacks/tool-permission-escalation.js";
import { alignmentFakingModule } from "../attacks/alignment-faking.js";
import { capabilityElicitationModule } from "../attacks/capability-elicitation.js";
import { instructionHierarchyViolationModule } from "../attacks/instruction-hierarchy-violation.js";
import { agenticScopeCreepModule } from "../attacks/agentic-scope-creep.js";
import { statePersistenceAttackModule } from "../attacks/state-persistence-attack.js";
import { encodingSerializationAttackModule } from "../attacks/encoding-serialization-attack.js";
import { multiHopReasoningExploitModule } from "../attacks/multi-hop-reasoning-exploit.js";
import { emotionalManipulationModule } from "../attacks/emotional-manipulation.js";

export const ALL_MODULES: AttackModule[] = [
  authBypassModule, rbacBypassModule, promptInjectionModule, outputEvasionModule,
  dataExfiltrationModule, rateLimitModule, sensitiveDataModule,
  indirectPromptInjectionModule, steganographicExfiltrationModule,
  outOfBandExfiltrationModule, trainingDataExtractionModule,
  sideChannelInferenceModule, toolMisuseModule, rogueAgentModule,
  goalHijackModule, identityPrivilegeModule, unexpectedCodeExecModule,
  cascadingFailureModule, multiAgentDelegationModule, memoryPoisoningModule,
  toolOutputManipulationModule, guardrailTimingModule, multiTurnEscalationModule,
  conversationManipulationModule, contextWindowAttackModule,
  slowBurnExfiltrationModule, brandReputationModule, competitorEndorsementModule,
  toxicContentModule, misinformationModule, piiDisclosureModule,
  regulatoryViolationModule, copyrightInfringementModule, consentBypassModule,
  sessionHijackingModule, crossTenantAccessModule, apiAbuseModule,
  supplyChainModule, socialEngineeringModule, harmfulAdviceModule,
  biasExploitationModule, contentFilterBypassModule, agenticWorkflowBypassModule,
  toolChainHijackModule, agentReflectionExploitModule, crossSessionInjectionModule,
  drugSynthesisModule, weaponsViolenceModule, financialCrimeModule,
  cyberCrimeModule, csamMinorSafetyModule, fakeQuotesMisinfoModule,
  competitorSabotageModule, defamationHarassmentModule, brandImpersonationModule,
  hateSpeechDogwhistleModule, radicalizationContentModule,
  targetedHarassmentModule, influenceOperationsModule,
  psychologicalManipulationModule, deceptiveMisinfoModule, hallucinationModule,
  overrelianceModule, overRefusalModule, ragPoisoningModule, ragAttributionModule,
  modelExtractionModule, membershipInferenceModule, backdoorTriggerModule,
  dataPoisoningModule, gradientLeakageModule, modelInversionModule,
  ragCorpusPoisoningModule, retrievalRankingAttackModule,
  vectorStoreManipulationModule, chunkBoundaryInjectionModule,
  embeddingInversionModule, structuredOutputInjectionModule,
  generatedCodeRceModule, markdownLinkInjectionModule,
  sycophancyExploitationModule, hallucinationInducementModule,
  formatConfusionAttackModule, modelDosModule, tokenFloodingDosModule,
  infiniteLoopAgentModule, quotaExhaustionAttackModule, inferenceAttackModule,
  reIdentificationModule, linkageAttackModule, differentialPrivacyViolationModule,
  logicBombConditionalModule, agenticLegalCommitmentModule,
  contextualIntegrityViolationModule, financialFraudFacilitationModule,
  gdprErasureBypassModule, mcpServerCompromiseModule,
  pluginManifestSpoofingModule, sdkDependencyAttackModule,
  fineTuningDataInjectionModule, promptTemplateInjectionModule, debugAccessModule,
  shellInjectionModule, sqlInjectionModule, unauthorizedCommitmentsModule,
  offTopicModule, divergentRepetitionModule, modelFingerprintingModule,
  specialTokenInjectionModule, crossLingualAttackModule, medicalSafetyModule,
  financialComplianceModule, pharmacySafetyModule, insuranceComplianceModule,
  ecommerceSecurityModule, telecomComplianceModule, housingDiscriminationModule,
  ssrfModule, pathTraversalModule, insecureOutputHandlingModule,
  multimodalGhostInjectionModule, graphConsensusPoisoningModule,
  interAgentProtocolAbuseModule, mcpToolNamespaceCollisionModule,
  computerUseInjectionModule, streamingVoiceInjectionModule,
  crossModalConflictModule, llmJudgeManipulationModule,
  retrievalTenantBleedModule,
  apiSpecificAttackModule,
  sandboxEscapeModule, toolPermissionEscalationModule, alignmentFakingModule,
  capabilityElicitationModule, instructionHierarchyViolationModule,
  agenticScopeCreepModule, statePersistenceAttackModule,
  encodingSerializationAttackModule, multiHopReasoningExploitModule,
  emotionalManipulationModule,
];

export const MCP_MODULES: AttackModule[] = [
  mcpToolMisuseModule, mcpDataExfiltrationModule,
  mcpIndirectPromptInjectionModule, mcpPathTraversalModule, mcpSsrfModule,
  mcpCrossTenantAccessModule, mcpDebugAccessModule,
];

// ── Helper functions ──

function mergeUniqueTool(
  tools: CodebaseAnalysis["tools"],
  nextTool: CodebaseAnalysis["tools"][number],
): void {
  if (
    tools.some(
      (tool) =>
        tool.name === nextTool.name && tool.parameters === nextTool.parameters,
    )
  ) {
    return;
  }
  tools.push(nextTool);
}

export async function enrichAnalysisWithTargetSurface(
  config: Config,
  analysis: CodebaseAnalysis,
  log: (msg: string) => void,
): Promise<void> {
  const adapter = getTargetAdapter(config);
  if (!adapter?.discoverSurface) return;

  try {
    const surface = await adapter.discoverSurface(config);
    if (surface.tools?.length) {
      for (const toolName of surface.tools) {
        mergeUniqueTool(analysis.tools, {
          name: toolName,
          description: "Discovered from MCP surface",
          parameters: "unknown",
        });
      }
    }
    analysis.mcpSurface = {
      serverName: surface.serverName,
      protocolVersion: surface.protocolVersion,
      capabilities: [...(surface.capabilities ?? [])],
      prompts: [...(surface.prompts ?? [])],
      resources: [...(surface.resources ?? [])],
    };

    const notes: string[] = [];
    if (surface.serverName) notes.push(`MCP server name: ${surface.serverName}`);
    if (surface.protocolVersion) notes.push(`MCP protocol version: ${surface.protocolVersion}`);
    if (surface.capabilities?.length) notes.push(`MCP capabilities: ${surface.capabilities.join(", ")}`);
    if (surface.prompts?.length) notes.push(`MCP prompts exposed: ${surface.prompts.join(", ")}`);
    if (surface.resources?.length) notes.push(`MCP resources exposed: ${surface.resources.join(", ")}`);

    for (const note of notes) {
      if (!analysis.knownWeaknesses.includes(note)) {
        analysis.knownWeaknesses.push(note);
      }
    }
  } catch (error) {
    log(`Warning: failed to discover target surface: ${(error as Error).message}`);
  }
}

async function maybeGenerateIdealResponse(
  config: Config,
  result: AttackResult,
): Promise<void> {
  const enabled =
    config.attackConfig.enableIdealResponses ??
    config.attackConfig.enableLlmGeneration;
  if (!enabled) return;
  if (result.verdict !== "PASS" && result.verdict !== "PARTIAL") return;

  const ideal = await generateIdealResponse(config, result);
  if (!ideal) return;

  result.idealResponse = ideal;
}

function getVerdictLabel(verdict: string): string {
  switch (verdict) {
    case "PASS": return "[!!] PASS";
    case "FAIL": return "[OK] FAIL";
    case "PARTIAL": return "[~] PARTIAL";
    default: return "[??] ERROR";
  }
}

// ── Public interface ──

export interface RunProgress {
  phase: string;
  message: string;
  round?: number;
  totalRounds?: number;
  attackIndex?: number;
  totalAttacks?: number;
  /** Included when an attack completes — allows live results rendering */
  result?: {
    category: string;
    name: string;
    description: string;
    severity: string;
    verdict: string;
    findings: string[];
    statusCode: number;
    responseTimeMs: number;
    strategyName?: string;
    llmReasoning?: string;
    payload?: string;
    responsePreview?: string;
    authMethod?: string;
    role?: string;
    conversation?: { stepIndex: number; payload: unknown; statusCode: number; responseBody: unknown; responseTimeMs: number }[];
  };
}

export interface RunResult {
  report: Report;
  jsonPath: string;
  mdPath: string;
}

/**
 * Run the full red-team pipeline. Callable from CLI or API server.
 *
 * @param config - Validated Config object (use loadConfig or loadConfigFromObject)
 * @param onProgress - Optional callback for progress updates
 * @param configDir - Directory for resolving relative paths in config (e.g., customAttacksFile). Defaults to cwd.
 */
export async function runRedTeam(
  config: Config,
  onProgress?: (p: RunProgress) => void,
  configDir?: string,
  signal?: AbortSignal,
): Promise<RunResult> {
  const log = (phase: string, message: string, extra?: Partial<RunProgress>) => {
    onProgress?.({ phase, message, ...extra });
  };

  const checkAbort = () => {
    if (signal?.aborted) throw new Error("Run cancelled");
  };

  const emitResult = (result: AttackResult, extra?: Partial<RunProgress>) => {
    // Extract payload message
    const payload = typeof (result.attack.payload as Record<string, unknown>)?.message === "string"
      ? (result.attack.payload as Record<string, unknown>).message as string
      : JSON.stringify(result.attack.payload);

    // Extract response preview (truncate to 2000 chars)
    let responsePreview = "";
    if (typeof result.responseBody === "string") {
      responsePreview = result.responseBody.slice(0, 2000);
    } else if (result.responseBody) {
      const rb = result.responseBody as Record<string, unknown>;
      responsePreview = typeof rb.response === "string"
        ? (rb.response as string).slice(0, 2000)
        : JSON.stringify(result.responseBody).slice(0, 2000);
    }

    onProgress?.({
      phase: "result",
      message: `${result.attack.category}: ${result.attack.name} → ${result.verdict}`,
      ...extra,
      result: {
        category: result.attack.category,
        name: result.attack.name,
        description: result.attack.description,
        severity: result.attack.severity,
        verdict: result.verdict,
        findings: result.findings,
        statusCode: result.statusCode,
        responseTimeMs: result.responseTimeMs,
        strategyName: result.attack.strategyName,
        llmReasoning: result.llmReasoning,
        payload,
        responsePreview,
        authMethod: result.attack.authMethod,
        role: result.attack.role,
        conversation: result.conversation,
      },
    });
  };

  // Force non-interactive mode (no TTY prompts)
  config.attackConfig.requireReviewConfirmation = false;

  const cDir = configDir ?? process.cwd();

  // 1. Custom attacks
  log("config", "Loading configuration...");
  let customAttacks: Attack[] = [];
  try {
    customAttacks = loadCustomAttacksFromConfig(config, { configDir: cDir });
  } catch (e) {
    log("config", `Custom attacks error: ${(e as Error).message}`);
  }
  if (customAttacks.length > 0) {
    log("config", `Custom attacks loaded: ${customAttacks.length} case(s)`);
  }

  const targetLabel = describeTarget(config);
  log("config", `Target: ${targetLabel}`);

  // Filter modules
  const moduleSet =
    (config.target.type ?? "http_agent") === "mcp" ? MCP_MODULES : ALL_MODULES;
  const enabledSet = config.attackConfig.enabledCategories;
  const activeModules = enabledSet?.length
    ? moduleSet.filter((m) => enabledSet.includes(m.category))
    : moduleSet;

  // 2. Analyze codebase
  checkAbort();
  log("analyze", "Analyzing target codebase...");
  const analysis = await analyzeCodebase(config);
  await enrichAnalysisWithTargetSurface(config, analysis, (msg) => log("analyze", msg));
  log("analyze", `Found ${analysis.tools.length} tools, ${analysis.roles.length} roles`);

  if (Math.max(0, config.attackConfig.appTailoredCustomPromptCount ?? 0) > 0) {
    log("analyze", "Generating app-tailored custom prompts from analysis...");
    const generated = await generateAppTailoredCustomAttacks(config, analysis);
    if (generated.length > 0) {
      log("analyze", `App-tailored custom cases: ${generated.length}`);
      customAttacks = [...customAttacks, ...generated];
    }
  }

  // Category applicability gating
  const skipIrrelevant =
    (config.target.type ?? "http_agent") === "mcp"
      ? false
      : (config.attackConfig.skipIrrelevantCategories ?? true);
  let relevantModules = activeModules;
  if (
    skipIrrelevant &&
    analysis.affectedFiles &&
    Object.keys(analysis.affectedFiles).length > 0
  ) {
    const before = relevantModules.length;
    relevantModules = relevantModules.filter((m) => {
      const files = analysis.affectedFiles?.[m.category];
      return files && files.length > 0;
    });
    const skipped = before - relevantModules.length;
    if (skipped > 0) {
      log("analyze", `Applicability gating: skipped ${skipped} categories with no relevant source files`);
    }
  }

  const appContext: AppContext = {
    tools: analysis.tools,
    roles: analysis.roles,
    systemPromptHints: analysis.systemPromptHints,
  };

  // 2.5. Static analysis
  let staticResult;
  if (config.codebasePath) {
    log("static", "Running static analysis...");
    staticResult = await runStaticAnalysis(config);
    log("static", `Checked ${staticResult.checkedFiles} files, found ${staticResult.findings.length} issues (score: ${staticResult.score}/100)`);
  }

  // 3. Pre-authenticate
  checkAbort();
  log("auth", "Pre-authenticating...");
  await preAuthenticate(config);

  // 3.5. Discovery round
  let discoveryIntel: Report["discovery"] | undefined;
  if (config.attackConfig.enableDiscovery) {
    log("discovery", "Running discovery round...");
    const intel = await runDiscoveryRound(config);
    applyDiscoveryIntel(config, intel);
    discoveryIntel = {
      discoveredTools: intel.discoveredTools,
      discoveredDataStores: intel.discoveredDataStores,
      discoveredPatterns: intel.discoveredPatterns,
      architectureHints: intel.architectureHints,
      guardrailProfile: intel.guardrailProfile,
      weaknesses: intel.weaknesses,
      authMechanisms: intel.authMechanisms,
      sessionArtifacts: intel.sessionArtifacts,
      privilegeBoundaries: intel.privilegeBoundaries,
      integrationPoints: intel.integrationPoints,
      dataFlows: intel.dataFlows,
      sensitiveDataClasses: intel.sensitiveDataClasses,
      fileHandlingSurfaces: intel.fileHandlingSurfaces,
      inputParsers: intel.inputParsers,
      configSources: intel.configSources,
      secretHandlingLocations: intel.secretHandlingLocations,
      detectionGaps: intel.detectionGaps,
      featureFlags: intel.featureFlags,
      defaultAssumptions: intel.defaultAssumptions,
      unknowns: intel.unknowns,
      targetSurfaces: intel.targetSurfaces,
      attackObjectives: intel.attackObjectives,
      promptManipulationSurfaces: intel.promptManipulationSurfaces,
      jailbreakRiskCategories: intel.jailbreakRiskCategories,
      systemPromptExposureSignals: intel.systemPromptExposureSignals,
      retrievalAttackSurfaces: intel.retrievalAttackSurfaces,
      memoryAttackSurfaces: intel.memoryAttackSurfaces,
      toolUseAttackSurfaces: intel.toolUseAttackSurfaces,
      agenticFailureModes: intel.agenticFailureModes,
      privacyAndLeakageRisks: intel.privacyAndLeakageRisks,
      unsafeCapabilityAreas: intel.unsafeCapabilityAreas,
      deceptionAndManipulationRisks: intel.deceptionAndManipulationRisks,
      boundaryConditions: intel.boundaryConditions,
      multimodalRiskSurfaces: intel.multimodalRiskSurfaces,
      summary: intel.summary,
      probeCount: intel.probeResults.length,
    };
    log("discovery", `Discovery complete: ${intel.discoveredTools.length} tools, ${intel.discoveredDataStores.length} data stores, ${intel.weaknesses.length} weaknesses`);
  }

  // 4. Run adaptive attack rounds
  checkAbort();
  log("attacks", "Running attacks...");
  const rounds: RoundResult[] = [];
  let allPreviousResults: AttackResult[] = [];
  let defenseProfiles: Map<AttackCategory, CategoryDefenseProfile> | undefined;

  for (let round = 1; round <= config.attackConfig.adaptiveRounds; round++) {
    log("attacks", `Round ${round}/${config.attackConfig.adaptiveRounds}`, {
      round,
      totalRounds: config.attackConfig.adaptiveRounds,
    });

    const skipBuiltinPlanner =
      round === 1 &&
      config.attackConfig.customAttacksOnly === true &&
      customAttacks.length > 0;

    const planned = skipBuiltinPlanner
      ? []
      : await planAttacks(
          config,
          analysis,
          relevantModules,
          allPreviousResults,
          round,
          defenseProfiles,
        );
    const attacks = mergeCustomAttacksForRound(config, round, planned, customAttacks);
    log("attacks", `Round ${round}: planned ${attacks.length} attacks`, {
      round,
      totalRounds: config.attackConfig.adaptiveRounds,
      totalAttacks: attacks.length,
    });

    const roundResults: AttackResult[] = [];

    for (let i = 0; i < attacks.length; i++) {
      checkAbort();
      const attack = attacks[i];
      const progressExtra = {
        round,
        totalRounds: config.attackConfig.adaptiveRounds,
        attackIndex: i + 1,
        totalAttacks: attacks.length,
      };

      // Rate-limit rapid-fire attacks
      const rapidFire = (attack.payload as Record<string, unknown>)
        ._rapidFire as number | undefined;
      if (rapidFire && attack.category === "rate_limit") {
        log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} (${rapidFire}x rapid-fire)...`, progressExtra);
        const cleanPayload = { ...attack.payload };
        delete (cleanPayload as Record<string, unknown>)._rapidFire;
        const cleanAttack = { ...attack, payload: cleanPayload };

        const responses = await executeRapidFire(config, cleanAttack, rapidFire);
        const got429 = responses.some((r) => r.statusCode === 429);
        const allOk = responses.every((r) => r.statusCode === 200);
        const lastResponse = responses[responses.length - 1];

        const result = await analyzeResponse(
          config, attack, lastResponse.statusCode, lastResponse.body,
          lastResponse.timeMs, appContext, lastResponse.executionTrace,
        );

        if (!got429 && allOk) {
          result.verdict = "PASS";
          result.findings.push(`All ${rapidFire} requests succeeded — rate limit not enforced`);
        } else if (got429) {
          result.verdict = "FAIL";
          result.findings.push(
            `Rate limit correctly enforced — got 429 after ${responses.filter((r) => r.statusCode === 200).length} requests`,
          );
        }

        log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} → ${getVerdictLabel(result.verdict)}`, progressExtra);
        await maybeGenerateIdealResponse(config, result);
        roundResults.push(result);
        emitResult(result, progressExtra);
        continue;
      }

      try {
        if (attack.steps && attack.steps.length > 0) {
          // Multi-turn attack (predefined steps)
          log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} (${1 + attack.steps.length} steps)...`, progressExtra);

          const { results: stepResults, stoppedEarly } = await executeMultiTurn(
            config, attack,
            async (cfg, atk, sc, b, t) => {
              const r = await analyzeResponse(cfg, atk, sc, b, t, appContext);
              return { verdict: r.verdict, findings: r.findings };
            },
          );
        } else if (
          config.attackConfig.enableAdaptiveMultiTurn &&
          config.attackConfig.enableMultiTurnGeneration
        ) {
          // Adaptive multi-turn attack
          const maxTurns = config.attackConfig.maxAdaptiveTurns ?? 15;
          log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} (adaptive, max ${maxTurns} turns)...`, progressExtra);

          const {
            results: stepResults,
            stoppedEarly,
            conversationHistory,
          } = await executeAdaptiveMultiTurn(
            config, attack,
            async (cfg, atk, sc, b, t) => {
              const r = await analyzeResponse(cfg, atk, sc, b, t, appContext);
              return { verdict: r.verdict, findings: r.findings };
            },
          );

          const lastStep = stepResults[stepResults.length - 1];
          const result = await analyzeResponse(
            config, attack, lastStep.statusCode, lastStep.body,
            lastStep.timeMs, appContext, lastStep.executionTrace,
          );
          result.stepIndex = lastStep.stepIndex;
          result.totalSteps = stepResults.length;

          result.conversation = conversationHistory.map((ch) => ({
            stepIndex: ch.stepIndex,
            payload: { message: ch.userMessage },
            statusCode: stepResults[ch.stepIndex]?.statusCode ?? 0,
            responseBody: ch.aiResponse,
            responseTimeMs: stepResults[ch.stepIndex]?.timeMs ?? 0,
          }));

          log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} → ${getVerdictLabel(result.verdict)} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${stoppedEarly ? ` (stopped early)` : ""}`, progressExtra);
          await maybeGenerateIdealResponse(config, result);
          roundResults.push(result);
          emitResult(result, progressExtra);
        } else {
          // Single-turn attack
          log("attacks", `[${i + 1}/${attacks.length}] ${attack.name}...`, progressExtra);
          const { statusCode, body, timeMs, executionTrace } =
            await executeAttack(config, attack);
          const result = await analyzeResponse(
            config, attack, statusCode, body, timeMs, appContext, executionTrace,
          );

          log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} → ${getVerdictLabel(result.verdict)} (${statusCode}, ${timeMs}ms)`, progressExtra);
          await maybeGenerateIdealResponse(config, result);
          roundResults.push(result);
          emitResult(result, progressExtra);
        }
      } catch (attackErr) {
        log("attacks", `[${i + 1}/${attacks.length}] ${attack.name} → ERROR: ${attackErr instanceof Error ? attackErr.message : String(attackErr)}`, progressExtra);
        const errResult: AttackResult = {
          attack,
          statusCode: 0,
          responseBody: "",
          responseTimeMs: 0,
          verdict: "ERROR" as const,
          findings: [
            `Attack execution failed: ${attackErr instanceof Error ? attackErr.message : String(attackErr)}`,
          ],
        };
        roundResults.push(errResult);
        emitResult(errResult, progressExtra);
      }

      if (config.attackConfig.delayBetweenRequestsMs > 0) {
        await sleep(config.attackConfig.delayBetweenRequestsMs);
      }
    }

    // Refinement pass
    const roundPartials = roundResults.filter((r) => r.verdict === "PARTIAL");
    if (roundPartials.length > 0 && config.attackConfig.enableLlmGeneration) {
      log("refine", `Refining ${roundPartials.length} PARTIAL results...`, { round });
      const refinedAttacks = await refinePartialAttacks(config, analysis, roundResults, round);

      if (refinedAttacks.length > 0) {
        log("refine", `Executing ${refinedAttacks.length} refined attacks`, { round });

        for (let i = 0; i < refinedAttacks.length; i++) {
          const attack = refinedAttacks[i];
          const progressExtra = { round, attackIndex: i + 1, totalAttacks: refinedAttacks.length };

          try {
            if (attack.steps && attack.steps.length > 0) {
              const { results: stepResults, stoppedEarly } = await executeMultiTurn(
                config, attack,
                async (cfg, atk, sc, b, t) => {
                  const r = await analyzeResponse(cfg, atk, sc, b, t, appContext);
                  return { verdict: r.verdict, findings: r.findings };
                },
              );
            } else if (
              config.attackConfig.enableAdaptiveMultiTurn &&
              config.attackConfig.enableMultiTurnGeneration
            ) {
              const maxTurns = config.attackConfig.maxAdaptiveTurns ?? 15;
              const {
                results: stepResults,
                stoppedEarly,
                conversationHistory,
              } = await executeAdaptiveMultiTurn(
                config, attack,
                async (cfg, atk, sc, b, t) => {
                  const r = await analyzeResponse(cfg, atk, sc, b, t, appContext);
                  return { verdict: r.verdict, findings: r.findings };
                },
              );

              const lastStep = stepResults[stepResults.length - 1];
              const result = await analyzeResponse(
                config, attack, lastStep.statusCode, lastStep.body,
                lastStep.timeMs, appContext, lastStep.executionTrace,
              );
              result.stepIndex = lastStep.stepIndex;
              result.totalSteps = stepResults.length;

              if (attack.steps && attack.steps.length > 0) {
                result.conversation = stepResults.map((sr) => ({
                  stepIndex: sr.stepIndex,
                  payload: sr.stepIndex === 0
                    ? attack.payload
                    : (attack.steps?.[sr.stepIndex - 1]?.payload ?? {}),
                  statusCode: sr.statusCode,
                  responseBody: sr.body,
                  responseTimeMs: sr.timeMs,
                }));
              } else {
                result.conversation = conversationHistory.map((ch) => ({
                  stepIndex: ch.stepIndex,
                  payload: { message: ch.userMessage },
                  statusCode: stepResults[ch.stepIndex]?.statusCode ?? 0,
                  responseBody: ch.aiResponse,
                  responseTimeMs: stepResults[ch.stepIndex]?.timeMs ?? 0,
                }));
              }

              log("refine", `[R${i + 1}/${refinedAttacks.length}] ${attack.name} → ${getVerdictLabel(result.verdict)}`, progressExtra);
              await maybeGenerateIdealResponse(config, result);
              roundResults.push(result);
              emitResult(result, progressExtra);
            } else {
              const { statusCode, body, timeMs, executionTrace } =
                await executeAttack(config, attack);
              const result = await analyzeResponse(
                config, attack, statusCode, body, timeMs, appContext, executionTrace,
              );

              log("refine", `[R${i + 1}/${refinedAttacks.length}] ${attack.name} → ${getVerdictLabel(result.verdict)}`, progressExtra);
              await maybeGenerateIdealResponse(config, result);
              roundResults.push(result);
              emitResult(result, progressExtra);
            }
          } catch (refineErr) {
            log("refine", `[R${i + 1}/${refinedAttacks.length}] ${attack.name} → ERROR: ${refineErr instanceof Error ? refineErr.message : String(refineErr)}`, progressExtra);
            const errResult: AttackResult = {
              attack,
              statusCode: 0,
              responseBody: "",
              responseTimeMs: 0,
              verdict: "ERROR" as const,
              findings: [
                `Refined attack execution failed: ${refineErr instanceof Error ? refineErr.message : String(refineErr)}`,
              ],
            };
            roundResults.push(errResult);
            emitResult(errResult, progressExtra);
          }

          if (config.attackConfig.delayBetweenRequestsMs > 0) {
            await sleep(config.attackConfig.delayBetweenRequestsMs);
          }
        }
      }
    }

    rounds.push({ round, results: roundResults });
    allPreviousResults = allPreviousResults.concat(roundResults);

    const passCount = roundResults.filter((r) => r.verdict === "PASS").length;
    const failCount = roundResults.filter((r) => r.verdict === "FAIL").length;
    log("attacks", `Round ${round}: ${passCount} vulns found, ${failCount} blocked`, { round });

    if (round < config.attackConfig.adaptiveRounds) {
      defenseProfiles = analyzeRound(roundResults, config, defenseProfiles);
    }
  }

  // 5. Generate report
  log("report", "Generating report...");
  const targetUrl = targetLabel;
  const report = generateReport(
    targetUrl,
    rounds,
    staticResult,
    analysis.affectedFiles,
    discoveryIntel,
  );
  // Skip file write when DB is configured (server stores to DB instead)
  let jsonPath = "";
  let mdPath = "";
  if (!process.env.DATABASE_URL) {
    const paths = writeReport(report);
    jsonPath = paths.jsonPath;
    mdPath = paths.mdPath;
    log("report", `Report written: ${jsonPath}`);
  } else {
    log("report", "Report generated (stored in database)");
  }

  return { report, jsonPath, mdPath };
}
