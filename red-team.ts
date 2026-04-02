#!/usr/bin/env npx tsx

import { createInterface } from "node:readline/promises";
import { loadEnvFile } from "./lib/env-loader.js";
import { loadConfig } from "./lib/config-loader.js";
import { describeTarget, getTargetAdapter } from "./lib/target-adapter.js";
import { analyzeCodebase } from "./lib/codebase-analyzer.js";
import { planAttacks, refinePartialAttacks } from "./lib/attack-planner.js";
import {
  preAuthenticate,
  executeAttack,
  executeMultiTurn,
  executeRapidFire,
  sleep,
} from "./lib/attack-runner.js";
import { analyzeResponse, type AppContext } from "./lib/response-analyzer.js";
import {
  generateReport,
  writeReport,
  printConsoleSummary,
} from "./lib/report-generator.js";
import { runStaticAnalysis } from "./lib/static-analyzer.js";
import { analyzeRound } from "./lib/round-analyzer.js";
import { generateIdealResponse } from "./lib/ideal-response-generator.js";
import type {
  AttackModule,
  Attack,
  AttackResult,
  AttackCategory,
  CategoryDefenseProfile,
  CodebaseAnalysis,
  Config,
  RoundResult,
} from "./lib/types.js";

// Import attack modules
import { authBypassModule } from "./attacks/auth-bypass.js";
import { rbacBypassModule } from "./attacks/rbac-bypass.js";
import { promptInjectionModule } from "./attacks/prompt-injection.js";
import { outputEvasionModule } from "./attacks/output-evasion.js";
import { dataExfiltrationModule } from "./attacks/data-exfiltration.js";
import { rateLimitModule } from "./attacks/rate-limit.js";
import { sensitiveDataModule } from "./attacks/sensitive-data.js";
import { indirectPromptInjectionModule } from "./attacks/indirect-prompt-injection.js";
import { steganographicExfiltrationModule } from "./attacks/steganographic-exfiltration.js";
import { outOfBandExfiltrationModule } from "./attacks/out-of-band-exfiltration.js";
import { trainingDataExtractionModule } from "./attacks/training-data-extraction.js";
import { sideChannelInferenceModule } from "./attacks/side-channel-inference.js";
import { toolMisuseModule } from "./attacks/tool-misuse.js";
import { rogueAgentModule } from "./attacks/rogue-agent.js";
import { goalHijackModule } from "./attacks/goal-hijack.js";
import { identityPrivilegeModule } from "./attacks/identity-privilege.js";
import { unexpectedCodeExecModule } from "./attacks/unexpected-code-exec.js";
import { cascadingFailureModule } from "./attacks/cascading-failure.js";
import { multiAgentDelegationModule } from "./attacks/multi-agent-delegation.js";
import { memoryPoisoningModule } from "./attacks/memory-poisoning.js";
import { toolOutputManipulationModule } from "./attacks/tool-output-manipulation.js";
import { guardrailTimingModule } from "./attacks/guardrail-timing.js";
import { multiTurnEscalationModule } from "./attacks/multi-turn-escalation.js";
import { conversationManipulationModule } from "./attacks/conversation-manipulation.js";
import { contextWindowAttackModule } from "./attacks/context-window-attack.js";
import { slowBurnExfiltrationModule } from "./attacks/slow-burn-exfiltration.js";
import { brandReputationModule } from "./attacks/brand-reputation.js";
import { competitorEndorsementModule } from "./attacks/competitor-endorsement.js";
import { toxicContentModule } from "./attacks/toxic-content.js";
import { misinformationModule } from "./attacks/misinformation.js";
import { piiDisclosureModule } from "./attacks/pii-disclosure.js";
import { regulatoryViolationModule } from "./attacks/regulatory-violation.js";
import { copyrightInfringementModule } from "./attacks/copyright-infringement.js";
import { consentBypassModule } from "./attacks/consent-bypass.js";
import { sessionHijackingModule } from "./attacks/session-hijacking.js";
import { crossTenantAccessModule } from "./attacks/cross-tenant-access.js";
import { apiAbuseModule } from "./attacks/api-abuse.js";
import { supplyChainModule } from "./attacks/supply-chain.js";
import { socialEngineeringModule } from "./attacks/social-engineering.js";
import { harmfulAdviceModule } from "./attacks/harmful-advice.js";
import { biasExploitationModule } from "./attacks/bias-exploitation.js";
import { contentFilterBypassModule } from "./attacks/content-filter-bypass.js";
import { agenticWorkflowBypassModule } from "./attacks/agentic-workflow-bypass.js";
import { toolChainHijackModule } from "./attacks/tool-chain-hijack.js";
import { agentReflectionExploitModule } from "./attacks/agent-reflection-exploit.js";
import { crossSessionInjectionModule } from "./attacks/cross-session-injection.js";
import { drugSynthesisModule } from "./attacks/drug-synthesis.js";
import { weaponsViolenceModule } from "./attacks/weapons-violence.js";
import { financialCrimeModule } from "./attacks/financial-crime.js";
import { cyberCrimeModule } from "./attacks/cyber-crime.js";
import { csamMinorSafetyModule } from "./attacks/csam-minor-safety.js";
import { fakeQuotesMisinfoModule } from "./attacks/fake-quotes-misinfo.js";
import { competitorSabotageModule } from "./attacks/competitor-sabotage.js";
import { defamationHarassmentModule } from "./attacks/defamation-harassment.js";
import { brandImpersonationModule } from "./attacks/brand-impersonation.js";
import { hateSpeechDogwhistleModule } from "./attacks/hate-speech-dogwhistle.js";
import { radicalizationContentModule } from "./attacks/radicalization-content.js";
import { targetedHarassmentModule } from "./attacks/targeted-harassment.js";
import { influenceOperationsModule } from "./attacks/influence-operations.js";
import { psychologicalManipulationModule } from "./attacks/psychological-manipulation.js";
import { deceptiveMisinfoModule } from "./attacks/deceptive-misinfo.js";
import { hallucinationModule } from "./attacks/hallucination.js";
import { overrelianceModule } from "./attacks/overreliance.js";
import { overRefusalModule } from "./attacks/over-refusal.js";
import { ragPoisoningModule } from "./attacks/rag-poisoning.js";
import { ragAttributionModule } from "./attacks/rag-attribution.js";
import { modelExtractionModule } from "./attacks/model-extraction.js";
import { membershipInferenceModule } from "./attacks/membership-inference.js";
import { backdoorTriggerModule } from "./attacks/backdoor-trigger.js";
import { dataPoisoningModule } from "./attacks/data-poisoning.js";
import { gradientLeakageModule } from "./attacks/gradient-leakage.js";
import { modelInversionModule } from "./attacks/model-inversion.js";
import { ragCorpusPoisoningModule } from "./attacks/rag-corpus-poisoning.js";
import { retrievalRankingAttackModule } from "./attacks/retrieval-ranking-attack.js";
import { vectorStoreManipulationModule } from "./attacks/vector-store-manipulation.js";
import { chunkBoundaryInjectionModule } from "./attacks/chunk-boundary-injection.js";
import { embeddingInversionModule } from "./attacks/embedding-inversion.js";
import { structuredOutputInjectionModule } from "./attacks/structured-output-injection.js";
import { generatedCodeRceModule } from "./attacks/generated-code-rce.js";
import { markdownLinkInjectionModule } from "./attacks/markdown-link-injection.js";
import { sycophancyExploitationModule } from "./attacks/sycophancy-exploitation.js";
import { hallucinationInducementModule } from "./attacks/hallucination-inducement.js";
import { formatConfusionAttackModule } from "./attacks/format-confusion-attack.js";
import { modelDosModule } from "./attacks/model-dos.js";
import { tokenFloodingDosModule } from "./attacks/token-flooding-dos.js";
import { infiniteLoopAgentModule } from "./attacks/infinite-loop-agent.js";
import { quotaExhaustionAttackModule } from "./attacks/quota-exhaustion-attack.js";
import { inferenceAttackModule } from "./attacks/inference-attack.js";
import { reIdentificationModule } from "./attacks/re-identification.js";
import { linkageAttackModule } from "./attacks/linkage-attack.js";
import { differentialPrivacyViolationModule } from "./attacks/differential-privacy-violation.js";
import { logicBombConditionalModule } from "./attacks/logic-bomb-conditional.js";
import { agenticLegalCommitmentModule } from "./attacks/agentic-legal-commitment.js";
import { contextualIntegrityViolationModule } from "./attacks/contextual-integrity-violation.js";
import { financialFraudFacilitationModule } from "./attacks/financial-fraud-facilitation.js";
import { gdprErasureBypassModule } from "./attacks/gdpr-erasure-bypass.js";
import { mcpServerCompromiseModule } from "./attacks/mcp-server-compromise.js";
import { pluginManifestSpoofingModule } from "./attacks/plugin-manifest-spoofing.js";
import { sdkDependencyAttackModule } from "./attacks/sdk-dependency-attack.js";
import { fineTuningDataInjectionModule } from "./attacks/fine-tuning-data-injection.js";
import { promptTemplateInjectionModule } from "./attacks/prompt-template-injection.js";
import { debugAccessModule } from "./attacks/debug-access.js";
import { shellInjectionModule } from "./attacks/shell-injection.js";
import { sqlInjectionModule } from "./attacks/sql-injection.js";
import { unauthorizedCommitmentsModule } from "./attacks/unauthorized-commitments.js";
import { offTopicModule } from "./attacks/off-topic.js";
import { divergentRepetitionModule } from "./attacks/divergent-repetition.js";
import { modelFingerprintingModule } from "./attacks/model-fingerprinting.js";
import { specialTokenInjectionModule } from "./attacks/special-token-injection.js";
import { crossLingualAttackModule } from "./attacks/cross-lingual-attack.js";
import { medicalSafetyModule } from "./attacks/medical-safety.js";
import { financialComplianceModule } from "./attacks/financial-compliance.js";
import { pharmacySafetyModule } from "./attacks/pharmacy-safety.js";
import { insuranceComplianceModule } from "./attacks/insurance-compliance.js";
import { ecommerceSecurityModule } from "./attacks/ecommerce-security.js";
import { telecomComplianceModule } from "./attacks/telecom-compliance.js";
import { housingDiscriminationModule } from "./attacks/housing-discrimination.js";
import { ssrfModule } from "./attacks/ssrf.js";
import { pathTraversalModule } from "./attacks/path-traversal.js";
import { insecureOutputHandlingModule } from "./attacks/insecure-output-handling.js";
import { mcpToolMisuseModule } from "./attacks-mcp/mcp-tool-misuse.js";
import { mcpDataExfiltrationModule } from "./attacks-mcp/mcp-data-exfiltration.js";
import { mcpIndirectPromptInjectionModule } from "./attacks-mcp/mcp-indirect-prompt-injection.js";
import { mcpPathTraversalModule } from "./attacks-mcp/mcp-path-traversal.js";
import { mcpSsrfModule } from "./attacks-mcp/mcp-ssrf.js";
import { mcpCrossTenantAccessModule } from "./attacks-mcp/mcp-cross-tenant-access.js";
import { mcpDebugAccessModule } from "./attacks-mcp/mcp-debug-access.js";

loadEnvFile();

const ALL_MODULES: AttackModule[] = [
  authBypassModule,
  rbacBypassModule,
  promptInjectionModule,
  outputEvasionModule,
  dataExfiltrationModule,
  rateLimitModule,
  sensitiveDataModule,
  indirectPromptInjectionModule,
  steganographicExfiltrationModule,
  outOfBandExfiltrationModule,
  trainingDataExtractionModule,
  sideChannelInferenceModule,
  toolMisuseModule,
  rogueAgentModule,
  goalHijackModule,
  identityPrivilegeModule,
  unexpectedCodeExecModule,
  cascadingFailureModule,
  multiAgentDelegationModule,
  memoryPoisoningModule,
  toolOutputManipulationModule,
  guardrailTimingModule,
  multiTurnEscalationModule,
  conversationManipulationModule,
  contextWindowAttackModule,
  slowBurnExfiltrationModule,
  brandReputationModule,
  competitorEndorsementModule,
  toxicContentModule,
  misinformationModule,
  piiDisclosureModule,
  regulatoryViolationModule,
  copyrightInfringementModule,
  consentBypassModule,
  sessionHijackingModule,
  crossTenantAccessModule,
  apiAbuseModule,
  supplyChainModule,
  socialEngineeringModule,
  harmfulAdviceModule,
  biasExploitationModule,
  contentFilterBypassModule,
  agenticWorkflowBypassModule,
  toolChainHijackModule,
  agentReflectionExploitModule,
  crossSessionInjectionModule,
  drugSynthesisModule,
  weaponsViolenceModule,
  financialCrimeModule,
  cyberCrimeModule,
  csamMinorSafetyModule,
  fakeQuotesMisinfoModule,
  competitorSabotageModule,
  defamationHarassmentModule,
  brandImpersonationModule,
  hateSpeechDogwhistleModule,
  radicalizationContentModule,
  targetedHarassmentModule,
  influenceOperationsModule,
  psychologicalManipulationModule,
  deceptiveMisinfoModule,
  hallucinationModule,
  overrelianceModule,
  overRefusalModule,
  ragPoisoningModule,
  ragAttributionModule,
  modelExtractionModule,
  membershipInferenceModule,
  backdoorTriggerModule,
  dataPoisoningModule,
  gradientLeakageModule,
  modelInversionModule,
  ragCorpusPoisoningModule,
  retrievalRankingAttackModule,
  vectorStoreManipulationModule,
  chunkBoundaryInjectionModule,
  embeddingInversionModule,
  structuredOutputInjectionModule,
  generatedCodeRceModule,
  markdownLinkInjectionModule,
  sycophancyExploitationModule,
  hallucinationInducementModule,
  formatConfusionAttackModule,
  modelDosModule,
  tokenFloodingDosModule,
  infiniteLoopAgentModule,
  quotaExhaustionAttackModule,
  inferenceAttackModule,
  reIdentificationModule,
  linkageAttackModule,
  differentialPrivacyViolationModule,
  logicBombConditionalModule,
  agenticLegalCommitmentModule,
  contextualIntegrityViolationModule,
  financialFraudFacilitationModule,
  gdprErasureBypassModule,
  mcpServerCompromiseModule,
  pluginManifestSpoofingModule,
  sdkDependencyAttackModule,
  fineTuningDataInjectionModule,
  promptTemplateInjectionModule,
  debugAccessModule,
  shellInjectionModule,
  sqlInjectionModule,
  unauthorizedCommitmentsModule,
  offTopicModule,
  divergentRepetitionModule,
  modelFingerprintingModule,
  specialTokenInjectionModule,
  crossLingualAttackModule,
  medicalSafetyModule,
  financialComplianceModule,
  pharmacySafetyModule,
  insuranceComplianceModule,
  ecommerceSecurityModule,
  telecomComplianceModule,
  housingDiscriminationModule,
  ssrfModule,
  pathTraversalModule,
  insecureOutputHandlingModule,
];

const MCP_MODULES: AttackModule[] = [
  mcpToolMisuseModule,
  mcpDataExfiltrationModule,
  mcpIndirectPromptInjectionModule,
  mcpPathTraversalModule,
  mcpSsrfModule,
  mcpCrossTenantAccessModule,
  mcpDebugAccessModule,
];

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

async function enrichAnalysisWithTargetSurface(
  config: Config,
  analysis: CodebaseAnalysis,
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
    if (surface.serverName) {
      notes.push(`MCP server name: ${surface.serverName}`);
    }
    if (surface.protocolVersion) {
      notes.push(`MCP protocol version: ${surface.protocolVersion}`);
    }
    if (surface.capabilities?.length) {
      notes.push(`MCP capabilities: ${surface.capabilities.join(", ")}`);
    }
    if (surface.prompts?.length) {
      notes.push(`MCP prompts exposed: ${surface.prompts.join(", ")}`);
    }
    if (surface.resources?.length) {
      notes.push(`MCP resources exposed: ${surface.resources.join(", ")}`);
    }

    for (const note of notes) {
      if (!analysis.knownWeaknesses.includes(note)) {
        analysis.knownWeaknesses.push(note);
      }
    }
  } catch (error) {
    console.warn(
      `  Warning: failed to discover target surface: ${(error as Error).message}`,
    );
  }
}

function summarizeAffectedFiles(
  analysis: CodebaseAnalysis,
  category: AttackCategory,
  max = 3,
): string {
  const files = analysis.affectedFiles?.[category] ?? [];
  if (files.length === 0) return "none mapped";
  const shown = files
    .slice(0, max)
    .map((f) => (f.line ? `${f.file}:${f.line}` : f.file));
  const suffix = files.length > max ? ` (+${files.length - max} more)` : "";
  return `${shown.join(", ")}${suffix}`;
}

function printPlannedAttackReview(
  round: number,
  attacks: Attack[],
  analysis: CodebaseAnalysis,
  label = "planned",
): void {
  console.log(`\n  Attack review for round ${round} (${label}):`);
  for (let i = 0; i < attacks.length; i++) {
    const a = attacks[i];
    const msg = (a.payload as Record<string, unknown>)?.message;
    const preview =
      typeof msg === "string"
        ? msg.replace(/\s+/g, " ").slice(0, 140)
        : "(no message)";
    console.log(
      `    ${i + 1}. [${a.severity}] ${a.category} :: ${a.name} (${a.authMethod}/${a.role})`,
    );
    console.log(
      `       files: ${summarizeAffectedFiles(analysis, a.category)} | prompt: ${preview}${preview.length >= 140 ? "..." : ""}`,
    );
  }
}

async function confirmAttackExecution(
  promptText: string,
  requireConfirmation: boolean,
): Promise<boolean> {
  if (!requireConfirmation) {
    return true;
  }
  if (!process.stdin.isTTY || !process.stdout.isTTY) {
    console.log(
      "  Non-interactive terminal detected — auto-approving attack execution.",
    );
    return true;
  }
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });
  try {
    const answer = (await rl.question(`${promptText} [y/N]: `))
      .trim()
      .toLowerCase();
    return answer === "y" || answer === "yes";
  } finally {
    rl.close();
  }
}

function logFindings(result: AttackResult): void {
  const deterministicFindings = result.findings.filter(
    (f) => !f.startsWith("LLM judge"),
  );
  const judgeFindings = result.findings.filter((f) =>
    f.startsWith("LLM judge"),
  );
  for (const f of deterministicFindings) {
    console.log(`    ${f}`);
  }
  for (const f of judgeFindings) {
    console.log(`    ${f}`);
  }
  if (judgeFindings.length === 0 && result.llmReasoning) {
    console.log(
      `    LLM judge: ${result.llmReasoning}${result.judgeConfidence != null ? ` (confidence ${result.judgeConfidence}%)` : ""}`,
    );
  }
}

async function maybeGenerateIdealResponse(
  config: Config,
  result: AttackResult,
): Promise<void> {
  const enabled =
    config.attackConfig.enableIdealResponses ?? config.attackConfig.enableLlmGeneration;
  if (!enabled) return;
  if (result.verdict !== "PASS" && result.verdict !== "PARTIAL") return;

  const ideal = await generateIdealResponse(config, result);
  if (!ideal) return;

  result.idealResponse = ideal;
  console.log(`    [Ideal Response] ${ideal.response.slice(0, 120)}${ideal.response.length > 120 ? "..." : ""}`);
  if (ideal.remediationHints.length > 0) {
    console.log(`    [Remediation] ${ideal.remediationHints[0]}`);
  }
}

async function main() {
  const configPath = process.argv[2];
  console.log("=== Red-Team Security Testing Framework ===\n");

  // 1. Load config
  console.log("[1/5] Loading configuration...");
  const config = loadConfig(configPath);
  const targetLabel = describeTarget(config);
  console.log(`  Target: ${targetLabel}`);
  console.log(`  Adaptive rounds: ${config.attackConfig.adaptiveRounds}`);
  console.log(
    `  LLM generation: ${config.attackConfig.enableLlmGeneration ? "enabled" : "disabled"}`,
  );

  // Filter modules based on enabledCategories (empty/absent = all enabled)
  const moduleSet =
    (config.target.type ?? "http_agent") === "mcp" ? MCP_MODULES : ALL_MODULES;
  const enabledSet = config.attackConfig.enabledCategories;
  const activeModules = enabledSet?.length
    ? moduleSet.filter((m) => enabledSet.includes(m.category))
    : moduleSet;
  if (enabledSet?.length) {
    console.log(
      `  Active categories (${activeModules.length}): ${enabledSet.join(", ")}`,
    );
  } else {
    console.log(`  Active categories: all (${moduleSet.length})`);
  }

  // 2. Analyze codebase
  console.log("\n[2/5] Analyzing target codebase...");
  const analysis = await analyzeCodebase(config);
  await enrichAnalysisWithTargetSurface(config, analysis);
  console.log(
    `  Found ${analysis.tools.length} tools, ${analysis.roles.length} roles`,
  );
  if (analysis.detectedFrameworks.length > 0) {
    console.log(
      `  Frameworks: ${analysis.detectedFrameworks.map((f) => `${f.name} (${f.confidence})`).join(", ")}`,
    );
  }
  if (analysis.toolChains.length > 0) {
    console.log(`  Dangerous tool chains: ${analysis.toolChains.length}`);
  }
  console.log(
    `  Identified ${analysis.knownWeaknesses.length} potential weaknesses`,
  );
  if (analysis.knownWeaknesses.length > 0) {
    for (const w of analysis.knownWeaknesses.slice(0, 5)) {
      console.log(`    - ${w}`);
    }
  }
  if (
    analysis.affectedFiles &&
    Object.keys(analysis.affectedFiles).length > 0
  ) {
    const totalFiles = new Set(
      Object.values(analysis.affectedFiles)
        .flat()
        .map((f) => f.file),
    ).size;
    console.log(
      `  Mapped ${Object.keys(analysis.affectedFiles).length} attack categories to ${totalFiles} target source files`,
    );
  }

  // 2.25. Category applicability gating — skip categories with no relevant source files
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
      console.log(
        `  Applicability gating: skipped ${skipped} categories with no relevant source files`,
      );
    }
  }

  // Build app context for the LLM judge (reduces false positives)
  const appContext: AppContext = {
    tools: analysis.tools,
    roles: analysis.roles,
    systemPromptHints: analysis.systemPromptHints,
  };

  // 2.5. Static analysis
  let staticResult;
  if (config.codebasePath) {
    console.log("\n[2.5/5] Running static analysis...");
    staticResult = await runStaticAnalysis(config);
    console.log(
      `  Checked ${staticResult.checkedFiles} files, found ${staticResult.findings.length} issues`,
    );
    console.log(`  Static score: ${staticResult.score}/100`);
  }

  // 3. Pre-authenticate
  console.log("\n[3/5] Pre-authenticating...");
  await preAuthenticate(config);

  // 4. Run adaptive attack rounds
  console.log("\n[4/5] Running attacks...");
  const rounds: RoundResult[] = [];
  let allPreviousResults: AttackResult[] = [];
  let defenseProfiles: Map<AttackCategory, CategoryDefenseProfile> | undefined;
  let cancelledByUser = false;
  const requireReviewConfirmation =
    config.attackConfig.requireReviewConfirmation ?? true;
  console.log(
    `  Review confirmation: ${requireReviewConfirmation ? "enabled" : "disabled"}`,
  );

  for (let round = 1; round <= config.attackConfig.adaptiveRounds; round++) {
    console.log(
      `\n  ── Round ${round}/${config.attackConfig.adaptiveRounds} ──`,
    );

    // Plan attacks for this round (with defense profiles from prior rounds)
    console.log("  Planning attacks with LLM... this may take a while.");
    const attacks = await planAttacks(
      config,
      analysis,
      relevantModules,
      allPreviousResults,
      round,
      defenseProfiles,
    );
    console.log(`  Planned ${attacks.length} attacks`);
    printPlannedAttackReview(round, attacks, analysis, "initial");
    const approved = await confirmAttackExecution(
      "  Proceed with these planned attacks?",
      requireReviewConfirmation,
    );
    if (!approved) {
      console.log("  Attack execution cancelled by user after review.");
      cancelledByUser = true;
      break;
    }

    const roundResults: AttackResult[] = [];

    for (let i = 0; i < attacks.length; i++) {
      const attack = attacks[i];
      const progress = `[${i + 1}/${attacks.length}]`;

      // Handle rate-limit rapid-fire attacks specially
      const rapidFire = (attack.payload as Record<string, unknown>)
        ._rapidFire as number | undefined;
      if (rapidFire && attack.category === "rate_limit") {
        console.log(
          `  ${progress} ${attack.name} (${rapidFire}x rapid-fire)...`,
        );
        const cleanPayload = { ...attack.payload };
        delete (cleanPayload as Record<string, unknown>)._rapidFire;
        const cleanAttack = { ...attack, payload: cleanPayload };

        const responses = await executeRapidFire(
          config,
          cleanAttack,
          rapidFire,
        );
        // Check if any got 429
        const got429 = responses.some((r) => r.statusCode === 429);
        const allOk = responses.every((r) => r.statusCode === 200);
        const lastResponse = responses[responses.length - 1];

        const result = await analyzeResponse(
          config,
          attack,
          lastResponse.statusCode,
          lastResponse.body,
          lastResponse.timeMs,
          appContext,
          lastResponse.executionTrace,
        );

        if (!got429 && allOk) {
          result.verdict = "PASS";
          result.findings.push(
            `All ${rapidFire} requests succeeded — rate limit not enforced`,
          );
        } else if (got429) {
          result.verdict = "FAIL";
          result.findings.push(
            `Rate limit correctly enforced — got 429 after ${responses.filter((r) => r.statusCode === 200).length} requests`,
          );
        }

        const icon =
          result.verdict === "PASS"
            ? "!!"
            : result.verdict === "FAIL"
              ? "OK"
              : "??";
        console.log(`    [${icon}] ${result.verdict}`);
        logFindings(result);
        await maybeGenerateIdealResponse(config, result);
        roundResults.push(result);
        continue;
      }

      // Multi-turn attack
      if (attack.steps && attack.steps.length > 0) {
        const totalSteps = 1 + attack.steps.length;
        process.stdout.write(
          `  ${progress} ${attack.name} (${totalSteps} steps)...`,
        );

        const { results: stepResults, stoppedEarly } = await executeMultiTurn(
          config,
          attack,
          async (cfg, atk, sc, b, t) => {
            const r = await analyzeResponse(cfg, atk, sc, b, t, appContext);
            return { verdict: r.verdict, findings: r.findings };
          },
        );

        const lastStep = stepResults[stepResults.length - 1];
        const result = await analyzeResponse(
          config,
          attack,
          lastStep.statusCode,
          lastStep.body,
          lastStep.timeMs,
          appContext,
          lastStep.executionTrace,
        );
        result.stepIndex = lastStep.stepIndex;
        result.totalSteps = stepResults.length;

        const icon =
          result.verdict === "PASS"
            ? "!!"
            : result.verdict === "PARTIAL"
              ? "~"
              : result.verdict === "FAIL"
                ? "OK"
                : "??";
        result.conversation = stepResults.map((sr) => ({
          stepIndex: sr.stepIndex,
          payload:
            sr.stepIndex === 0
              ? attack.payload
              : (attack.steps?.[sr.stepIndex - 1]?.payload ?? {}),
          statusCode: sr.statusCode,
          responseBody: sr.body,
          responseTimeMs: sr.timeMs,
        }));

        const earlyTag = stoppedEarly
          ? ` (stopped at step ${lastStep.stepIndex + 1})`
          : "";
        console.log(
          ` [${icon}] ${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
        );
        logFindings(result);
        await maybeGenerateIdealResponse(config, result);

        roundResults.push(result);
      } else {
        // Single-turn attack
        process.stdout.write(`  ${progress} ${attack.name}...`);
        const { statusCode, body, timeMs, executionTrace } =
          await executeAttack(config, attack);
        const result = await analyzeResponse(
          config,
          attack,
          statusCode,
          body,
          timeMs,
          appContext,
          executionTrace,
        );

        const icon =
          result.verdict === "PASS"
            ? "!!"
            : result.verdict === "PARTIAL"
              ? "~"
              : result.verdict === "FAIL"
                ? "OK"
                : "??";
        console.log(
          ` [${icon}] ${result.verdict} (${statusCode}, ${timeMs}ms)`,
        );
        logFindings(result);
        await maybeGenerateIdealResponse(config, result);

        roundResults.push(result);
      }

      // Delay between requests
      if (config.attackConfig.delayBetweenRequestsMs > 0) {
        await sleep(config.attackConfig.delayBetweenRequestsMs);
      }
    }

    // ── Refinement pass: convert PARTIALs from this round ──
    const roundPartials = roundResults.filter((r) => r.verdict === "PARTIAL");
    if (roundPartials.length > 0 && config.attackConfig.enableLlmGeneration) {
      console.log(`\n  ── Refining ${roundPartials.length} PARTIAL results ──`);
      const refinedAttacks = await refinePartialAttacks(
        config,
        analysis,
        roundResults,
        round,
      );

      if (refinedAttacks.length > 0) {
        console.log("  Refinement planning complete.");
        console.log(`  Executing ${refinedAttacks.length} refined attacks`);
        printPlannedAttackReview(round, refinedAttacks, analysis, "refined");
        const refineApproved = await confirmAttackExecution(
          "  Proceed with refined attacks?",
          requireReviewConfirmation,
        );
        if (!refineApproved) {
          console.log("  Skipping refined attacks (user declined).");
        } else {
          for (let i = 0; i < refinedAttacks.length; i++) {
            const attack = refinedAttacks[i];
            const progress = `[R${i + 1}/${refinedAttacks.length}]`;

            if (attack.steps && attack.steps.length > 0) {
              const totalSteps = 1 + attack.steps.length;
              process.stdout.write(
                `  ${progress} ${attack.name} (${totalSteps} steps)...`,
              );

              const { results: stepResults, stoppedEarly } =
                await executeMultiTurn(
                  config,
                  attack,
                  async (cfg, atk, sc, b, t) => {
                    const r = await analyzeResponse(
                      cfg,
                      atk,
                      sc,
                      b,
                      t,
                      appContext,
                    );
                    return { verdict: r.verdict, findings: r.findings };
                  },
                );

              const lastStep = stepResults[stepResults.length - 1];
              const result = await analyzeResponse(
                config,
                attack,
                lastStep.statusCode,
                lastStep.body,
                lastStep.timeMs,
                appContext,
                lastStep.executionTrace,
              );
              result.stepIndex = lastStep.stepIndex;
              result.totalSteps = stepResults.length;
              result.conversation = stepResults.map((sr) => ({
                stepIndex: sr.stepIndex,
                payload:
                  sr.stepIndex === 0
                    ? attack.payload
                    : (attack.steps?.[sr.stepIndex - 1]?.payload ?? {}),
                statusCode: sr.statusCode,
                responseBody: sr.body,
                responseTimeMs: sr.timeMs,
              }));

              const icon =
                result.verdict === "PASS"
                  ? "!!"
                  : result.verdict === "PARTIAL"
                    ? "~"
                    : result.verdict === "FAIL"
                      ? "OK"
                      : "??";
              const earlyTag = stoppedEarly
                ? ` (stopped at step ${lastStep.stepIndex + 1})`
                : "";
              console.log(
                ` [${icon}] ${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
              );
              logFindings(result);
              await maybeGenerateIdealResponse(config, result);
              roundResults.push(result);
            } else {
              process.stdout.write(`  ${progress} ${attack.name}...`);
              const { statusCode, body, timeMs, executionTrace } =
                await executeAttack(config, attack);
              const result = await analyzeResponse(
                config,
                attack,
                statusCode,
                body,
                timeMs,
                appContext,
                executionTrace,
              );

              const icon =
                result.verdict === "PASS"
                  ? "!!"
                  : result.verdict === "PARTIAL"
                    ? "~"
                    : result.verdict === "FAIL"
                      ? "OK"
                      : "??";
              console.log(
                ` [${icon}] ${result.verdict} (${statusCode}, ${timeMs}ms)`,
              );
              logFindings(result);
              await maybeGenerateIdealResponse(config, result);
              roundResults.push(result);
            }

            if (config.attackConfig.delayBetweenRequestsMs > 0) {
              await sleep(config.attackConfig.delayBetweenRequestsMs);
            }
          }

          const refinedPasses = roundResults
            .slice(-refinedAttacks.length)
            .filter((r) => r.verdict === "PASS").length;
          const refinedPartials = roundResults
            .slice(-refinedAttacks.length)
            .filter((r) => r.verdict === "PARTIAL").length;
          console.log(
            `  Refinement: ${refinedPasses} converted to PASS, ${refinedPartials} still PARTIAL`,
          );
        }
      }
    }

    rounds.push({ round, results: roundResults });
    allPreviousResults = allPreviousResults.concat(roundResults);

    const passCount = roundResults.filter((r) => r.verdict === "PASS").length;
    const failCount = roundResults.filter((r) => r.verdict === "FAIL").length;
    console.log(
      `  Round ${round}: ${passCount} vulns found, ${failCount} blocked`,
    );

    // Analyze round results to build per-category defense profiles for next round
    if (round < config.attackConfig.adaptiveRounds) {
      defenseProfiles = analyzeRound(roundResults, config, defenseProfiles);

      const blockedCategories = [...defenseProfiles.values()]
        .filter((p) => p.blockRate > 0)
        .sort((a, b) => b.blockRate - a.blockRate);

      if (blockedCategories.length > 0) {
        console.log(
          `\n  Defense analysis (${blockedCategories.length} categories with blocks):`,
        );
        for (const p of blockedCategories.slice(0, 10)) {
          console.log(
            `    ${p.category}: ${p.blockRate}% blocked → dominant defense: ${p.dominantDefense}`,
          );
        }
        if (blockedCategories.length > 10) {
          console.log(`    ... and ${blockedCategories.length - 10} more`);
        }
      }
    }
  }

  // 5. Generate report
  console.log("\n[5/5] Generating report...");
  if (cancelledByUser) {
    console.log(
      "  Report includes results from rounds executed before cancellation.",
    );
  }
  const targetUrl = targetLabel;
  const report = generateReport(
    targetUrl,
    rounds,
    staticResult,
    analysis.affectedFiles,
  );
  const { jsonPath, mdPath } = writeReport(report);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Markdown: ${mdPath}`);

  printConsoleSummary(report);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
