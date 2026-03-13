#!/usr/bin/env npx tsx

import { loadConfig } from "./lib/config-loader.js";
import { analyzeCodebase } from "./lib/codebase-analyzer.js";
import { planAttacks } from "./lib/attack-planner.js";
import {
  preAuthenticate,
  executeAttack,
  executeMultiTurn,
  executeRapidFire,
  sleep,
  runWithConcurrency,
} from "./lib/attack-runner.js";
import { analyzeResponse } from "./lib/response-analyzer.js";
import {
  generateReport,
  writeReport,
  printConsoleSummary,
} from "./lib/report-generator.js";
import { runStaticAnalysis } from "./lib/static-analyzer.js";
import type { AttackModule, AttackResult, RoundResult } from "./lib/types.js";

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

async function main() {
  const configPath = process.argv[2];
  console.log("=== Red-Team Security Testing Framework ===\n");

  // 1. Load config
  console.log("[1/5] Loading configuration...");
  const config = loadConfig(configPath);
  console.log(
    `  Target: ${config.target.baseUrl}${config.target.agentEndpoint}`,
  );
  console.log(`  Adaptive rounds: ${config.attackConfig.adaptiveRounds}`);
  console.log(
    `  LLM generation: ${config.attackConfig.enableLlmGeneration ? "enabled" : "disabled"}`,
  );

  // Filter modules based on enabledCategories (empty/absent = all enabled)
  const enabledSet = config.attackConfig.enabledCategories;
  const activeModules = enabledSet?.length
    ? ALL_MODULES.filter((m) => enabledSet.includes(m.category))
    : ALL_MODULES;
  if (enabledSet?.length) {
    console.log(
      `  Active categories (${activeModules.length}): ${enabledSet.join(", ")}`,
    );
  } else {
    console.log(`  Active categories: all (${ALL_MODULES.length})`);
  }

  // 2. Analyze codebase
  console.log("\n[2/5] Analyzing target codebase...");
  const analysis = await analyzeCodebase(config);
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

  for (let round = 1; round <= config.attackConfig.adaptiveRounds; round++) {
    console.log(
      `\n  ── Round ${round}/${config.attackConfig.adaptiveRounds} ──`,
    );

    // Plan attacks for this round
    const attacks = await planAttacks(
      config,
      analysis,
      activeModules,
      allPreviousResults,
      round,
    );
    console.log(`  Planned ${attacks.length} attacks`);

    const concurrency = config.attackConfig.concurrency || 1;
    console.log(`  Concurrency: ${concurrency}`);

    // Build a task for each attack that returns its result
    const attackTasks = attacks.map((attack, i) => async (): Promise<AttackResult> => {
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
        console.log(
          `    [${icon}] ${result.verdict} — ${result.findings[0] ?? ""}`,
        );

        if (config.attackConfig.delayBetweenRequestsMs > 0) {
          await sleep(config.attackConfig.delayBetweenRequestsMs);
        }
        return result;
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
            const r = await analyzeResponse(cfg, atk, sc, b, t);
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
        const earlyTag = stoppedEarly
          ? ` (stopped at step ${lastStep.stepIndex + 1})`
          : "";
        console.log(
          ` [${icon}] ${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
        );
        if (result.findings.length > 0) {
          console.log(`    ${result.findings[0]}`);
        }

        if (config.attackConfig.delayBetweenRequestsMs > 0) {
          await sleep(config.attackConfig.delayBetweenRequestsMs);
        }
        return result;
      }

      // Single-turn attack
      process.stdout.write(`  ${progress} ${attack.name}...`);
      const { statusCode, body, timeMs } = await executeAttack(
        config,
        attack,
      );
      const result = await analyzeResponse(
        config,
        attack,
        statusCode,
        body,
        timeMs,
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
      if (result.findings.length > 0) {
        console.log(`    ${result.findings[0]}`);
      }

      if (config.attackConfig.delayBetweenRequestsMs > 0) {
        await sleep(config.attackConfig.delayBetweenRequestsMs);
      }
      return result;
    });

    const roundResults = await runWithConcurrency(attackTasks, concurrency);

    rounds.push({ round, results: roundResults });
    allPreviousResults = allPreviousResults.concat(roundResults);
    console.log(
      `  Round ${round}: ${roundResults.filter((r) => r.verdict === "PASS").length} vulns found`,
    );
  }

  // 5. Generate report
  console.log("\n[5/5] Generating report...");
  const targetUrl = `${config.target.baseUrl}${config.target.agentEndpoint}`;
  const report = generateReport(targetUrl, rounds, staticResult);
  const { jsonPath, mdPath } = writeReport(report);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Markdown: ${mdPath}`);

  printConsoleSummary(report);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
