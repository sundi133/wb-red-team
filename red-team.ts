#!/usr/bin/env npx tsx

import { createInterface } from "node:readline/promises";
import { dirname, resolve } from "node:path";

// Color coding for security results
function getColoredIcon(verdict: string): string {
  const colors = {
    reset: "\x1b[0m",
    red: "\x1b[91m", // PASS = RED (attack succeeded - bad for security)
    green: "\x1b[92m", // FAIL = GREEN (defense held - good for security)
    yellow: "\x1b[93m", // PARTIAL = YELLOW (uncertain)
    gray: "\x1b[90m", // ERROR = GRAY
  };

  switch (verdict) {
    case "PASS":
      return `${colors.red}[!!]${colors.reset}`;
    case "FAIL":
      return `${colors.green}[OK]${colors.reset}`;
    case "PARTIAL":
      return `${colors.yellow}[~]${colors.reset}`;
    default:
      return `${colors.gray}[??]${colors.reset}`;
  }
}
import { loadEnvFile } from "./lib/env-loader.js";
import { loadConfig } from "./lib/config-loader.js";
import { describeTarget, getTargetAdapter } from "./lib/target-adapter.js";
import { analyzeCodebase } from "./lib/codebase-analyzer.js";
import { planAttacks, refinePartialAttacks } from "./lib/attack-planner.js";
import {
  preAuthenticate,
  executeAttack,
  executeMultiTurn,
  executeAdaptiveMultiTurn,
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
import {
  loadCustomAttacksFromConfig,
  mergeCustomAttacksForRound,
} from "./lib/custom-attacks-loader.js";
import { generateAppTailoredCustomAttacks } from "./lib/app-tailored-custom-prompts.js";
import {
  runDiscoveryRound,
  applyDiscoveryIntel,
} from "./lib/discovery-round.js";
import {
  ALL_MODULES,
  MCP_MODULES,
  enrichAnalysisWithTargetSurface,
} from "./lib/run.js";
import type {
  Attack,
  AttackResult,
  AttackCategory,
  CategoryDefenseProfile,
  CodebaseAnalysis,
  Config,
  Report,
  RoundResult,
} from "./lib/types.js";

loadEnvFile();

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
    config.attackConfig.enableIdealResponses ??
    config.attackConfig.enableLlmGeneration;
  if (!enabled) return;
  if (result.verdict !== "PASS" && result.verdict !== "PARTIAL") return;

  const ideal = await generateIdealResponse(config, result);
  if (!ideal) return;

  result.idealResponse = ideal;
  console.log(
    `    [Ideal Response] ${ideal.response.slice(0, 120)}${ideal.response.length > 120 ? "..." : ""}`,
  );
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
  const configDir = dirname(resolve(configPath ?? "config.json"));
  let customAttacks: Attack[] = [];
  try {
    customAttacks = loadCustomAttacksFromConfig(config, { configDir });
  } catch (e) {
    console.error(`  ${(e as Error).message}`);
    console.error(
      "  Fix or remove customAttacksFile in config.json to run without file-based custom attacks.",
    );
    process.exit(1);
  }
  if (customAttacks.length > 0) {
    console.log(`  Custom attacks loaded: ${customAttacks.length} case(s)`);
  }
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
  await enrichAnalysisWithTargetSurface(config, analysis, console.warn);
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

  if (Math.max(0, config.attackConfig.appTailoredCustomPromptCount ?? 0) > 0) {
    console.log("\n  Generating app-tailored custom prompts from analysis...");
    const generated = await generateAppTailoredCustomAttacks(config, analysis);
    if (generated.length > 0) {
      console.log(`  App-tailored custom cases: ${generated.length}`);
      customAttacks = [...customAttacks, ...generated];
    } else {
      console.log(
        "  App-tailored generation returned no cases (see errors above if any).",
      );
    }
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

  // 3.5. Discovery round (optional — probes target to enrich sensitivePatterns and applicationDetails)
  let discoveryIntel: Report["discovery"] | undefined;
  if (config.attackConfig.enableDiscovery) {
    console.log("\n[3.5/5] Running discovery round...");
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
    console.log(
      `  Discovery complete: ${intel.discoveredTools.length} tools, ${intel.discoveredDataStores.length} data stores, ${intel.discoveredPatterns.length} patterns, ${intel.weaknesses.length} weaknesses`,
    );
  }

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
    const skipBuiltinPlanner =
      round === 1 &&
      config.attackConfig.customAttacksOnly === true &&
      customAttacks.length > 0;

    console.log(
      skipBuiltinPlanner
        ? "  Skipping built-in planner (customAttacksOnly)."
        : "  Planning attacks with LLM... this may take a while.",
    );
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
    const attacks = mergeCustomAttacksForRound(
      config,
      round,
      planned,
      customAttacks,
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

        console.log(`    ${getColoredIcon(result.verdict)} ${result.verdict}`);
        logFindings(result);
        await maybeGenerateIdealResponse(config, result);
        roundResults.push(result);
        continue;
      }

      try {
        // Multi-turn attack (predefined steps) or Adaptive multi-turn attack
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
        } else if (
          config.attackConfig.enableAdaptiveMultiTurn &&
          config.attackConfig.enableMultiTurnGeneration
        ) {
          // Adaptive multi-turn attack (generates follow-ups based on AI responses)
          const maxTurns = config.attackConfig.maxAdaptiveTurns ?? 15;
          process.stdout.write(
            `  ${progress} ${attack.name} (adaptive, max ${maxTurns} turns)...`,
          );

          const {
            results: stepResults,
            stoppedEarly,
            conversationHistory,
          } = await executeAdaptiveMultiTurn(
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

          const icon = getColoredIcon(result.verdict);
          // For adaptive multi-turn, use the actual conversation history with real messages
          result.conversation = conversationHistory.map((ch) => ({
            stepIndex: ch.stepIndex,
            payload: { message: ch.userMessage }, // Use the actual message sent
            statusCode: stepResults[ch.stepIndex]?.statusCode ?? 0,
            responseBody: ch.aiResponse,
            responseTimeMs: stepResults[ch.stepIndex]?.timeMs ?? 0,
          }));

          const earlyTag = stoppedEarly
            ? ` (stopped at step ${lastStep.stepIndex + 1})`
            : "";
          console.log(
            ` ${icon}${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
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

          const icon = getColoredIcon(result.verdict);
          console.log(` ${icon}${result.verdict} (${statusCode}, ${timeMs}ms)`);
          logFindings(result);
          await maybeGenerateIdealResponse(config, result);

          roundResults.push(result);
        }
      } catch (attackErr) {
        console.log(
          ` [??] ERROR — ${attackErr instanceof Error ? attackErr.message : String(attackErr)}`,
        );
        roundResults.push({
          attack,
          statusCode: 0,
          responseBody: "",
          responseTimeMs: 0,
          verdict: "ERROR" as const,
          findings: [
            `Attack execution failed: ${attackErr instanceof Error ? attackErr.message : String(attackErr)}`,
          ],
        });
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

            try {
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
              } else if (
                config.attackConfig.enableAdaptiveMultiTurn &&
                config.attackConfig.enableMultiTurnGeneration
              ) {
                // Adaptive multi-turn refined attack
                const maxTurns = config.attackConfig.maxAdaptiveTurns ?? 15;
                process.stdout.write(
                  `  ${progress} ${attack.name} (adaptive, max ${maxTurns} turns)...`,
                );

                const {
                  results: stepResults,
                  stoppedEarly,
                  conversationHistory,
                } = await executeAdaptiveMultiTurn(
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

                // Handle conversation mapping for both predefined and adaptive multi-turn
                if (attack.steps && attack.steps.length > 0) {
                  // Predefined multi-turn
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
                } else {
                  // Adaptive multi-turn - use actual conversation history
                  result.conversation = conversationHistory.map((ch) => ({
                    stepIndex: ch.stepIndex,
                    payload: { message: ch.userMessage }, // Use the actual message sent
                    statusCode: stepResults[ch.stepIndex]?.statusCode ?? 0,
                    responseBody: ch.aiResponse,
                    responseTimeMs: stepResults[ch.stepIndex]?.timeMs ?? 0,
                  }));
                }

                const icon = getColoredIcon(result.verdict);
                const earlyTag = stoppedEarly
                  ? ` (stopped at step ${lastStep.stepIndex + 1})`
                  : "";
                console.log(
                  ` ${icon}${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`,
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

                const icon = getColoredIcon(result.verdict);
                console.log(
                  ` ${icon}${result.verdict} (${statusCode}, ${timeMs}ms)`,
                );
                logFindings(result);
                await maybeGenerateIdealResponse(config, result);
                roundResults.push(result);
              }
            } catch (refineErr) {
              console.log(
                ` [??] ERROR — ${refineErr instanceof Error ? refineErr.message : String(refineErr)}`,
              );
              roundResults.push({
                attack,
                statusCode: 0,
                responseBody: "",
                responseTimeMs: 0,
                verdict: "ERROR" as const,
                findings: [
                  `Refined attack execution failed: ${refineErr instanceof Error ? refineErr.message : String(refineErr)}`,
                ],
              });
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
    discoveryIntel,
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
