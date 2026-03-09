#!/usr/bin/env npx tsx

import { loadConfig } from "./lib/config-loader.js";
import { analyzeCodebase } from "./lib/codebase-analyzer.js";
import { planAttacks } from "./lib/attack-planner.js";
import { preAuthenticate, executeAttack, executeMultiTurn, executeRapidFire, sleep } from "./lib/attack-runner.js";
import { analyzeResponse } from "./lib/response-analyzer.js";
import { generateReport, writeReport, printConsoleSummary } from "./lib/report-generator.js";
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
];

async function main() {
  const configPath = process.argv[2];
  console.log("=== Red-Team Security Testing Framework ===\n");

  // 1. Load config
  console.log("[1/5] Loading configuration...");
  const config = loadConfig(configPath);
  console.log(`  Target: ${config.target.baseUrl}${config.target.agentEndpoint}`);
  console.log(`  Adaptive rounds: ${config.attackConfig.adaptiveRounds}`);
  console.log(`  LLM generation: ${config.attackConfig.enableLlmGeneration ? "enabled" : "disabled"}`);

  // 2. Analyze codebase
  console.log("\n[2/5] Analyzing target codebase...");
  const analysis = await analyzeCodebase(config);
  console.log(`  Found ${analysis.tools.length} tools, ${analysis.roles.length} roles`);
  console.log(`  Identified ${analysis.knownWeaknesses.length} potential weaknesses`);
  if (analysis.knownWeaknesses.length > 0) {
    for (const w of analysis.knownWeaknesses.slice(0, 5)) {
      console.log(`    - ${w}`);
    }
  }

  // 3. Pre-authenticate
  console.log("\n[3/5] Pre-authenticating...");
  await preAuthenticate(config);

  // 4. Run adaptive attack rounds
  console.log("\n[4/5] Running attacks...");
  const rounds: RoundResult[] = [];
  let allPreviousResults: AttackResult[] = [];

  for (let round = 1; round <= config.attackConfig.adaptiveRounds; round++) {
    console.log(`\n  ── Round ${round}/${config.attackConfig.adaptiveRounds} ──`);

    // Plan attacks for this round
    const attacks = await planAttacks(config, analysis, ALL_MODULES, allPreviousResults, round);
    console.log(`  Planned ${attacks.length} attacks`);

    const roundResults: AttackResult[] = [];

    for (let i = 0; i < attacks.length; i++) {
      const attack = attacks[i];
      const progress = `[${i + 1}/${attacks.length}]`;

      // Handle rate-limit rapid-fire attacks specially
      const rapidFire = (attack.payload as Record<string, unknown>)._rapidFire as number | undefined;
      if (rapidFire && attack.category === "rate_limit") {
        console.log(`  ${progress} ${attack.name} (${rapidFire}x rapid-fire)...`);
        const cleanPayload = { ...attack.payload };
        delete (cleanPayload as Record<string, unknown>)._rapidFire;
        const cleanAttack = { ...attack, payload: cleanPayload };

        const responses = await executeRapidFire(config, cleanAttack, rapidFire);
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
          result.findings.push(`All ${rapidFire} requests succeeded — rate limit not enforced`);
        } else if (got429) {
          result.verdict = "FAIL";
          result.findings.push(`Rate limit correctly enforced — got 429 after ${responses.filter((r) => r.statusCode === 200).length} requests`);
        }

        const icon = result.verdict === "PASS" ? "!!" : result.verdict === "FAIL" ? "OK" : "??";
        console.log(`    [${icon}] ${result.verdict} — ${result.findings[0] ?? ""}`);
        roundResults.push(result);
        continue;
      }

      // Multi-turn attack
      if (attack.steps && attack.steps.length > 0) {
        const totalSteps = 1 + attack.steps.length;
        process.stdout.write(`  ${progress} ${attack.name} (${totalSteps} steps)...`);

        const { results: stepResults, stoppedEarly } = await executeMultiTurn(
          config,
          attack,
          async (cfg, atk, sc, b, t) => {
            const r = await analyzeResponse(cfg, atk, sc, b, t);
            return { verdict: r.verdict, findings: r.findings };
          },
        );

        const lastStep = stepResults[stepResults.length - 1];
        const result = await analyzeResponse(config, attack, lastStep.statusCode, lastStep.body, lastStep.timeMs);
        result.stepIndex = lastStep.stepIndex;
        result.totalSteps = stepResults.length;

        const icon = result.verdict === "PASS" ? "!!" : result.verdict === "PARTIAL" ? "~" : result.verdict === "FAIL" ? "OK" : "??";
        const earlyTag = stoppedEarly ? ` (stopped at step ${lastStep.stepIndex + 1})` : "";
        console.log(` [${icon}] ${result.verdict} (${lastStep.statusCode}, ${lastStep.timeMs}ms)${earlyTag}`);
        if (result.findings.length > 0) {
          console.log(`    ${result.findings[0]}`);
        }

        roundResults.push(result);
      } else {
        // Single-turn attack
        process.stdout.write(`  ${progress} ${attack.name}...`);
        const { statusCode, body, timeMs } = await executeAttack(config, attack);
        const result = await analyzeResponse(config, attack, statusCode, body, timeMs);

        const icon = result.verdict === "PASS" ? "!!" : result.verdict === "PARTIAL" ? "~" : result.verdict === "FAIL" ? "OK" : "??";
        console.log(` [${icon}] ${result.verdict} (${statusCode}, ${timeMs}ms)`);
        if (result.findings.length > 0) {
          console.log(`    ${result.findings[0]}`);
        }

        roundResults.push(result);
      }

      // Delay between requests
      if (config.attackConfig.delayBetweenRequestsMs > 0) {
        await sleep(config.attackConfig.delayBetweenRequestsMs);
      }
    }

    rounds.push({ round, results: roundResults });
    allPreviousResults = allPreviousResults.concat(roundResults);
    console.log(`  Round ${round}: ${roundResults.filter((r) => r.verdict === "PASS").length} vulns found`);
  }

  // 5. Generate report
  console.log("\n[5/5] Generating report...");
  const targetUrl = `${config.target.baseUrl}${config.target.agentEndpoint}`;
  const report = generateReport(targetUrl, rounds);
  const { jsonPath, mdPath } = writeReport(report);
  console.log(`  JSON: ${jsonPath}`);
  console.log(`  Markdown: ${mdPath}`);

  printConsoleSummary(report);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
