#!/usr/bin/env npx tsx
/**
 * Submit a red-team run and show live terminal progress bar.
 *
 * Usage:
 *   npx tsx scripts/run-with-progress.ts configs/config.insurance.json
 *   npm run scan -- configs/config.insurance.json
 *
 * Options:
 *   --dashboard URL   Dashboard URL (default: http://localhost:4200)
 *   --docker          Auto-replace localhost with host.docker.internal
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const args = process.argv.slice(2);
let configPath = "";
let dashboardUrl = "http://localhost:4200";
let dockerMode = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === "--dashboard" && args[i + 1]) { dashboardUrl = args[++i]; }
  else if (args[i] === "--docker") { dockerMode = true; }
  else if (!args[i].startsWith("-")) { configPath = args[i]; }
}

if (!configPath) {
  console.error("\n  Usage: npx tsx scripts/run-with-progress.ts <config.json> [--docker] [--dashboard URL]\n");
  process.exit(1);
}

// Load config
let configJson = readFileSync(resolve(configPath), "utf-8");
if (dockerMode) {
  configJson = configJson.replace(/localhost:(\d+)/g, "host.docker.internal:$1");
}
const config = JSON.parse(configJson);

// Terminal helpers
const COLORS = {
  reset: "\x1b[0m",
  red: "\x1b[91m",
  green: "\x1b[92m",
  yellow: "\x1b[93m",
  blue: "\x1b[94m",
  gray: "\x1b[90m",
  bold: "\x1b[1m",
  cyan: "\x1b[96m",
};

function progressBar(current: number, total: number, width = 30): string {
  const pct = total > 0 ? current / total : 0;
  const filled = Math.round(pct * width);
  const empty = width - filled;
  const bar = "█".repeat(filled) + "░".repeat(empty);
  return `${bar} ${Math.round(pct * 100)}%`;
}

function verdictIcon(verdict: string): string {
  switch (verdict) {
    case "PASS": return `${COLORS.red}✗${COLORS.reset}`;
    case "FAIL": return `${COLORS.green}✓${COLORS.reset}`;
    case "PARTIAL": return `${COLORS.yellow}~${COLORS.reset}`;
    default: return `${COLORS.gray}?${COLORS.reset}`;
  }
}

async function main() {
  console.log(`\n  ${COLORS.bold}🛡️  Red Team Security Scan${COLORS.reset}\n`);
  console.log(`  Target: ${COLORS.cyan}${config.target?.baseUrl || "unknown"}${config.target?.agentEndpoint || ""}${COLORS.reset}`);
  console.log(`  Config: ${configPath}`);
  console.log(`  Dashboard: ${dashboardUrl}\n`);

  // Submit run
  let runId: string;
  try {
    const res = await fetch(`${dashboardUrl}/api/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(config),
    });
    if (!res.ok) {
      const err = await res.text();
      console.error(`  ${COLORS.red}Failed to start run: ${res.status} ${err}${COLORS.reset}`);
      process.exit(1);
    }
    const data = await res.json() as { runId: string };
    runId = data.runId;
  } catch (err) {
    console.error(`  ${COLORS.red}Can't reach dashboard at ${dashboardUrl}${COLORS.reset}`);
    console.error(`  Is it running? Try: docker compose up -d\n`);
    process.exit(1);
  }

  console.log(`  Run ID: ${COLORS.blue}${runId.slice(0, 8)}${COLORS.reset}`);
  console.log(`  View live: ${dashboardUrl} → Runs tab\n`);

  // Poll for progress
  let lastResultCount = 0;
  let progressOffset = 0;
  const startTime = Date.now();

  const poll = setInterval(async () => {
    try {
      const res = await fetch(`${dashboardUrl}/api/run/${runId}?since=${progressOffset}`);
      const data = await res.json() as Record<string, unknown>;
      progressOffset = (data.progressTotal as number) || 0;

      const allProgress = (data.progress as Record<string, unknown>[]) || [];
      const status = data.status as string;

      // Count results from all progress
      const resultEvents = allProgress.filter(p => (p as Record<string, unknown>).result);
      const totalResults = progressOffset; // approximate

      // Get latest phase message
      const latestNonResult = allProgress.filter(p => (p as Record<string, unknown>).phase !== "result").pop() as Record<string, unknown> | undefined;
      const phase = (latestNonResult?.phase as string) || "";
      const message = (latestNonResult?.message as string) || "";

      // Count verdicts from new results
      const newResults = resultEvents.map(p => (p as Record<string, unknown>).result as Record<string, unknown>);

      // Print new results
      for (const r of newResults.slice(lastResultCount > 0 ? 0 : 0)) {
        if (r && lastResultCount < (data.progressTotal as number || 0)) {
          // Only print first time
        }
      }

      // Get summary if available
      const summary = data.summary as Record<string, number> | undefined;

      // Calculate elapsed
      const elapsed = Math.round((Date.now() - startTime) / 1000);
      const mins = Math.floor(elapsed / 60);
      const secs = elapsed % 60;
      const timeStr = mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;

      // Clear line and print progress
      process.stdout.write("\r\x1b[K");

      if (status === "running") {
        // Show progress bar based on phase
        let estimatedTotal = 100;
        let estimatedCurrent = progressOffset;

        if (summary) {
          estimatedTotal = summary.totalAttacks || 100;
          estimatedCurrent = (summary.passed || 0) + (summary.failed || 0) + (summary.partial || 0) + (summary.errors || 0);
        }

        const bar = progressBar(Math.min(estimatedCurrent, estimatedTotal), estimatedTotal);
        const phaseLabel = phase ? `[${phase}]` : "";

        process.stdout.write(
          `  ${COLORS.blue}${bar}${COLORS.reset} ${COLORS.gray}${phaseLabel}${COLORS.reset} ${message.slice(0, 50)} ${COLORS.gray}(${timeStr})${COLORS.reset}`
        );
      } else if (status === "done" || status === "error" || status === "cancelled") {
        clearInterval(poll);
        console.log();

        if (status === "done" && summary) {
          const score = summary.score ?? 0;
          const scoreColor = score >= 70 ? COLORS.green : score >= 40 ? COLORS.yellow : COLORS.red;

          console.log(`\n  ${COLORS.bold}═══════════════════════════════════════${COLORS.reset}`);
          console.log(`  ${COLORS.bold}Scan Complete${COLORS.reset} (${timeStr})`);
          console.log(`  ${COLORS.bold}═══════════════════════════════════════${COLORS.reset}\n`);
          console.log(`  Score:   ${scoreColor}${COLORS.bold}${score}/100${COLORS.reset}`);
          console.log(`  Attacks: ${summary.totalAttacks}`);
          console.log(`  Vulns:   ${COLORS.red}${summary.passed}${COLORS.reset}`);
          console.log(`  Blocked: ${COLORS.green}${summary.failed}${COLORS.reset}`);
          console.log(`  Partial: ${COLORS.yellow}${summary.partial}${COLORS.reset}`);
          if (summary.errors) console.log(`  Errors:  ${COLORS.gray}${summary.errors}${COLORS.reset}`);
          console.log(`\n  Run ID:  ${COLORS.blue}${runId}${COLORS.reset}`);
          console.log(`  Report:  ${dashboardUrl} → Reports tab`);
          console.log(`  Risk:    ${dashboardUrl} → Risk tab`);
          console.log();
        } else if (status === "cancelled") {
          console.log(`\n  ${COLORS.yellow}Scan cancelled${COLORS.reset} (${timeStr})\n`);
        } else {
          const error = (data.error as string) || "Unknown error";
          console.log(`\n  ${COLORS.red}Scan failed: ${error}${COLORS.reset}\n`);

          // Check if partial results exist
          if (summary && summary.totalAttacks > 0) {
            console.log(`  Partial results: ${summary.totalAttacks} attacks, ${summary.passed} vulns found`);
            console.log(`  Check: ${dashboardUrl} → Reports tab\n`);
          }
        }

        process.exit(status === "done" ? 0 : 1);
      }
    } catch {
      // transient error, keep polling
    }
  }, 2000);
}

main().catch((err) => {
  console.error("Error:", err.message);
  process.exit(1);
});
