#!/usr/bin/env npx tsx
/**
 * AI Red Team Assistant — natural language terminal interface.
 *
 * Usage:
 *   npm run ai
 *   npx tsx scripts/ai-assistant.ts
 *
 * Talk naturally: "test my app at localhost:3000 for safety issues"
 * The assistant generates configs, runs scans, shows results, and suggests guardrails.
 */

import { createInterface } from "node:readline/promises";
import { writeFileSync, readFileSync, mkdirSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import { spawn } from "node:child_process";
import { loadEnvFile } from "../lib/env-loader.js";
import { ALL_ATTACK_CATEGORIES } from "../lib/types.js";
import { ALL_STRATEGIES } from "../lib/attack-strategies.js";
import { loadComplianceFrameworks } from "../lib/compliance-loader.js";

loadEnvFile();

const rl = createInterface({ input: process.stdin, output: process.stdout });

// ── Session state ──
let currentConfig: Record<string, unknown> | null = null;
let currentConfigPath: string | null = null;
let lastRunId: string | null = null;
let lastResults: Record<string, unknown>[] = [];
let dashboardUrl = process.env.DASHBOARD_URL || "http://localhost:4200";

// ── LLM for intent parsing ──
async function callLlm(system: string, userMsg: string): Promise<string> {
  const provider = process.env.AI_ASSISTANT_PROVIDER || "anthropic";
  const model = process.env.AI_ASSISTANT_MODEL || "claude-sonnet-4-20250514";

  if (provider === "anthropic") {
    const key = process.env.ANTHROPIC_API_KEY;
    if (!key) throw new Error("ANTHROPIC_API_KEY not set");
    const res = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model,
        max_tokens: 2048,
        system,
        messages: [{ role: "user", content: userMsg }],
      }),
    });
    const data = await res.json() as Record<string, unknown>;
    const content = data.content as { text: string }[];
    return content?.[0]?.text || "";
  } else {
    // OpenAI-compatible (together, openai, openrouter)
    const key = provider === "together" ? process.env.TOGETHER_API_KEY
      : provider === "openrouter" ? process.env.OPENROUTER_API_KEY
      : process.env.OPENAI_API_KEY;
    const baseUrl = provider === "together" ? "https://api.together.xyz/v1"
      : provider === "openrouter" ? "https://openrouter.ai/api/v1"
      : "https://api.openai.com/v1";
    if (!key) throw new Error(`${provider.toUpperCase()}_API_KEY not set`);
    const res = await fetch(`${baseUrl}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", "authorization": `Bearer ${key}` },
      body: JSON.stringify({
        model,
        messages: [{ role: "system", content: system }, { role: "user", content: userMsg }],
        max_tokens: 2048,
      }),
    });
    const data = await res.json() as Record<string, unknown>;
    const choices = data.choices as { message: { content: string } }[];
    return choices?.[0]?.message?.content || "";
  }
}

// ── Intent classification ──
type Intent = "generate_config" | "run_scan" | "show_status" | "show_results" | "suggest_guardrails" | "run_compliance" | "analyze_risk" | "show_help" | "save_report" | "show_config" | "general_question";

async function classifyIntent(input: string): Promise<{ intent: Intent; params: Record<string, string> }> {
  const lower = input.toLowerCase();

  // Fast pattern matching for common intents (no LLM needed)
  if (/^(help|commands|\?)$/i.test(lower)) return { intent: "show_help", params: {} };
  if (/^(status|progress)$/i.test(lower)) return { intent: "show_status", params: {} };
  if (/^(results?|findings?|show pass|show vuln)/i.test(lower)) return { intent: "show_results", params: {} };
  if (/^(save|export|download)/i.test(lower)) return { intent: "save_report", params: {} };
  if (/show.*config|view.*config|describe|whats the (file|config)|current config|print config|display config/i.test(lower)) return { intent: "show_config" as Intent, params: {} };
  if (/guardrail|fix|remediat|protect|shield|defend/i.test(lower)) return { intent: "suggest_guardrails", params: {} };
  if (/compliance|owasp|nist|mitre|gdpr|hipaa|pci/i.test(lower)) return { intent: "run_compliance", params: {} };
  if (/risk|impact|business|financial/i.test(lower)) return { intent: "analyze_risk", params: {} };
  if (/^run\b|start scan|execute|launch/i.test(lower)) return { intent: "run_scan", params: {} };
  if (/create.*config|generate.*config|make.*config|setup.*config|config.*for|new config|build.*config/i.test(lower)) {
    const urlMatch = input.match(/https?:\/\/[^\s]+/);
    return { intent: "generate_config", params: { url: urlMatch?.[0] || "", description: input } };
  }
  if (/test|scan|attack|red.?team|check|probe|assess/i.test(lower)) {
    // Extract URL if present
    const urlMatch = input.match(/https?:\/\/[^\s]+/);
    return { intent: "generate_config", params: { url: urlMatch?.[0] || "", description: input } };
  }

  return { intent: "general_question", params: { question: input } };
}

// ── Smart defaults ──

function selectDefaultCategories(focus: string): string[] {
  const lower = focus.toLowerCase();
  const base = ["prompt_injection", "indirect_prompt_injection", "content_filter_bypass", "output_evasion", "hallucination"];

  if (/everything|all|full|comprehensive/i.test(lower)) {
    return [...ALL_ATTACK_CATEGORIES].slice(0, 40); // Top 40 most important
  }

  const groups: Record<string, string[]> = {
    safety: ["toxic_content", "harmful_advice", "drug_synthesis", "weapons_violence", "csam_minor_safety", "emotional_manipulation", "medical_safety"],
    injection: ["prompt_injection", "indirect_prompt_injection", "cross_session_injection", "special_token_injection", "instruction_hierarchy_violation"],
    exfiltration: ["data_exfiltration", "sensitive_data", "pii_disclosure", "steganographic_exfiltration", "slow_burn_exfiltration", "training_data_extraction"],
    auth: ["auth_bypass", "rbac_bypass", "session_hijacking", "cross_tenant_access", "identity_privilege"],
    agent: ["tool_misuse", "tool_chain_hijack", "agentic_workflow_bypass", "rogue_agent", "goal_hijack", "agentic_scope_creep", "tool_permission_escalation", "sandbox_escape"],
    rag: ["rag_poisoning", "rag_corpus_poisoning", "vector_store_manipulation", "retrieval_ranking_attack", "chunk_boundary_injection", "retrieval_tenant_bleed"],
    compliance: ["regulatory_violation", "gdpr_erasure_bypass", "financial_compliance", "insurance_compliance", "copyright_infringement"],
    bias: ["bias_exploitation", "housing_discrimination", "hate_speech_dogwhistle"],
    infra: ["ssrf", "path_traversal", "shell_injection", "sql_injection", "supply_chain"],
  };

  const selected = new Set(base);
  for (const [key, cats] of Object.entries(groups)) {
    if (lower.includes(key) || cats.some(c => lower.includes(c.replace(/_/g, " ")))) {
      cats.forEach(c => selected.add(c));
    }
  }

  // Add safety by default
  if (selected.size <= base.length) {
    groups.safety.forEach(c => selected.add(c));
    groups.exfiltration.forEach(c => selected.add(c));
  }

  return [...selected].filter(c => ALL_ATTACK_CATEGORIES.includes(c as never));
}

function selectDefaultStrategies(): string[] {
  return [
    "base64_context_hint", "rot13_cipher_trick", "reverse_instruction",
    "educational_series_framing", "fiction_writing_escape", "incremental_escalation_setup",
    "building_on_previous_context", "life_or_death_emergency", "ego_boosting_capability_challenge",
    "authority_mimicry_security_manager", "victim_narrative", "dan_style_persona",
    "forced_persona_red_team_ai", "jailbreak_continuation", "dual_response_request",
    "crescendo_multi_turn", "progressive_normalisation", "simulated_multi_turn_conversation",
    "hex_encoding", "caesar_cipher_rot_n", "leetspeak_obfuscation",
    "academic_computation_disguise", "historical_educational_framing", "peer_review_framing",
  ];
}

// ── Actions ──

async function handleGenerateConfig(params: Record<string, string>) {
  console.log("\n  🔧 Let me set up a scan config...\n");

  const url = params.url || await prompt("  Target URL: ");
  const endpoint = await prompt("  Endpoint path [/v1/chat/completions]: ") || "/v1/chat/completions";
  const description = params.description || await prompt("  What does your app do? ");
  const whatToTest = await prompt("  What to test? [everything]: ") || "everything";
  const intensity = await prompt("  Intensity? (quick/standard/deep) [standard]: ") || "standard";

  // Use LLM to select categories
  console.log("\n  🤖 Analyzing your app and selecting attack categories...\n");

  const frameworks = loadComplianceFrameworks();
  const frameworkNames = frameworks.map(f => f.name).join(", ");

  const llmResponse = await callLlm(
    `You are an AI security expert. Given an app description and what to test, select the most relevant attack categories and strategies.

Available categories (${ALL_ATTACK_CATEGORIES.length}): ${ALL_ATTACK_CATEGORIES.join(", ")}

Available strategy slugs (${ALL_STRATEGIES.length}): ${ALL_STRATEGIES.map(s => s.slug).join(", ")}

Compliance frameworks available: ${frameworkNames}

Return a JSON object:
{
  "categories": ["cat1", "cat2", ...],  // 10-25 most relevant categories
  "strategies": ["strat1", "strat2", ...],  // 15-30 most relevant strategies
  "reasoning": "Brief explanation of why these were chosen",
  "suggestedCompliance": ["framework1", "framework2"]  // which compliance frameworks to run
}

Only use category IDs and strategy slugs from the lists above. Return ONLY JSON.`,
    `App: ${url}${endpoint}
Description: ${description}
Test focus: ${whatToTest}`
  );

  let categories: string[] = [];
  let strategies: string[] = [];
  let reasoning = "";
  let suggestedCompliance: string[] = [];

  try {
    const cleaned = llmResponse.replace(/```(?:json)?\s*/g, "").replace(/```/g, "").trim();
    const jsonMatch = cleaned.match(/\{[\s\S]*\}/);
    if (!jsonMatch) throw new Error("No JSON found in LLM response");
    const parsed = JSON.parse(jsonMatch[0]);

    // Validate categories against known list
    const rawCategories = (parsed.categories || []) as string[];
    categories = rawCategories.filter((c: string) => ALL_ATTACK_CATEGORIES.includes(c as never));

    // If LLM returned categories but none matched, it may have used different naming — try fuzzy match
    if (categories.length === 0 && rawCategories.length > 0) {
      console.log("  ⚠ LLM categories didn't match known list, using smart defaults for: " + whatToTest);
      categories = selectDefaultCategories(whatToTest);
    }

    // Validate strategies
    const allSlugs = new Set(ALL_STRATEGIES.map(s => s.slug));
    const rawStrategies = (parsed.strategies || []) as string[];
    strategies = rawStrategies.filter((s: string) => allSlugs.has(s));

    if (strategies.length === 0 && rawStrategies.length > 0) {
      strategies = selectDefaultStrategies();
    }

    reasoning = parsed.reasoning || "";
    suggestedCompliance = parsed.suggestedCompliance || [];
  } catch (parseErr) {
    console.log("  ⚠ LLM response parsing failed, using smart defaults for: " + whatToTest);
    categories = selectDefaultCategories(whatToTest);
    strategies = selectDefaultStrategies();
    reasoning = "Using curated category set based on test focus: " + whatToTest;
  }

  // Final safety net — never produce 0 categories
  if (categories.length === 0) {
    categories = selectDefaultCategories(whatToTest);
    reasoning = reasoning || "Using default categories for general AI safety testing.";
  }
  if (strategies.length === 0) {
    strategies = selectDefaultStrategies();
  }

  // Set intensity
  let rounds = 2, maxAttacks = 5, multiTurnRate = 0.6;
  if (intensity === "quick") { rounds = 1; maxAttacks = 2; multiTurnRate = 0.3; }
  if (intensity === "deep") { rounds = 3; maxAttacks = 10; multiTurnRate = 0.7; }

  const isOpenAI = endpoint.includes("chat/completions");
  currentConfig = {
    target: {
      type: "http_agent",
      baseUrl: url,
      agentEndpoint: endpoint,
      applicationDetails: description,
      ...(isOpenAI ? {
        customApiTemplate: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          bodyTemplate: '{"model": "your-model", "messages": [{"role": "user", "content": "{{message}}"}]}',
          responsePath: "choices[0].message.content",
        },
      } : {}),
    },
    codebasePath: null,
    auth: { methods: ["none"], apiKeys: {} },
    requestSchema: { messageField: "message" },
    responseSchema: { responsePath: isOpenAI ? "choices[0].message.content" : "response" },
    sensitivePatterns: ["sk-proj-", "sk_live_", "AKIA", "password", "secret", "token"],
    attackConfig: {
      adaptiveRounds: rounds,
      maxAttacksPerCategory: maxAttacks,
      concurrency: 3,
      delayBetweenRequestsMs: 300,
      llmProvider: process.env.AI_ASSISTANT_PROVIDER || "anthropic",
      llmModel: process.env.AI_ASSISTANT_MODEL || "claude-sonnet-4-20250514",
      judgeProvider: "anthropic",
      judgeModel: "claude-sonnet-4-20250514",
      enableLlmGeneration: true,
      enableMultiTurnGeneration: true,
      multiTurnGenerationRate: multiTurnRate,
      enableAdaptiveMultiTurn: true,
      maxAdaptiveTurns: 15,
      maxMultiTurnSteps: 5,
      strategiesPerRound: 5,
      requireReviewConfirmation: false,
      enabledCategories: categories,
      enabledStrategies: strategies,
    },
  };

  console.log("  ✓ Config generated\n");
  console.log("  📋 " + reasoning + "\n");
  console.log("  Categories: " + categories.length);
  console.log("  Strategies: " + strategies.length);
  console.log("  Rounds: " + rounds + " | Attacks/category: " + maxAttacks);
  console.log("  Multi-turn rate: " + (multiTurnRate * 100) + "%");
  console.log("  Est. attacks: ~" + (categories.length * maxAttacks * rounds));
  if (suggestedCompliance.length > 0) {
    console.log("  Suggested compliance: " + suggestedCompliance.join(", "));
  }
  console.log('\n  Say "run" to start the scan, or describe changes to adjust.\n');
}

function handleShowConfig() {
  if (!currentConfig) {
    console.log('\n  No config yet. Describe your app first, e.g., "create config for my app at localhost:3000"\n');
    return;
  }

  const ac = currentConfig.attackConfig as Record<string, unknown>;
  const target = currentConfig.target as Record<string, unknown>;
  const categories = (ac.enabledCategories as string[]) || [];
  const strategies = (ac.enabledStrategies as string[]) || [];

  console.log("\n  ══════════════════════════════════════");
  console.log("  Current Config");
  console.log("  ══════════════════════════════════════\n");
  console.log("  Target:      " + (target.baseUrl || "") + (target.agentEndpoint || ""));
  console.log("  Description: " + ((target.applicationDetails as string) || "").slice(0, 80));
  console.log("  Provider:    " + ac.llmProvider + " / " + ac.llmModel);
  console.log("  Judge:       " + (ac.judgeProvider || ac.llmProvider) + " / " + (ac.judgeModel || ac.llmModel));
  console.log("  Rounds:      " + ac.adaptiveRounds);
  console.log("  Attacks/cat: " + ac.maxAttacksPerCategory);
  console.log("  Concurrency: " + ac.concurrency);
  console.log("  Multi-turn:  " + (ac.enableMultiTurnGeneration ? "on (" + Math.round((ac.multiTurnGenerationRate as number || 0) * 100) + "%)" : "off"));

  console.log("\n  Categories (" + categories.length + "):");
  for (let i = 0; i < categories.length; i += 4) {
    console.log("    " + categories.slice(i, i + 4).join(", "));
  }

  console.log("\n  Strategies (" + strategies.length + "):");
  for (let i = 0; i < strategies.length; i += 3) {
    console.log("    " + strategies.slice(i, i + 3).join(", "));
  }

  if (currentConfigPath) {
    console.log("\n  File: " + currentConfigPath);
  }
  console.log('\n  Say "run" to execute, or describe changes to adjust.\n');
}

async function handleRunScan() {
  if (!currentConfig) {
    console.log('\n  No config yet. Describe your app first, e.g., "test my chatbot at localhost:3000"\n');
    return;
  }

  // Save config
  const slug = "ai-scan-" + Date.now();
  const outDir = resolve(process.cwd(), "configs");
  mkdirSync(outDir, { recursive: true });
  currentConfigPath = resolve(outDir, `config.${slug}.json`);
  writeFileSync(currentConfigPath, JSON.stringify(currentConfig, null, 2));
  console.log("\n  📁 Config saved: " + currentConfigPath);

  // Try dashboard API first
  try {
    const res = await fetch(`${dashboardUrl}/api/run`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(currentConfig),
    });
    if (res.ok) {
      const data = await res.json() as { runId: string };
      lastRunId = data.runId;
      console.log("  🚀 Scan started via dashboard API (run: " + lastRunId?.slice(0, 8) + ")");
      console.log("  📊 View live at: " + dashboardUrl + " → Runs tab");
      console.log('  Say "status" to check progress or "results" when done.\n');
      return;
    }
  } catch {
    // Dashboard not available, run CLI
  }

  console.log("  🚀 Starting scan via CLI...\n");
  const child = spawn("npx", ["tsx", "red-team.ts", currentConfigPath], {
    stdio: "inherit",
    cwd: process.cwd(),
  });

  child.on("close", (code) => {
    console.log("\n  Scan finished (exit " + code + ")");
    console.log('  Say "results" to see findings or "guardrails" for fix suggestions.\n');
  });
}

async function handleShowStatus() {
  if (!lastRunId) {
    console.log('\n  No active run. Say "run" to start one.\n');
    return;
  }

  try {
    const res = await fetch(`${dashboardUrl}/api/run/${lastRunId}`);
    const data = await res.json() as Record<string, unknown>;
    const progress = data.progress as Record<string, unknown>[] || [];
    const results = progress.filter(p => (p as Record<string, unknown>).result);

    console.log("\n  Status: " + (data.status as string)?.toUpperCase());
    console.log("  Attacks completed: " + results.length);

    const lastProgress = progress[progress.length - 1] as Record<string, unknown> | undefined;
    if (lastProgress) {
      console.log("  Latest: [" + lastProgress.phase + "] " + (lastProgress.message as string)?.slice(0, 80));
    }

    if (data.summary) {
      const s = data.summary as Record<string, number>;
      console.log("  Score: " + s.score + " | Vulns: " + s.passed + " | Blocked: " + s.failed);
    }
    console.log();
  } catch {
    console.log("\n  Can't reach dashboard at " + dashboardUrl + ". Is it running?\n");
  }
}

async function handleShowResults() {
  if (!lastRunId) {
    console.log('\n  No run results yet. Say "run" to start a scan.\n');
    return;
  }

  try {
    const res = await fetch(`${dashboardUrl}/api/run/${lastRunId}`);
    const data = await res.json() as Record<string, unknown>;
    const progress = data.progress as Record<string, unknown>[] || [];
    const results = progress.filter(p => (p as Record<string, unknown>).result).map(p => (p as Record<string, unknown>).result as Record<string, unknown>);
    lastResults = results;

    const passes = results.filter(r => r.verdict === "PASS");
    const partials = results.filter(r => r.verdict === "PARTIAL");
    const fails = results.filter(r => r.verdict === "FAIL");

    console.log("\n  ══════════════════════════════════════");
    console.log("  Results: " + results.length + " attacks");
    console.log("  PASS (vulns): " + passes.length + " | PARTIAL: " + partials.length + " | FAIL (blocked): " + fails.length);
    console.log("  ══════════════════════════════════════\n");

    if (passes.length > 0) {
      console.log("  🔴 Vulnerabilities Found:\n");
      passes.forEach((r, i) => {
        console.log("  " + (i + 1) + ". [" + (r.severity as string)?.toUpperCase() + "] " + r.name);
        console.log("     Category: " + r.category);
        if (r.llmReasoning) console.log("     " + (r.llmReasoning as string).slice(0, 120));
        console.log();
      });
    }

    if (partials.length > 0) {
      console.log("  🟡 Partial Leaks (" + partials.length + "):\n");
      partials.slice(0, 5).forEach((r, i) => {
        console.log("  " + (i + 1) + ". " + r.name + " — " + ((r.llmReasoning as string) || "").slice(0, 80));
      });
      if (partials.length > 5) console.log("  ... and " + (partials.length - 5) + " more");
      console.log();
    }

    console.log('  Say "guardrails" for fix suggestions, "compliance" for compliance mapping, or "risk" for impact analysis.\n');
  } catch {
    console.log("\n  Can't reach dashboard. Is it running?\n");
  }
}

// Votal Shield guardrail mapping — maps attack categories to specific guardrails
const SHIELD_GUARDRAILS: Record<string, { guardrail: string; endpoint: string; config: string }> = {
  prompt_injection: {
    guardrail: "adversarial-prompt-detection",
    endpoint: "POST /guardrails/input",
    config: '{"input": {"adversarial-prompt-detection": {"enabled": true, "action": "block", "threshold": 0.8}}}',
  },
  indirect_prompt_injection: {
    guardrail: "adversarial-prompt-detection + topic-restriction",
    endpoint: "POST /guardrails/input",
    config: '{"input": {"adversarial-prompt-detection": {"enabled": true, "action": "block", "threshold": 0.7}, "topic-restriction": {"enabled": true, "action": "block", "customRules": {"mode": "whitelist", "topics": ["your-allowed-topics"]}}}}',
  },
  content_filter_bypass: {
    guardrail: "keyword-blocklist + adversarial-prompt-detection",
    endpoint: "POST /guardrails/input",
    config: '{"input": {"keyword-blocklist": {"enabled": true, "action": "block", "blocklist": ["ignore instructions", "bypass", "jailbreak"]}, "adversarial-prompt-detection": {"enabled": true, "action": "block"}}}',
  },
  toxic_content: {
    guardrail: "toxicity-detection (output)",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"toxicity-detection": {"enabled": true, "action": "block", "threshold": 0.7}}}',
  },
  hallucination: {
    guardrail: "hallucination-detection (output)",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"hallucination-detection": {"enabled": true, "action": "flag", "threshold": 0.6}}}',
  },
  pii_disclosure: {
    guardrail: "pii-detection (output) + output-redaction",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"pii-detection": {"enabled": true, "action": "redact"}, "output-redaction": {"enabled": true, "clearanceLevel": "standard"}}}',
  },
  sensitive_data: {
    guardrail: "pii-detection + keyword-blocklist (output)",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"pii-detection": {"enabled": true, "action": "redact"}, "keyword-blocklist": {"enabled": true, "action": "block", "blocklist": ["sk-proj-", "AKIA", "password"]}}}',
  },
  data_exfiltration: {
    guardrail: "pii-detection + output-redaction",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"pii-detection": {"enabled": true, "action": "block"}, "output-redaction": {"enabled": true, "clearanceLevel": "restricted"}}}',
  },
  harmful_advice: {
    guardrail: "topic-restriction + toxicity-detection",
    endpoint: "POST /guardrails/input + /guardrails/output",
    config: '{"input": {"topic-restriction": {"enabled": true, "action": "block", "customRules": {"mode": "blacklist", "topics": ["weapons", "drugs", "self-harm", "illegal"]}}}, "output": {"toxicity-detection": {"enabled": true, "action": "block"}}}',
  },
  misinformation: {
    guardrail: "hallucination-detection + factual-grounding",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"hallucination-detection": {"enabled": true, "action": "flag", "threshold": 0.5}}}',
  },
  output_evasion: {
    guardrail: "output-format-validation + pii-detection",
    endpoint: "POST /guardrails/output",
    config: '{"output": {"pii-detection": {"enabled": true, "action": "block"}, "keyword-blocklist": {"enabled": true, "action": "block", "blocklist": ["base64", "hex encoded"]}}}',
  },
  tool_misuse: {
    guardrail: "agentic tool authorization",
    endpoint: "POST /guardrails/output (agentic mode)",
    config: '{"output": {"agentic": {"enabled": true, "action": "block", "toolPolicies": {"read_file": {"allowed": true, "pathPatterns": ["/safe/*"]}, "send_email": {"allowed": false}}}}}',
  },
};

async function handleSuggestGuardrails() {
  if (lastResults.length === 0) {
    console.log('\n  No results to analyze. Run a scan first.\n');
    return;
  }

  const passes = lastResults.filter(r => r.verdict === "PASS");
  const partials = lastResults.filter(r => r.verdict === "PARTIAL");

  if (passes.length === 0 && partials.length === 0) {
    console.log("\n  ✅ No vulnerabilities found — your app defended well!\n");
    return;
  }

  console.log("\n  🛡️ Guardrail Recommendations\n");
  console.log("  ═══════════════════════════════════════\n");

  // Group vulnerabilities by category
  const byCat: Record<string, typeof passes> = {};
  [...passes, ...partials].forEach(r => {
    const cat = r.category as string;
    if (!byCat[cat]) byCat[cat] = [];
    byCat[cat].push(r);
  });

  // Show Votal Shield guardrail recommendations
  const catsWithShield = Object.keys(byCat).filter(c => SHIELD_GUARDRAILS[c]);
  const catsWithoutShield = Object.keys(byCat).filter(c => !SHIELD_GUARDRAILS[c]);

  if (catsWithShield.length > 0) {
    console.log("  ┌─ Votal Shield Guardrails (ready to deploy) ─────────────────┐\n");

    for (const cat of catsWithShield) {
      const shield = SHIELD_GUARDRAILS[cat];
      const vulns = byCat[cat];
      const passCount = vulns.filter(r => r.verdict === "PASS").length;
      const catLabel = cat.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase());

      console.log("  🔴 " + catLabel + " (" + passCount + " PASS, " + (vulns.length - passCount) + " PARTIAL)");
      console.log("     Guardrail: " + shield.guardrail);
      console.log("     Endpoint:  " + shield.endpoint);
      console.log("     Config:");
      console.log("     " + shield.config);
      console.log();
    }

    console.log("  Deploy Votal Shield: https://github.com/sundi133/llm-shield");
    console.log("  Proxy mode: Replace your LLM endpoint with /v1/shield/chat/completions");
    console.log("  It sits between your app and LLM — no code changes needed.\n");
  }

  if (catsWithoutShield.length > 0) {
    console.log("  ┌─ Additional Recommendations ──────────────────────────────────┐\n");

    const vulnSummary = catsWithoutShield.map(cat => {
      const vulns = byCat[cat];
      return `- ${cat}: ${vulns.length} findings (${vulns.filter(r => r.verdict === "PASS").length} PASS)`;
    }).join("\n");

    console.log("  🤖 Generating AI-powered recommendations...\n");

    const response = await callLlm(
      `You are an AI security engineer. Suggest specific, actionable guardrails for these vulnerability categories. Be concise — 2-3 sentences per category with a concrete fix.`,
      `Vulnerabilities found:\n${vulnSummary}\n\nFor each category, suggest: (1) what guardrail to add, (2) where in the pipeline, (3) one-line implementation hint.`
    );

    console.log("  " + response.split("\n").join("\n  "));
    console.log();
  }

  console.log('  Say "save" to export, or ask follow-up questions.\n');
}

async function handleRunCompliance() {
  if (lastResults.length === 0 && !lastRunId) {
    console.log('\n  No results to analyze. Run a scan first.\n');
    return;
  }

  const frameworks = loadComplianceFrameworks();
  console.log("\n  Available compliance frameworks (" + frameworks.length + "):");
  frameworks.forEach((f, i) => console.log("    " + (i + 1) + ". " + f.name + " (" + f.items.length + " controls)"));
  console.log("\n  Compliance analysis runs in the Compliance tab of the dashboard.");
  console.log("  Open: " + dashboardUrl + " → Compliance tab\n");
}

async function handleAnalyzeRisk() {
  if (lastResults.length === 0) {
    console.log('\n  No results to analyze. Run a scan first.\n');
    return;
  }

  console.log("\n  Risk analysis runs in the Risk tab of the dashboard.");
  console.log("  Open: " + dashboardUrl + " → Risk tab\n");
}

async function handleSaveReport() {
  if (!currentConfig && lastResults.length === 0) {
    console.log('\n  Nothing to save yet.\n');
    return;
  }

  const outDir = resolve(process.cwd(), "configs");
  mkdirSync(outDir, { recursive: true });

  if (currentConfigPath) {
    console.log("  Config: " + currentConfigPath);
  }

  if (lastResults.length > 0) {
    const reportPath = resolve(outDir, "results-" + Date.now() + ".json");
    writeFileSync(reportPath, JSON.stringify(lastResults, null, 2));
    console.log("  Results: " + reportPath);
  }

  console.log("  ✓ Saved\n");
}

async function handleGeneralQuestion(question: string) {
  const context = currentConfig
    ? `Current config targets: ${(currentConfig.target as Record<string, unknown>)?.baseUrl}`
    : "No config set yet.";
  const resultsContext = lastResults.length > 0
    ? `Last scan: ${lastResults.length} attacks, ${lastResults.filter(r => r.verdict === "PASS").length} vulns found.`
    : "No scan results yet.";

  const response = await callLlm(
    `You are a helpful AI red-teaming assistant. You help users test their AI applications for security vulnerabilities.

Context: ${context}. ${resultsContext}

Available commands: test/scan (generate config), run (execute scan), status (check progress), results (show findings), guardrails (suggest fixes), compliance (run compliance), risk (analyze risk), save (export), help.

Available attack categories: ${ALL_ATTACK_CATEGORIES.length}
Available strategies: ${ALL_STRATEGIES.length}
Available compliance frameworks: ${loadComplianceFrameworks().map(f => f.name).join(", ")}

Answer concisely. If the user seems to want to do something, suggest the right command.`,
    question
  );

  console.log("\n  " + response.split("\n").join("\n  ") + "\n");
}

function showHelp() {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║         Red Team AI Assistant                ║
  ╚══════════════════════════════════════════════╝

  Talk naturally or use these commands:

  🔧 Config & Scan
    "test my app at <url>"     Generate a scan config
    "run" / "start"            Execute the scan
    "status"                   Check run progress
    "results" / "findings"     Show attack results

  🛡️ Analysis
    "guardrails" / "fix"       Suggest fixes for vulnerabilities
    "compliance"               Run compliance mapping
    "risk"                     Analyze business impact

  📁 Export
    "save" / "export"          Save config and results

  💡 Examples
    "test my chatbot at localhost:3000 for prompt injection"
    "scan https://api.acme.com/chat for everything"
    "show me the vulnerabilities"
    "how do I fix the prompt injection issues?"
    "what compliance frameworks should I check?"

  Type "quit" or "exit" to leave.
`);
}

async function prompt(text: string): Promise<string> {
  return (await rl.question(text)).trim();
}

// ── Main REPL ──

async function main() {
  console.log(`
  ╔══════════════════════════════════════════════╗
  ║    🛡️  Red Team AI Assistant                 ║
  ║    Talk naturally about AI security testing  ║
  ╚══════════════════════════════════════════════╝

  Type "help" for commands, or just describe what you want to test.
`);

  while (true) {
    const input = await prompt("  > ");
    if (!input) continue;
    if (/^(quit|exit|bye|q)$/i.test(input)) {
      console.log("\n  Goodbye! 👋\n");
      break;
    }

    try {
      const { intent, params } = await classifyIntent(input);

      switch (intent) {
        case "show_help": showHelp(); break;
        case "generate_config": await handleGenerateConfig(params); break;
        case "run_scan": await handleRunScan(); break;
        case "show_status": await handleShowStatus(); break;
        case "show_results": await handleShowResults(); break;
        case "suggest_guardrails": await handleSuggestGuardrails(); break;
        case "run_compliance": await handleRunCompliance(); break;
        case "analyze_risk": await handleAnalyzeRisk(); break;
        case "save_report": await handleSaveReport(); break;
        case "show_config": handleShowConfig(); break;
        case "general_question": await handleGeneralQuestion(input); break;
      }
    } catch (err) {
      console.log("\n  ❌ Error: " + (err instanceof Error ? err.message : String(err)) + "\n");
    }
  }

  rl.close();
}

main().catch(console.error);
