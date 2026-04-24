#!/usr/bin/env npx tsx
/**
 * Interactive config generator — chat-style CLI that asks questions,
 * generates a config with reasoning, and lets the user refine before running.
 *
 * Usage:
 *   npm run gen:interactive
 *   npx tsx scripts/gen-interactive.ts
 */

import { createInterface } from "node:readline/promises";
import { writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { execSync } from "node:child_process";
import { loadEnvFile } from "../lib/env-loader.js";
import { ALL_ATTACK_CATEGORIES } from "../lib/types.js";
import { ALL_STRATEGIES } from "../lib/attack-strategies.js";

loadEnvFile();

const rl = createInterface({ input: process.stdin, output: process.stdout });

async function ask(prompt: string, defaultVal?: string): Promise<string> {
  const suffix = defaultVal ? ` [${defaultVal}]` : "";
  const answer = (await rl.question(`  ${prompt}${suffix}: `)).trim();
  return answer || defaultVal || "";
}

async function choose(prompt: string, options: string[]): Promise<string> {
  console.log(`\n  ${prompt}`);
  options.forEach((o, i) => console.log(`    [${i + 1}] ${o}`));
  const answer = await ask("Choice", "1");
  const idx = parseInt(answer, 10) - 1;
  return options[Math.max(0, Math.min(idx, options.length - 1))];
}

// Category domain mapping for smart selection
const CATEGORY_DOMAINS: Record<string, string[]> = {
  "Prompt Injection & Jailbreak": ["prompt_injection", "indirect_prompt_injection", "content_filter_bypass", "instruction_hierarchy_violation", "special_token_injection", "cross_lingual_attack", "universal_adversarial_trigger"],
  "Data Exfiltration & Privacy": ["data_exfiltration", "sensitive_data", "pii_disclosure", "training_data_extraction", "steganographic_exfiltration", "out_of_band_exfiltration", "slow_burn_exfiltration", "side_channel_inference"],
  "Auth & Access Control": ["auth_bypass", "rbac_bypass", "session_hijacking", "cross_tenant_access", "identity_privilege", "debug_access"],
  "Agent & Tool Abuse": ["tool_misuse", "tool_chain_hijack", "tool_output_manipulation", "agentic_workflow_bypass", "goal_hijack", "rogue_agent", "multi_agent_delegation", "agentic_scope_creep", "tool_permission_escalation"],
  "Safety & Harmful Content": ["toxic_content", "harmful_advice", "drug_synthesis", "weapons_violence", "misinformation", "hallucination", "hallucination_inducement", "bias_exploitation", "hate_speech_dogwhistle"],
  "Output & Response Attacks": ["output_evasion", "insecure_output_handling", "structured_output_injection", "markdown_link_injection", "format_confusion_attack"],
  "RAG & Retrieval": ["rag_poisoning", "rag_corpus_poisoning", "retrieval_ranking_attack", "vector_store_manipulation", "chunk_boundary_injection", "embedding_inversion", "retrieval_tenant_bleed"],
  "Model Security": ["model_extraction", "model_inversion", "membership_inference", "backdoor_trigger", "data_poisoning", "model_fingerprinting", "capability_elicitation", "alignment_faking", "reward_hacking"],
  "Compliance & Regulatory": ["regulatory_violation", "medical_safety", "financial_compliance", "pharmacy_safety", "insurance_compliance", "housing_discrimination", "copyright_infringement", "gdpr_erasure_bypass"],
  "Infrastructure & DoS": ["ssrf", "path_traversal", "shell_injection", "sql_injection", "rate_limit", "model_dos", "token_flooding_dos", "sandbox_escape"],
  "Supply Chain": ["supply_chain", "mcp_server_compromise", "plugin_manifest_spoofing", "sdk_dependency_attack"],
  "Social Engineering & Manipulation": ["social_engineering", "psychological_manipulation", "emotional_manipulation", "sycophancy_exploitation", "overreliance", "over_refusal", "conversation_manipulation", "multi_turn_escalation"],
};

function selectCategoriesForGoal(goal: string): { categories: string[]; reasons: Record<string, string> } {
  const g = goal.toLowerCase();
  const selected: string[] = [];
  const reasons: Record<string, string> = {};

  const matchers: [string[], string, string][] = [
    [["safety", "harmful", "toxic", "content", "advice", "medical", "drug"], "Safety & Harmful Content", "Tests if the model generates harmful, toxic, or dangerous content"],
    [["injection", "prompt", "jailbreak", "bypass"], "Prompt Injection & Jailbreak", "Tests if safety controls can be overridden via prompt manipulation"],
    [["data", "leak", "exfil", "pii", "privacy", "secret"], "Data Exfiltration & Privacy", "Tests if the model leaks sensitive data, PII, or credentials"],
    [["auth", "access", "rbac", "session", "privilege"], "Auth & Access Control", "Tests authentication and authorization boundaries"],
    [["tool", "agent", "function", "action", "scope"], "Agent & Tool Abuse", "Tests if agent tools can be misused or hijacked"],
    [["output", "evasion", "filter", "guardrail"], "Output & Response Attacks", "Tests if output filters and guardrails can be bypassed"],
    [["rag", "retrieval", "vector", "embedding"], "RAG & Retrieval", "Tests RAG pipeline vulnerabilities"],
    [["model", "extraction", "fingerprint", "alignment"], "Model Security", "Tests model-level security (extraction, backdoors, alignment)"],
    [["compliance", "regulatory", "hipaa", "gdpr", "financial", "insurance"], "Compliance & Regulatory", "Tests compliance with industry regulations"],
    [["infra", "dos", "ssrf", "sql", "shell", "sandbox"], "Infrastructure & DoS", "Tests infrastructure-level vulnerabilities"],
    [["supply", "mcp", "plugin"], "Supply Chain", "Tests supply chain and plugin security"],
    [["social", "manipulat", "escalat", "conversation", "multi-turn", "crescendo"], "Social Engineering & Manipulation", "Tests social engineering and multi-turn escalation attacks"],
    [["misinformation", "hallucination", "fake", "false"], "Safety & Harmful Content", "Tests for misinformation and hallucination vulnerabilities"],
    [["everything", "all", "comprehensive", "full"], "ALL", "Comprehensive test across all domains"],
  ];

  for (const [keywords, domain, reason] of matchers) {
    if (keywords.some(k => g.includes(k))) {
      if (domain === "ALL") {
        // Select from every domain
        for (const [d, cats] of Object.entries(CATEGORY_DOMAINS)) {
          const pick = cats.slice(0, 4);
          selected.push(...pick);
          reasons[d] = "Comprehensive testing — sampling top categories from each domain";
        }
        break;
      }
      const cats = CATEGORY_DOMAINS[domain] || [];
      selected.push(...cats);
      reasons[domain] = reason;
    }
  }

  // Always include prompt injection (most fundamental test)
  if (!selected.includes("prompt_injection")) {
    selected.unshift("prompt_injection");
    reasons["Prompt Injection & Jailbreak"] = reasons["Prompt Injection & Jailbreak"] || "Always included — most fundamental LLM security test";
  }

  return { categories: [...new Set(selected)], reasons };
}

function selectStrategiesForGoal(goal: string): { strategies: string[]; reasons: string[] } {
  const g = goal.toLowerCase();
  const strategies: string[] = [];
  const reasons: string[] = [];

  // Always include core strategies
  strategies.push(
    "base64_context_hint", "rot13_cipher_trick", "reverse_instruction",
    "educational_series_framing", "fiction_writing_escape",
    "incremental_escalation_setup", "building_on_previous_context",
  );
  reasons.push("Core encoding + escalation strategies (always included)");

  if (g.includes("social") || g.includes("manipulat") || g.includes("everything") || g.includes("all")) {
    strategies.push("life_or_death_emergency", "ego_boosting_capability_challenge", "authority_mimicry_security_manager", "victim_narrative");
    reasons.push("Social engineering — urgency, authority, and emotional manipulation");
  }

  if (g.includes("jailbreak") || g.includes("bypass") || g.includes("everything") || g.includes("all")) {
    strategies.push("dan_style_persona", "forced_persona_red_team_ai", "jailbreak_continuation", "dual_response_request");
    reasons.push("Jailbreak techniques — persona override, continuation attacks");
  }

  if (g.includes("multi-turn") || g.includes("escalat") || g.includes("crescendo") || g.includes("everything") || g.includes("all")) {
    strategies.push("crescendo_multi_turn", "progressive_normalisation", "simulated_multi_turn_conversation");
    reasons.push("Multi-turn escalation — gradual trust building and topic shifting");
  }

  if (g.includes("encod") || g.includes("obfusc") || g.includes("everything") || g.includes("all")) {
    strategies.push("hex_encoding", "morse_code_encoding", "caesar_cipher_rot_n", "leetspeak_obfuscation", "unicode_homoglyph_hint", "ascii_art_injection", "emoji_braille_encoding");
    reasons.push("Advanced encoding — hex, morse, caesar, ASCII art, emoji steganography");
  }

  if (g.includes("academic") || g.includes("research") || g.includes("everything") || g.includes("all")) {
    strategies.push("academic_computation_disguise", "historical_educational_framing", "peer_review_framing");
    reasons.push("Academic framing — disguise attacks as research/educational requests");
  }

  return { strategies: [...new Set(strategies)], reasons };
}

async function main() {
  console.log("\n  ╔══════════════════════════════════════════╗");
  console.log("  ║   Red Team AI — Interactive Config Gen   ║");
  console.log("  ╚══════════════════════════════════════════╝\n");

  // Step 1: Gather info
  console.log("  Step 1: Tell me about your app\n");
  const slug = await ask("Config name (slug)", "my-app");
  const baseUrl = await ask("App URL", "http://host.docker.internal:4000");
  const endpoint = await ask("Chat/agent endpoint path", "/v1/chat/completions");
  const appDetails = await ask("Describe your app (tools, roles, data it handles)");
  const whatToTest = await ask("What do you want to test?", "everything — safety, injection, data leaks, compliance");

  // Step 2: Auth
  console.log("\n  Step 2: Authentication\n");
  const authMethod = await choose("How does your app authenticate?", [
    "No auth (public endpoint)",
    "API key in header",
    "Bearer token",
    "JWT with secret",
  ]);

  let auth: Record<string, unknown>;
  if (authMethod.includes("No auth")) {
    auth = { methods: ["none"], apiKeys: {} };
  } else if (authMethod.includes("API key")) {
    const key = await ask("API key value (or env var name like $MY_KEY)");
    auth = { methods: ["api_key"], apiKeys: { default: key } };
  } else if (authMethod.includes("Bearer")) {
    const token = await ask("Bearer token (or env var name)");
    auth = { methods: ["bearer"], bearerToken: token };
  } else {
    const secret = await ask("JWT secret");
    auth = { methods: ["jwt"], jwtSecret: secret, credentials: [], apiKeys: {} };
  }

  // Step 3: Smart category selection with reasoning
  console.log("\n  Step 3: Selecting attack categories\n");
  const { categories, reasons } = selectCategoriesForGoal(whatToTest + " " + appDetails);

  console.log("  Selected " + categories.length + " categories based on your goals:\n");
  for (const [domain, reason] of Object.entries(reasons)) {
    const domainCats = CATEGORY_DOMAINS[domain] || [];
    const matched = domainCats.filter(c => categories.includes(c));
    console.log("    ✓ " + domain + " (" + matched.length + " categories)");
    console.log("      Reason: " + reason);
    console.log("      → " + matched.join(", "));
    console.log();
  }

  // Step 4: Strategy selection with reasoning
  const { strategies, reasons: stratReasons } = selectStrategiesForGoal(whatToTest);
  console.log("  Selected " + strategies.length + " attack strategies:\n");
  for (const reason of stratReasons) {
    console.log("    ✓ " + reason);
  }
  console.log();

  // Step 5: Intensity
  console.log("  Step 4: Attack intensity\n");
  const intensity = await choose("How thorough should the test be?", [
    "Quick scan (1 round, 2 attacks/category, ~5 min)",
    "Standard (2 rounds, 5 attacks/category, ~20 min)",
    "Deep scan (3 rounds, 10 attacks/category, ~60 min)",
  ]);

  let rounds = 2, maxAttacks = 5, multiTurnRate = 0.6;
  if (intensity.includes("Quick")) { rounds = 1; maxAttacks = 2; multiTurnRate = 0.3; }
  if (intensity.includes("Deep")) { rounds = 3; maxAttacks = 10; multiTurnRate = 0.7; }

  // Step 6: LLM provider
  console.log("\n  Step 5: LLM provider for attack generation\n");
  const provider = await choose("Which LLM provider for generating attacks?", [
    "anthropic (Claude)",
    "together (Llama, DeepSeek, Kimi)",
    "openai (GPT)",
    "openrouter (any model)",
  ]);
  const providerName = provider.split(" ")[0];

  let model = "claude-sonnet-4-20250514";
  if (providerName === "together") model = await ask("Model name", "deepseek-ai/DeepSeek-V3");
  else if (providerName === "openai") model = await ask("Model name", "gpt-4o");
  else if (providerName === "openrouter") model = await ask("Model name", "anthropic/claude-sonnet-4-20250514");

  // Build config
  const isOpenAICompatible = endpoint.includes("chat/completions");
  const config: Record<string, unknown> = {
    target: {
      type: "http_agent",
      baseUrl,
      agentEndpoint: endpoint,
      applicationDetails: appDetails,
      ...(isOpenAICompatible ? {
        customApiTemplate: {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          bodyTemplate: '{"model": "your-model", "messages": [{"role": "user", "content": "{{message}}"}]}',
          responsePath: "choices[0].message.content",
        },
      } : {}),
    },
    codebasePath: null,
    codebaseGlob: "**/*.ts",
    auth,
    requestSchema: {
      messageField: "message",
      roleField: "role",
      ...(isOpenAICompatible ? {} : { apiKeyField: "api_key" }),
    },
    responseSchema: {
      responsePath: isOpenAICompatible ? "choices[0].message.content" : "response",
      ...(isOpenAICompatible ? { toolCallsPath: "choices[0].message.tool_calls" } : {}),
    },
    sensitivePatterns: ["sk-proj-", "sk_live_", "AKIA", "xoxb-", "password", "secret", "token", "credentials"],
    attackConfig: {
      adaptiveRounds: rounds,
      maxAttacksPerCategory: maxAttacks,
      concurrency: 3,
      delayBetweenRequestsMs: 300,
      llmProvider: providerName,
      llmModel: model,
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

  // Show summary
  const totalEstimate = categories.length * maxAttacks * rounds;
  console.log("\n  ┌──────────────────────────────────────────┐");
  console.log("  │         Config Summary                   │");
  console.log("  ├──────────────────────────────────────────┤");
  console.log("  │  Target: " + baseUrl);
  console.log("  │  Categories: " + categories.length);
  console.log("  │  Strategies: " + strategies.length);
  console.log("  │  Rounds: " + rounds + " adaptive");
  console.log("  │  Attacks/category: " + maxAttacks);
  console.log("  │  Multi-turn rate: " + (multiTurnRate * 100) + "%");
  console.log("  │  Estimated attacks: ~" + totalEstimate);
  console.log("  │  LLM: " + providerName + "/" + model);
  console.log("  │  Judge: anthropic/claude-sonnet-4");
  console.log("  └──────────────────────────────────────────┘\n");

  // Iterate
  let done = false;
  while (!done) {
    const action = await choose("What would you like to do?", [
      "Save config and exit",
      "Save config and run immediately",
      "Add more categories",
      "Remove categories",
      "Change intensity (rounds/attacks)",
      "View full JSON",
      "Start over",
    ]);

    if (action.includes("Save config and exit") || action.includes("Save config and run")) {
      const outDir = resolve(process.cwd(), "configs");
      mkdirSync(outDir, { recursive: true });
      const outPath = resolve(outDir, `config.${slug}.json`);
      writeFileSync(outPath, JSON.stringify(config, null, 2));
      console.log("\n  ✓ Config saved: " + outPath);

      if (action.includes("run")) {
        console.log("  Starting red-team run...\n");
        try {
          execSync(`npx tsx red-team.ts ${outPath}`, { stdio: "inherit" });
        } catch {
          console.log("\n  Run finished (or was interrupted).");
        }
      }
      done = true;

    } else if (action.includes("Add more")) {
      console.log("\n  Available domains:");
      for (const [domain, cats] of Object.entries(CATEGORY_DOMAINS)) {
        const inConfig = cats.filter(c => (config.attackConfig as Record<string, unknown[]>).enabledCategories.includes(c));
        console.log("    " + (inConfig.length > 0 ? "✓" : "○") + " " + domain + " (" + inConfig.length + "/" + cats.length + ")");
      }
      const addDomain = await ask("Add domain (type name or 'all')");
      const ad = addDomain.toLowerCase();
      for (const [domain, cats] of Object.entries(CATEGORY_DOMAINS)) {
        if (ad === "all" || domain.toLowerCase().includes(ad)) {
          const current = (config.attackConfig as Record<string, string[]>).enabledCategories;
          for (const c of cats) {
            if (!current.includes(c)) current.push(c);
          }
          console.log("  ✓ Added " + domain + " categories");
        }
      }
      console.log("  Now: " + ((config.attackConfig as Record<string, string[]>).enabledCategories.length) + " categories");

    } else if (action.includes("Remove")) {
      const cats = (config.attackConfig as Record<string, string[]>).enabledCategories;
      console.log("\n  Current categories (" + cats.length + "):");
      for (const [domain, domCats] of Object.entries(CATEGORY_DOMAINS)) {
        const inConfig = domCats.filter(c => cats.includes(c));
        if (inConfig.length > 0) {
          console.log("    " + domain + ": " + inConfig.join(", "));
        }
      }
      const removeDomain = await ask("Remove domain (type name)");
      const rd = removeDomain.toLowerCase();
      for (const [domain, domCats] of Object.entries(CATEGORY_DOMAINS)) {
        if (domain.toLowerCase().includes(rd)) {
          (config.attackConfig as Record<string, string[]>).enabledCategories =
            cats.filter(c => !domCats.includes(c));
          console.log("  ✓ Removed " + domain + " categories");
        }
      }
      console.log("  Now: " + ((config.attackConfig as Record<string, string[]>).enabledCategories.length) + " categories");

    } else if (action.includes("Change intensity")) {
      const newIntensity = await choose("New intensity?", [
        "Quick (1 round, 2/category)",
        "Standard (2 rounds, 5/category)",
        "Deep (3 rounds, 10/category)",
        "Custom",
      ]);
      const ac = config.attackConfig as Record<string, unknown>;
      if (newIntensity.includes("Quick")) { ac.adaptiveRounds = 1; ac.maxAttacksPerCategory = 2; }
      else if (newIntensity.includes("Standard")) { ac.adaptiveRounds = 2; ac.maxAttacksPerCategory = 5; }
      else if (newIntensity.includes("Deep")) { ac.adaptiveRounds = 3; ac.maxAttacksPerCategory = 10; }
      else {
        ac.adaptiveRounds = parseInt(await ask("Rounds", "2"), 10);
        ac.maxAttacksPerCategory = parseInt(await ask("Attacks per category", "5"), 10);
      }
      console.log("  ✓ Updated: " + ac.adaptiveRounds + " rounds, " + ac.maxAttacksPerCategory + " attacks/category");

    } else if (action.includes("View full JSON")) {
      console.log("\n" + JSON.stringify(config, null, 2) + "\n");

    } else if (action.includes("Start over")) {
      console.log("  Restarting...\n");
      rl.close();
      return main();
    }
  }

  rl.close();
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
