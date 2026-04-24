/**
 * Shared tool handlers for the target-analyst workflow.
 *
 * Used by both:
 *   - tool-server.ts  (HTTP transport, for manual testing)
 *   - mcp-server.ts   (MCP stdio transport, registered with Hermes via `hermes mcp add`)
 *
 * Each handler takes a plain args object and returns a JSON-serializable result.
 */

import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { glob } from "glob";

export interface ReadRepoArgs {
  path: string;
  pattern?: string;
  maxFiles?: number;
  maxBytesPerFile?: number;
}

export async function readRepo({
  path,
  pattern = "**/*.{ts,tsx,js,py,md,json,yaml,yml}",
  maxFiles = 40,
  maxBytesPerFile = 20_000,
}: ReadRepoArgs) {
  const abs = resolve(path);
  const files = await glob(pattern, {
    cwd: abs,
    nodir: true,
    absolute: true,
    ignore: ["**/node_modules/**", "**/dist/**", "**/.next/**"],
  });
  const picked = files.slice(0, maxFiles);
  const out: { path: string; content: string; truncated: boolean }[] = [];
  for (const f of picked) {
    try {
      const buf = await readFile(f);
      const truncated = buf.length > maxBytesPerFile;
      out.push({
        path: f.replace(abs + "/", ""),
        content: buf.slice(0, maxBytesPerFile).toString("utf8"),
        truncated,
      });
    } catch {
      // skip unreadable files
    }
  }
  return { root: abs, total: files.length, returned: out.length, files: out };
}

export interface ProbeTargetArgs {
  baseUrl: string;
  endpoint: string;
  message: string;
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
}

export async function probeTarget({
  baseUrl,
  endpoint,
  message,
  headers = {},
  body = {},
}: ProbeTargetArgs) {
  const url = baseUrl.replace(/\/$/, "") + endpoint;
  const started = Date.now();
  try {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify({ message, ...body }),
    });
    const txt = await r.text();
    let parsed: unknown = txt;
    try {
      parsed = JSON.parse(txt);
    } catch {
      /* keep raw */
    }
    return {
      status: r.status,
      timeMs: Date.now() - started,
      responseHeaders: Object.fromEntries(r.headers.entries()),
      body: parsed,
    };
  } catch (e: any) {
    return { status: 0, timeMs: Date.now() - started, error: String(e?.message ?? e) };
  }
}

export interface ReadPriorReportsArgs {
  dir?: string;
  limit?: number;
}

export async function readPriorReports({ dir = "report", limit = 3 }: ReadPriorReportsArgs) {
  const abs = resolve(dir);
  if (!existsSync(abs)) return { dir: abs, reports: [] };
  const files = (await glob("report-*.json", { cwd: abs, absolute: true }))
    .sort()
    .reverse()
    .slice(0, limit);
  const reports: unknown[] = [];
  for (const f of files) {
    try {
      const buf = await readFile(f, "utf8");
      const json = JSON.parse(buf);
      reports.push({
        file: f.replace(abs + "/", ""),
        target: json.target ?? json.config?.target,
        score: json.score,
        summary: json.summary,
        categoryBreakdown: json.categoryBreakdown,
        topFindings: (json.findings ?? []).slice(0, 15),
      });
    } catch {
      /* skip */
    }
  }
  return { dir: abs, reports };
}

export interface WriteConfigArgs {
  path: string;
  config: unknown;
}

export async function writeConfig({ path, config }: WriteConfigArgs) {
  const abs = resolve(path);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, JSON.stringify(config, null, 2));
  return { written: abs, bytes: (await readFile(abs)).length };
}

export interface WriteCustomAttacksArgs {
  path: string;
  rows: Array<Record<string, string>>;
}

export async function writeCustomAttacks({ path, rows }: WriteCustomAttacksArgs) {
  const abs = resolve(path);
  await mkdir(dirname(abs), { recursive: true });
  if (abs.endsWith(".json")) {
    await writeFile(abs, JSON.stringify(rows, null, 2));
  } else {
    const headers = Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
    const esc = (v: string) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [headers.join(","), ...rows.map((r) => headers.map((h) => esc(r[h] ?? "")).join(","))];
    await writeFile(abs, lines.join("\n"));
  }
  return { written: abs, rows: rows.length };
}

export interface WritePolicyArgs {
  path: string;
  policy: unknown;
}

export async function writePolicy({ path, policy }: WritePolicyArgs) {
  const abs = resolve(path);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, JSON.stringify(policy, null, 2));
  return { written: abs };
}

// ── Tool metadata used by both MCP and HTTP transports ──

export const TOOL_DEFS = [
  {
    name: "read_repo",
    description:
      "Read a local source tree. Returns up to maxFiles files truncated to maxBytesPerFile each. Use to discover tool names, roles, guardrails, sensitive data flows in the target app.",
    inputSchema: {
      type: "object",
      required: ["path"],
      properties: {
        path: { type: "string", description: "Absolute or relative path to the target repo root" },
        pattern: { type: "string", description: "Glob pattern (default: **/*.{ts,tsx,js,py,md,json,yaml,yml})" },
        maxFiles: { type: "integer", description: "Max files to return (default 40)" },
        maxBytesPerFile: { type: "integer", description: "Max bytes per file (default 20000)" },
      },
    },
  },
  {
    name: "probe_target",
    description:
      "Send a BENIGN message to the live target AI app. Observe JSON shape, refusal language, tool-call format. Do NOT use for attacks.",
    inputSchema: {
      type: "object",
      required: ["baseUrl", "endpoint", "message"],
      properties: {
        baseUrl: { type: "string" },
        endpoint: { type: "string" },
        message: { type: "string" },
        headers: { type: "object", description: "Additional headers (e.g. Authorization)" },
        body: { type: "object", description: "Additional body fields merged with {message}" },
      },
    },
  },
  {
    name: "read_prior_reports",
    description:
      "Ingest prior wb-red-team reports from the report/ dir so the new config builds on past findings.",
    inputSchema: {
      type: "object",
      properties: {
        dir: { type: "string", description: "Default: report" },
        limit: { type: "integer", description: "Default: 3" },
      },
    },
  },
  {
    name: "write_config",
    description: "Emit a wb-red-team config JSON to disk.",
    inputSchema: {
      type: "object",
      required: ["path", "config"],
      properties: { path: { type: "string" }, config: { type: "object" } },
    },
  },
  {
    name: "write_custom_attacks",
    description:
      "Emit the customAttacksFile as CSV (.csv) or JSON (.json). rows is an array of {category, prompt, role, note}.",
    inputSchema: {
      type: "object",
      required: ["path", "rows"],
      properties: { path: { type: "string" }, rows: { type: "array" } },
    },
  },
  {
    name: "write_policy",
    description: "Emit a judge policy JSON with target-specific category overrides.",
    inputSchema: {
      type: "object",
      required: ["path", "policy"],
      properties: { path: { type: "string" }, policy: { type: "object" } },
    },
  },
  // ── New tools: run, status, results, guardrails, reference ──
  {
    name: "run_scan",
    description:
      "Start a red-team security scan. Pass the config JSON or a path to a config file. Returns a runId. The scan runs in the background — use check_run_status to poll.",
    inputSchema: {
      type: "object",
      required: ["config"],
      properties: {
        config: { type: "object", description: "The full wb-red-team config JSON object" },
        dashboardUrl: { type: "string", description: "Dashboard URL (default: http://localhost:4200)" },
      },
    },
  },
  {
    name: "check_run_status",
    description:
      "Check the status of a running red-team scan. Returns status (queued/running/done/error), attack count, and latest progress.",
    inputSchema: {
      type: "object",
      required: ["runId"],
      properties: {
        runId: { type: "string" },
        dashboardUrl: { type: "string", description: "Default: http://localhost:4200" },
      },
    },
  },
  {
    name: "get_run_results",
    description:
      "Get the full results of a completed red-team scan. Returns all attack verdicts, findings, and threat assessments.",
    inputSchema: {
      type: "object",
      required: ["runId"],
      properties: {
        runId: { type: "string" },
        dashboardUrl: { type: "string", description: "Default: http://localhost:4200" },
      },
    },
  },
  {
    name: "cancel_run",
    description: "Cancel a running red-team scan.",
    inputSchema: {
      type: "object",
      required: ["runId"],
      properties: {
        runId: { type: "string" },
        dashboardUrl: { type: "string", description: "Default: http://localhost:4200" },
      },
    },
  },
  {
    name: "list_categories_and_strategies",
    description:
      "List all available attack categories (141) and delivery strategies (143) with their compliance framework mappings. Use to help users choose which categories to include in their config.",
    inputSchema: {
      type: "object",
      properties: {
        dashboardUrl: { type: "string", description: "Default: http://localhost:4200" },
      },
    },
  },
  {
    name: "suggest_guardrails",
    description:
      "Given red-team scan results (PASS verdicts), suggest specific guardrails using Votal Shield (llm-shield). Returns guardrail configs for /guardrails/input and /guardrails/output endpoints.",
    inputSchema: {
      type: "object",
      required: ["vulnerabilities"],
      properties: {
        vulnerabilities: {
          type: "array",
          description: "Array of {category, name, severity, reasoning} for PASS results",
          items: {
            type: "object",
            properties: {
              category: { type: "string" },
              name: { type: "string" },
              severity: { type: "string" },
              reasoning: { type: "string" },
            },
          },
        },
      },
    },
  },
] as const;

// ── New tool implementations ──

const DEFAULT_DASHBOARD = "http://localhost:4200";

async function runScan({ config, dashboardUrl }: { config: unknown; dashboardUrl?: string }) {
  const url = (dashboardUrl || DEFAULT_DASHBOARD) + "/api/run";
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(config),
  });
  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Failed to start scan: ${res.status} ${err}`);
  }
  return res.json();
}

async function checkRunStatus({ runId, dashboardUrl }: { runId: string; dashboardUrl?: string }) {
  const url = (dashboardUrl || DEFAULT_DASHBOARD) + "/api/run/" + runId;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Run not found: ${res.status}`);
  const data = await res.json() as Record<string, unknown>;
  const progress = data.progress as Record<string, unknown>[] || [];
  const results = progress.filter(p => (p as Record<string, unknown>).result);
  const lastMsg = progress.length > 0 ? progress[progress.length - 1] : null;

  return {
    runId,
    status: data.status,
    attacksCompleted: results.length,
    latestPhase: (lastMsg as Record<string, unknown>)?.phase,
    latestMessage: ((lastMsg as Record<string, unknown>)?.message as string)?.slice(0, 100),
    summary: data.summary,
    error: data.error,
  };
}

async function getRunResults({ runId, dashboardUrl }: { runId: string; dashboardUrl?: string }) {
  const url = (dashboardUrl || DEFAULT_DASHBOARD) + "/api/run/" + runId;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Run not found: ${res.status}`);
  const data = await res.json() as Record<string, unknown>;
  const progress = data.progress as Record<string, unknown>[] || [];
  const results = progress
    .filter(p => (p as Record<string, unknown>).result)
    .map(p => (p as Record<string, unknown>).result);

  const passes = results.filter(r => (r as Record<string, unknown>).verdict === "PASS");
  const partials = results.filter(r => (r as Record<string, unknown>).verdict === "PARTIAL");
  const fails = results.filter(r => (r as Record<string, unknown>).verdict === "FAIL");

  return {
    runId,
    status: data.status,
    total: results.length,
    passed: passes.length,
    partial: partials.length,
    failed: fails.length,
    summary: data.summary,
    vulnerabilities: passes.map((r: unknown) => {
      const res = r as Record<string, unknown>;
      return {
        category: res.category,
        name: res.name,
        severity: res.severity,
        verdict: res.verdict,
        reasoning: (res.llmReasoning as string)?.slice(0, 200),
        findings: res.findings,
      };
    }),
    partialLeaks: partials.slice(0, 10).map((r: unknown) => {
      const res = r as Record<string, unknown>;
      return { category: res.category, name: res.name, severity: res.severity };
    }),
  };
}

async function cancelRun({ runId, dashboardUrl }: { runId: string; dashboardUrl?: string }) {
  const url = (dashboardUrl || DEFAULT_DASHBOARD) + "/api/run/" + runId;
  const res = await fetch(url, { method: "DELETE" });
  return res.json();
}

async function listCategoriesAndStrategies({ dashboardUrl }: { dashboardUrl?: string }) {
  const url = (dashboardUrl || DEFAULT_DASHBOARD) + "/api/reference";
  try {
    const res = await fetch(url);
    if (res.ok) return res.json();
  } catch {
    // Dashboard not available — return from local imports
  }
  // Fallback: load directly
  const { ALL_ATTACK_CATEGORIES } = await import("../lib/types.js");
  const { ALL_STRATEGIES } = await import("../lib/attack-strategies.js");
  return {
    categories: ALL_ATTACK_CATEGORIES,
    strategies: ALL_STRATEGIES.map((s: { slug: string; name: string; levelName: string }) => ({
      slug: s.slug, name: s.name, level: s.levelName,
    })),
  };
}

// Votal Shield guardrail mapping
const SHIELD_GUARDRAIL_MAP: Record<string, { guardrail: string; endpoint: string; config: string }> = {
  prompt_injection: { guardrail: "adversarial-prompt-detection", endpoint: "/guardrails/input", config: '{"adversarial-prompt-detection": {"enabled": true, "action": "block", "threshold": 0.8}}' },
  indirect_prompt_injection: { guardrail: "adversarial-prompt-detection + topic-restriction", endpoint: "/guardrails/input", config: '{"adversarial-prompt-detection": {"enabled": true, "threshold": 0.7}, "topic-restriction": {"enabled": true, "customRules": {"mode": "whitelist", "topics": ["allowed-topics"]}}}' },
  content_filter_bypass: { guardrail: "keyword-blocklist + adversarial-prompt-detection", endpoint: "/guardrails/input", config: '{"keyword-blocklist": {"enabled": true, "action": "block"}, "adversarial-prompt-detection": {"enabled": true}}' },
  toxic_content: { guardrail: "toxicity-detection", endpoint: "/guardrails/output", config: '{"toxicity-detection": {"enabled": true, "action": "block", "threshold": 0.7}}' },
  hallucination: { guardrail: "hallucination-detection", endpoint: "/guardrails/output", config: '{"hallucination-detection": {"enabled": true, "action": "flag", "threshold": 0.6}}' },
  pii_disclosure: { guardrail: "pii-detection + output-redaction", endpoint: "/guardrails/output", config: '{"pii-detection": {"enabled": true, "action": "redact"}}' },
  sensitive_data: { guardrail: "pii-detection + keyword-blocklist", endpoint: "/guardrails/output", config: '{"pii-detection": {"enabled": true, "action": "block"}, "keyword-blocklist": {"enabled": true, "blocklist": ["sk-proj-", "AKIA", "password"]}}' },
  data_exfiltration: { guardrail: "pii-detection + output-redaction", endpoint: "/guardrails/output", config: '{"pii-detection": {"enabled": true, "action": "block"}, "output-redaction": {"enabled": true, "clearanceLevel": "restricted"}}' },
  harmful_advice: { guardrail: "topic-restriction + toxicity-detection", endpoint: "/guardrails/input + /guardrails/output", config: '{"topic-restriction": {"enabled": true, "customRules": {"mode": "blacklist", "topics": ["weapons", "drugs", "self-harm"]}}}' },
  misinformation: { guardrail: "hallucination-detection", endpoint: "/guardrails/output", config: '{"hallucination-detection": {"enabled": true, "action": "flag"}}' },
  output_evasion: { guardrail: "output-format-validation + pii-detection", endpoint: "/guardrails/output", config: '{"pii-detection": {"enabled": true, "action": "block"}}' },
  tool_misuse: { guardrail: "agentic tool authorization", endpoint: "/guardrails/output (agentic)", config: '{"agentic": {"enabled": true, "toolPolicies": {"dangerous_tool": {"allowed": false}}}}' },
};

function suggestGuardrails({ vulnerabilities }: { vulnerabilities: { category: string; name: string; severity: string; reasoning?: string }[] }) {
  const suggestions = vulnerabilities.map(v => {
    const shield = SHIELD_GUARDRAIL_MAP[v.category];
    return {
      vulnerability: v.name,
      category: v.category,
      severity: v.severity,
      shieldGuardrail: shield ? {
        guardrail: shield.guardrail,
        endpoint: shield.endpoint,
        config: shield.config,
        deployUrl: "https://github.com/sundi133/llm-shield",
      } : null,
      generalFix: shield ? null : `Add input/output validation for ${v.category} attacks. Consider implementing a content filter or policy engine.`,
    };
  });

  return {
    totalVulnerabilities: vulnerabilities.length,
    withShieldGuardrail: suggestions.filter(s => s.shieldGuardrail).length,
    suggestions,
    deploymentNote: "Deploy Votal Shield as a proxy: replace your LLM endpoint with /v1/shield/chat/completions. No code changes needed.",
  };
}

export async function dispatch(name: string, args: any): Promise<unknown> {
  switch (name) {
    case "read_repo":
      return readRepo(args);
    case "probe_target":
      return probeTarget(args);
    case "read_prior_reports":
      return readPriorReports(args);
    case "write_config":
      return writeConfig(args);
    case "write_custom_attacks":
      return writeCustomAttacks(args);
    case "write_policy":
      return writePolicy(args);
    case "run_scan":
      return runScan(args);
    case "check_run_status":
      return checkRunStatus(args);
    case "get_run_results":
      return getRunResults(args);
    case "cancel_run":
      return cancelRun(args);
    case "list_categories_and_strategies":
      return listCategoriesAndStrategies(args);
    case "suggest_guardrails":
      return suggestGuardrails(args);
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}
