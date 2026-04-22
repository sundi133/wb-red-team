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
] as const;

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
    default:
      throw new Error(`unknown tool: ${name}`);
  }
}
