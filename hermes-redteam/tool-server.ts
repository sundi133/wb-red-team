/**
 * Reconnaissance tool server for Hermes Agent.
 *
 * Exposes HTTP tools that Hermes calls to analyze a target AI app and emit
 * wb-red-team config artifacts. Hermes is the analyst; wb-red-team is the
 * executor. See hermes-redteam/README.md for the full workflow.
 *
 * Uses Node stdlib only (no Express) to avoid adding dependencies.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { existsSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { glob } from "glob";

const PORT = Number(process.env.HERMES_TOOL_PORT ?? 4300);
const ROOT = resolve(process.cwd());

type Handler = (body: any) => Promise<unknown>;

const handlers: Record<string, Handler> = {
  "/tool/read_repo": readRepo,
  "/tool/probe_target": probeTarget,
  "/tool/read_prior_reports": readPriorReports,
  "/tool/write_config": writeConfig,
  "/tool/write_custom_attacks": writeCustomAttacks,
  "/tool/write_policy": writePolicy,
};

async function readBody(req: IncomingMessage): Promise<any> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function json(res: ServerResponse, status: number, data: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

// ── Tools ────────────────────────────────────────────────────────────────

async function readRepo({ path, pattern = "**/*.{ts,tsx,js,py,md,json,yaml,yml}", maxFiles = 40, maxBytesPerFile = 20_000 }: {
  path: string;
  pattern?: string;
  maxFiles?: number;
  maxBytesPerFile?: number;
}) {
  const abs = resolve(path);
  const files = await glob(pattern, { cwd: abs, nodir: true, absolute: true, ignore: ["**/node_modules/**", "**/dist/**", "**/.next/**"] });
  const picked = files.slice(0, maxFiles);
  const out: { path: string; content: string; truncated: boolean }[] = [];
  for (const f of picked) {
    try {
      const buf = await readFile(f);
      const truncated = buf.length > maxBytesPerFile;
      out.push({ path: f.replace(abs + "/", ""), content: buf.slice(0, maxBytesPerFile).toString("utf8"), truncated });
    } catch {
      // skip unreadable files
    }
  }
  return { root: abs, total: files.length, returned: out.length, files: out };
}

async function probeTarget({ baseUrl, endpoint, message, headers = {}, body = {} }: {
  baseUrl: string;
  endpoint: string;
  message: string;
  headers?: Record<string, string>;
  body?: Record<string, unknown>;
}) {
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
    try { parsed = JSON.parse(txt); } catch { /* keep raw */ }
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

async function readPriorReports({ dir = "report", limit = 3 }: { dir?: string; limit?: number }) {
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
    } catch { /* skip */ }
  }
  return { dir: abs, reports };
}

async function writeConfig({ path, config }: { path: string; config: unknown }) {
  const abs = resolve(path);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, JSON.stringify(config, null, 2));
  return { written: abs, bytes: (await readFile(abs)).length };
}

async function writeCustomAttacks({ path, rows }: { path: string; rows: Array<Record<string, string>> }) {
  const abs = resolve(path);
  await mkdir(dirname(abs), { recursive: true });
  if (abs.endsWith(".json")) {
    await writeFile(abs, JSON.stringify(rows, null, 2));
  } else {
    // CSV
    const headers = Array.from(new Set(rows.flatMap((r) => Object.keys(r))));
    const esc = (v: string) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [headers.join(","), ...rows.map((r) => headers.map((h) => esc(r[h] ?? "")).join(","))];
    await writeFile(abs, lines.join("\n"));
  }
  return { written: abs, rows: rows.length };
}

async function writePolicy({ path, policy }: { path: string; policy: unknown }) {
  const abs = resolve(path);
  await mkdir(dirname(abs), { recursive: true });
  await writeFile(abs, JSON.stringify(policy, null, 2));
  return { written: abs };
}

// ── Server ────────────────────────────────────────────────────────────────

const server = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") return json(res, 200, { ok: true });
  if (req.method === "GET" && req.url === "/tools") {
    return json(res, 200, { tools: Object.keys(handlers) });
  }
  const handler = handlers[req.url ?? ""];
  if (req.method !== "POST" || !handler) return json(res, 404, { error: "not found", tools: Object.keys(handlers) });
  try {
    const body = await readBody(req);
    const out = await handler(body);
    json(res, 200, out);
  } catch (e: any) {
    json(res, 500, { error: String(e?.message ?? e) });
  }
});

server.listen(PORT, () => {
  console.log(`[hermes-redteam] tool server listening on http://127.0.0.1:${PORT}`);
  console.log(`[hermes-redteam] cwd: ${ROOT}`);
  console.log(`[hermes-redteam] tools: ${Object.keys(handlers).join(", ")}`);
});
