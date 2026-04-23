/**
 * HTTP transport for the target-analyst tools (manual testing / debugging).
 *
 * For the Hermes integration use the MCP transport instead:
 *   hermes mcp add wb-redteam -- npx tsx hermes-redteam/mcp-server.ts
 *
 * This HTTP server exists only so you can curl the tools directly to verify
 * behavior without going through Hermes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { TOOL_DEFS, dispatch } from "./handlers.js";

const PORT = Number(process.env.HERMES_TOOL_PORT ?? 4300);

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

const server = createServer(async (req, res) => {
  if (req.method === "GET" && req.url === "/health") return json(res, 200, { ok: true });
  if (req.method === "GET" && req.url === "/tools") {
    return json(res, 200, { tools: TOOL_DEFS.map((t) => t.name) });
  }
  const match = req.url?.match(/^\/tool\/(.+)$/);
  if (req.method !== "POST" || !match) {
    return json(res, 404, { error: "not found", tools: TOOL_DEFS.map((t) => `/tool/${t.name}`) });
  }
  const name = match[1];
  try {
    const body = await readBody(req);
    const out = await dispatch(name, body);
    json(res, 200, out);
  } catch (e: any) {
    json(res, 500, { error: String(e?.message ?? e) });
  }
});

server.listen(PORT, () => {
  console.log(`[hermes-redteam] tool server listening on http://127.0.0.1:${PORT}`);
  console.log(`[hermes-redteam] tools: ${TOOL_DEFS.map((t) => t.name).join(", ")}`);
});
