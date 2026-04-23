#!/usr/bin/env node
/**
 * MCP stdio server for the target-analyst workflow.
 *
 * Registered with Hermes via:
 *   hermes mcp add wb-redteam -- npx tsx /abs/path/to/hermes-redteam/mcp-server.ts
 *
 * Exposes six tools to any MCP client (Hermes, Claude Code, etc.):
 *   read_repo, probe_target, read_prior_reports,
 *   write_config, write_custom_attacks, write_policy
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { TOOL_DEFS, dispatch } from "./handlers.js";

const server = new Server(
  { name: "wb-redteam-tools", version: "1.0.0" },
  { capabilities: { tools: {} } },
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOL_DEFS.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    const result = await dispatch(name, args ?? {});
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (e: any) {
    return {
      isError: true,
      content: [{ type: "text", text: `Error calling ${name}: ${String(e?.message ?? e)}` }],
    };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);
// MCP stdio servers MUST NOT write anything non-protocol to stdout.
// Diagnostics go to stderr.
process.stderr.write(
  `[wb-redteam-mcp] ready, ${TOOL_DEFS.length} tools: ${TOOL_DEFS.map((t) => t.name).join(", ")}\n`,
);
