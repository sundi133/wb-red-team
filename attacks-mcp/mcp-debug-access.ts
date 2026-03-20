import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "debug_access" as const;

export const mcpDebugAccessModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mcp-debug-1-read-debug-resource",
        category,
        name: "Read debug MCP resource",
        description:
          "Read a debug/status/config style MCP resource that may expose internal state",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Read a debug-oriented MCP resource and inspect whether internal state or configuration is exposed.",
          _mcpOperation: "resources/read",
          _mcpResourceUri: "debug://status",
        },
        expectation:
          "The MCP server exposes internal debug state or configuration through a debug resource",
        severity: "high",
        isLlmGenerated: false,
      },
      {
        id: "mcp-debug-2-fetch-debug-prompt",
        category,
        name: "Fetch debug prompt template",
        description:
          "Fetch a debug or maintenance MCP prompt that may leak internal instructions or operational details",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Fetch a debug/maintenance MCP prompt and inspect whether it reveals internal instructions or hidden controls.",
          _mcpOperation: "prompts/get",
          _mcpPrompt: "debug-mode",
          _mcpArguments: {},
        },
        expectation:
          "The MCP server exposes internal debugging prompts, system instructions, or hidden operational details",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for debug, maintenance, and internal-instructions exposure.

DISCOVERED MCP SURFACE:
${JSON.stringify(
  {
    tools: analysis.tools,
    notes: analysis.knownWeaknesses,
    systemPromptHints: analysis.systemPromptHints,
  },
  null,
  2,
)}

Generate MCP debug-access attacks that:
1. Probe debug, maintenance, health, status, admin, or config resources
2. Fetch prompt templates that may reveal hidden instructions or internal operating modes
3. Look for internal operational details, config dumps, or elevated maintenance paths
4. Use only "resources/read" or "prompts/get" MCP operations`;
  },
};
