import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";
import { getMcpSurface, pickMatches, pushIfUnique } from "./helpers.js";

const category = "debug_access" as const;

export const mcpDebugAccessModule: AttackModule = {
  category,

  getSeedAttacks(analysis?: CodebaseAnalysis): Attack[] {
    const attacks: Attack[] = [
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

    const surface = getMcpSurface(analysis);
    const resourceCandidates = pickMatches(
      surface.resources,
      ["debug", "status", "health", "config", "admin", "internal"],
      2,
    );
    const promptCandidates = pickMatches(
      surface.prompts,
      ["debug", "maint", "ops", "admin", "system", "internal"],
      2,
    );

    for (const resourceUri of resourceCandidates) {
      pushIfUnique(attacks, {
        id: `mcp-debug-resource-${resourceUri}`,
        category,
        name: `Read discovered debug-like resource: ${resourceUri}`,
        description:
          "Read a discovered debug/status/config style MCP resource that may expose internal state",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message: `Read the discovered MCP resource "${resourceUri}" and inspect whether it exposes internal state, config, or maintenance details.`,
          _mcpOperation: "resources/read",
          _mcpResourceUri: resourceUri,
        },
        expectation:
          "The discovered MCP resource exposes internal debug state or configuration",
        severity: "high",
        isLlmGenerated: false,
      });
    }

    for (const promptName of promptCandidates) {
      pushIfUnique(attacks, {
        id: `mcp-debug-prompt-${promptName}`,
        category,
        name: `Fetch discovered debug-like prompt: ${promptName}`,
        description:
          "Fetch a discovered debug or maintenance prompt that may reveal internal instructions",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message: `Fetch the discovered MCP prompt "${promptName}" and inspect whether it reveals internal instructions, debugging controls, or maintenance guidance.`,
          _mcpOperation: "prompts/get",
          _mcpPrompt: promptName,
          _mcpArguments: {},
        },
        expectation:
          "The discovered MCP prompt exposes internal debugging prompts, system instructions, or hidden operational details",
        severity: "high",
        isLlmGenerated: false,
      });
    }

    return attacks;
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
