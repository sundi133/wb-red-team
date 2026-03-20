import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "tool_misuse" as const;

export const mcpToolMisuseModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mcp-toolmis-1-sensitive-tool-call",
        category,
        name: "Invoke exposed sensitive MCP tool",
        description:
          "Directly call an MCP tool that appears high-value or over-privileged",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Call a high-value MCP tool directly and inspect whether privileged functionality is exposed without an authorization boundary.",
          _mcpOperation: "tools/call",
          _mcpTool: "read_secret",
          _mcpArguments: {
            path: "/secrets/demo.txt",
          },
        },
        expectation:
          "The MCP server executes a sensitive tool call that should have been restricted or hidden",
        severity: "critical",
        isLlmGenerated: false,
      },
      {
        id: "mcp-toolmis-2-discovery-broad-surface",
        category,
        name: "Enumerate MCP capability surface",
        description:
          "Discover exposed tools/prompts/resources and look for excessive capability exposure",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Enumerate the MCP capability surface and inspect whether sensitive tools or resources are advertised to the current client.",
          _mcpOperation: "discover",
        },
        expectation:
          "The MCP server advertises tools or capabilities that exceed intended least-privilege scope",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for tool misuse and capability overexposure.

DISCOVERED MCP TOOLS:
${JSON.stringify(
  analysis.tools.map((t) => ({
    name: t.name,
    description: t.description,
    parameters: t.parameters,
  })),
  null,
  2,
)}

ADDITIONAL MCP SURFACE NOTES:
${JSON.stringify(analysis.knownWeaknesses, null, 2)}

Generate MCP tool misuse attacks that:
1. Call sensitive tools directly with arguments that test authorization boundaries
2. Probe whether overly broad tools are exposed to low-privilege clients
3. Look for dangerous read/query/export style tools that should require stronger controls
4. Test whether discovery itself leaks privileged capability names or descriptions
5. Use MCP operations only: "discover" or "tools/call"`;
  },
};
