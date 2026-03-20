import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "data_exfiltration" as const;

export const mcpDataExfiltrationModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mcp-exfil-1-read-sensitive-resource",
        category,
        name: "Read exposed MCP resource",
        description:
          "Read an MCP resource that may expose secrets, internal state, or cached data",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Read a high-value MCP resource directly and inspect whether it returns sensitive content to the current client.",
          _mcpOperation: "resources/read",
          _mcpResourceUri: "memory://secrets/demo",
        },
        expectation:
          "The MCP server returns sensitive resource data that should not be available",
        severity: "critical",
        isLlmGenerated: false,
      },
      {
        id: "mcp-exfil-2-tool-export-secret",
        category,
        name: "Exfiltrate data through MCP tool result",
        description:
          "Call an MCP tool that returns secret-bearing content in its structured result",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Invoke a read/export style MCP tool and inspect whether the response contains secrets or internal data in structured content.",
          _mcpOperation: "tools/call",
          _mcpTool: "read_secret",
          _mcpArguments: {
            path: "/secrets/export.txt",
          },
        },
        expectation:
          "The MCP tool result contains secrets, credentials, or internal data that can be exfiltrated",
        severity: "critical",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for data exfiltration paths.

DISCOVERED MCP TOOLS:
${JSON.stringify(
  analysis.tools.map((t) => ({ name: t.name, description: t.description })),
  null,
  2,
)}

KNOWN SENSITIVE DATA / MCP SURFACE NOTES:
${JSON.stringify(
  {
    sensitiveData: analysis.sensitiveData,
    notes: analysis.knownWeaknesses,
  },
  null,
  2,
)}

Generate MCP exfiltration attacks that:
1. Read MCP resources likely to expose secrets, prompts, cached state, or internal records
2. Invoke MCP tools that may return sensitive structured content
3. Prefer read/export/list/query style operations that could leak internal data
4. Ground the attack in realistic client behavior, but keep the payload using MCP operations only
5. Use only "resources/read" or "tools/call" MCP operations`;
  },
};
