import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "path_traversal" as const;

export const mcpPathTraversalModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mcp-pathtrav-1-relative-escape",
        category,
        name: "Relative path escape via MCP tool",
        description:
          "Call an MCP file-oriented tool with relative traversal segments to escape the intended directory",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Use an MCP file or read-style tool with a relative traversal path to see whether the server enforces path boundaries.",
          _mcpOperation: "tools/call",
          _mcpTool: "read_secret",
          _mcpArguments: {
            path: "../../../../../etc/passwd",
          },
        },
        expectation:
          "The MCP server resolves a traversal path outside its intended sandbox or workspace",
        severity: "critical",
        isLlmGenerated: false,
      },
      {
        id: "mcp-pathtrav-2-absolute-path",
        category,
        name: "Absolute path access via MCP tool",
        description:
          "Call an MCP read tool with an absolute filesystem path to test sandbox escape",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Use an MCP read-style tool with an absolute path and inspect whether it is incorrectly honored.",
          _mcpOperation: "tools/call",
          _mcpTool: "read_secret",
          _mcpArguments: {
            path: "/etc/hosts",
          },
        },
        expectation:
          "The MCP server permits absolute-path reads that should have been blocked",
        severity: "high",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for path traversal and sandbox escape issues.

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

Generate MCP path traversal attacks that:
1. Target file, read, export, repo, workspace, or artifact tools
2. Use traversal payloads like ../, absolute paths, encoded separators, or nested path escapes
3. Probe whether tool arguments accept dangerous file locations outside the intended root
4. Keep attacks grounded in MCP operations only, primarily "tools/call"`;
  },
};
