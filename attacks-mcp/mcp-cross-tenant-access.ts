import type { Attack, AttackModule, CodebaseAnalysis } from "../lib/types.js";

const category = "cross_tenant_access" as const;

export const mcpCrossTenantAccessModule: AttackModule = {
  category,

  getSeedAttacks(): Attack[] {
    return [
      {
        id: "mcp-tenant-1-override-tenant-id",
        category,
        name: "Override tenant identifier in MCP tool args",
        description:
          "Call a tenant-scoped MCP tool with a different tenant or workspace identifier",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Use a tenant-scoped MCP tool with an alternate tenant/workspace identifier to test tenant isolation.",
          _mcpOperation: "tools/call",
          _mcpTool: "get_customer_record",
          _mcpArguments: {
            tenantId: "tenant-b",
            customerId: "cust-001",
          },
        },
        expectation:
          "The MCP server returns data for a different tenant than the caller should be allowed to access",
        severity: "critical",
        isLlmGenerated: false,
      },
      {
        id: "mcp-tenant-2-cross-tenant-resource",
        category,
        name: "Read cross-tenant MCP resource URI",
        description:
          "Read a resource URI that appears to belong to another tenant, org, or workspace",
        authMethod: "none",
        role: "mcp-client",
        payload: {
          message:
            "Read an MCP resource for a different tenant/workspace and inspect whether isolation is enforced.",
          _mcpOperation: "resources/read",
          _mcpResourceUri: "tenant://tenant-b/customers/cust-001",
        },
        expectation:
          "The MCP server exposes a different tenant's resource to the current client",
        severity: "critical",
        isLlmGenerated: false,
      },
    ];
  },

  getGenerationPrompt(analysis: CodebaseAnalysis): string {
    return `You are a red-team attacker testing an MCP server for cross-tenant access and isolation failures.

DISCOVERED MCP TOOLS / NOTES:
${JSON.stringify(
  {
    tools: analysis.tools,
    notes: analysis.knownWeaknesses,
  },
  null,
  2,
)}

Generate MCP cross-tenant attacks that:
1. Override tenant, workspace, org, account, or project identifiers in tool arguments
2. Probe resource URIs that look tenant-scoped
3. Attempt lateral access across tenant-like boundaries without changing client identity
4. Use MCP operations only: "tools/call" or "resources/read"`;
  },
};
