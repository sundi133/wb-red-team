import type { Attack, Config, Credential, McpExecutionTrace } from "./types.js";
import { discoverMcpSurface } from "./mcp/discovery.js";
import { McpSession } from "./mcp/session.js";

export interface AttackExecutionResult {
  statusCode: number;
  body: unknown;
  timeMs: number;
  executionTrace?: McpExecutionTrace;
}

export interface TargetSurfaceSummary {
  transport: Config["target"]["type"];
  serverName?: string;
  protocolVersion?: string;
  capabilities?: string[];
  tools?: string[];
  prompts?: string[];
  resources?: string[];
}

export interface TargetAdapter {
  readonly type: NonNullable<Config["target"]["type"]>;
  preAuthenticate(config: Config): Promise<void>;
  loginForToken?(config: Config, cred: Credential): Promise<string>;
  executeAttack(config: Config, attack: Attack): Promise<AttackExecutionResult>;
  discoverSurface?(config: Config): Promise<TargetSurfaceSummary>;
}

class McpTargetAdapter implements TargetAdapter {
  readonly type = "mcp" as const;

  async preAuthenticate(config: Config): Promise<void> {
    const session = new McpSession(config);
    try {
      await session.initialize();
    } finally {
      await session.close();
    }
  }

  async executeAttack(
    config: Config,
    attack: Attack,
  ): Promise<AttackExecutionResult> {
    const operation = attack.payload._mcpOperation;
    const start = Date.now();

    if (typeof operation !== "string") {
      return {
        statusCode: 400,
        body: {
          error:
            'MCP attack payload requires "_mcpOperation" (supported: "discover", "tools/call", "resources/read", "prompts/get")',
        },
        timeMs: Date.now() - start,
      };
    }

    let session: McpSession | undefined;
    try {
      let result: unknown;
      switch (operation) {
        case "discover": {
          result = await discoverMcpSurface(config);
          break;
        }
        case "tools/call": {
          session = new McpSession(config);
          const toolName = attack.payload._mcpTool;
          if (typeof toolName !== "string" || !toolName) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP tools/call requires payload field "_mcpTool" to be a non-empty string',
              },
              timeMs: Date.now() - start,
            };
          }
          const toolArgs =
            typeof attack.payload._mcpArguments === "object" &&
            attack.payload._mcpArguments !== null
              ? (attack.payload._mcpArguments as Record<string, unknown>)
              : {};
          result = await session.callTool(toolName, toolArgs);
          break;
        }
        case "resources/read": {
          session = new McpSession(config);
          const uri = attack.payload._mcpResourceUri;
          if (typeof uri !== "string" || !uri) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP resources/read requires payload field "_mcpResourceUri" to be a non-empty string',
              },
              timeMs: Date.now() - start,
            };
          }
          result = await session.readResource(uri);
          break;
        }
        case "prompts/get": {
          session = new McpSession(config);
          const promptName = attack.payload._mcpPrompt;
          if (typeof promptName !== "string" || !promptName) {
            return {
              statusCode: 400,
              body: {
                error:
                  'MCP prompts/get requires payload field "_mcpPrompt" to be a non-empty string',
              },
              timeMs: Date.now() - start,
            };
          }
          const promptArgs =
            typeof attack.payload._mcpArguments === "object" &&
            attack.payload._mcpArguments !== null
              ? (attack.payload._mcpArguments as Record<string, unknown>)
              : {};
          result = await session.getPrompt(promptName, promptArgs);
          break;
        }
        default:
          return {
            statusCode: 400,
            body: {
              error: `Unsupported MCP operation "${operation}"`,
            },
            timeMs: Date.now() - start,
          };
      }

      const executionTrace = session?.getExecutionTrace(operation);
      return {
        statusCode: 200,
        body: {
          operation,
          result,
        },
        timeMs: Date.now() - start,
        executionTrace,
      };
    } catch (error) {
      const executionTrace = session?.getExecutionTrace(operation);
      return {
        statusCode: 0,
        body: { error: (error as Error).message },
        timeMs: Date.now() - start,
        executionTrace,
      };
    } finally {
      await session?.close();
    }
  }

  async discoverSurface(config: Config): Promise<TargetSurfaceSummary> {
    const result = await discoverMcpSurface(config);
    return {
      transport: config.target.type ?? "mcp",
      serverName: result.serverInfo?.name,
      protocolVersion: result.protocolVersion,
      capabilities: result.capabilities,
      tools: result.tools.map((tool) => tool.name),
      prompts: result.prompts.map((prompt) => prompt.name),
      resources: result.resources.map((resource) => resource.uri),
    };
  }
}

let mcpTargetAdapter: TargetAdapter | undefined;

export function getTargetAdapter(config: Config): TargetAdapter | undefined {
  const targetType = config.target.type ?? "http_agent";
  if (targetType === "mcp") {
    mcpTargetAdapter ??= new McpTargetAdapter();
    return mcpTargetAdapter;
  }
  return undefined;
}

export function describeTarget(config: Config): string {
  if ((config.target.type ?? "http_agent") === "mcp") {
    const mcp = config.target.mcp;
    if (!mcp) return "mcp://unknown";
    if (mcp.transport === "stdio") {
      const args = (mcp.args ?? []).join(" ");
      return `mcp+stdio://${mcp.command ?? "unknown"}${args ? ` ${args}` : ""}`;
    }
    return `mcp+${mcp.transport}:${mcp.url ?? "unknown"}`;
  }

  return `${config.target.baseUrl ?? ""}${config.target.agentEndpoint ?? ""}`;
}
