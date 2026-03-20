import readline from "node:readline";

const rl = readline.createInterface({
  input: process.stdin,
  crlfDelay: Infinity,
});

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

rl.on("line", (line) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  let msg;
  try {
    msg = JSON.parse(trimmed);
  } catch {
    return;
  }

  if (!("id" in msg)) {
    return;
  }

  const { id, method, params } = msg;

  switch (method) {
    case "initialize":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: params?.protocolVersion || "2024-11-05",
          capabilities: {
            tools: {},
            prompts: {},
            resources: {},
          },
          serverInfo: {
            name: "mock-mcp-server",
            version: "1.0.0",
          },
        },
      });
      break;
    case "tools/list":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          tools: [
            {
              name: "read_secret",
              description: "Read a fake secret",
              inputSchema: {
                type: "object",
                properties: {
                  path: { type: "string" },
                },
              },
            },
          ],
        },
      });
      break;
    case "prompts/list":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          prompts: [
            {
              name: "security-review",
              description: "Review security posture",
            },
          ],
        },
      });
      break;
    case "resources/list":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          resources: [
            {
              uri: "memory://secrets/demo",
              name: "Demo Secret",
              mimeType: "text/plain",
            },
          ],
        },
      });
      break;
    case "tools/call":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          content: [{ type: "text", text: "tool called successfully" }],
          structuredContent: {
            tool: params?.name,
            arguments: params?.arguments || {},
            secret: "demo-secret",
          },
        },
      });
      break;
    case "resources/read":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          contents: [
            {
              uri: params?.uri,
              mimeType: "text/plain",
              text: "fake-resource-data",
            },
          ],
        },
      });
      break;
    case "prompts/get":
      send({
        jsonrpc: "2.0",
        id,
        result: {
          messages: [
            {
              role: "user",
              content: {
                type: "text",
                text: `Prompt requested: ${params?.name}`,
              },
            },
          ],
        },
      });
      break;
    default:
      send({
        jsonrpc: "2.0",
        id,
        error: {
          code: -32601,
          message: `Method not found: ${method}`,
        },
      });
      break;
  }
});
