/**
 * WebSocket chat target executor for agentic apps that use JSON-over-WS.
 *
 * Outbound frame: {"type":"message","content":"<user text>"}
 * Inbound frames: type chunk|message|done|tool_call|tool_result|error.
 *
 * Configure via config.target.websocket (path, subprotocols, token, responseTimeoutMs).
 */
import { randomUUID } from "node:crypto";
import WebSocket from "ws";
import type { Attack, Config } from "./types.js";

interface WsInboundMessage {
  type?: string;
  content?: string;
  message?: string;
  full_response?: string;
  name?: string;
  args?: Record<string, unknown>;
}

export async function executeWebSocketAttack(
  config: Config,
  attack: Attack,
): Promise<{ statusCode: number; body: unknown; timeMs: number }> {
  const wsCfg = config.target.websocket;
  if (!wsCfg?.path) {
    return {
      statusCode: 500,
      body: { error: "target.websocket.path is required for websocket_agent" },
      timeMs: 0,
    };
  }

  const baseUrl = config.target.baseUrl;
  if (!baseUrl) {
    return {
      statusCode: 500,
      body: { error: "target.baseUrl is required" },
      timeMs: 0,
    };
  }

  const messageField = config.requestSchema.messageField;
  const payload = { ...attack.payload };
  delete payload._jwtClaims;
  const messageText =
    typeof payload[messageField] === "string"
      ? (payload[messageField] as string)
      : JSON.stringify(payload[messageField] ?? "");

  const base = new URL(baseUrl);
  const wsProto = base.protocol === "https:" ? "wss:" : "ws:";
  const params = new URLSearchParams();
  params.set("session_id", randomUUID());
  const token = wsCfg.token ?? config.auth.bearerToken;
  if (token) params.set("token", token);

  const wsUrl = `${wsProto}//${base.host}${wsCfg.path}?${params.toString()}`;
  const subprotocols = wsCfg.subprotocols?.length
    ? wsCfg.subprotocols
    : undefined;
  const timeoutMs = wsCfg.responseTimeoutMs ?? 120_000;

  const start = Date.now();

  return new Promise((resolve) => {
    let settled = false;
    let ws: WebSocket | undefined;

    const finish = (statusCode: number, body: unknown) => {
      if (settled) return;
      settled = true;
      resolve({
        statusCode,
        body,
        timeMs: Date.now() - start,
      });
    };

    const timer = setTimeout(() => {
      try {
        ws?.close();
      } catch {
        /* ignore */
      }
      finish(0, {
        error: `WebSocket response timeout after ${timeoutMs}ms`,
      });
    }, timeoutMs);

    try {
      ws = new WebSocket(wsUrl, subprotocols);
    } catch (e) {
      clearTimeout(timer);
      return finish(0, { error: (e as Error).message });
    }

    const toolCalls: Array<{
      tool?: string;
      function?: { name?: string };
      result?: unknown;
      output?: unknown;
    }> = [];

    let chunkBuffer = "";

    ws.on("open", () => {
      try {
        ws!.send(
          JSON.stringify({
            type: "message",
            content: messageText,
          }),
        );
      } catch (e) {
        clearTimeout(timer);
        finish(0, { error: (e as Error).message });
      }
    });

    ws.on("message", (data: WebSocket.RawData) => {
      let msg: WsInboundMessage;
      try {
        msg = JSON.parse(String(data)) as WsInboundMessage;
      } catch {
        return;
      }

      switch (msg.type) {
        case "error": {
          const errText = msg.message ?? msg.content ?? "Unknown error";
          clearTimeout(timer);
          try {
            ws?.close();
          } catch {
            /* ignore */
          }
          finish(200, {
            response: errText,
            error: true,
            tool_calls: toolCalls.length ? toolCalls : undefined,
          });
          break;
        }
        case "chunk":
          chunkBuffer += msg.content ?? "";
          break;
        case "tool_call":
          toolCalls.push({
            tool: msg.name,
            function: { name: msg.name },
            result: msg.args,
          });
          break;
        case "tool_result":
          toolCalls.push({
            tool: msg.name,
            result: msg.content ?? msg.args,
          });
          break;
        case "message":
        case "done": {
          const text =
            msg.full_response ?? msg.content ?? chunkBuffer ?? "";
          chunkBuffer = "";
          clearTimeout(timer);
          try {
            ws?.close();
          } catch {
            /* ignore */
          }
          finish(200, {
            response: text,
            tool_calls: toolCalls.length ? toolCalls : undefined,
            user: undefined,
            guardrails: undefined,
          });
          break;
        }
        default:
          break;
      }
    });

    ws.on("error", (err: Error) => {
      clearTimeout(timer);
      finish(0, { error: err.message });
    });

    ws.on("close", () => {
      clearTimeout(timer);
      // If we never got a terminal message, return partial buffer
      if (!settled && chunkBuffer.length > 0) {
        finish(200, {
          response: chunkBuffer,
          tool_calls: toolCalls.length ? toolCalls : undefined,
        });
      } else if (!settled) {
        finish(0, { error: "WebSocket closed before a complete response" });
      }
    });
  });
}
