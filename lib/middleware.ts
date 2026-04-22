/**
 * HTTP request middleware pipeline.
 * Handles CORS, authentication, RBAC, and tenant scoping.
 * When DATABASE_URL is not set, passes ctx=null for backward compatibility.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { validateToken, type AuthContext } from "./auth.js";
import { validateDevToken } from "./auth-dev.js";
import { validateApiKey } from "./auth-apikey.js";
import { checkPermission } from "./rbac.js";
import { isDbConfigured } from "./db.js";
import type { Role } from "./rbac.js";

export interface RequestContext {
  tenantId: string;
  userId: string;
  role: Role;
  ip: string;
}

type Handler = (
  req: IncomingMessage,
  res: ServerResponse,
  ctx: RequestContext | null,
) => Promise<void>;

/**
 * Wrap the server handler with authentication and authorization.
 * When DATABASE_URL is not set, all requests pass through with ctx=null.
 */
export function withMiddleware(
  handler: Handler,
): (req: IncomingMessage, res: ServerResponse) => void {
  return (req, res) => {
    void handleRequest(req, res, handler);
  };
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  handler: Handler,
): Promise<void> {
  try {
    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization",
    );

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? "/", `http://localhost`);

    // Static files and public API endpoints — no auth needed
    if (!url.pathname.startsWith("/api/") || url.pathname === "/api/auth-config" || url.pathname === "/api/reference") {
      return handler(req, res, null);
    }

    // If no DB configured, skip auth (backward compat)
    if (!isDbConfigured()) {
      return handler(req, res, null);
    }

    // Validate token — try multiple auth methods
    let authCtx: AuthContext;
    try {
      if (process.env.AUTH_MODE === "dev") {
        // Dev mode: auto-authenticate all requests as admin
        authCtx = await validateDevToken("Bearer " + (process.env.DEV_API_KEY || "dev-key"));
      } else if (req.headers["x-api-key"]) {
        // API key auth — for CI/CD, scripts, and programmatic access
        authCtx = await validateApiKey(req.headers["x-api-key"] as string);
      } else {
        // OIDC JWT auth — for browser/Clerk
        authCtx = await validateToken(req.headers.authorization);
      }
    } catch (err) {
      res.writeHead(401, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          error: "Unauthorized",
          detail: err instanceof Error ? err.message : String(err),
        }),
      );
      return;
    }

    // RBAC check
    if (!checkPermission(req.method!, url.pathname, authCtx.role)) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Forbidden" }));
      return;
    }

    // Build context
    const ctx: RequestContext = {
      tenantId: authCtx.tenantId,
      userId: authCtx.userId,
      role: authCtx.role,
      ip: req.socket.remoteAddress ?? "",
    };

    return handler(req, res, ctx);
  } catch (err) {
    console.error("Middleware error:", err);
    if (!res.headersSent) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Internal server error" }));
    }
  }
}
