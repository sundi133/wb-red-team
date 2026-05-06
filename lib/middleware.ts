/**
 * HTTP request middleware pipeline.
 * Handles CORS, authentication, RBAC, and tenant scoping.
 * When DATABASE_URL is not set, passes ctx=null for backward compatibility.
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { validateToken, type AuthContext } from "./auth.js";
import { validateDevToken } from "./auth-dev.js";
import { validateApiKey } from "./auth-apikey.js";
import { validateSimpleSession } from "./auth-simple.js";
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

const rateBuckets = new Map<string, { windowStart: number; count: number }>();

function boolEnv(name: string): boolean {
  return process.env[name] === "true" || process.env[name] === "1";
}

function applyCors(req: IncomingMessage, res: ServerResponse): boolean {
  const origin = req.headers.origin;
  const configured = process.env.DASHBOARD_CORS_ORIGIN ?? "";
  const allowed = configured
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

  res.setHeader("Vary", "Origin");
  if (configured === "*") {
    res.setHeader("Access-Control-Allow-Origin", "*");
  } else if (origin && allowed.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
  } else if (origin && allowed.length > 0) {
    return false;
  }

  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader(
    "Access-Control-Allow-Headers",
    "Content-Type, Authorization, X-API-Key, X-Dashboard-Token",
  );
  return true;
}

function checkApiRateLimit(req: IncomingMessage): boolean {
  const max = parseInt(process.env.DASHBOARD_RATE_LIMIT_MAX || "300", 10);
  if (!Number.isFinite(max) || max <= 0) return true;

  const windowMs = parseInt(
    process.env.DASHBOARD_RATE_LIMIT_WINDOW_MS || "60000",
    10,
  );
  const key = req.socket.remoteAddress ?? "unknown";
  const now = Date.now();
  const bucket = rateBuckets.get(key);
  if (!bucket || now - bucket.windowStart >= windowMs) {
    rateBuckets.set(key, { windowStart: now, count: 1 });
    return true;
  }

  bucket.count++;
  return bucket.count <= max;
}

function hasValidDashboardToken(req: IncomingMessage): boolean {
  const expected = process.env.DASHBOARD_TOKEN;
  if (!expected) return false;

  const authHeader = req.headers.authorization ?? "";
  const bearer =
    typeof authHeader === "string" && authHeader.startsWith("Bearer ")
      ? authHeader.slice("Bearer ".length)
      : "";
  const dashboardToken = req.headers["x-dashboard-token"];
  return bearer === expected || dashboardToken === expected;
}

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
    const corsAllowed = applyCors(req, res);
    if (req.method === "OPTIONS") {
      if (!corsAllowed) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "CORS origin not allowed" }));
        return;
      }
      res.writeHead(204);
      res.end();
      return;
    }

    const url = new URL(req.url ?? "/", `http://localhost`);
    if (!corsAllowed) {
      res.writeHead(403, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "CORS origin not allowed" }));
      return;
    }

    if (url.pathname.startsWith("/api/") && !checkApiRateLimit(req)) {
      res.writeHead(429, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Rate limit exceeded" }));
      return;
    }

    if (
      url.pathname.startsWith("/api/") &&
      url.pathname !== "/api/auth-config" &&
      url.pathname !== "/api/auth/login" &&
      url.pathname !== "/api/auth/logout" &&
      url.pathname !== "/api/auth/me" &&
      boolEnv("DASHBOARD_REQUIRE_AUTH")
    ) {
      if (!process.env.DASHBOARD_TOKEN) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error:
              "Dashboard auth is enabled but DASHBOARD_TOKEN is not configured",
          }),
        );
        return;
      }
      if (!hasValidDashboardToken(req)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Unauthorized" }));
        return;
      }
      if (isDbConfigured() && boolEnv("DASHBOARD_TOKEN_BYPASS_RBAC")) {
        return handler(req, res, null);
      }
    }

    // Static files and public API endpoints — no auth needed
    if (
      !url.pathname.startsWith("/api/") ||
      url.pathname === "/api/auth-config" ||
      url.pathname === "/api/reference" ||
      url.pathname === "/api/auth/login" ||
      url.pathname === "/api/auth/logout" ||
      url.pathname === "/api/auth/me"
    ) {
      return handler(req, res, null);
    }

    const authMode = process.env.AUTH_MODE || "none";

    // If no DB configured, skip auth unless an explicit auth mode still applies.
    if (!isDbConfigured() && authMode !== "simple") {
      return handler(req, res, null);
    }

    // Validate token — try multiple auth methods
    let authCtx: AuthContext;
    try {
      if (authMode === "dev") {
        // Dev mode: auto-authenticate all requests as admin
        authCtx = await validateDevToken("Bearer " + (process.env.DEV_API_KEY || "dev-key"));
      } else if (authMode === "simple") {
        authCtx = await validateSimpleSession(req.headers.cookie);
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
