import { createHmac, timingSafeEqual } from "node:crypto";
import { query, isDbConfigured } from "./db.js";
import { generateTenantKey } from "./encryption.js";
import type { AuthContext } from "./auth.js";
import type { Role } from "./rbac.js";

interface SimpleAuthUser {
  username: string;
  password: string;
  role: Role;
  email?: string;
  name?: string;
}

interface SessionPayload {
  username: string;
  exp: number;
}

export interface SimpleAuthUserInfo {
  username: string;
  role: Role;
  email?: string;
  name: string;
}

const SESSION_COOKIE = "rt_session";

function getSessionSecret(): string {
  return (
    process.env.SIMPLE_AUTH_SESSION_SECRET ||
    process.env.SESSION_SECRET ||
    "dev-only-simple-auth-secret"
  );
}

function getSessionTtlSeconds(): number {
  const hours = parseInt(process.env.SIMPLE_AUTH_SESSION_TTL_HOURS || "12", 10);
  return Math.max(1, hours) * 60 * 60;
}

function getCookieSecure(): boolean {
  return process.env.SIMPLE_AUTH_COOKIE_SECURE === "true";
}

function base64UrlEncode(input: string): string {
  return Buffer.from(input, "utf8").toString("base64url");
}

function base64UrlDecode(input: string): string {
  return Buffer.from(input, "base64url").toString("utf8");
}

function signPayload(payload: string): string {
  return createHmac("sha256", getSessionSecret())
    .update(payload)
    .digest("base64url");
}

function safeCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a);
  const bBuf = Buffer.from(b);
  if (aBuf.length !== bBuf.length) return false;
  return timingSafeEqual(aBuf, bBuf);
}

function parseSimpleAuthUsers(): SimpleAuthUser[] {
  if (process.env.SIMPLE_AUTH_USERS) {
    const raw = JSON.parse(process.env.SIMPLE_AUTH_USERS) as unknown;
    if (!Array.isArray(raw)) {
      throw new Error("SIMPLE_AUTH_USERS must be a JSON array");
    }
    return raw.map((entry, index) => {
      if (!entry || typeof entry !== "object") {
        throw new Error(`SIMPLE_AUTH_USERS[${index}] must be an object`);
      }
      const user = entry as Record<string, unknown>;
      const username = String(user.username || "").trim();
      const password = String(user.password || "");
      const role = String(user.role || "viewer") as Role;
      if (!username || !password) {
        throw new Error(
          `SIMPLE_AUTH_USERS[${index}] must include username and password`,
        );
      }
      if (!["admin", "viewer", "auditor"].includes(role)) {
        throw new Error(
          `SIMPLE_AUTH_USERS[${index}].role must be admin, viewer, or auditor`,
        );
      }
      return {
        username,
        password,
        role,
        email: typeof user.email === "string" ? user.email : undefined,
        name: typeof user.name === "string" ? user.name : undefined,
      };
    });
  }

  const username = (process.env.SIMPLE_AUTH_USERNAME || "").trim();
  const password = process.env.SIMPLE_AUTH_PASSWORD || "";
  if (!username || !password) {
    throw new Error(
      "Simple auth requires SIMPLE_AUTH_USERS or SIMPLE_AUTH_USERNAME and SIMPLE_AUTH_PASSWORD",
    );
  }

  const role = (process.env.SIMPLE_AUTH_ROLE || "admin") as Role;
  if (!["admin", "viewer", "auditor"].includes(role)) {
    throw new Error("SIMPLE_AUTH_ROLE must be admin, viewer, or auditor");
  }

  return [
    {
      username,
      password,
      role,
      email: process.env.SIMPLE_AUTH_EMAIL || undefined,
      name: process.env.SIMPLE_AUTH_NAME || undefined,
    },
  ];
}

function findSimpleAuthUser(username: string): SimpleAuthUser | undefined {
  return parseSimpleAuthUsers().find((user) => user.username === username);
}

function parseCookies(cookieHeader: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  if (!cookieHeader) return cookies;
  for (const part of cookieHeader.split(";")) {
    const [rawKey, ...rawValue] = part.trim().split("=");
    if (!rawKey) continue;
    cookies[rawKey] = decodeURIComponent(rawValue.join("="));
  }
  return cookies;
}

async function ensureSimpleAuthContext(
  user: SimpleAuthUser,
): Promise<AuthContext> {
  if (!isDbConfigured()) {
    return {
      sub: `simple:${user.username}`,
      email: user.email,
      tenantId: "local",
      role: user.role,
      userId: user.username,
    };
  }

  const tenantName = process.env.SIMPLE_AUTH_TENANT || "default";
  let tenantId: string;
  const existingTenant = await query<{ id: string }>(
    "SELECT id FROM tenants WHERE name = $1",
    [tenantName],
  );
  if (existingTenant.rows.length > 0) {
    tenantId = existingTenant.rows[0].id;
  } else {
    const encKey = generateTenantKey();
    const createdTenant = await query<{ id: string }>(
      `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
       VALUES ($1, $2, $3)
       RETURNING id`,
      [tenantName, `simple-auth:${tenantName}`, encKey],
    );
    tenantId = createdTenant.rows[0].id;
  }

  const sub = `simple:${user.username}`;
  const email = user.email || `${user.username}@local`;
  const userResult = await query<{ id: string; role: string }>(
    `INSERT INTO users (tenant_id, sub, email, role)
     VALUES ($1, $2, $3, $4)
     ON CONFLICT (tenant_id, sub) DO UPDATE
       SET email = EXCLUDED.email,
           role = EXCLUDED.role
     RETURNING id, role`,
    [tenantId, sub, email, user.role],
  );

  return {
    sub,
    email,
    tenantId,
    role: userResult.rows[0].role as Role,
    userId: userResult.rows[0].id,
  };
}

function serializeSession(payload: SessionPayload): string {
  const encoded = base64UrlEncode(JSON.stringify(payload));
  const signature = signPayload(encoded);
  return `${encoded}.${signature}`;
}

function deserializeSession(token: string): SessionPayload {
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) {
    throw new Error("Invalid session token");
  }
  const expected = signPayload(encoded);
  if (!safeCompare(signature, expected)) {
    throw new Error("Invalid session signature");
  }
  const payload = JSON.parse(base64UrlDecode(encoded)) as SessionPayload;
  if (!payload.username || typeof payload.exp !== "number") {
    throw new Error("Invalid session payload");
  }
  if (payload.exp < Math.floor(Date.now() / 1000)) {
    throw new Error("Session expired");
  }
  return payload;
}

export async function loginSimpleUser(
  username: string,
  password: string,
): Promise<{ auth: AuthContext; user: SimpleAuthUserInfo; token: string }> {
  const user = findSimpleAuthUser(username);
  if (!user || user.password !== password) {
    throw new Error("Invalid username or password");
  }

  const auth = await ensureSimpleAuthContext(user);
  const token = serializeSession({
    username: user.username,
    exp: Math.floor(Date.now() / 1000) + getSessionTtlSeconds(),
  });

  return {
    auth,
    token,
    user: {
      username: user.username,
      role: auth.role,
      email: user.email,
      name: user.name || user.username,
    },
  };
}

export async function validateSimpleSession(
  cookieHeader: string | undefined,
): Promise<AuthContext> {
  const cookies = parseCookies(cookieHeader);
  const token = cookies[SESSION_COOKIE];
  if (!token) {
    throw new Error("Missing session cookie");
  }

  const payload = deserializeSession(token);
  const user = findSimpleAuthUser(payload.username);
  if (!user) {
    throw new Error("User no longer exists");
  }

  return ensureSimpleAuthContext(user);
}

export async function getSimpleSessionUser(
  cookieHeader: string | undefined,
): Promise<SimpleAuthUserInfo> {
  const auth = await validateSimpleSession(cookieHeader);
  const user = findSimpleAuthUser(auth.sub.replace(/^simple:/, ""));
  if (!user) {
    throw new Error("User no longer exists");
  }
  return {
    username: user.username,
    role: auth.role,
    email: user.email,
    name: user.name || user.username,
  };
}

export function buildSimpleSessionCookie(token: string): string {
  const maxAge = getSessionTtlSeconds();
  const secure = getCookieSecure() ? "; Secure" : "";
  return `${SESSION_COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

export function buildSimpleLogoutCookie(): string {
  const secure = getCookieSecure() ? "; Secure" : "";
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}
