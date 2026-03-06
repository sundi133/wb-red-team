import * as jose from "jose";
import type { Config, Attack, Credential } from "./types.js";

// Cache JWT tokens per role
const tokenCache = new Map<string, string>();

export async function preAuthenticate(config: Config): Promise<void> {
  if (!config.auth.methods.includes("jwt")) return;

  console.log("  Pre-authenticating credentials...");
  for (const cred of config.auth.credentials) {
    try {
      const token = await loginForToken(config, cred);
      tokenCache.set(cred.role, token);
      console.log(`    [OK] ${cred.role} → token cached`);
    } catch (e) {
      console.error(`    [FAIL] ${cred.role}: ${(e as Error).message}`);
    }
  }
}

async function loginForToken(config: Config, cred: Credential): Promise<string> {
  const url = `${config.target.baseUrl}${config.target.authEndpoint}`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email: cred.email, password: cred.password }),
  });
  if (!res.ok) throw new Error(`Login failed: ${res.status}`);
  const data = (await res.json()) as { token?: string };
  if (!data.token) throw new Error("No token in login response");
  return data.token;
}

export async function forgeJwt(config: Config, claims: Record<string, unknown>): Promise<string> {
  const secret = new TextEncoder().encode(config.auth.jwtSecret);
  return new jose.SignJWT(claims as jose.JWTPayload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("8h")
    .sign(secret);
}

export async function executeAttack(
  config: Config,
  attack: Attack,
): Promise<{ statusCode: number; body: unknown; timeMs: number }> {
  const url = `${config.target.baseUrl}${config.target.agentEndpoint}`;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(attack.headers ?? {}),
  };

  // Set up auth
  switch (attack.authMethod) {
    case "jwt": {
      const token = tokenCache.get(attack.role);
      if (token) headers["Authorization"] = `Bearer ${token}`;
      break;
    }
    case "api_key": {
      const key = config.auth.apiKeys[attack.role];
      if (key) headers["X-Api-Key"] = key;
      break;
    }
    case "forged_jwt": {
      // Forge a JWT with custom claims — the attack payload should specify the desired claims
      const forgedClaims = (attack.payload._jwtClaims as Record<string, unknown>) ?? {
        sub: "hacker@evil.com",
        role: attack.role,
        name: "Forged User",
      };
      try {
        const forgedToken = await forgeJwt(config, forgedClaims);
        headers["Authorization"] = `Bearer ${forgedToken}`;
      } catch {
        // If forge fails, proceed without auth
      }
      break;
    }
    case "body_role": {
      // role goes in payload — already handled by the attack's payload definition
      break;
    }
    case "none":
      break;
  }

  // Build request body — remove internal fields
  const body = { ...attack.payload };
  delete body._jwtClaims;

  const start = Date.now();
  try {
    const res = await fetch(url, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    const timeMs = Date.now() - start;
    let responseBody: unknown;
    try {
      responseBody = await res.json();
    } catch {
      responseBody = await res.text();
    }
    return { statusCode: res.status, body: responseBody, timeMs };
  } catch (e) {
    return { statusCode: 0, body: { error: (e as Error).message }, timeMs: Date.now() - start };
  }
}

export async function executeRapidFire(
  config: Config,
  attack: Attack,
  count: number,
): Promise<{ statusCode: number; body: unknown; timeMs: number }[]> {
  const promises = Array.from({ length: count }, () => executeAttack(config, attack));
  return Promise.all(promises);
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
