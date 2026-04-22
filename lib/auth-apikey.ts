/**
 * API key authentication — for CI/CD, scripts, and local testing.
 *
 * Usage:
 *   curl -H "X-API-Key: rtk_xxxx" http://localhost:4200/api/runs
 *
 * Generate keys via:
 *   npx tsx scripts/create-api-key.ts --tenant default --role admin --name "CI pipeline"
 */

import { createHash } from "node:crypto";
import { query } from "./db.js";
import type { AuthContext } from "./auth.js";
import type { Role } from "./rbac.js";

function hashKey(key: string): string {
  return createHash("sha256").update(key).digest("hex");
}

/**
 * Validate an API key and return the auth context.
 */
export async function validateApiKey(
  apiKey: string,
): Promise<AuthContext> {
  if (!apiKey || !apiKey.startsWith("rtk_")) {
    throw new Error("Invalid API key format (must start with rtk_)");
  }

  const keyHash = hashKey(apiKey);

  const result = await query<{
    id: string;
    tenant_id: string;
    user_id: string | null;
    role: string;
    name: string;
  }>(
    `SELECT ak.id, ak.tenant_id, ak.user_id, ak.role, ak.name
     FROM api_keys ak WHERE ak.key_hash = $1`,
    [keyHash],
  );

  if (result.rows.length === 0) {
    throw new Error("Invalid API key");
  }

  const row = result.rows[0];

  // Update last_used timestamp (fire and forget)
  query("UPDATE api_keys SET last_used = now() WHERE id = $1", [row.id]).catch(
    () => {},
  );

  return {
    sub: `apikey:${row.name}`,
    email: undefined,
    tenantId: row.tenant_id,
    role: row.role as Role,
    userId: row.user_id ?? row.id,
  };
}
