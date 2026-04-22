/**
 * Development-mode authentication.
 * Uses a simple API key (DEV_API_KEY env var) instead of OIDC JWT.
 * Auto-creates a default tenant and admin user on first use.
 *
 * NEVER use in production — set AUTH_MODE=dev only for local testing.
 */

import { query } from "./db.js";
import { generateTenantKey } from "./encryption.js";
import type { AuthContext } from "./auth.js";
import type { Role } from "./rbac.js";

let devTenantId: string | null = null;
let devUserId: string | null = null;

/**
 * Validate a dev API key from the Authorization header.
 * Format: "Bearer <DEV_API_KEY>" or "ApiKey <DEV_API_KEY>"
 */
export async function validateDevToken(
  authHeader: string | undefined,
): Promise<AuthContext> {
  const devKey = process.env.DEV_API_KEY || "dev-key";

  if (!authHeader) {
    throw new Error("Missing Authorization header");
  }

  // Accept "Bearer <key>" or "ApiKey <key>"
  const token = authHeader.replace(/^(Bearer|ApiKey)\s+/i, "").trim();
  if (token !== devKey) {
    throw new Error("Invalid dev API key");
  }

  // Ensure default tenant exists
  if (!devTenantId) {
    const existing = await query<{ id: string }>(
      "SELECT id FROM tenants WHERE name = $1",
      ["default"],
    );

    if (existing.rows.length > 0) {
      devTenantId = existing.rows[0].id;
    } else {
      const encKey = generateTenantKey();
      const result = await query<{ id: string }>(
        `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
         VALUES ($1, $2, $3) RETURNING id`,
        ["default", "https://localhost/dev", encKey],
      );
      devTenantId = result.rows[0].id;
      console.log(`  Dev mode: created default tenant ${devTenantId}`);
    }
  }

  // Ensure default admin user exists
  if (!devUserId) {
    const existing = await query<{ id: string }>(
      "SELECT id FROM users WHERE tenant_id = $1 AND sub = $2",
      [devTenantId, "dev-admin"],
    );

    if (existing.rows.length > 0) {
      devUserId = existing.rows[0].id;
    } else {
      const result = await query<{ id: string }>(
        `INSERT INTO users (tenant_id, sub, email, role)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [devTenantId, "dev-admin", "admin@localhost", "admin"],
      );
      devUserId = result.rows[0].id;
      console.log(`  Dev mode: created admin user ${devUserId}`);
    }
  }

  return {
    sub: "dev-admin",
    email: "admin@localhost",
    tenantId: devTenantId,
    role: "admin" as Role,
    userId: devUserId,
  };
}
