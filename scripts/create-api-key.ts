#!/usr/bin/env npx tsx
/**
 * Create an API key for programmatic access (CI/CD, scripts, local testing).
 *
 * Usage:
 *   npx tsx scripts/create-api-key.ts [--tenant NAME] [--role ROLE] [--name LABEL]
 *
 * Examples:
 *   npx tsx scripts/create-api-key.ts
 *   npx tsx scripts/create-api-key.ts --tenant default --role admin --name "CI pipeline"
 *   npx tsx scripts/create-api-key.ts --role viewer --name "Read-only dashboard"
 */

import { randomBytes, createHash } from "node:crypto";
import { loadEnvFile } from "../lib/env-loader.js";
import { isDbConfigured, runMigrations, query, closePool } from "../lib/db.js";
import { generateTenantKey } from "../lib/encryption.js";

loadEnvFile();

function parseArgs(): { tenant: string; role: string; name: string } {
  const args = process.argv.slice(2);
  let tenant = "default";
  let role = "admin";
  let name = "api-key";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--tenant" && args[i + 1]) tenant = args[++i];
    else if (args[i] === "--role" && args[i + 1]) role = args[++i];
    else if (args[i] === "--name" && args[i + 1]) name = args[++i];
  }

  if (!["admin", "viewer", "auditor"].includes(role)) {
    console.error(`Invalid role: ${role}. Must be admin, viewer, or auditor.`);
    process.exit(1);
  }

  return { tenant, role, name };
}

async function main() {
  if (!isDbConfigured()) {
    console.error("DATABASE_URL is not set.");
    process.exit(1);
  }

  await runMigrations();

  const { tenant, role, name } = parseArgs();

  // Ensure tenant exists
  let tenantId: string;
  const existing = await query<{ id: string }>(
    "SELECT id FROM tenants WHERE name = $1",
    [tenant],
  );

  if (existing.rows.length > 0) {
    tenantId = existing.rows[0].id;
  } else {
    const encKey = generateTenantKey();
    const result = await query<{ id: string }>(
      `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
       VALUES ($1, $2, $3) RETURNING id`,
      [tenant, "https://localhost/dev", encKey],
    );
    tenantId = result.rows[0].id;
    console.log(`Created tenant: ${tenant} (${tenantId})`);
  }

  // Generate API key
  const rawKey = "rtk_" + randomBytes(32).toString("hex");
  const keyHash = createHash("sha256").update(rawKey).digest("hex");

  await query(
    `INSERT INTO api_keys (tenant_id, key_hash, name, role)
     VALUES ($1, $2, $3, $4)`,
    [tenantId, keyHash, name, role],
  );

  console.log("\n  API key created successfully!\n");
  console.log(`  Key:    ${rawKey}`);
  console.log(`  Tenant: ${tenant}`);
  console.log(`  Role:   ${role}`);
  console.log(`  Name:   ${name}`);
  console.log("\n  Usage:\n");
  console.log(`  curl -H "X-API-Key: ${rawKey}" http://localhost:4200/api/runs`);
  console.log(`\n  curl -X POST http://localhost:4200/api/run \\`);
  console.log(`    -H "X-API-Key: ${rawKey}" \\`);
  console.log(`    -H "Content-Type: application/json" \\`);
  console.log(`    -d @config.json\n`);
  console.log("  Save this key — it cannot be retrieved later.\n");

  await closePool();
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
