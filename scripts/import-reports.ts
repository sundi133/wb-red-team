#!/usr/bin/env npx tsx
/**
 * Import existing JSON report files from disk into Postgres.
 * Run once after migrating to enterprise mode.
 *
 * Usage:
 *   DATABASE_URL=postgres://... MASTER_ENCRYPTION_KEY=... npx tsx scripts/import-reports.ts
 *
 * Or if .env has them:
 *   npx tsx scripts/import-reports.ts
 */

import { readdirSync, readFileSync } from "fs";
import { join, resolve } from "path";
import { loadEnvFile } from "../lib/env-loader.js";
import { isDbConfigured, runMigrations, query, closePool } from "../lib/db.js";
import { encryptWithTenantKey, generateTenantKey } from "../lib/encryption.js";
import type { Report } from "../lib/types.js";

loadEnvFile();

const REPORT_DIR = resolve(import.meta.dirname ?? process.cwd(), "..", "report");

async function main() {
  if (!isDbConfigured()) {
    console.error("DATABASE_URL is not set. Add it to .env or export it.");
    process.exit(1);
  }

  if (!process.env.MASTER_ENCRYPTION_KEY) {
    console.error("MASTER_ENCRYPTION_KEY is not set. Generate one with: openssl rand -hex 32");
    process.exit(1);
  }

  console.log("Running migrations...");
  await runMigrations();

  // Ensure a default tenant exists
  let tenantId: string;
  const existingTenant = await query<{ id: string }>(
    "SELECT id FROM tenants WHERE name = $1",
    ["default"],
  );

  if (existingTenant.rows.length > 0) {
    tenantId = existingTenant.rows[0].id;
    console.log(`Using existing tenant: ${tenantId}`);
  } else {
    const encKey = generateTenantKey();
    const result = await query<{ id: string }>(
      `INSERT INTO tenants (name, oidc_issuer, encryption_key_enc)
       VALUES ($1, $2, $3) RETURNING id`,
      ["default", "https://localhost/dev", encKey],
    );
    tenantId = result.rows[0].id;
    console.log(`Created default tenant: ${tenantId}`);
  }

  // Get tenant encryption key
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;

  // Find report files
  let files: string[];
  try {
    files = readdirSync(REPORT_DIR).filter((f) => f.endsWith(".json")).sort();
  } catch {
    console.error(`No report directory found at ${REPORT_DIR}`);
    process.exit(1);
  }

  if (files.length === 0) {
    console.log("No report files found to import.");
    await closePool();
    return;
  }

  console.log(`Found ${files.length} report files to import.\n`);

  let imported = 0;
  let skipped = 0;

  for (const file of files) {
    // Check if already imported
    const existing = await query<{ id: string }>(
      "SELECT id FROM reports WHERE filename = $1 AND tenant_id = $2",
      [file, tenantId],
    );
    if (existing.rows.length > 0) {
      console.log(`  SKIP ${file} (already imported)`);
      skipped++;
      continue;
    }

    try {
      const raw = readFileSync(join(REPORT_DIR, file), "utf-8");
      const report: Report = JSON.parse(raw);
      const s = report.summary;

      // Encrypt
      const { ciphertext, iv, authTag } = encryptWithTenantKey(raw, tenantKeyEnc);

      await query(
        `INSERT INTO reports (
          tenant_id, run_id, filename, report_enc, iv, auth_tag,
          score, total_attacks, passed, partial, failed, errors,
          target_url, report_ts
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          tenantId,
          null,
          file,
          ciphertext,
          iv,
          authTag,
          s.score,
          s.totalAttacks,
          s.passed,
          s.partial,
          s.failed,
          s.errors,
          report.targetUrl,
          report.timestamp,
        ],
      );

      console.log(`  OK   ${file} (score: ${s.score}, ${s.totalAttacks} attacks)`);
      imported++;
    } catch (err) {
      console.error(`  FAIL ${file}: ${(err as Error).message}`);
    }
  }

  console.log(`\nDone. Imported: ${imported}, Skipped: ${skipped}, Total: ${files.length}`);
  await closePool();
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
