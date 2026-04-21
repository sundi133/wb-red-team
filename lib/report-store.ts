/**
 * Report storage — dual-write to Postgres (encrypted) and optionally to disk.
 * When DATABASE_URL is not set, falls back to file-only mode.
 */

import { query } from "./db.js";
import { encryptWithTenantKey, decryptWithTenantKey } from "./encryption.js";
import { writeReport as writeReportFile } from "./report-generator.js";
import type { Report } from "./types.js";

export interface ReportMeta {
  id: string;
  filename: string;
  timestamp: string;
  targetUrl: string;
  score: number;
  totalAttacks: number;
  passed: number;
  partial: number;
  failed: number;
  errors: number;
  runId: string | null;
}

/**
 * Store a report: encrypt and write to Postgres, and optionally write to disk.
 */
export async function storeReport(
  report: Report,
  tenantId: string,
  runId: string | null,
  opts?: { skipFile?: boolean },
): Promise<{ reportId: string; jsonPath?: string; mdPath?: string }> {
  // Always write file as fallback (unless opted out)
  let jsonPath: string | undefined;
  let mdPath: string | undefined;
  if (!opts?.skipFile) {
    const filePaths = writeReportFile(report);
    jsonPath = filePaths.jsonPath;
    mdPath = filePaths.mdPath;
  }

  // Get tenant's encryption key
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  if (tenantResult.rows.length === 0) {
    throw new Error(`Tenant not found: ${tenantId}`);
  }

  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;

  // Encrypt the full report JSON
  const reportJson = JSON.stringify(report);
  const { ciphertext, iv, authTag } = encryptWithTenantKey(
    reportJson,
    tenantKeyEnc,
  );

  // Build filename from timestamp
  const ts = report.timestamp.replace(/[:.]/g, "-");
  const filename = `report-${ts}.json`;

  // Extract plaintext summary fields for listing/search without decryption
  const s = report.summary;

  const result = await query<{ id: string }>(
    `INSERT INTO reports (
      tenant_id, run_id, filename, report_enc, iv, auth_tag,
      score, total_attacks, passed, partial, failed, errors,
      target_url, report_ts
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
    RETURNING id`,
    [
      tenantId,
      runId,
      filename,
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

  return { reportId: result.rows[0].id, jsonPath, mdPath };
}

/**
 * Retrieve and decrypt a report from Postgres.
 */
export async function getReport(
  reportId: string,
  tenantId: string,
): Promise<Report> {
  const result = await query<{
    report_enc: Buffer;
    iv: Buffer;
    auth_tag: Buffer;
    tenant_id: string;
  }>(
    `SELECT r.report_enc, r.iv, r.auth_tag, r.tenant_id
     FROM reports r WHERE r.id = $1 AND r.tenant_id = $2`,
    [reportId, tenantId],
  );

  if (result.rows.length === 0) {
    throw new Error("Report not found");
  }

  const row = result.rows[0];

  // Get tenant encryption key
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;

  const json = decryptWithTenantKey(
    row.report_enc,
    row.iv,
    row.auth_tag,
    tenantKeyEnc,
  );

  return JSON.parse(json) as Report;
}

/**
 * List reports for a tenant (uses plaintext summary columns, no decryption).
 */
export async function listReports(
  tenantId: string,
  opts: {
    page?: number;
    limit?: number;
    search?: string;
  } = {},
): Promise<{ items: ReportMeta[]; total: number }> {
  const limit = Math.min(opts.limit ?? 50, 200);
  const page = opts.page ?? 1;
  const offset = (page - 1) * limit;

  const conditions: string[] = ["tenant_id = $1"];
  const params: unknown[] = [tenantId];
  let paramIdx = 2;

  if (opts.search) {
    conditions.push(
      `(target_url ILIKE $${paramIdx} OR filename ILIKE $${paramIdx})`,
    );
    params.push(`%${opts.search}%`);
    paramIdx++;
  }

  const where = conditions.join(" AND ");

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) as count FROM reports WHERE ${where}`,
    params,
  );

  const result = await query<{
    id: string;
    filename: string;
    report_ts: string;
    target_url: string;
    score: number;
    total_attacks: number;
    passed: number;
    partial: number;
    failed: number;
    errors: number;
    run_id: string | null;
  }>(
    `SELECT id, filename, report_ts, target_url, score,
            total_attacks, passed, partial, failed, errors, run_id
     FROM reports WHERE ${where}
     ORDER BY report_ts DESC
     LIMIT $${paramIdx++} OFFSET $${paramIdx++}`,
    [...params, limit, offset],
  );

  return {
    items: result.rows.map((r) => ({
      id: r.id,
      filename: r.filename,
      timestamp: r.report_ts,
      targetUrl: r.target_url,
      score: r.score,
      totalAttacks: r.total_attacks,
      passed: r.passed,
      partial: r.partial,
      failed: r.failed,
      errors: r.errors,
      runId: r.run_id,
    })),
    total: parseInt(countResult.rows[0].count, 10),
  };
}

/**
 * Get a report by filename (for backward compatibility with file-based APIs).
 */
export async function getReportByFilename(
  filename: string,
  tenantId: string,
): Promise<{ id: string; report: Report } | null> {
  const result = await query<{
    id: string;
    report_enc: Buffer;
    iv: Buffer;
    auth_tag: Buffer;
  }>(
    `SELECT id, report_enc, iv, auth_tag
     FROM reports WHERE filename = $1 AND tenant_id = $2`,
    [filename, tenantId],
  );

  if (result.rows.length === 0) return null;

  const row = result.rows[0];
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;

  const json = decryptWithTenantKey(
    row.report_enc,
    row.iv,
    row.auth_tag,
    tenantKeyEnc,
  );

  return { id: row.id, report: JSON.parse(json) as Report };
}
