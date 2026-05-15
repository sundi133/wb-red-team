/**
 * Guardrail report storage — dual-write to Postgres (encrypted) and disk.
 * Falls back to file-only mode when DATABASE_URL is not set.
 */

import { query } from "./db.js";
import { encryptWithTenantKey, decryptWithTenantKey } from "./encryption.js";

/** Convert filename-style timestamps like "2026-05-12T14-26-27Z" to valid ISO "2026-05-12T14:26:27Z". */
function normalizeTimestamp(ts: string | undefined): string | undefined {
  if (!ts) return undefined;
  // Match pattern: date T HH-MM-SS and replace dashes in time with colons
  const fixed = ts.replace(/T(\d{2})-(\d{2})-(\d{2})/, "T$1:$2:$3");
  const d = new Date(fixed);
  return isNaN(d.getTime()) ? undefined : d.toISOString();
}

export interface GuardrailReportMeta {
  filename: string;
  created_at: string;
  model: string;
  guardrails: string[];
  goodTotal: number;
  badTotal: number;
  blocked: number;
  total: number;
}

/** Extract summary fields from a parsed guardrail report. */
export function extractGuardrailSummary(parsed: any): {
  model: string;
  guardrails: string[];
  goodTotal: number;
  badTotal: number;
  blocked: number;
  total: number;
  reportTs: string;
} {
  const results = parsed.results || [];
  const goodTotal = results.filter(
    (r: any) => r.without_guardrails?.category === "good",
  ).length;
  const badTotal = results.filter(
    (r: any) => r.without_guardrails?.category === "bad",
  ).length;
  const blocked = results.filter((r: any) => {
    const g = r.with_guardrails;
    if (!g || g.category !== "bad") return false;
    if (g.verdict)
      return (
        g.verdict === "guardrail_blocked" ||
        g.verdict === "safe_refusal_or_redirect"
      );
    return (
      g.status_code === 400 ||
      g.status_code === 403 ||
      (g.response_text || "").toLowerCase().includes("blocked by votal guardrails")
    );
  }).length;

  return {
    model: parsed.model || "",
    guardrails: parsed.guardrails || [],
    goodTotal,
    badTotal,
    blocked,
    total: results.length,
    reportTs: normalizeTimestamp(parsed.created_at) || new Date().toISOString(),
  };
}

/**
 * Store a guardrail report: encrypt and write to Postgres.
 */
export async function storeGuardrailReport(
  reportJson: string,
  tenantId: string,
  filename: string,
): Promise<{ reportId: string }> {
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  if (tenantResult.rows.length === 0) {
    throw new Error(`Tenant not found: ${tenantId}`);
  }

  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;
  const { ciphertext, iv, authTag } = encryptWithTenantKey(
    reportJson,
    tenantKeyEnc,
  );

  const parsed = JSON.parse(reportJson);
  const summary = extractGuardrailSummary(parsed);

  const result = await query<{ id: string }>(
    `INSERT INTO guardrail_reports (
      tenant_id, filename, report_enc, iv, auth_tag,
      model, guardrails, good_total, bad_total, blocked, total, report_ts
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (tenant_id, filename) DO UPDATE SET
      report_enc = EXCLUDED.report_enc,
      iv = EXCLUDED.iv,
      auth_tag = EXCLUDED.auth_tag,
      model = EXCLUDED.model,
      guardrails = EXCLUDED.guardrails,
      good_total = EXCLUDED.good_total,
      bad_total = EXCLUDED.bad_total,
      blocked = EXCLUDED.blocked,
      total = EXCLUDED.total,
      report_ts = EXCLUDED.report_ts
    RETURNING id`,
    [
      tenantId,
      filename,
      ciphertext,
      iv,
      authTag,
      summary.model,
      JSON.stringify(summary.guardrails),
      summary.goodTotal,
      summary.badTotal,
      summary.blocked,
      summary.total,
      summary.reportTs,
    ],
  );

  return { reportId: result.rows[0].id };
}

/**
 * Retrieve and decrypt a guardrail report from Postgres.
 */
export async function getGuardrailReport(
  filename: string,
  tenantId: string,
): Promise<string | null> {
  const result = await query<{
    report_enc: Buffer;
    iv: Buffer;
    auth_tag: Buffer;
  }>(
    `SELECT report_enc, iv, auth_tag
     FROM guardrail_reports WHERE filename = $1 AND tenant_id = $2`,
    [filename, tenantId],
  );

  if (result.rows.length === 0) return null;

  const row = result.rows[0];
  const tenantResult = await query<{ encryption_key_enc: string }>(
    "SELECT encryption_key_enc FROM tenants WHERE id = $1",
    [tenantId],
  );
  const tenantKeyEnc = tenantResult.rows[0].encryption_key_enc;

  return decryptWithTenantKey(row.report_enc, row.iv, row.auth_tag, tenantKeyEnc);
}

/**
 * List guardrail reports for a tenant (plaintext summary columns, no decryption).
 */
export async function listGuardrailReports(
  tenantId: string,
): Promise<GuardrailReportMeta[]> {
  const result = await query<{
    filename: string;
    report_ts: string;
    model: string;
    guardrails: string[];
    good_total: number;
    bad_total: number;
    blocked: number;
    total: number;
  }>(
    `SELECT filename, report_ts, model, guardrails,
            good_total, bad_total, blocked, total
     FROM guardrail_reports
     WHERE tenant_id = $1
     ORDER BY report_ts DESC`,
    [tenantId],
  );

  return result.rows.map((r) => ({
    filename: r.filename,
    created_at: r.report_ts,
    model: r.model || "",
    guardrails: r.guardrails || [],
    goodTotal: r.good_total,
    badTotal: r.bad_total,
    blocked: r.blocked,
    total: r.total,
  }));
}
