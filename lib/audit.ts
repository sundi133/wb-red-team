/**
 * Immutable audit log.
 * Append-only — no UPDATE or DELETE operations.
 */

import { query } from "./db.js";
import type { RequestContext } from "./middleware.js";

export type AuditAction =
  | "run.start"
  | "run.cancel"
  | "run.view"
  | "report.view"
  | "report.list"
  | "report.export_csv"
  | "compliance.analyze"
  | "compliance.list_frameworks"
  | "audit.view";

export interface AuditEntry {
  id: string;
  tenantId: string;
  userId: string | null;
  action: AuditAction;
  targetType: string | null;
  targetId: string | null;
  metadata: Record<string, unknown> | null;
  ipAddress: string | null;
  createdAt: string;
}

/**
 * Write an audit log entry. Fire-and-forget — errors are logged but don't fail the request.
 */
export async function logAudit(
  ctx: RequestContext,
  action: AuditAction,
  targetType?: string,
  targetId?: string,
  metadata?: Record<string, unknown>,
): Promise<void> {
  try {
    await query(
      `INSERT INTO audit_log (tenant_id, user_id, action, target_type, target_id, metadata, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        ctx.tenantId,
        ctx.userId,
        action,
        targetType ?? null,
        targetId ?? null,
        metadata ? JSON.stringify(metadata) : null,
        ctx.ip || null,
      ],
    );
  } catch (err) {
    console.error("Audit log write failed:", err);
  }
}

/**
 * Query the audit log for a tenant.
 */
export async function queryAuditLog(
  tenantId: string,
  opts: {
    limit?: number;
    offset?: number;
    action?: string;
    since?: string;
  } = {},
): Promise<{ entries: AuditEntry[]; total: number }> {
  const limit = Math.min(opts.limit ?? 100, 500);
  const offset = opts.offset ?? 0;

  const conditions: string[] = ["tenant_id = $1"];
  const params: unknown[] = [tenantId];
  let paramIdx = 2;

  if (opts.action) {
    conditions.push(`action = $${paramIdx++}`);
    params.push(opts.action);
  }
  if (opts.since) {
    conditions.push(`created_at >= $${paramIdx++}`);
    params.push(opts.since);
  }

  const where = conditions.join(" AND ");

  const countResult = await query<{ count: string }>(
    `SELECT COUNT(*) as count FROM audit_log WHERE ${where}`,
    params,
  );

  const result = await query<{
    id: string;
    tenant_id: string;
    user_id: string | null;
    action: string;
    target_type: string | null;
    target_id: string | null;
    metadata: Record<string, unknown> | null;
    ip_address: string | null;
    created_at: string;
  }>(
    `SELECT id, tenant_id, user_id, action, target_type, target_id, metadata, ip_address, created_at
     FROM audit_log WHERE ${where}
     ORDER BY created_at DESC
     LIMIT $${paramIdx++} OFFSET $${paramIdx++}`,
    [...params, limit, offset],
  );

  return {
    entries: result.rows.map((r) => ({
      id: r.id,
      tenantId: r.tenant_id,
      userId: r.user_id,
      action: r.action as AuditAction,
      targetType: r.target_type,
      targetId: r.target_id,
      metadata: r.metadata,
      ipAddress: r.ip_address,
      createdAt: r.created_at,
    })),
    total: parseInt(countResult.rows[0].count, 10),
  };
}
