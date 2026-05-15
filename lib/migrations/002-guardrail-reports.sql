-- Migration 002: Guardrail reports persistence
-- Stores LiteLLM guardrail evaluation reports in the database

CREATE TABLE IF NOT EXISTS guardrail_reports (
  id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id     UUID NOT NULL REFERENCES tenants(id),
  filename      TEXT NOT NULL,
  report_enc    BYTEA NOT NULL,
  iv            BYTEA NOT NULL,
  auth_tag      BYTEA NOT NULL,
  model         TEXT,
  guardrails    JSONB,
  good_total    INTEGER NOT NULL DEFAULT 0,
  bad_total     INTEGER NOT NULL DEFAULT 0,
  blocked       INTEGER NOT NULL DEFAULT 0,
  total         INTEGER NOT NULL DEFAULT 0,
  report_ts     TIMESTAMPTZ,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_guardrail_reports_tenant ON guardrail_reports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_guardrail_reports_tenant_ts ON guardrail_reports(tenant_id, report_ts DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_guardrail_reports_filename ON guardrail_reports(tenant_id, filename);
