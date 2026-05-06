# Dashboard Security

The dashboard can expose sensitive scan artifacts: prompts, model responses,
tool traces, headers, and report files. Keep it bound to localhost unless you
are deliberately putting it behind an authenticated internal proxy.

Recommended local settings:

```env
DASHBOARD_HOST=127.0.0.1
DASHBOARD_REQUIRE_AUTH=true
DASHBOARD_TOKEN=change-me
DASHBOARD_TOKEN_BYPASS_RBAC=false
DASHBOARD_CORS_ORIGIN=http://127.0.0.1:4200
MAX_REPORT_BODY_BYTES=2000000
DASHBOARD_RATE_LIMIT_MAX=300
DASHBOARD_RATE_LIMIT_WINDOW_MS=60000
```

Security controls implemented in the built-in server:

- Binds to `DASHBOARD_HOST`, defaulting to `127.0.0.1`.
- Requires `Authorization: Bearer <DASHBOARD_TOKEN>` for `/api/*` when
  `DASHBOARD_REQUIRE_AUTH=true`, except public auth/config endpoints.
- In enterprise mode, OIDC/API-key/RBAC still applies unless
  `DASHBOARD_TOKEN_BYPASS_RBAC=true` is explicitly set.
- Restricts CORS to `DASHBOARD_CORS_ORIGIN` when configured.
- Rejects oversized request bodies using `MAX_REPORT_BODY_BYTES`.
- Applies a lightweight per-IP API rate limit.
- Validates report filenames with a strict allowlist and verifies resolved
  paths stay inside the report directory.

For enterprise mode, continue to use Postgres-backed OIDC/API-key/simple auth
and RBAC. Dashboard token auth is intended as a simple local hardening layer.
