---
title: White-Box Scanning
nav_order: 4
---

# White-Box Scanning

Red-Team AI can read your application's source code to discover tools, roles, guardrails, hardcoded secrets, and call graphs — then generate attacks tailored to your actual implementation.

## Enabling white-box mode

Add `codebaseRepo` to your config JSON:

```json
{
  "target": {
    "baseUrl": "https://your-agent.example.com",
    "agentEndpoint": "/api/agent"
  },
  "codebaseRepo": "https://github.com/yourorg/your-app.git",
  "codebaseRepoBranch": "main",
  "codebaseGlob": "**/*"
}
```

Each run shallow-clones the repo into an isolated temp directory, analyzes the code, runs the scan, and cleans up automatically. Multiple concurrent runs against different repos work without conflicts.

| Config field | Required | Description |
|--------------|----------|-------------|
| `codebaseRepo` | For white-box | Git HTTPS URL to clone |
| `codebaseRepoBranch` | No | Branch or tag (default: HEAD) |
| `codebaseGlob` | No | File pattern to analyze (default: `**/*`) |
| `codebaseRepoToken` | For private repos | Git personal access token |
| `codebasePath` | Alternative | Local filesystem path (use instead of `codebaseRepo` for local dev) |

## Private repos & tokens

**Create a GitHub fine-grained token:**

1. github.com → avatar (top right) → **Settings**
2. **Developer settings** (bottom of left sidebar)
3. **Personal access tokens** → **Fine-grained tokens** → **Generate new token**
4. Configure:
   - **Token name**: `red-team-scanner`
   - **Expiration**: 90 days
   - **Repository access**: Only select repositories → pick the repo(s)
   - **Permissions** → Repository permissions → **Contents: Read-only**
5. Generate, then copy (`github_pat_...`)

**Use the token — environment variable (recommended):**

```
CODEBASE_REPO_TOKEN=github_pat_xxxxxxxxxxxx
```

**Or per-request in config:**

```json
{
  "codebaseRepo": "https://github.com/yourorg/private-app.git",
  "codebaseRepoToken": "github_pat_xxxxxxxxxxxx"
}
```

## Other Git providers

| Provider | How to create token | Token format |
|----------|---------------------|--------------|
| **GitLab** | Settings → Access Tokens → scope: `read_repository` | `glpat-xxxxxxxxxxxx` |
| **Bitbucket** | Settings → App passwords → permission: Repositories: Read | `username:app_password` |
| **Azure DevOps** | User settings → Personal access tokens → scope: Code (Read) | `your-pat-token` |

## Black-box mode

If `codebaseRepo` and `codebasePath` are both omitted or `null`, the scanner runs in pure black-box mode — no source code analysis, attacks are generated from `applicationDetails` and live target probing only. See the [API-Only Testing]({{ site.baseurl }}/api-only/) page.

## What white-box analysis discovers

- **Tools** — function names, parameters, permissions, call graphs
- **Roles** — user types, privilege levels, RBAC rules
- **Guardrails** — input/output filters, regex patterns, blocklists
- **Secrets** — hardcoded API keys, JWT secrets, database credentials
- **Architecture** — framework, endpoints, middleware chain, data flow
