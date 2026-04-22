# Hermes Agent as wb-red-team's config compiler

Hermes Agent is the **analyst**; wb-red-team is the **executor**. Hermes reads
the target's code, probes it gently, reads past reports, and emits a
target-specific `config.<slug>.json` + `attacks-<slug>.csv` + `policy-<slug>.json`.
Then you run wb-red-team the normal way, pointed at that config.

Tested against **Hermes Agent v0.10.x**. Tools are exposed to Hermes via MCP
(Model Context Protocol), the mechanism Hermes natively supports.

## Files in this directory

| File | Role |
|---|---|
| `mcp-server.ts` | MCP stdio server — this is what Hermes actually calls |
| `tool-server.ts` | Optional HTTP mirror for manual `curl` testing |
| `handlers.ts` | Six shared tool implementations used by both transports |
| `skills/target-analyst.md` | The Hermes skill that drives the workflow |
| `setup.sh` | One-shot installer / registrar (`npm run hermes:setup`) |

## Step-by-step (local)

### 1. One-shot setup

```bash
npm run hermes:setup
```

Idempotent. Does:

1. installs Hermes Agent if missing
2. picks the profile at `$HERMES_HOME` (default `~/.hermes-redteam-analyst`)
3. sets `provider.type` / `provider.model` via `hermes config set`
4. copies `skills/target-analyst.md` into `$HERMES_HOME/skills/` (auto-discovered)
5. registers `mcp-server.ts` via `hermes mcp add wb-redteam -- npx tsx .../mcp-server.ts`
6. verifies via `hermes skills list` and `hermes mcp list`

Non-interactive:

```bash
PROVIDER=anthropic  MODEL=claude-sonnet-4-5           npm run hermes:setup
PROVIDER=openrouter MODEL=nousresearch/hermes-4-70b   npm run hermes:setup
HERMES_HOME=~/.hermes-redteam-acme PROVIDER=openrouter npm run hermes:setup
```

Export the provider's API key before the next step (e.g. `export OPENROUTER_API_KEY=...`).

<details>
<summary>Manual equivalent, if your Hermes version's flags differ</summary>

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | sh
export HERMES_HOME="$HOME/.hermes-redteam-analyst"

hermes config set provider.type openrouter
hermes config set provider.model nousresearch/hermes-4-70b
export OPENROUTER_API_KEY=sk-or-...

cp hermes-redteam/skills/target-analyst.md "$HERMES_HOME/skills/"

# MCP registration — run `hermes mcp add --help` on your machine if this form
# isn't accepted and substitute the correct flags:
hermes mcp add wb-redteam -- npx tsx "$(pwd)/hermes-redteam/mcp-server.ts"

hermes skills list     # should include target-analyst
hermes mcp list        # should include wb-redteam
```
</details>

### 2. Make sure the target is reachable

For the demo:

```bash
git clone https://github.com/sundi133/demo-agentic-app.git
cd demo-agentic-app && npm install && npm run dev   # http://localhost:3000
```

For an enterprise deployment, ensure your shell (and therefore the MCP server
that Hermes spawns) can reach the target URL — VPN, in-cluster, or bastion.

### 3. Run the analyst

Hermes v0.10 uses `hermes chat`, not `hermes run`, and skills are selected
via the top-level `--skills` flag. `repoPath` is **optional** — omit it for
black-box / enterprise targets.

**White-box (with source access):**

```bash
export HERMES_HOME="$HOME/.hermes-redteam-analyst"

hermes --skills target-analyst chat "Run the target-analyst workflow with these inputs:
slug=demo
repoPath=../demo-agentic-app/src
baseUrl=http://localhost:3000
endpoint=/api/exfil-test-agent
authHeaders={}
appHint=Internal support copilot with mocked tools (read_file, db_query, send_email, slack_dm); JWT auth.

Use the wb-redteam MCP tools. Write outputs under ./configs/."
```

**Black-box (deployed enterprise app, no source):**

```bash
export HERMES_HOME="$HOME/.hermes-redteam-analyst"
export ENTERPRISE_BEARER=...

hermes --skills target-analyst chat "Run the target-analyst workflow with these inputs:
slug=acme-prod
baseUrl=https://agent.prod.acme.internal
endpoint=/v1/assistant/chat
authHeaders={\"Authorization\":\"Bearer $ENTERPRISE_BEARER\"}
appHint=Customer-support copilot, multi-tenant, CRM + order tools.

Use the wb-redteam MCP tools. Write outputs under ./configs/."
```

Hermes will:

1. `read_repo` on `repoPath` **(skipped if omitted)**
2. `probe_target` 5–8 times with benign messages
3. `read_prior_reports` from `report/`
4. Synthesize the three files
5. `write_config`, `write_custom_attacks`, `write_policy`

Output paths (relative to the wb-red-team repo root):

```
configs/config.<slug>.json
configs/attacks-<slug>.csv
configs/policy-<slug>.json
```

In black-box mode the generated config omits `codebasePath` and marks
`applicationDetails` as observation-only so future runs re-probe rather
than trust stale inferences.

### 4. Run wb-red-team with the generated config

```bash
npx tsx red-team.ts configs/config.<slug>.json
```

Reports land in `report/` and show up in the dashboard (`npm run dashboard`).

### 5. Iterate

Every time the target changes, re-run step 3. Hermes's memory picks up where
the last analysis left off. Keep a profile per target:

```bash
HERMES_HOME=~/.hermes-redteam-acme     hermes --skills target-analyst chat "..."
HERMES_HOME=~/.hermes-redteam-fintech  hermes --skills target-analyst chat "..."
```

## Optional: HTTP tool server for manual curl testing

```bash
npm run hermes:tools        # http://127.0.0.1:4300

curl -X POST http://127.0.0.1:4300/tool/probe_target \
  -H 'Content-Type: application/json' \
  -d '{"baseUrl":"http://localhost:3000","endpoint":"/api/exfil-test-agent","message":"hello"}'
```

This is independent of the MCP transport — useful for verifying the handlers
behave as expected without going through Hermes.

## Troubleshooting

- **`hermes --skills target-analyst chat ...` says skill not found** → run
  `hermes skills list`. If empty, Hermes v0.10 may require an explicit
  `hermes skills add "$HERMES_HOME/skills/target-analyst.md"` rather than
  auto-discovery. Check `hermes skills --help` on your machine.
- **Hermes can't see the MCP tools** → `hermes mcp list` should show
  `wb-redteam`. If not, `hermes mcp add --help` and adapt `setup.sh`'s
  registration call. You can also try launching the MCP server directly
  to confirm it's valid: `npx tsx hermes-redteam/mcp-server.ts` (it will
  wait on stdin — `Ctrl-C` to exit).
- **Probe returns HTML instead of JSON** → login page or WAF. Add the
  right `Authorization` header to the inputs.
- **wb-red-team rejects the generated config** → run the config through
  `red-team.ts` and read the validation error; adjust the skill and re-run.

## What this scaffold does NOT do

- Does **not** replace wb-red-team's attack loop. `red-team.ts` still runs
  the actual attacks; Hermes just produces its configs.
- Does **not** need Ollama. Any provider Hermes supports works.
- Does **not** write outside `./configs/`, `$HERMES_HOME`, and files you pass
  explicitly to the write_* tools.
