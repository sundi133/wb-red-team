# Hermes Agent as wb-red-team's config compiler

Hermes Agent is the **analyst**; wb-red-team is the **executor**. Hermes reads
the target's code, probes it gently, reads past reports, and emits a
target-specific `config.<slug>.json` + `attacks-<slug>.csv` + `policy-<slug>.json`.
Then you run wb-red-team the normal way, pointed at that config.

Contents of this directory:

| File | Role |
|---|---|
| `tool-server.ts` | Tiny HTTP server exposing 6 reconnaissance tools to Hermes |
| `skills/target-analyst.md` | The Hermes skill that drives the workflow |
| `tools.toml` | Hermes tool manifest (register this with your Hermes profile) |

## Step-by-step (local)

### 1. Install Hermes Agent

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | sh
hermes --version
```

### 2. Create a dedicated profile for red-team config authoring

```bash
export HERMES_HOME="$HOME/.hermes-redteam-analyst"
hermes init
```

Point Hermes at any provider you like:

```bash
# Pick one
hermes config set provider.type anthropic      && export ANTHROPIC_API_KEY=sk-ant-...
hermes config set provider.type openai         && export OPENAI_API_KEY=sk-...
hermes config set provider.type openrouter     && export OPENROUTER_API_KEY=sk-or-...
hermes config set provider.model claude-sonnet-4-5   # or whatever fits your provider
```

### 3. Install the skill and tool manifest into the profile

```bash
cp hermes-redteam/skills/target-analyst.md   "$HERMES_HOME/skills/"
cp hermes-redteam/tools.toml                 "$HERMES_HOME/tools/redteam.toml"
hermes tools list     # should show read_repo, probe_target, read_prior_reports, write_config, write_custom_attacks, write_policy
```

(If your Hermes version uses a slightly different tool-manifest path or syntax,
see https://hermes-agent.nousresearch.com/docs/user-guide/configuration/ and
adjust `tools.toml` accordingly.)

### 4. Start the tool server

In terminal A, from the repo root:

```bash
npx tsx hermes-redteam/tool-server.ts
# [hermes-redteam] tool server listening on http://127.0.0.1:4300
```

### 5. Make sure the target is reachable

For the demo:

```bash
# in a separate terminal
git clone https://github.com/sundi133/demo-agentic-app.git
cd demo-agentic-app && npm install && npm run dev   # http://localhost:3000
```

For an enterprise deployment, make sure the tool server can reach the target URL
(VPN, in-cluster, bastion — whichever applies).

### 6. Run the analyst

In terminal B:

```bash
export HERMES_HOME="$HOME/.hermes-redteam-analyst"
hermes run --skill target-analyst --input '{
  "slug": "demo",
  "repoPath": "../demo-agentic-app/src",
  "baseUrl": "http://localhost:3000",
  "endpoint": "/api/exfil-test-agent",
  "authHeaders": { "Authorization": "Bearer <token-if-needed>" },
  "appHint": "Internal support copilot with mocked tools (read_file, db_query, read_repo, send_email, slack_dm, read_inbox); JWT auth with roles admin/engineer/manager/viewer/intern; returns fake PII from fixtures."
}'
```

Hermes will:

1. `read_repo` on `../demo-agentic-app/src`
2. `probe_target` 5–8 times with benign messages
3. `read_prior_reports` from `report/`
4. Synthesize the three files
5. `write_config`, `write_custom_attacks`, `write_policy`

Output paths (relative to the wb-red-team repo root):

```
configs/config.demo.json
configs/attacks-demo.csv
configs/policy-demo.json
```

### 7. Run wb-red-team with the generated config

```bash
npx tsx red-team.ts configs/config.demo.json
```

Reports land in `report/` and show up in the dashboard (`npm run dashboard`).

### 8. Iterate

Every time the target changes (new tool, new role, new endpoint), re-run
step 6. Hermes's memory means it picks up where the last analysis left off
rather than starting cold. Keep a profile per target:

```bash
HERMES_HOME=~/.hermes-redteam-acme     hermes run --skill target-analyst --input '{...acme...}'
HERMES_HOME=~/.hermes-redteam-fintech  hermes run --skill target-analyst --input '{...fintech...}'
```

## What this scaffold does NOT do

- Does **not** replace wb-red-team's attack loop. `red-team.ts` still runs
  the actual attacks; Hermes just produces its configs.
- Does **not** need Ollama. Any provider Hermes supports works.
- Does **not** write to your target, the network, or anywhere outside
  `./configs/` and the files you pass explicitly.

## Troubleshooting

- `hermes tools list` is empty → tool server isn't running, or the manifest
  path doesn't match your Hermes version. Try `curl http://127.0.0.1:4300/tools`
  to confirm the server is up, then check Hermes docs for the correct
  manifest location.
- Probe returns HTML instead of JSON → you hit a login page or WAF. Add the
  right `authHeaders` to the `hermes run --input`.
- wb-red-team rejects the generated config → run
  `npx tsx red-team.ts configs/config.demo.json` and read the validation
  error; adjust the skill or the config by hand and re-run.
