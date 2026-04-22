#!/usr/bin/env bash
#
# Hermes Agent setup for wb-red-team's target-analyst workflow.
#
# What this does (idempotent):
#   1. Installs Hermes Agent if missing
#   2. Creates/uses a dedicated Hermes profile at $HERMES_HOME
#   3. Configures the provider (interactive unless $PROVIDER is set)
#   4. Installs the target-analyst skill + tool manifest into the profile
#   5. Verifies tools are registered
#
# Does NOT start the tool server and does NOT run Hermes.
# The script prints the two commands to run at the end.
#
# Usage:
#   ./hermes-redteam/setup.sh
#   PROVIDER=anthropic MODEL=claude-sonnet-4-5 ./hermes-redteam/setup.sh
#   HERMES_HOME=~/.hermes-redteam-acme ./hermes-redteam/setup.sh

set -euo pipefail

# ── Resolve repo root (script may be invoked from anywhere) ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Config (override via env) ──
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes-redteam-analyst}"
PROVIDER="${PROVIDER:-}"
MODEL="${MODEL:-}"
INSTALL_URL="${HERMES_INSTALL_URL:-https://hermes-agent.nousresearch.com/install.sh}"

# ── Pretty logging ──
log()  { printf "\033[1;34m[setup]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m  %s\n" "$*" >&2; }
err()  { printf "\033[1;31m[err]\033[0m   %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

# ── Preflight ──
log "repo root:    $REPO_ROOT"
log "HERMES_HOME:  $HERMES_HOME"

command -v curl >/dev/null || die "curl not found"
command -v node >/dev/null || die "node not found (>= 18 required)"

node_major=$(node -p "parseInt(process.versions.node.split('.')[0],10)")
[ "$node_major" -ge 18 ] || die "node >= 18 required, found $(node --version)"

[ -f "$REPO_ROOT/hermes-redteam/skills/target-analyst.md" ] \
  || die "target-analyst.md not found — run from wb-red-team repo"
[ -f "$REPO_ROOT/hermes-redteam/tools.toml" ] \
  || die "tools.toml not found — run from wb-red-team repo"

# ── 1. Install Hermes if missing ──
if command -v hermes >/dev/null; then
  log "hermes already installed: $(hermes --version 2>&1 | head -1)"
else
  log "installing Hermes Agent from $INSTALL_URL"
  curl -fsSL "$INSTALL_URL" | sh
  command -v hermes >/dev/null \
    || die "hermes still not on PATH after install; open a new shell or check installer output"
fi

# ── 2. Initialize profile ──
export HERMES_HOME
mkdir -p "$HERMES_HOME"

if [ -f "$HERMES_HOME/config.toml" ] || [ -f "$HERMES_HOME/config.yaml" ]; then
  log "profile already initialized at $HERMES_HOME (skipping hermes init)"
else
  log "initializing profile at $HERMES_HOME"
  hermes init || warn "hermes init returned non-zero — continuing; verify with 'hermes config show'"
fi

# ── 3. Provider config ──
if [ -z "$PROVIDER" ]; then
  echo
  echo "Choose a provider:"
  echo "  1) anthropic   (needs ANTHROPIC_API_KEY)"
  echo "  2) openai      (needs OPENAI_API_KEY)"
  echo "  3) openrouter  (needs OPENROUTER_API_KEY)"
  echo "  4) ollama      (local, needs Ollama running on 127.0.0.1:11434)"
  echo "  5) skip        (I'll configure Hermes manually)"
  read -rp "Selection [1-5]: " sel
  case "$sel" in
    1) PROVIDER=anthropic  ;;
    2) PROVIDER=openai     ;;
    3) PROVIDER=openrouter ;;
    4) PROVIDER=ollama     ;;
    5) PROVIDER=skip       ;;
    *) die "invalid selection: $sel" ;;
  esac
fi

default_model_for() {
  case "$1" in
    anthropic)  echo "claude-sonnet-4-5" ;;
    openai)     echo "gpt-4o" ;;
    openrouter) echo "nousresearch/hermes-4-70b" ;;
    ollama)     echo "hermes4" ;;
    *)          echo "" ;;
  esac
}

required_env_for() {
  case "$1" in
    anthropic)  echo "ANTHROPIC_API_KEY" ;;
    openai)     echo "OPENAI_API_KEY" ;;
    openrouter) echo "OPENROUTER_API_KEY" ;;
    ollama)     echo "" ;;
    *)          echo "" ;;
  esac
}

if [ "$PROVIDER" != "skip" ]; then
  [ -z "$MODEL" ] && MODEL="$(default_model_for "$PROVIDER")"
  log "setting provider=$PROVIDER model=$MODEL"
  hermes config set provider.type  "$PROVIDER" || warn "hermes config set provider.type failed — check manually"
  [ -n "$MODEL" ] && hermes config set provider.model "$MODEL" || true

  if [ "$PROVIDER" = "ollama" ]; then
    hermes config set provider.base_url "http://127.0.0.1:11434" || true
  fi

  req_env="$(required_env_for "$PROVIDER")"
  if [ -n "$req_env" ] && [ -z "${!req_env:-}" ]; then
    warn "$req_env is not set in your environment. Export it before running Hermes:"
    warn "  export $req_env=..."
  fi
fi

# ── 4. Install skill + tool manifest ──
mkdir -p "$HERMES_HOME/skills" "$HERMES_HOME/tools"

skill_src="$REPO_ROOT/hermes-redteam/skills/target-analyst.md"
skill_dst="$HERMES_HOME/skills/target-analyst.md"
if [ -f "$skill_dst" ] && ! cmp -s "$skill_src" "$skill_dst"; then
  log "updating existing skill (backup: ${skill_dst}.bak)"
  cp "$skill_dst" "${skill_dst}.bak"
fi
cp "$skill_src" "$skill_dst"
log "installed skill: $skill_dst"

tools_src="$REPO_ROOT/hermes-redteam/tools.toml"
tools_dst="$HERMES_HOME/tools/redteam.toml"
if [ -f "$tools_dst" ] && ! cmp -s "$tools_src" "$tools_dst"; then
  log "updating existing tool manifest (backup: ${tools_dst}.bak)"
  cp "$tools_dst" "${tools_dst}.bak"
fi
cp "$tools_src" "$tools_dst"
log "installed tool manifest: $tools_dst"

# ── 5. Verify ──
echo
log "verifying tools with 'hermes tools list'..."
if hermes tools list 2>&1 | grep -qE "read_repo|probe_target"; then
  log "tools registered OK"
else
  warn "tools not visible to hermes. This may mean:"
  warn "  (a) your Hermes version uses a different manifest path — see"
  warn "      https://hermes-agent.nousresearch.com/docs/user-guide/configuration/"
  warn "  (b) the tool server at http://127.0.0.1:4300 is not running yet"
  warn "  (c) the manifest path is $tools_dst — move if your version expects elsewhere"
fi

# ── Done ──
cat <<EOF

\033[1;32m✓ Hermes target-analyst profile is ready at $HERMES_HOME\033[0m

Next, in two terminals:

  \033[1mTerminal A — tool server (from $REPO_ROOT):\033[0m
    npm run hermes:tools

  \033[1mTerminal B — run the analyst (white-box example):\033[0m
    export HERMES_HOME="$HERMES_HOME"
    hermes run --skill target-analyst --input '{
      "slug": "demo",
      "repoPath": "../demo-agentic-app/src",
      "baseUrl": "http://localhost:3000",
      "endpoint": "/api/exfil-test-agent",
      "authHeaders": {},
      "appHint": "Internal support copilot with mocked tools; JWT auth."
    }'

  \033[1mOr black-box (no source):\033[0m
    hermes run --skill target-analyst --input '{
      "slug": "acme-prod",
      "baseUrl": "https://agent.prod.acme.internal",
      "endpoint": "/v1/assistant/chat",
      "authHeaders": { "Authorization": "Bearer \$ENTERPRISE_BEARER" },
      "appHint": "Customer-support copilot, multi-tenant, CRM + order tools."
    }'

Output files land in ./configs/. Then run:
    npx tsx red-team.ts configs/config.<slug>.json

EOF
