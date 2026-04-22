#!/usr/bin/env bash
#
# Hermes Agent setup for wb-red-team's target-analyst workflow.
# Tested against Hermes Agent v0.10.x.
#
# What this does (idempotent):
#   1. Installs Hermes Agent if missing
#   2. Picks a Hermes profile via $HERMES_HOME
#   3. Sets provider/model via `hermes config set`
#   4. Copies target-analyst skill into $HERMES_HOME/skills/ (auto-discovered)
#   5. Registers the MCP tool server via `hermes mcp add`
#   6. Verifies with `hermes skills list` + `hermes mcp list`
#
# Does NOT start a long-running process and does NOT invoke `hermes chat`.
# The script prints the exact run command at the end.
#
# Usage:
#   ./hermes-redteam/setup.sh
#   PROVIDER=anthropic MODEL=claude-sonnet-4-5 ./hermes-redteam/setup.sh
#   HERMES_HOME=~/.hermes-redteam-acme PROVIDER=openrouter ./hermes-redteam/setup.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes-redteam-analyst}"
PROVIDER="${PROVIDER:-}"
MODEL="${MODEL:-}"
MCP_NAME="${MCP_NAME:-wb-redteam}"
INSTALL_URL="${HERMES_INSTALL_URL:-https://hermes-agent.nousresearch.com/install.sh}"

log()  { printf "\033[1;34m[setup]\033[0m %s\n" "$*"; }
warn() { printf "\033[1;33m[warn]\033[0m  %s\n" "$*" >&2; }
err()  { printf "\033[1;31m[err]\033[0m   %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

log "repo root:    $REPO_ROOT"
log "HERMES_HOME:  $HERMES_HOME"
log "MCP name:     $MCP_NAME"

command -v curl >/dev/null || die "curl not found"
command -v node >/dev/null || die "node not found (>= 18 required)"
node_major=$(node -p "parseInt(process.versions.node.split('.')[0],10)")
[ "$node_major" -ge 18 ] || die "node >= 18 required, found $(node --version)"

[ -f "$REPO_ROOT/hermes-redteam/skills/target-analyst.md" ] \
  || die "target-analyst.md not found — run from wb-red-team repo"
[ -f "$REPO_ROOT/hermes-redteam/mcp-server.ts" ] \
  || die "mcp-server.ts not found — run from wb-red-team repo"

# ── 1. Install Hermes if missing ──
if command -v hermes >/dev/null; then
  log "hermes already installed: $(hermes --version 2>&1 | head -1)"
else
  log "installing Hermes Agent from $INSTALL_URL"
  curl -fsSL "$INSTALL_URL" | sh
  command -v hermes >/dev/null \
    || die "hermes still not on PATH after install; open a new shell and re-run"
fi

# ── 2. Profile directory (Hermes creates the config.yaml on first `config set`) ──
export HERMES_HOME
mkdir -p "$HERMES_HOME/skills"

# ── 3. Provider config ──
if [ -z "$PROVIDER" ]; then
  echo
  echo "Choose a provider [default: 1]:"
  echo "  1) anthropic   (needs ANTHROPIC_API_KEY)  [default]"
  echo "  2) openai      (needs OPENAI_API_KEY)"
  echo "  3) openrouter  (needs OPENROUTER_API_KEY)"
  echo "  4) ollama      (local, needs Ollama running on 127.0.0.1:11434)"
  echo "  5) skip        (I'll configure Hermes manually)"
  read -rp "Selection [1-5] (enter = 1): " sel
  case "${sel:-1}" in
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
  hermes config set provider.type  "$PROVIDER" || warn "hermes config set provider.type failed"
  [ -n "$MODEL" ] && hermes config set provider.model "$MODEL" || true
  if [ "$PROVIDER" = "ollama" ]; then
    hermes config set provider.base_url "http://127.0.0.1:11434" || true
  fi

  req_env="$(required_env_for "$PROVIDER")"
  if [ -n "$req_env" ] && [ -z "${!req_env:-}" ]; then
    warn "$req_env is not set. Export it before running 'hermes chat':"
    warn "  export $req_env=..."
  fi
fi

# ── 4. Install skill (Hermes auto-discovers *.md in $HERMES_HOME/skills/) ──
skill_src="$REPO_ROOT/hermes-redteam/skills/target-analyst.md"
skill_dst="$HERMES_HOME/skills/target-analyst.md"
if [ -f "$skill_dst" ] && ! cmp -s "$skill_src" "$skill_dst"; then
  log "updating existing skill (backup: ${skill_dst}.bak)"
  cp "$skill_dst" "${skill_dst}.bak"
fi
cp "$skill_src" "$skill_dst"
log "installed skill: $skill_dst"

# ── 5. Register MCP tool server ──
mcp_entry="npx tsx $REPO_ROOT/hermes-redteam/mcp-server.ts"
log "registering MCP server '$MCP_NAME' -> $mcp_entry"

# `hermes mcp list` — check if already registered
if hermes mcp list 2>/dev/null | grep -qw "$MCP_NAME"; then
  log "MCP server '$MCP_NAME' already registered (removing + re-adding to pick up updates)"
  hermes mcp remove "$MCP_NAME" 2>/dev/null || hermes mcp rm "$MCP_NAME" 2>/dev/null || true
fi

# Try the most common `hermes mcp add` forms. If your Hermes version uses
# different flags, run `hermes mcp add --help` and adapt manually.
if ! hermes mcp add "$MCP_NAME" -- npx tsx "$REPO_ROOT/hermes-redteam/mcp-server.ts" 2>/dev/null; then
  if ! hermes mcp add "$MCP_NAME" --command "npx" --args "tsx $REPO_ROOT/hermes-redteam/mcp-server.ts" 2>/dev/null; then
    if ! hermes mcp add --name "$MCP_NAME" --command "npx tsx $REPO_ROOT/hermes-redteam/mcp-server.ts" 2>/dev/null; then
      warn "automatic 'hermes mcp add' failed — your Hermes version likely uses different flags."
      warn "Run this manually, adapting to 'hermes mcp add --help' output:"
      warn "  hermes mcp add $MCP_NAME -- npx tsx $REPO_ROOT/hermes-redteam/mcp-server.ts"
    fi
  fi
fi

# ── 6. Verify ──
echo
log "verifying with 'hermes skills list'..."
if hermes skills list 2>&1 | grep -qi "target-analyst"; then
  log "  target-analyst skill registered OK"
else
  warn "  target-analyst not visible. Try 'hermes skills list' manually."
  warn "  If your Hermes version doesn't auto-discover *.md skills, you may"
  warn "  need 'hermes skills add $skill_dst' or 'hermes skills install ...'."
fi

log "verifying with 'hermes mcp list'..."
if hermes mcp list 2>&1 | grep -qw "$MCP_NAME"; then
  log "  MCP server '$MCP_NAME' registered OK"
else
  warn "  '$MCP_NAME' not visible. Run 'hermes mcp list' and 'hermes mcp add --help'."
fi

# ── Done ──
cat <<EOF

$(printf "\033[1;32m✓ Hermes target-analyst profile ready at $HERMES_HOME\033[0m")

Next, in two terminals:

  $(printf "\033[1mTerminal A — HTTP tool server (optional, for manual curl testing):\033[0m")
    npm run hermes:tools

  $(printf "\033[1mTerminal B — run the analyst:\033[0m")
    export HERMES_HOME="$HERMES_HOME"
    # Put target inputs in a variable (real Hermes accepts a chat prompt, not --input)
    INPUT='slug=demo, repoPath=../demo-agentic-app/src, baseUrl=http://localhost:3000, endpoint=/api/exfil-test-agent, authHeaders={}, appHint="Internal support copilot with mocked tools; JWT auth."'
    hermes --skills target-analyst chat "Run the target-analyst workflow with these inputs: \$INPUT. Write all outputs under ./configs/."

  Or black-box (no source):
    INPUT='slug=acme-prod, baseUrl=https://agent.prod.acme.internal, endpoint=/v1/assistant/chat, authHeaders={"Authorization":"Bearer \$ENTERPRISE_BEARER"}, appHint="Customer-support copilot, multi-tenant, CRM + order tools."'
    hermes --skills target-analyst chat "Run the target-analyst workflow with these inputs: \$INPUT. Write all outputs under ./configs/."

Output files land in ./configs/. Then run:
    npx tsx red-team.ts configs/config.<slug>.json

EOF
