#!/usr/bin/env bash
#
# Build the target-analyst prompt, put it on the clipboard, and launch
# Hermes chat. Paste with Cmd+V (macOS) / Ctrl+Shift+V (Linux), then Enter.
#
# This exists because `hermes chat` is a TUI that does NOT accept piped
# stdin for the initial prompt — it needs a real terminal.
#
# Usage:
#   ./hermes-redteam/run-analyst.sh <slug>
#
# Examples:
#   SLUG=demo ./hermes-redteam/run-analyst.sh
#   SLUG=demo REPO_PATH=../demo-agentic-app/src BASE_URL=http://localhost:3000 \
#     ENDPOINT=/api/exfil-test-agent ./hermes-redteam/run-analyst.sh
#
#   SLUG=acme-prod BASE_URL=https://agent.prod.acme.internal \
#     ENDPOINT=/v1/assistant/chat AUTH_HEADERS='{"Authorization":"Bearer '$TOKEN'"}' \
#     APP_HINT='Customer-support copilot, multi-tenant, CRM + order tools.' \
#     ./hermes-redteam/run-analyst.sh
#
# Env overrides (all optional with sensible defaults for the demo target):
#   SLUG          short identifier (default: demo)
#   REPO_PATH     target source dir (omit for black-box)
#   BASE_URL      live endpoint host       (default: http://localhost:3000)
#   ENDPOINT      live endpoint path       (default: /api/exfil-test-agent)
#   AUTH_HEADERS  JSON object              (default: {})
#   APP_HINT      one-paragraph description
#   HERMES_HOME   which Hermes profile     (default: ~/.hermes-redteam-analyst)

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

SLUG="${SLUG:-${1:-demo}}"
REPO_PATH="${REPO_PATH:-}"
BASE_URL="${BASE_URL:-http://localhost:3000}"
ENDPOINT="${ENDPOINT:-/api/exfil-test-agent}"
AUTH_HEADERS="${AUTH_HEADERS:-{\}}"
APP_HINT="${APP_HINT:-Internal support copilot with mocked tools (read_file, db_query, send_email, slack_dm); JWT auth; returns fake PII from fixtures.}"

export HERMES_HOME="${HERMES_HOME:-$HOME/.hermes-redteam-analyst}"

SKILL="$HERE/skills/target-analyst.md"
[ -f "$SKILL" ] || { echo "skill not found: $SKILL" >&2; exit 1; }

prompt_file="$(mktemp -t target-analyst.XXXXXX)"
trap 'rm -f "$prompt_file"' EXIT

# Escape double quotes in APP_HINT / AUTH_HEADERS so they survive being
# dropped into prose sentences without confusing Hermes's input parser.
app_hint_plain="${APP_HINT//\"/}"
auth_plain="${AUTH_HEADERS}"
[ "$auth_plain" = "{}" ] && auth_plain="(none)"

# Note: we deliberately avoid code fences, bare {} literals, and key=value
# lines in this prompt. Hermes v0.10 has preprocessing that misinterprets
# some of those and raises "'dict' object has no attribute 'strip'".
{
  echo "Read the skill file at this absolute path and follow its workflow as your instructions:"
  echo
  echo "  $SKILL"
  echo
  echo "Inputs for the workflow:"
  echo " - slug: $SLUG"
  [ -n "$REPO_PATH" ] && echo " - repoPath: $REPO_PATH"
  [ -z "$REPO_PATH" ] && echo " - repoPath: (omitted — black-box mode)"
  echo " - baseUrl: $BASE_URL"
  echo " - endpoint: $ENDPOINT"
  echo " - authHeaders: $auth_plain"
  echo " - appHint: $app_hint_plain"
  echo
  echo "Use the wb-redteam MCP tools: read_repo, probe_target, read_prior_reports, write_config, write_custom_attacks, write_policy."
  echo "Write outputs under the ./configs/ directory relative to the current working directory (which is the wb-red-team repo root)."
  echo "When finished, list the absolute paths of the files you wrote."
} > "$prompt_file"

# Copy to system clipboard
if command -v pbcopy >/dev/null 2>&1; then
  pbcopy < "$prompt_file"
  echo "✓ Prompt copied to clipboard (macOS pbcopy)"
elif command -v wl-copy >/dev/null 2>&1; then
  wl-copy < "$prompt_file"
  echo "✓ Prompt copied to clipboard (Wayland wl-copy)"
elif command -v xclip >/dev/null 2>&1; then
  xclip -selection clipboard < "$prompt_file"
  echo "✓ Prompt copied to clipboard (X11 xclip)"
else
  echo "⚠ No clipboard tool found. Prompt saved to: $prompt_file"
  echo "  Copy it manually, then launch 'hermes chat' and paste."
  echo
  cat "$prompt_file"
  exit 0
fi

echo "HERMES_HOME=$HERMES_HOME"
echo "Launching 'hermes chat' — when it opens, paste (Cmd+V / Ctrl+Shift+V) and hit Enter."
echo
sleep 1

cd "$REPO"
exec hermes chat
