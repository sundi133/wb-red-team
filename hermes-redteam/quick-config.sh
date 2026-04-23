#!/usr/bin/env bash
#
# Minimal config-only run: no probing, no repo scanning. Give Hermes:
#   - app details (one paragraph)
#   - endpoint (baseUrl + path)
#   - what to test (comma-separated priorities)
# And it writes ./configs/config.<slug>.json.
#
# Usage (env vars):
#   SLUG=acme-prod \
#     BASE_URL=https://agent.prod.acme.internal \
#     ENDPOINT=/v1/assistant/chat \
#     APP_DETAILS='Customer support copilot with tools for orders, refunds, CRM lookups. Multi-tenant. Roles: agent, supervisor, admin. Sensitive data: customer PII (SSN, email), order history.' \
#     WHAT_TO_TEST='tool misuse, auth bypass, PII leaks, prompt injection' \
#     AUTH_HINT='Bearer token in env ENTERPRISE_BEARER' \
#     npm run hermes:quick
#
# Everything except SLUG has a reasonable default for the demo app.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

SLUG="${SLUG:-${1:-demo}}"
BASE_URL="${BASE_URL:-http://localhost:3000}"
ENDPOINT="${ENDPOINT:-/api/exfil-test-agent}"
APP_DETAILS="${APP_DETAILS:-Internal support copilot with tools (read_file, db_query, send_email, slack_dm). JWT auth. Roles: admin, engineer, manager, viewer, intern. Returns fake PII from fixtures.}"
WHAT_TO_TEST="${WHAT_TO_TEST:-tool misuse, auth bypass, PII leaks, prompt injection, data exfiltration}"
AUTH_HINT="${AUTH_HINT:-(none)}"

export HERMES_HOME="${HERMES_HOME:-$HOME/.hermes-redteam-analyst}"

SKILL="$HERE/skills/quick-config.md"
README="$REPO/README.md"
[ -f "$SKILL" ]  || { echo "skill not found: $SKILL" >&2; exit 1; }
[ -f "$README" ] || { echo "README not found: $README" >&2; exit 1; }

prompt_file="$(mktemp -t quick-config.XXXXXX)"
trap 'rm -f "$prompt_file"' EXIT

{
  echo "Read the skill file at this absolute path and follow its workflow exactly:"
  echo
  echo "  $SKILL"
  echo
  echo "The wb-red-team README (for config shape + category IDs) is at:"
  echo
  echo "  $README"
  echo
  echo "Inputs:"
  echo " - slug: $SLUG"
  echo " - baseUrl: $BASE_URL"
  echo " - endpoint: $ENDPOINT"
  echo " - appDetails: $APP_DETAILS"
  echo " - whatToTest: $WHAT_TO_TEST"
  echo " - authHint: $AUTH_HINT"
  echo " - readmePath: $README"
  echo
  echo "Use the wb-redteam MCP tools read_repo (to load the README only) and write_config (to write the output)."
  echo "Do NOT call probe_target, read_prior_reports, write_custom_attacks, or write_policy."
  echo "Write exactly one file: ./configs/config.$SLUG.json"
  echo "When done, print the absolute path of the file you wrote."
} > "$prompt_file"

if command -v pbcopy >/dev/null 2>&1; then
  pbcopy < "$prompt_file"; echo "✓ Prompt copied to clipboard (pbcopy)"
elif command -v wl-copy >/dev/null 2>&1; then
  wl-copy < "$prompt_file"; echo "✓ Prompt copied to clipboard (wl-copy)"
elif command -v xclip >/dev/null 2>&1; then
  xclip -selection clipboard < "$prompt_file"; echo "✓ Prompt copied to clipboard (xclip)"
else
  echo "⚠ No clipboard tool. Prompt saved to: $prompt_file"
  cat "$prompt_file"
  exit 0
fi

echo "HERMES_HOME=$HERMES_HOME"
echo "Launching 'hermes chat' — paste (Cmd+V / Ctrl+Shift+V) and hit Enter."
echo
sleep 1

cd "$REPO"
exec hermes chat
