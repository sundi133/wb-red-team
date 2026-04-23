#!/usr/bin/env bash
#
# Friendly wrapper around `npm run gen:config` — takes CLI flags, prompts
# interactively for anything missing, and prints the next command.
#
# Non-interactive usage (CLI flags):
#   ./hermes-redteam/gen.sh \
#     --slug acme-prod \
#     --base-url https://agent.prod.acme.internal \
#     --endpoint /v1/assistant/chat \
#     --app "Customer-support copilot, multi-tenant, CRM + order tools." \
#     --test "tool misuse, auth bypass, PII leaks, prompt injection" \
#     --auth "Bearer token in env ENTERPRISE_BEARER"
#
# Interactive usage:
#   ./hermes-redteam/gen.sh            # asks for each field
#
# Or via npm:
#   npm run gen -- --slug acme-prod ...

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"

SLUG=""
BASE_URL=""
ENDPOINT=""
APP_DETAILS=""
WHAT_TO_TEST=""
AUTH_HINT=""

# ── Parse flags ──
while [ $# -gt 0 ]; do
  case "$1" in
    --slug)     SLUG="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    --endpoint) ENDPOINT="$2"; shift 2 ;;
    --app)      APP_DETAILS="$2"; shift 2 ;;
    --test)     WHAT_TO_TEST="$2"; shift 2 ;;
    --auth)     AUTH_HINT="$2"; shift 2 ;;
    -h|--help)
      sed -n '4,15p' "${BASH_SOURCE[0]}" | sed 's/^# //; s/^#//'
      exit 0
      ;;
    *)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
  esac
done

# ── Interactive prompts for anything still empty ──
ask() {
  local var="$1" label="$2" default="${3:-}"
  local current="${!var}"
  [ -n "$current" ] && return
  if [ -n "$default" ]; then
    read -rp "$label [$default]: " v
    printf -v "$var" '%s' "${v:-$default}"
  else
    read -rp "$label: " v
    printf -v "$var" '%s' "$v"
  fi
}

echo "wb-red-team config generator"
echo "─────────────────────────────"
ask SLUG          "Slug (short id, e.g. acme-prod)"  "demo"
ask BASE_URL      "Target base URL"                  "http://localhost:3000"
ask ENDPOINT      "Agent endpoint path"              "/api/exfil-test-agent"
ask APP_DETAILS   "App details (one paragraph)"      "Internal support copilot with mocked tools (read_file, db_query, send_email, slack_dm); JWT auth."
ask WHAT_TO_TEST  "What to test (comma-separated)"   "tool misuse, auth bypass, PII leaks, prompt injection, data exfiltration"
ask AUTH_HINT     "Auth hint (or '(none)')"          "(none)"

# ── Sanity: ANTHROPIC_API_KEY ──
if [ -z "${ANTHROPIC_API_KEY:-}" ] && [ "${PROVIDER:-anthropic}" = "anthropic" ]; then
  echo
  echo "⚠ ANTHROPIC_API_KEY is not set. Export it and re-run:"
  echo "    export ANTHROPIC_API_KEY=sk-ant-..."
  exit 1
fi

# ── Run the generator ──
echo
cd "$REPO"
SLUG="$SLUG" \
  BASE_URL="$BASE_URL" \
  ENDPOINT="$ENDPOINT" \
  APP_DETAILS="$APP_DETAILS" \
  WHAT_TO_TEST="$WHAT_TO_TEST" \
  AUTH_HINT="$AUTH_HINT" \
  npx tsx "$HERE/gen-config.ts"
