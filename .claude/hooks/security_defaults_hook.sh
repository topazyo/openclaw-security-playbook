#!/usr/bin/env bash
# .claude/hooks/security_defaults_hook.sh
# PostToolUse: fires after Write|Edit tool calls.
# Reads file_path from stdin JSON, skips non-infrastructure files,
# then verifies immutable security defaults from CLAUDE.md Section 4.
# Exits 1 (blocks) if any default is violated.

set -euo pipefail

INFRA_PATTERN='\.(ya?ml)$|Dockerfile|docker-compose|nginx\.conf|tls|gateway'

PAYLOAD="$(cat)"

# Extract tool_input.file_path from stdin JSON
CHANGED_FILE="$(echo "$PAYLOAD" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
tool_input = data.get('tool_input', {})
print(tool_input.get('file_path') or tool_input.get('path') or '')
")"

# Nothing to check if no path extracted
[[ -z "$CHANGED_FILE" ]] && exit 0

# Skip CI workflow files — they reference services like "gateway" by image
# name but do NOT define their bind addresses, so the immutable-defaults
# check produces only false positives on them. Match both forward and
# backslash separators (Claude Code on Windows passes Windows paths).
if echo "$CHANGED_FILE" | grep -qE '[/\\]\.github[/\\]workflows[/\\]'; then
    exit 0
fi

# Skip files that are not infrastructure-relevant
if ! echo "$CHANGED_FILE" | grep -qE "$INFRA_PATTERN"; then
    exit 0
fi

VIOLATIONS=()

check_file() {
  local FILE="$1"
  [[ -f "$FILE" ]] || return 0

  local CONTENT
  CONTENT=$(cat "$FILE")

  # Gateway bind address — accept both combined 127.0.0.1:18789 and split address:/port: keys ## FIX: C6-M-07
  if grep -qE '(^|[[:space:]])gateway:|127\.0\.0\.1:18789' "$FILE"; then ## FIX: C6-M-07
    local gw_combined gw_split_addr gw_split_port ## FIX: C6-M-07
    gw_combined=$(echo "$CONTENT" | grep -cE '127\.0\.0\.1:18789' || true) ## FIX: C6-M-07
    gw_split_addr=$(echo "$CONTENT" | grep -cE 'address:[[:space:]]*"?127\.0\.0\.1"?' || true) ## FIX: C6-M-07
    gw_split_port=$(echo "$CONTENT" | grep -cE 'port:[[:space:]]*18789' || true) ## FIX: C6-M-07
    if [[ "$gw_combined" -eq 0 && ( "$gw_split_addr" -eq 0 || "$gw_split_port" -eq 0 ) ]]; then ## FIX: C6-M-07
      VIOLATIONS+=("Gateway bind: expected 127.0.0.1:18789 (or split address:/port:) in $FILE") ## FIX: C6-M-07
    fi ## FIX: C6-M-07
  fi ## FIX: C6-M-07

  # MCP server bind — accept both combined 127.0.0.1:8443 and split address:/port: keys ## FIX: C6-M-07
  if grep -qE '(^|[[:space:]])mcp[._]server:|(^|[[:space:]])mcp:|127\.0\.0\.1:8443' "$FILE"; then ## FIX: C6-M-07
    local mcp_combined mcp_split_addr mcp_split_port ## FIX: C6-M-07
    mcp_combined=$(echo "$CONTENT" | grep -cE '127\.0\.0\.1:8443' || true) ## FIX: C6-M-07
    mcp_split_addr=$(echo "$CONTENT" | grep -cE 'address:[[:space:]]*"?127\.0\.0\.1"?' || true) ## FIX: C6-M-07
    mcp_split_port=$(echo "$CONTENT" | grep -cE 'port:[[:space:]]*8443' || true) ## FIX: C6-M-07
    if [[ "$mcp_combined" -eq 0 && ( "$mcp_split_addr" -eq 0 || "$mcp_split_port" -eq 0 ) ]]; then ## FIX: C6-M-07
      VIOLATIONS+=("MCP server bind: expected 127.0.0.1:8443 (or split address:/port:) in $FILE") ## FIX: C6-M-07
    fi ## FIX: C6-M-07
  fi ## FIX: C6-M-07

  # Container user (non-root)
  if grep -q 'user:' "$FILE"; then
    if echo "$CONTENT" | grep -E 'user:' | grep -qvE '"?1000:1000"?'; then
      VIOLATIONS+=("Container user: must be 1000:1000 in $FILE")
    fi
  fi

  # cap_drop ALL
  if grep -q 'cap_drop' "$FILE"; then
    if ! echo "$CONTENT" | grep -A3 'cap_drop' | grep -qE '^\s*-\s*ALL'; then
      VIOLATIONS+=("cap_drop: must include ALL in $FILE")
    fi
  fi

  # read_only filesystem
  if grep -q 'read_only' "$FILE"; then
    if echo "$CONTENT" | grep 'read_only' | grep -qE 'false'; then
      VIOLATIONS+=("read_only: must not be false in $FILE")
    fi
  fi

  # no-new-privileges
  if grep -q 'no-new-privileges' "$FILE"; then
    if echo "$CONTENT" | grep 'no-new-privileges' | grep -qE 'false'; then
      VIOLATIONS+=("no-new-privileges: must not be false in $FILE")
    fi
  fi

  # Skills config
  if grep -qE 'autoUpdate|autoInstall|requireSignature' "$FILE"; then
    if echo "$CONTENT" | grep 'autoUpdate' | grep -qE 'true'; then
      VIOLATIONS+=("Skills autoUpdate: must be false in $FILE")
    fi
    if echo "$CONTENT" | grep 'autoInstall' | grep -qE 'true'; then
      VIOLATIONS+=("Skills autoInstall: must be false in $FILE")
    fi
    if echo "$CONTENT" | grep 'requireSignature' | grep -qE 'false'; then
      VIOLATIONS+=("Skills requireSignature: must be true in $FILE")
    fi
  fi

  # TLS version — only TLS 1.3 permitted
  if grep -qE 'ssl_protocols|tls_version|TLSv' "$FILE"; then
    if echo "$CONTENT" | grep -qE 'TLSv1(\b|\.[12])'; then
      VIOLATIONS+=("TLS: only TLS 1.3 permitted in $FILE — found older version reference")
    fi
  fi
}

check_file "$CHANGED_FILE"

if [[ ${#VIOLATIONS[@]} -gt 0 ]]; then
  echo "" >&2
  echo "[check-security-defaults] REGRESSION BLOCKER — immutable security defaults violated:" >&2
  for V in "${VIOLATIONS[@]}"; do
    echo "   ❌ $V" >&2
  done
  echo "" >&2
  echo "   These defaults are immutable (Cycle 1 baseline). Fix before proceeding." >&2
  echo "   See CLAUDE.md Section 4 for required values." >&2
  exit 1
fi

echo "[check-security-defaults] $CHANGED_FILE — all immutable security defaults intact."
exit 0
