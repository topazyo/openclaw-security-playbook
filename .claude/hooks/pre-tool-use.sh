#!/usr/bin/env bash

set -euo pipefail

payload="$(cat)"

extract_value() {
  local key="$1"

  python3 - "$key" <<'PY' <<< "$payload"
import json
import sys

key = sys.argv[1]

try:
    data = json.load(sys.stdin)
except Exception:
    print("")
    raise SystemExit(0)

def find_value(obj, wanted):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == wanted and isinstance(v, str):
                return v
            found = find_value(v, wanted)
            if found:
                return found
    if isinstance(obj, list):
        for item in obj:
            found = find_value(item, wanted)
            if found:
                return found
    return ""

print(find_value(data, key))
PY
}

tool_name="$(extract_value tool_name)"
command="$(extract_value command)"
query="$(extract_value query)"

combined_input="${tool_name}
${command}
${query}"

normalized="$(printf '%s' "$combined_input" | tr '[:upper:]' '[:lower:]')"

block() {
  local reason="$1"

  printf 'Blocked by Claude Code security hook: %s\n' "$reason" >&2
  exit 2
}

case "$normalized" in
  *"rm -rf /"* )
    block "destructive root delete command"
    ;;
  *"rm -rf ."* )
    block "destructive repository delete command"
    ;;
  *"rm -rf ./"* )
    block "destructive repository delete command"
    ;;
  *"git push --force"* )
    block "forced git push is forbidden"
    ;;
  *"git push -f"* )
    block "forced git push is forbidden"
    ;;
  *"git reset --hard"* )
    block "hard git reset is forbidden"
    ;;
  *"drop table"* )
    block "dangerous SQL command detected"
    ;;
  *"truncate table"* )
    block "dangerous SQL command detected"
    ;;
  *"delete from"* )
    block "potentially destructive SQL command detected"
    ;;
  *"curl http"* )
    block "direct remote fetch with curl is forbidden"
    ;;
  *"wget http"* )
    block "direct remote fetch with wget is forbidden"
    ;;
  *"npm install"* )
    block "package installation requires explicit approval"
    ;;
  *"pnpm install"* )
    block "package installation requires explicit approval"
    ;;
  *"yarn add"* )
    block "package installation requires explicit approval"
    ;;
esac

exit 0