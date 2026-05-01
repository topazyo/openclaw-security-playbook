#!/usr/bin/env bash

set -euo pipefail

payload="$(cat)"

repo_root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$repo_root"

extract_paths() {
  python3 <<'PY' <<< "$payload"
import json
import sys

try:
    data = json.load(sys.stdin)
except Exception:
    raise SystemExit(0)

paths = set()

def walk(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            lowered = str(key).lower()
            if lowered in {"file_path", "filepath", "path"} and isinstance(value, str):
                paths.add(value)
            else:
                walk(value)
    elif isinstance(obj, list):
        for item in obj:
            walk(item)

walk(data)

for path in sorted(paths):
    print(path)
PY
}

mapfile -t changed_paths < <(extract_paths)

if [ "${#changed_paths[@]}" -eq 0 ]; then
  mapfile -t changed_paths < <(git diff --name-only --diff-filter=ACMR 2>/dev/null || true)
fi

if [ "${#changed_paths[@]}" -eq 0 ]; then
  exit 0
fi

path_exists() {
  local candidate="$1"

  [ -f "$candidate" ]
}

run_if_available() {
  local command_name="$1"

  command -v "$command_name" >/dev/null 2>&1
}

format_file() {
  local file="$1"

  case "$file" in
    *.js|*.jsx|*.ts|*.tsx|*.json|*.css|*.scss|*.md|*.yaml|*.yml )
      if [ -x "./node_modules/.bin/prettier" ]; then
        ./node_modules/.bin/prettier --write "$file"
      elif run_if_available prettier; then
        prettier --write "$file"
      fi

      if [ -x "./node_modules/.bin/eslint" ]; then
        case "$file" in
          *.js|*.jsx|*.ts|*.tsx )
            ./node_modules/.bin/eslint --fix "$file" || true
            ;;
        esac
      elif run_if_available eslint; then
        case "$file" in
          *.js|*.jsx|*.ts|*.tsx )
            eslint --fix "$file" || true
            ;;
        esac
      fi
      ;;

    *.py )
      if run_if_available black; then
        black "$file"
      elif run_if_available python3; then
        python3 -m black "$file" 2>/dev/null || true
      elif run_if_available python; then
        python -m black "$file" 2>/dev/null || true
      fi
      ;;

    *.cs )
      if run_if_available dotnet; then
        dotnet format --include "$file" || true
      fi
      ;;
  esac
}

run_tests_for_file() {
  local file="$1"

  case "$file" in
    *.test.js|*.test.jsx|*.test.ts|*.test.tsx|*.spec.js|*.spec.jsx|*.spec.ts|*.spec.tsx )
      if [ -x "./node_modules/.bin/jest" ]; then
        ./node_modules/.bin/jest "$file" --runInBand || true
      elif [ -x "./node_modules/.bin/vitest" ]; then
        ./node_modules/.bin/vitest run "$file" || true
      elif run_if_available npm; then
        npm test -- "$file" || true
      fi
      ;;

    *_test.py|test_*.py|*/tests/*.py )
      if run_if_available pytest; then
        pytest "$file" || true
      elif run_if_available python3; then
        python3 -m pytest "$file" || true
      elif run_if_available python; then
        python -m pytest "$file" || true
      fi
      ;;

    *.cs )
      if run_if_available dotnet; then
        dotnet test --no-restore || true
      fi
      ;;
  esac
}

for file in "${changed_paths[@]}"; do
  if path_exists "$file"; then
    format_file "$file"
  fi
done

for file in "${changed_paths[@]}"; do
  if path_exists "$file"; then
    run_tests_for_file "$file"
  fi
done

for file in "${changed_paths[@]}"; do
  if path_exists "$file"; then
    git add "$file" 2>/dev/null || true
  fi
done

exit 0