#!/usr/bin/env bash
# dependency-audit.sh — Weekly Python dependency vulnerability audit   # FIX: C5-11
#
# Runs pip-audit against a requirements file and exits non-zero when
# vulnerabilities are found.  Suitable for use in CI and as the weekly
# supply-chain check referenced in docs/procedures/vulnerability-management.md.
#
# Usage:
#   ./scripts/supply-chain/dependency-audit.sh [OPTIONS]
#
# Options:
#   --requirements FILE   Requirements file to audit (default: requirements.txt)
#   --format FORMAT       Output format: text|json|cyclonedx (default: text)
#   --output FILE         Write report to FILE instead of stdout
#   --help                Show this help message
#
# Exit codes:
#   0   No vulnerabilities found
#   1   Vulnerabilities found (red run)
#   2   pip-audit not available or invocation error
#
# Examples:
#   # Audit production deps (green on clean tree)
#   ./scripts/supply-chain/dependency-audit.sh
#
#   # Audit a fixture with seeded CVEs (should exit 1)
#   ./scripts/supply-chain/dependency-audit.sh --requirements tests/fixtures/seeded-cve-requirements.txt
#
#   # Generate an HTML-equivalent JSON report for email
#   ./scripts/supply-chain/dependency-audit.sh --format json --output weekly-dependency-report.json

set -euo pipefail

# ---------------------------------------------------------------------------
# Defaults                                                           # FIX: C5-11
# ---------------------------------------------------------------------------
REQUIREMENTS="requirements.txt"
FORMAT="text"
OUTPUT=""
# Allow overriding the pip-audit binary path (used by tests to supply the  # FIX: C5-11
# .venv/Scripts/pip-audit.exe via its WSL mount path without modifying PATH)
_PIP_AUDIT_CMD="${PIP_AUDIT_BIN:-pip-audit}"                               # FIX: C5-11

# ---------------------------------------------------------------------------
# Argument parsing                                                   # FIX: C5-11
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --requirements)
            REQUIREMENTS="$2"
            shift 2
            ;;
        --format)
            FORMAT="$2"
            case "$FORMAT" in
                json|cyclonedx|text) ;;  # FIX: C5-11 — validate early so bad format exits before tool check
                *)
                    echo "ERROR: unknown format: $FORMAT (valid: text, json, cyclonedx)" >&2  # FIX: C5-11
                    exit 2  # FIX: C5-11
                    ;;
            esac
            shift 2
            ;;
        --output)
            OUTPUT="$2"
            shift 2
            ;;
        --help)
            sed -n '3,/^$/p' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Dependency check                                                   # FIX: C5-11
# ---------------------------------------------------------------------------
if ! command -v "$_PIP_AUDIT_CMD" &>/dev/null; then  # FIX: C5-11
    echo "ERROR: pip-audit not found in PATH — install it with: pip install pip-audit" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Validate requirements file                                         # FIX: C5-11
# ---------------------------------------------------------------------------
if [[ ! -f "$REQUIREMENTS" ]]; then
    echo "ERROR: requirements file not found: $REQUIREMENTS" >&2
    exit 2
fi

# ---------------------------------------------------------------------------
# Build pip-audit command                                            # FIX: C5-11
# ---------------------------------------------------------------------------
AUDIT_CMD=("$_PIP_AUDIT_CMD" -r "$REQUIREMENTS")  # FIX: C5-11

case "$FORMAT" in
    json)
        AUDIT_CMD+=(--format json)
        ;;
    cyclonedx)
        AUDIT_CMD+=(--format cyclonedx-json)
        ;;
    text)
        # default human-readable output
        ;;
    *)
        echo "ERROR: unknown format: $FORMAT (valid: text, json, cyclonedx)" >&2
        exit 2
        ;;
esac

if [[ -n "$OUTPUT" ]]; then
    AUDIT_CMD+=(--output "$OUTPUT")
fi

# ---------------------------------------------------------------------------
# Run audit                                                          # FIX: C5-11
# ---------------------------------------------------------------------------
echo "Auditing dependencies in: $REQUIREMENTS" >&2

set +e
"${AUDIT_CMD[@]}" </dev/null  # FIX: C5-11 — redirect stdin so the child process cannot consume
EXIT_CODE=$?                   # the bash script's own stdin pipe when run via `bash -s`
set -e

# ---------------------------------------------------------------------------
# Result reporting                                                   # FIX: C5-11
# ---------------------------------------------------------------------------
if [[ $EXIT_CODE -eq 0 ]]; then
    echo "PASS: No known vulnerabilities found in $REQUIREMENTS" >&2
elif [[ $EXIT_CODE -eq 1 ]]; then
    echo "FAIL: Vulnerabilities detected in $REQUIREMENTS — review output above" >&2
else
    echo "ERROR: pip-audit exited with code $EXIT_CODE" >&2
fi

exit $EXIT_CODE
