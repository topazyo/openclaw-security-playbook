#!/usr/bin/env bash
# check_credential_scope.sh — Assess what credentials may have been exposed
#
# USAGE: ./check_credential_scope.sh [YYYY-MM-DD]
#   Optional date argument sets the start of the investigation window.
#   Defaults to the BrandDefense disclosure date (2026-01-27).
#
# Part of: https://github.com/topazyo/openclaw-security-playbook

set -euo pipefail

INCIDENT_START="${1:-2026-01-27}"
OUTPUT_DIR="${HOME}/openclaw-credential-scope-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${OUTPUT_DIR}"

echo "============================================================"
echo " OpenClaw Credential Exposure Scope Assessment"
echo " Checking from: ${INCIDENT_START}"
echo " Output: ${OUTPUT_DIR}"
echo "============================================================"
echo ""

echo "[+] Step 1: Backup credential files (keys that survived rotation)..."
find ~/ \( -path "*/.moltbot/*" -o -path "*/.clawdbot/*" -o -path "*/.openclaw/*" \)     -name "*.bak*" -type f 2>/dev/null     > "${OUTPUT_DIR}/backup-files.txt"

if [ -s "${OUTPUT_DIR}/backup-files.txt" ]; then
    echo "    !! CRITICAL: Found backup files — keys in these files were NOT rotated:"
    cat "${OUTPUT_DIR}/backup-files.txt"
    echo ""
    echo "    ACTION REQUIRED: Rotate at providers BEFORE deleting these files."
    echo "      Anthropic: https://console.anthropic.com/settings/keys"
    echo "      OpenAI:    https://platform.openai.com/api-keys"
    echo "      AWS:       https://console.aws.amazon.com/iam/"
    echo "      Google:    https://console.cloud.google.com/apis/credentials"
else
    echo "    OK: No backup credential files found"
fi

if [[ "$(uname)" == "Darwin" ]]; then
    echo ""
    echo "[+] Step 2: macOS Keychain access events since ${INCIDENT_START}..."
    log show         --predicate 'eventMessage contains "Clawdbot" OR eventMessage contains "OpenClaw" OR eventMessage contains "Moltbot"'         --start "${INCIDENT_START} 00:00:00"         2>/dev/null         | tee "${OUTPUT_DIR}/keychain-access.log"         | tail -20
fi

if command -v secret-tool &>/dev/null; then
    echo ""
    echo "[+] Step 2: Linux Secret Service entries..."
    secret-tool search service clawdbot-anthropic 2>/dev/null         | tee "${OUTPUT_DIR}/secret-service-entries.txt" || true
    journalctl --since="${INCIDENT_START}" 2>/dev/null         | grep -iE "(secret service|gnome-keyring|clawdbot|openclaw|moltbot)"         | tee -a "${OUTPUT_DIR}/secret-service-entries.txt" || true
fi

echo ""
echo "[+] Step 3: Email exfiltration check..."
for jsonl_file in ~/.openclaw/logs/telemetry.jsonl ~/.moltbot/logs/telemetry.jsonl; do
    if [ -f "${jsonl_file}" ]; then
        jq -r 'select(
            .event_type == "tool_executed"
            and .tool_name == "email_send"
        ) | [.timestamp, (.tool_args.recipients | tostring), (.tool_args.subject // "")] | @tsv'             "${jsonl_file}" 2>/dev/null             | tee "${OUTPUT_DIR}/email-sends.tsv"
    fi
done

echo ""
echo "[+] Step 4: Sensitive file read check..."
for jsonl_file in ~/.openclaw/logs/telemetry.jsonl ~/.moltbot/logs/telemetry.jsonl; do
    if [ -f "${jsonl_file}" ]; then
        jq -r 'select(
            .event_type == "tool_executed"
            and .tool_name == "file_read"
            and (.tool_args.path | test("\.ssh|\.aws|\.moltbot|\.clawdbot|credentials|\.bak|\.env"))
        ) | [.timestamp, .tool_args.path] | @tsv'             "${jsonl_file}" 2>/dev/null             | tee "${OUTPUT_DIR}/sensitive-reads.tsv"
    fi
done

echo ""
echo "============================================================"
echo " Scope assessment complete: ${OUTPUT_DIR}"
echo ""
echo " MANDATORY ROTATION if any of the following are true:"
echo "  - backup-files.txt is non-empty"
echo "  - sensitive-reads.tsv contains .ssh or .aws paths"
echo "  - email-sends.tsv shows external recipients"
echo "============================================================"
