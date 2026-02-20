#!/usr/bin/env bash
# build_timeline.sh — Reconstruct attack timeline from openclaw-telemetry logs
#
# USAGE: ./build_timeline.sh --incident-dir ~/openclaw-incident-TIMESTAMP
#
# Outputs a chronological TSV timeline of all tool executions,
# messages received, and config changes, highlighting high-risk events.
# Part of: https://github.com/topazyo/openclaw-security-playbook

set -euo pipefail

INCIDENT_DIR="${1:-}"
if [ -z "${INCIDENT_DIR}" ]; then
    echo "Usage: $0 --incident-dir <path>"
    exit 1
fi
INCIDENT_DIR="${INCIDENT_DIR#--incident-dir=}"

OUTPUT="${INCIDENT_DIR}/timeline.tsv"

echo "Building attack timeline..."
printf "timestamp\tevent_type\tsession_id\ttool_name\tdetail\trisk_level\n" > "${OUTPUT}"

find "${INCIDENT_DIR}/logs" -name "telemetry.jsonl" 2>/dev/null | while read -r jsonl; do
    jq -r '
        . as $event |
        (
            if .event_type == "tool_executed" then
                if (.tool_name | test("exec|shell|python_repl")) then "CRITICAL"
                elif (.tool_name == "file_read" and
                      (.tool_args.path | test("\.ssh|\.aws|\.bak|credentials"))) then "HIGH"
                elif (.tool_name == "email_send") then "MEDIUM"
                elif (.tool_name == "browser_action") then "MEDIUM"
                else "LOW"
                end
            elif .event_type == "config_changed" then "HIGH"
            elif .event_type == "skill_loaded" then "MEDIUM"
            else "INFO"
            end
        ) as $risk |
        (
            if .event_type == "tool_executed" then
                (.tool_name + " | " + (.tool_args | tostring | .[0:120]))
            elif .event_type == "message_received" then
                ("channel=" + (.channel // "unknown") + " | " + (.summary // ""))
            elif .event_type == "config_changed" then
                (.field // "unknown") + "=" + (.new_value // "")
            elif .event_type == "skill_loaded" then
                (.skill_name // "unknown")
            else .
            end
        ) as $detail |
        [.timestamp, .event_type, (.session_id // ""), (.tool_name // ""), $detail, $risk]
        | @tsv
    ' "${jsonl}" 2>/dev/null >> "${OUTPUT}"
done

sort -t$'\t' -k1,1 "${OUTPUT}" -o "${OUTPUT}.sorted"
mv "${OUTPUT}.sorted" "${OUTPUT}"

total=$(wc -l < "${OUTPUT}")
critical=$(grep -c "CRITICAL" "${OUTPUT}" || true)
high=$(grep -c "HIGH" "${OUTPUT}" || true)

echo "Timeline built: ${OUTPUT}"
echo "Total events:   $((total - 1))"
echo "CRITICAL:       ${critical}"
echo "HIGH:           ${high}"
echo ""
echo "First suspicious event:"
grep -E "CRITICAL|HIGH" "${OUTPUT}" | head -1 || echo "(none)"
echo ""
echo "To review: column -t -s $'\t' ${OUTPUT} | less -S"
