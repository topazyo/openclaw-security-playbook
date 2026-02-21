#!/usr/bin/env bash
# build_timeline.sh — Reconstruct attack timeline from openclaw-telemetry logs
#
# USAGE: ./build_timeline.sh --incident-dir ~/openclaw-incident-TIMESTAMP
#
# Outputs a chronological TSV timeline of all tool executions,
# messages received, and config changes, highlighting high-risk events.
# Part of: https://github.com/topazyo/openclaw-security-playbook

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

print_help() {
    cat <<'EOF'
build_timeline.sh — Reconstruct attack timeline from openclaw-telemetry logs

Usage:
  ./scripts/forensics/build_timeline.sh --incident-dir <path>
  ./scripts/forensics/build_timeline.sh --incident-dir=<path>
  ./scripts/forensics/build_timeline.sh --help|-h

Exit codes:
  0  Timeline built with no HIGH/CRITICAL findings
  1  CRITICAL findings present in timeline
  2  Warnings present (HIGH findings or input/telemetry issues)
EOF
}

INCIDENT_DIR=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        --incident-dir)
            shift
            INCIDENT_DIR="${1:-}"
            ;;
        --incident-dir=*)
            INCIDENT_DIR="${1#--incident-dir=}"
            ;;
        --help|-h)
            print_help
            exit 0
            ;;
        *)
            echo -e "${YELLOW}[WARN] Unknown argument: $1${NC}"
            print_help
            exit 2
            ;;
    esac
    shift
done

if [ -z "${INCIDENT_DIR}" ] || [ ! -d "${INCIDENT_DIR}" ]; then
    echo -e "${YELLOW}[WARN] Missing or invalid incident directory${NC}"
    print_help
    exit 2
fi

if [ ! -d "${INCIDENT_DIR}/logs" ]; then
    echo -e "${YELLOW}[WARN] No logs directory found: ${INCIDENT_DIR}/logs${NC}"
    exit 2
fi

OUTPUT="${INCIDENT_DIR}/timeline.tsv"

echo "Building attack timeline..."
printf "timestamp\tevent_type\tsession_id\ttool_name\tdetail\trisk_level\n" > "${OUTPUT}"

log_inputs=0
find "${INCIDENT_DIR}/logs" -name "telemetry.jsonl" 2>/dev/null | while read -r jsonl; do
    log_inputs=$((log_inputs + 1))
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

if [ ! -s "${OUTPUT}" ]; then
    echo -e "${YELLOW}[WARN] No telemetry events parsed for timeline${NC}"
    exit 2
fi

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

if [ "${critical}" -gt 0 ]; then
    echo -e "${RED}[CRITICAL] Timeline contains critical events${NC}"
    exit 1
elif [ "${high}" -gt 0 ]; then
    echo -e "${YELLOW}[WARN] Timeline contains high-risk events${NC}"
    exit 2
else
    echo -e "${GREEN}[PASS] Timeline built with no high/critical findings${NC}"
    exit 0
fi
