#!/usr/bin/env bash
# collect_evidence.sh — OpenClaw Incident Evidence Preservation
#
# USAGE: ./collect_evidence.sh [--containment]
#   --containment: Also stop the agent's services/containers after evidence  ## FIX: C5-H-06
#                  collection. This does NOT block network traffic — apply   ## FIX: C5-H-06
#                  iptables/ufw rules separately if network containment is   ## FIX: C5-H-06
#                  required (see docs/guides/06-incident-response.md         ## FIX: C5-H-06
#                  Playbook 1 Step 1.2).                                     ## FIX: C5-H-06
#
# Run this BEFORE stopping the agent process to preserve in-memory state.
# Part of: https://github.com/topazyo/openclaw-security-playbook
# Part 3: https://cloudsecops.hashnode.dev/openclaw-detecting-compromise

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

print_help() {
    cat <<'EOF'
collect_evidence.sh — OpenClaw Incident Evidence Preservation

Usage:
  ./scripts/forensics/collect_evidence.sh [--containment] [--help|-h]

Options:
  --containment   After evidence collection, attempt to stop the moltbot and
                  openclaw systemd services and the clawdbot Docker container.
                  Each stop attempt that fails is recorded as a warning and
                  causes a non-zero exit. This flag does NOT block network
                  traffic — use iptables/ufw separately if network
                  containment is required.
  --help, -h      Show this help message and exit

Exit codes:
    0  Successful execution (no critical issues, no warnings)
    1  Critical findings detected during collection
    2  Warnings detected (including failed containment commands) or
       invalid arguments

Run this before stopping the agent process to preserve volatile state.
EOF
}

record_warning() {
    echo -e "${YELLOW}[WARN] $1${NC}"
    WARNINGS=$((WARNINGS + 1))
}

run_capture() {
    local description="$1"
    local output_path="$2"
    shift 2

    if "$@" > "${output_path}" 2>/dev/null; then
        return 0
    else
        local exit_code=$? # FIX: C5-finding-2
    fi

    : > "${output_path}"
    record_warning "Failed to ${description} (exit ${exit_code})"
}

run_append_capture() {
    local description="$1"
    local output_path="$2"
    shift 2

    if "$@" >> "${output_path}" 2>/dev/null; then
        return 0
    else
        local exit_code=$? # FIX: C5-finding-2
    fi

    record_warning "Failed to ${description} (exit ${exit_code})"
}

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
INCIDENT_DIR="${HOME}/openclaw-incident-${TIMESTAMP}"
CONTAINMENT=false
CRITICAL_ISSUES=0
WARNINGS=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --containment)
            CONTAINMENT=true
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

echo "============================================================"
echo " OpenClaw Incident Evidence Collection"
echo " Incident directory: ${INCIDENT_DIR}"
echo " Containment mode: ${CONTAINMENT}"
echo "============================================================"
echo ""

mkdir -p "${INCIDENT_DIR}"/{logs,config,network,process,filesystem,hashes}

echo "[+] Phase 0: Capturing volatile state before containment..."

run_capture "capture active network connections" "${INCIDENT_DIR}/network/connections.txt" ss -tnap
run_capture "capture network listeners" "${INCIDENT_DIR}/network/listeners.txt" ss -lntp
run_append_capture "capture established TCP connections via lsof" "${INCIDENT_DIR}/network/connections.txt" lsof -nP -iTCP -sTCP:ESTABLISHED
run_capture "capture network routes" "${INCIDENT_DIR}/network/routes.txt" netstat -rn

run_capture "capture process tree" "${INCIDENT_DIR}/process/process-tree.txt" ps auxf
agent_process_capture_rc=0                                                       ## FIX: C5-H-06
ps aux | grep -E "(openclaw|moltbot|clawdbot|node)" > "${INCIDENT_DIR}/process/agent-processes.txt" 2>/dev/null || agent_process_capture_rc=$?  ## FIX: C5-H-06
if [ "${agent_process_capture_rc}" -gt 1 ]; then
    : > "${INCIDENT_DIR}/process/agent-processes.txt"
    record_warning "Failed to capture filtered agent process list (exit ${agent_process_capture_rc})"
fi

echo "[+] Phase 1: Copying agent logs..."
for dir in ~/.openclaw ~/.moltbot ~/.clawdbot; do
    if [ -d "${dir}/logs" ]; then
        dirname=$(basename "$dir")
        mkdir -p "${INCIDENT_DIR}/logs/${dirname}"
        if cp -r "${dir}/logs/." "${INCIDENT_DIR}/logs/${dirname}/" 2>/dev/null; then
            echo "    Copied: ${dir}/logs/"
        else
            record_warning "Failed to copy logs from ${dir}/logs"
        fi
    fi
done

echo "[+] Phase 2: Copying configuration files..."
for dir in ~/.openclaw ~/.moltbot ~/.clawdbot; do
    if [ -d "${dir}" ]; then
        dirname=$(basename "$dir")
        mkdir -p "${INCIDENT_DIR}/config/${dirname}"
        if [ -f "${dir}/config.yml" ] && ! cp "${dir}/config.yml"  "${INCIDENT_DIR}/config/${dirname}/" 2>/dev/null; then
            record_warning "Failed to copy ${dir}/config.yml"
        fi
        if [ -f "${dir}/config.json" ] && ! cp "${dir}/config.json" "${INCIDENT_DIR}/config/${dirname}/" 2>/dev/null; then
            record_warning "Failed to copy ${dir}/config.json"
        fi
    fi
done

echo "[+] Phase 3: Copying SOUL.md files (potential persistence artifacts)..."
for dir in ~/.openclaw ~/.moltbot ~/.clawdbot; do
    if [ -f "${dir}/SOUL.md" ]; then
        dirname=$(basename "$dir")
        cp "${dir}/SOUL.md" "${INCIDENT_DIR}/filesystem/SOUL.md.${dirname}.evidence"
        echo "    Copied: ${dir}/SOUL.md"
    fi
done

echo "[+] Phase 4: Documenting backup credential files..."
find ~/ \( -path "*/.moltbot/*" -o -path "*/.clawdbot/*" -o -path "*/.openclaw/*" \)     -name "*.bak*" -type f 2>/dev/null     > "${INCIDENT_DIR}/filesystem/backup-credential-files.txt"

bak_count=$(wc -l < "${INCIDENT_DIR}/filesystem/backup-credential-files.txt")
if [ "${bak_count}" -gt 0 ]; then
    echo -e "    ${RED}[CRITICAL] Found ${bak_count} backup credential files${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
    echo -e "    ${GREEN}[PASS] No backup credential files found${NC}"
fi

echo "[+] Phase 5: Verifying telemetry hash chain integrity..."
HASH_INPUT_FOUND=false
for jsonl_file in ~/.openclaw/logs/telemetry.jsonl ~/.moltbot/logs/telemetry.jsonl; do
    if [ -f "${jsonl_file}" ]; then
        HASH_INPUT_FOUND=true
        echo "    Checking: ${jsonl_file}"
        if python3 "$(dirname "$0")/verify_hash_chain.py" --input "${jsonl_file}" --output "${INCIDENT_DIR}/hashes/hash-chain-verify.json" >/dev/null 2>&1; then
            echo -e "    ${GREEN}[PASS] Hash chain intact${NC}"
        else
            echo -e "    ${RED}[CRITICAL] Hash chain broken — log tampering possible${NC}"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        fi
    fi
done

if [ "${HASH_INPUT_FOUND}" = false ]; then
    echo -e "    ${YELLOW}[WARN] No telemetry hash-chain inputs found${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo -e "${GREEN}[PASS] Evidence collection finished${NC}"

echo "[+] Phase 6: Capturing skill manifests..."
for dir in ~/.openclaw/skills ~/.moltbot/skills ~/.clawdbot/skills; do
    if [ -d "${dir}" ]; then
        dirname=$(basename "$(dirname "$dir")")
        if ! find "${dir}" -name "*.md" -type f 2>/dev/null | sort > "${INCIDENT_DIR}/filesystem/skills-present-${dirname}.txt"; then
            : > "${INCIDENT_DIR}/filesystem/skills-present-${dirname}.txt"
            record_warning "Failed to capture skill manifests from ${dir}"
        fi
    fi
done

echo "[+] Phase 7: Capturing crontab and systemd units..."
if command -v crontab >/dev/null 2>&1; then
    if ! crontab -l > "${INCIDENT_DIR}/filesystem/crontab.txt" 2>/dev/null; then
        echo "(no crontab)" > "${INCIDENT_DIR}/filesystem/crontab.txt"
    fi
else
    : > "${INCIDENT_DIR}/filesystem/crontab.txt"
    record_warning "Failed to capture crontab entries (crontab command unavailable)"
fi

systemd_services_rc=0                                                            ## FIX: C5-H-06
{ systemctl list-units --type=service 2>/dev/null | grep -iE "(openclaw|moltbot|clawdbot)" > "${INCIDENT_DIR}/filesystem/systemd-services.txt" 2>/dev/null; } || systemd_services_rc=$?  ## FIX: C5-H-06
if [ "${systemd_services_rc}" -gt 1 ]; then
    : > "${INCIDENT_DIR}/filesystem/systemd-services.txt"
    record_warning "Failed to capture systemd service inventory (exit ${systemd_services_rc})"
fi

echo ""
echo "============================================================"
echo " Evidence collection complete: ${INCIDENT_DIR}"
echo "============================================================"
echo ""
echo " Next steps:"
echo "  1. Review SOUL.md files for injected instructions"
echo "  2. Check hash chain report for log tampering"
echo "  3. If backup credential files found: rotate at providers FIRST"
echo "  4. Run build_timeline.sh to reconstruct attack sequence"
echo "  5. Run check_credential_scope.sh to assess what was exposed"
echo ""

if [ "${CONTAINMENT}" = true ]; then
    echo "[+] Running containment (--containment flag set)..."                ## FIX: C5-H-06
    echo "    Note: stops services/containers only — does NOT block network." ## FIX: C5-H-06
    if ! systemctl stop moltbot 2>/dev/null; then                             ## FIX: C5-H-06
        record_warning "Failed to stop moltbot during containment"            ## FIX: C5-H-06
    fi
    if ! systemctl stop openclaw 2>/dev/null; then                            ## FIX: C5-H-06
        record_warning "Failed to stop openclaw during containment"           ## FIX: C5-H-06
    fi
    if ! docker stop clawdbot 2>/dev/null; then                               ## FIX: C5-H-06
        record_warning "Failed to stop clawdbot during containment"           ## FIX: C5-H-06
    fi
    echo "    Containment step finished (service/container stop attempted)."  ## FIX: C5-H-06
fi

echo ""
echo "============================================================"
echo " Evidence Collection Summary"
echo "============================================================"
echo -e " Critical issues: ${RED}${CRITICAL_ISSUES}${NC}"
echo -e " Warnings: ${YELLOW}${WARNINGS}${NC}"

if [ "${CRITICAL_ISSUES}" -gt 0 ]; then
    exit 1
elif [ "${WARNINGS}" -gt 0 ]; then
    exit 2
else
    exit 0
fi
