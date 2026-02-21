#!/usr/bin/env bash
# collect_evidence.sh — OpenClaw Incident Evidence Preservation
#
# USAGE: ./collect_evidence.sh [--containment]
#   --containment: Also stop the agent and block network after evidence collection
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
  --containment   Also stop agent services after evidence collection
  --help, -h      Show this help message and exit

Exit codes:
    0  Successful execution (no critical issues, no warnings)
    1  Critical findings detected during collection
    2  Warnings detected or invalid arguments

Run this before stopping the agent process to preserve volatile state.
EOF
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

ss -tnap > "${INCIDENT_DIR}/network/connections.txt" 2>/dev/null || true
ss -lntp > "${INCIDENT_DIR}/network/listeners.txt" 2>/dev/null || true
lsof -nP -iTCP -sTCP:ESTABLISHED >> "${INCIDENT_DIR}/network/connections.txt" 2>/dev/null || true
netstat -rn > "${INCIDENT_DIR}/network/routes.txt" 2>/dev/null || true

ps auxf > "${INCIDENT_DIR}/process/process-tree.txt" 2>/dev/null || true
ps aux | grep -E "(openclaw|moltbot|clawdbot|node)"     > "${INCIDENT_DIR}/process/agent-processes.txt" 2>/dev/null || true

echo "[+] Phase 1: Copying agent logs..."
for dir in ~/.openclaw ~/.moltbot ~/.clawdbot; do
    if [ -d "${dir}/logs" ]; then
        dirname=$(basename "$dir")
        mkdir -p "${INCIDENT_DIR}/logs/${dirname}"
        cp -r "${dir}/logs/." "${INCIDENT_DIR}/logs/${dirname}/" 2>/dev/null || true
        echo "    Copied: ${dir}/logs/"
    fi
done

echo "[+] Phase 2: Copying configuration files..."
for dir in ~/.openclaw ~/.moltbot ~/.clawdbot; do
    if [ -d "${dir}" ]; then
        dirname=$(basename "$dir")
        mkdir -p "${INCIDENT_DIR}/config/${dirname}"
        cp "${dir}/config.yml"  "${INCIDENT_DIR}/config/${dirname}/" 2>/dev/null || true
        cp "${dir}/config.json" "${INCIDENT_DIR}/config/${dirname}/" 2>/dev/null || true
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
        find "${dir}" -name "*.md" -type f 2>/dev/null             | sort > "${INCIDENT_DIR}/filesystem/skills-present-${dirname}.txt"
    fi
done

echo "[+] Phase 7: Capturing crontab and systemd units..."
crontab -l > "${INCIDENT_DIR}/filesystem/crontab.txt" 2>/dev/null || echo "(no crontab)"
systemctl list-units --type=service | grep -iE "(openclaw|moltbot|clawdbot)"     > "${INCIDENT_DIR}/filesystem/systemd-services.txt" 2>/dev/null || true

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
    echo "[+] Running containment (--containment flag set)..."
    systemctl stop moltbot 2>/dev/null || true
    systemctl stop openclaw 2>/dev/null || true
    docker stop clawdbot 2>/dev/null || true
    echo "    Agent stopped."
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
