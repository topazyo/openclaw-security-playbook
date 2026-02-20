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

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
INCIDENT_DIR="${HOME}/openclaw-incident-${TIMESTAMP}"
CONTAINMENT=false

for arg in "$@"; do
    case $arg in
        --containment) CONTAINMENT=true ;;
    esac
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
    echo "    !! CRITICAL: Found ${bak_count} backup credential files"
else
    echo "    OK: No backup credential files found"
fi

echo "[+] Phase 5: Verifying telemetry hash chain integrity..."
for jsonl_file in ~/.openclaw/logs/telemetry.jsonl ~/.moltbot/logs/telemetry.jsonl; do
    if [ -f "${jsonl_file}" ]; then
        echo "    Checking: ${jsonl_file}"
        python3 "$(dirname "$0")/verify_hash_chain.py"             --input "${jsonl_file}"             --output "${INCIDENT_DIR}/hashes/hash-chain-verify.json" 2>/dev/null             && echo "    Hash chain: INTACT"             || echo "    Hash chain: !! BROKEN — log tampering possible"
    fi
done

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
