#!/bin/bash
#
# OpenClaw Security Verification Script
# 
# Checks for seven defense layers:
# 1. Credential isolation
# 2. Network segmentation
# 3. Runtime sandboxing
# 4. Runtime enforcement
# 5. Supply chain security
# 6. Monitoring and telemetry
# 7. Governance and policy artifacts
#
################################################################################
# COMPREHENSIVE SECURITY STACK
################################################################################
#
# This script provides BASIC security verification. For comprehensive
# production security, combine with these community tools:
#
# RUNTIME SECURITY ENFORCEMENT (Layer 4):
#   • openclaw-shield: https://github.com/knostic/openclaw-shield
#     5-layer defense: Prompt Guard, Output Scanner, Tool Blocker, Input Audit
#     Prevents malicious tool execution, redacts secrets from outputs
#
# BEHAVIORAL MONITORING (Layer 6):
#   • openclaw-telemetry: https://github.com/knostic/openclaw-telemetry
#     Enterprise telemetry with SIEM integration, tamper-proof audit trails
#     Detects anomalous behavior patterns and prompt injection attempts
#
# SHADOW AI DISCOVERY (Layer 7):
#   • openclaw-detect: https://github.com/knostic/openclaw-detect
#     MDM-deployable scripts for discovering unauthorized AI installations
#     Supports Intune, Jamf, JumpCloud, Kandji, Workspace ONE
#
# INTEGRATION GUIDE:
#   docs/guides/07-community-tools-integration.md
#
# COMBINED CONFIGURATION:
#   configs/examples/with-community-tools.yml
#
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Counters
CRITICAL_ISSUES=0
WARNINGS=0

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

print_help() {
        cat <<'EOF'
OpenClaw Security Verification Script

Usage:
    ./scripts/verification/verify_openclaw_security.sh [--help|-h]

Description:
    Runs seven-layer security verification checks for OpenClaw/ClawdBot environments.

Exit codes:
    0  All checks passed
    1  One or more critical issues found
    2  Warnings found (no critical issues) or invalid arguments
EOF
}

if [ "$#" -gt 0 ]; then
        case "$1" in
                --help|-h)
                        print_help
                        exit 0
                        ;;
                *)
                        echo -e "${YELLOW}⚠ WARNING: Unknown argument: $1${NC}"
                        print_help
                        exit 2
                        ;;
        esac
fi

echo "OpenClaw Security Verification"
echo "=============================="
echo ""

# Check 1: Credential Isolation
echo "[1/7] Checking credential isolation..."
BACKUP_FILES=$(find ~/.openclaw ~/.clawdbot ~/.moltbot -type f \( -name "*.bak*" -o -name "*~" -o -name "*.swp" \) 2>/dev/null || true)
PLAINTEXT_KEYS=$(grep -rE "(sk-ant-|sk-proj-|AKIA[0-9A-Z]{16})" ~/.openclaw ~/.clawdbot ~/.moltbot 2>/dev/null || true)

if [ -n "$BACKUP_FILES" ]; then
    BACKUP_COUNT=$(echo "$BACKUP_FILES" | wc -l)
    echo -e "${RED}✗ CRITICAL: Found ${BACKUP_COUNT} backup files that may contain credentials${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
    echo -e "${GREEN}✓ No backup credential files found${NC}"
fi

if [ -n "$PLAINTEXT_KEYS" ]; then
    echo -e "${RED}✗ CRITICAL: Potential plaintext credential patterns found${NC}"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
    echo -e "${GREEN}✓ No plaintext credential patterns found in local config paths${NC}"
fi

echo ""

# Check 2: Network Segmentation
echo "[2/7] Checking network binding..."
if ss -lntp 2>/dev/null | grep -q ":18789"; then
    BINDING=$(ss -lntp 2>/dev/null | grep ":18789" | awk '{print $4}')
    if echo "$BINDING" | grep -q "0.0.0.0\|:::"; then
        echo -e "${RED}✗ CRITICAL: Gateway exposed on all interfaces${NC}"
        echo "  Current binding: $BINDING"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    elif echo "$BINDING" | grep -q "127.0.0.1"; then
        echo -e "${GREEN}✓ Gateway bound to localhost only${NC}"
    else
        echo -e "${YELLOW}⚠ WARNING: Unexpected gateway binding: $BINDING${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}⚠ WARNING: Gateway not listening on port 18789${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 3: Runtime Sandboxing
echo "[3/7] Checking runtime sandboxing..."
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^clawdbot-production$'; then
    USER_ID=$(docker inspect clawdbot-production --format '{{.Config.User}}' 2>/dev/null || true)
    READ_ONLY=$(docker inspect clawdbot-production --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null || true)
    CAP_DROP=$(docker inspect clawdbot-production --format '{{.HostConfig.CapDrop}}' 2>/dev/null || true)

    if [ "$USER_ID" = "1000:1000" ] && [ "$READ_ONLY" = "true" ] && echo "$CAP_DROP" | grep -q "ALL"; then
        echo -e "${GREEN}✓ Runtime hardening checks passed (non-root, read-only, cap_drop ALL)${NC}"
    else
        echo -e "${YELLOW}⚠ WARNING: Runtime hardening appears incomplete${NC}"
        echo "  User=${USER_ID} ReadOnly=${READ_ONLY} CapDrop=${CAP_DROP}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}⚠ WARNING: clawdbot-production container not running; sandbox checks skipped${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 4: Runtime Enforcement
echo "[4/7] Checking runtime enforcement (openclaw-shield)..."
if [ -f ~/.openclaw/config/shield/config.yml ]; then
    if grep -q "enabled: true" ~/.openclaw/config/shield/config.yml; then
        echo -e "${GREEN}✓ Shield configuration found and enabled${NC}"
    else
        echo -e "${YELLOW}⚠ WARNING: Shield config present but not clearly enabled${NC}"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}⚠ WARNING: Shield configuration not found at ~/.openclaw/config/shield/config.yml${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 5: Supply Chain Security
echo "[5/7] Checking supply chain policy defaults..."
SKILLS_CFG=~/.openclaw/config/skills.yml
if [ -f "$SKILLS_CFG" ]; then
    if grep -q "requireSignature: true" "$SKILLS_CFG" && grep -q "autoUpdate: false" "$SKILLS_CFG" && grep -q "autoInstall: false" "$SKILLS_CFG"; then
        echo -e "${GREEN}✓ Skill policy defaults are hardened (signature required, auto update/install disabled)${NC}"
    else
        echo -e "${RED}✗ CRITICAL: Skill policy defaults are not hardened${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    fi
else
    echo -e "${YELLOW}⚠ WARNING: Skills configuration not found at ${SKILLS_CFG}${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 6: Monitoring
echo "[6/7] Checking telemetry/monitoring configuration..."
if [ -f ~/.openclaw/config/telemetry/config.yml ] || [ -f ~/.openclaw/logs/telemetry.jsonl ]; then
    echo -e "${GREEN}✓ Telemetry artifact detected (config or telemetry log)${NC}"
else
    echo -e "${YELLOW}⚠ WARNING: No telemetry configuration/log detected${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 7: Governance
echo "[7/7] Checking governance and detection artifacts..."
if [ -d "${REPO_ROOT}/detections/sigma" ] && [ -f "${REPO_ROOT}/configs/organization-policies/security-policy.json" ]; then
    echo -e "${GREEN}✓ Governance artifacts present (detections and organization policy)${NC}"
else
    echo -e "${YELLOW}⚠ WARNING: Missing governance artifacts in repository${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""
echo "=============================="
echo "Verification Summary"
echo "=============================="
echo -e "Critical issues: ${RED}$CRITICAL_ISSUES${NC}"
echo -e "Warnings: ${YELLOW}$WARNINGS${NC}"

if [ $CRITICAL_ISSUES -gt 0 ]; then
    echo ""
    echo -e "${RED}✗ CRITICAL ISSUES DETECTED${NC}"
    echo "  Address critical issues immediately before continuing operation."
    echo ""
    echo "For comprehensive production security, also deploy:"
    echo "  • openclaw-shield (runtime security enforcement)"
    echo "  • openclaw-telemetry (behavioral monitoring)"
    echo "  • openclaw-detect (shadow AI discovery)"
    echo ""
    echo "See: docs/guides/07-community-tools-integration.md"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo ""
    echo -e "${YELLOW}⚠ Warnings found. Review recommendations above.${NC}"
    exit 2
else
    echo ""
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo "Consider enhancing security with community tools:"
    echo "  • openclaw-shield: Runtime security enforcement"
    echo "  • openclaw-telemetry: Enterprise behavioral monitoring"
    echo "  • openclaw-detect: Shadow AI discovery"
    echo ""
    echo "See: docs/guides/07-community-tools-integration.md"
    exit 0
fi
