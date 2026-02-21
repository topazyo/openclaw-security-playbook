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
WILDCARD_BIND_REGEX='0\.0\.0\.0|\[::\]|:::|(^|[[:space:]:])::([[:space:]:]|$)|\*'
GATEWAY_CFG_PATHS=(
    "$HOME/.openclaw/config/gateway.yml"
    "$HOME/.clawdbot/config/gateway.yml"
    "$HOME/.moltbot/config/gateway.yml"
)

for gateway_cfg in "${GATEWAY_CFG_PATHS[@]}"; do
    if [ -f "$gateway_cfg" ]; then
        if grep -Eq "$WILDCARD_BIND_REGEX" "$gateway_cfg"; then
            echo -e "${RED}✗ CRITICAL: Gateway config contains wildcard bind in ${gateway_cfg}${NC}"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        elif grep -Eq '127\.0\.0\.1|localhost' "$gateway_cfg"; then
            echo -e "${GREEN}✓ Gateway config uses localhost binding (${gateway_cfg})${NC}"
        else
            echo -e "${YELLOW}⚠ WARNING: Gateway bind not explicit in ${gateway_cfg}${NC}"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
done

if command -v ss >/dev/null 2>&1; then
    if ss -lntp 2>/dev/null | grep -q ":18789"; then
        BINDING=$(ss -lntp 2>/dev/null | grep ":18789" | awk '{print $4}' | head -1)
        if echo "$BINDING" | grep -Eq "$WILDCARD_BIND_REGEX"; then
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
elif command -v netstat >/dev/null 2>&1; then
    if netstat -lnt 2>/dev/null | grep -q ":18789"; then
        BINDING=$(netstat -lnt 2>/dev/null | grep ":18789" | awk '{print $4}' | head -1)
        if echo "$BINDING" | grep -Eq "$WILDCARD_BIND_REGEX"; then
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
else
    echo -e "${YELLOW}⚠ WARNING: Neither ss nor netstat found; live bind check skipped${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

if command -v openssl >/dev/null 2>&1; then
    if openssl s_client -connect 127.0.0.1:8443 -tls1_2 </dev/null >/dev/null 2>&1; then
        echo -e "${RED}✗ CRITICAL: TLS 1.2 accepted on 127.0.0.1:8443 (must be TLS 1.3 only)${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    else
        if openssl s_client -connect 127.0.0.1:8443 -tls1_3 </dev/null >/dev/null 2>&1; then
            echo -e "${GREEN}✓ TLS 1.3-only posture validated on 127.0.0.1:8443${NC}"
        else
            echo -e "${YELLOW}⚠ WARNING: Could not validate TLS posture on 127.0.0.1:8443${NC}"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
else
    echo -e "${YELLOW}⚠ WARNING: openssl not available; TLS downgrade check skipped${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 3: Runtime Sandboxing
echo "[3/7] Checking runtime sandboxing..."
if command -v docker >/dev/null 2>&1 && docker ps --format '{{.Names}}' | grep -q '^clawdbot-production$'; then
    USER_ID=$(docker inspect clawdbot-production --format '{{.Config.User}}' 2>/dev/null || true)
    READ_ONLY=$(docker inspect clawdbot-production --format '{{.HostConfig.ReadonlyRootfs}}' 2>/dev/null || true)
    CAP_DROP=$(docker inspect clawdbot-production --format '{{.HostConfig.CapDrop}}' 2>/dev/null || true)
    CAP_ADD=$(docker inspect clawdbot-production --format '{{.HostConfig.CapAdd}}' 2>/dev/null || true)
    SECURITY_OPT=$(docker inspect clawdbot-production --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null || true)
    PIDS_LIMIT=$(docker inspect clawdbot-production --format '{{.HostConfig.PidsLimit}}' 2>/dev/null || true)
    TMPFS_MOUNTS=$(docker inspect clawdbot-production --format '{{json .HostConfig.Tmpfs}}' 2>/dev/null || true)

    RUNTIME_OK=true

    if [ "$USER_ID" != "1000:1000" ]; then
        echo -e "${RED}✗ CRITICAL: Container is not running as 1000:1000 (actual: ${USER_ID:-unset})${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if [ "$READ_ONLY" != "true" ]; then
        echo -e "${RED}✗ CRITICAL: Container root filesystem is not read-only${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if ! echo "$CAP_DROP" | grep -q "ALL"; then
        echo -e "${RED}✗ CRITICAL: cap_drop does not include ALL${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if ! echo "$SECURITY_OPT" | grep -q "no-new-privileges"; then
        echo -e "${RED}✗ CRITICAL: no-new-privileges is not enabled${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if ! echo "$SECURITY_OPT" | grep -q "seccomp"; then
        echo -e "${RED}✗ CRITICAL: seccomp profile not configured${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if [ -z "$PIDS_LIMIT" ] || [ "$PIDS_LIMIT" = "0" ] || [ "$PIDS_LIMIT" = "-1" ]; then
        echo -e "${RED}✗ CRITICAL: pids_limit not set${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if [ -z "$TMPFS_MOUNTS" ] || [ "$TMPFS_MOUNTS" = "null" ] || [ "$TMPFS_MOUNTS" = "{}" ]; then
        echo -e "${RED}✗ CRITICAL: tmpfs mounts not configured${NC}"
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
        RUNTIME_OK=false
    fi

    if [ -n "$CAP_ADD" ] && [ "$CAP_ADD" != "[]" ]; then
        CLEAN_CAP_ADD=$(echo "$CAP_ADD" | tr -d '[] ')
        if [ "$CLEAN_CAP_ADD" != "NET_BIND_SERVICE" ]; then
            echo -e "${RED}✗ CRITICAL: Unexpected capabilities added: $CAP_ADD${NC}"
            CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
            RUNTIME_OK=false
        fi
    fi

    if [ "$RUNTIME_OK" = true ]; then
        echo -e "${GREEN}✓ Runtime hardening checks passed (8/8 controls)${NC}"
    else
        echo -e "${YELLOW}⚠ WARNING: Runtime hardening has critical gaps${NC}"
        echo "  User=${USER_ID} ReadOnly=${READ_ONLY} CapDrop=${CAP_DROP} CapAdd=${CAP_ADD} Pids=${PIDS_LIMIT}"
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
    if (grep -Eq "requireSignature:[[:space:]]*true|require_signature:[[:space:]]*true" "$SKILLS_CFG") && \
       (grep -Eq "autoUpdate:[[:space:]]*false|auto_update:[[:space:]]*false" "$SKILLS_CFG") && \
       (grep -Eq "autoInstall:[[:space:]]*false|auto_install:[[:space:]]*false" "$SKILLS_CFG"); then
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
