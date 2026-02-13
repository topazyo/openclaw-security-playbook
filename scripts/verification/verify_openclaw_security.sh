#!/bin/bash
#
# OpenClaw Security Verification Script
# 
# Checks for three critical attack vectors:
# 1. Network exposure (binding to 0.0.0.0 instead of 127.0.0.1)
# 2. Backup file persistence (deleted credentials still harvestable)
# 3. Logging configuration (visibility into agent behavior)
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

echo "OpenClaw Security Verification"
echo "=============================="
echo ""

# Check 1: Network Binding
echo "[1/3] Checking network binding..."
if ss -lntp 2>/dev/null | grep -q ":18789"; then
    BINDING=$(ss -lntp 2>/dev/null | grep ":18789" | awk '{print $4}')

    if echo "$BINDING" | grep -q "0.0.0.0\|:::"; then
        echo -e "${RED}✗ CRITICAL: Gateway exposed on all interfaces${NC}"
        echo "  Current binding: $BINDING"
        echo "  Fix: Edit ~/.moltbot/config.yml or ~/.clawdbot/config.yml"
        echo "       Set: gateway.bind.address = \"127.0.0.1\""
        CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
    elif echo "$BINDING" | grep -q "127.0.0.1"; then
        echo -e "${GREEN}✓ Gateway bound to localhost only${NC}"
        echo "  Binding: $BINDING"
    else
        echo -e "${YELLOW}⚠ WARNING: Unexpected binding${NC}"
        echo "  Binding: $BINDING"
        WARNINGS=$((WARNINGS + 1))
    fi
else
    echo -e "${YELLOW}⚠ Gateway not running or not listening on port 18789${NC}"
    WARNINGS=$((WARNINGS + 1))
fi

echo ""

# Check 2: Backup File Persistence
echo "[2/3] Checking for backup files..."
BACKUP_FILES=$(find ~/.clawdbot ~/.moltbot ~/clawd -name "*.bak*" 2>/dev/null || true)

if [ -n "$BACKUP_FILES" ]; then
    BACKUP_COUNT=$(echo "$BACKUP_FILES" | wc -l)
    echo -e "${RED}✗ CRITICAL: Found $BACKUP_COUNT backup files with deleted credentials${NC}"
    echo ""
    echo "  Files found:"
    echo "$BACKUP_FILES" | sed 's/^/    /'
    echo ""
    echo "  IMMEDIATE ACTION REQUIRED:"
    echo "  1. Rotate credentials at providers FIRST:"
    echo "     - Anthropic: https://console.anthropic.com/settings/keys"
    echo "     - OpenAI: https://platform.openai.com/api-keys"
    echo "     - AWS: https://console.aws.amazon.com/iam/"
    echo "  2. THEN securely delete backups:"
    echo "     shred -vfz -n 3 ~/.clawdbot/*.bak* ~/.moltbot/*.bak* 2>/dev/null"
    CRITICAL_ISSUES=$((CRITICAL_ISSUES + 1))
else
    echo -e "${GREEN}✓ No backup files found${NC}"
fi

echo ""

# Check 3: Logging Configuration
echo "[3/3] Checking logging configuration..."
CONFIG_FOUND=false

for CONFIG_PATH in ~/.moltbot/config.yml ~/.clawdbot/config.yml ~/.openclaw/config.yml; do
    if [ -f "$CONFIG_PATH" ]; then
        CONFIG_FOUND=true

        if grep -q "logging:" "$CONFIG_PATH" && grep -q "toolExecution:" "$CONFIG_PATH"; then
            echo -e "${GREEN}✓ Tool execution logging enabled in $CONFIG_PATH${NC}"
        else
            echo -e "${YELLOW}⚠ WARNING: Tool execution logging not configured in $CONFIG_PATH${NC}"
            echo "  Recommendation: Enable logging for visibility"
            echo "  Add to config:"
            echo "    logging:"
            echo "      toolExecution:"
            echo "        enabled: true"
            WARNINGS=$((WARNINGS + 1))
        fi
    fi
done

if [ "$CONFIG_FOUND" = false ]; then
    echo -e "${YELLOW}⚠ WARNING: No configuration file found${NC}"
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
