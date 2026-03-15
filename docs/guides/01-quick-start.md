---
title: Quick Start Guide
layer: Cross-layer
estimated_time: 15 minutes
difficulty: Beginner
---

# Quick Start Guide

**Estimated Time:** 15 minutes  
**Difficulty:** Beginner  
**Prerequisites:** Docker, Docker Compose v2, Python 3.11+, basic command-line knowledge

This guide gets you from a fresh clone to a validated reference security configuration in about 15 minutes.

## Platform Notes

### Linux
Use the commands as written.

### macOS
Use the commands as written; install GNU tools if a command differs from BSD behavior.

### Windows
Use WSL2 for the shell-based steps in this guide. The Windows Credential Manager example below is the only native PowerShell path documented here.

## Table of Contents

1. [Pre-Flight Security Check](#pre-flight-security-check)
2. [Install OpenClaw/ClawdBot](#install-openclawclawdbot)
3. [Apply Essential Hardening](#apply-essential-hardening)
4. [Verify Security Posture](#verify-security-posture)
5. [Test Your Deployment](#test-your-deployment)
6. [Next Steps](#next-steps)

---

## Pre-Flight Security Check

Before installing, verify your environment is secure:

These commands assume a POSIX shell. On Windows, run them from WSL2.

```bash
# Check for existing insecure installations
ps aux | grep -E 'claw|molt|openclaw'

# Check for exposed ports
netstat -tuln | grep 18789

# Check for backup files with credentials
find ~ -name "*.bak*" -o -name "credentials*.yml" 2>/dev/null
```

**If you find existing installations:**
1. Stop them: `docker stop $(docker ps -q --filter "name=claw")`
2. Document configuration before removing
3. Rotate any exposed credentials

---

## Install the Playbook Tooling

```bash
# Clone the repository
git clone https://github.com/openclaw/openclaw-security-playbook.git
cd openclaw-security-playbook

# Create a virtual environment and install dependencies
python -m venv .venv
source .venv/bin/activate  # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Validate the canonical hardened runtime definition
docker compose -f configs/examples/docker-compose-full-stack.yml config
```

This repository provides security tooling, hardened reference configuration, and verification scripts. For runtime deployment, prefer the canonical service definition in `configs/examples/docker-compose-full-stack.yml` or the hardened Docker guidance in `scripts/hardening/docker/README.md` instead of an ad hoc `docker run` command.

---

## Apply Essential Hardening

### Step 1: Configure Localhost Binding

```bash
cat > ~/.openclaw/config/gateway.yml << 'EOF'
gateway:
  bind:
    address: "127.0.0.1"  # ⚠️ CRITICAL: localhost only
    port: 18789

  auth:
    mode: "required"
    tokenSecret: "${GATEWAY_TOKEN}"
EOF

# Generate secure token
export GATEWAY_TOKEN=$(openssl rand -base64 32)
echo "GATEWAY_TOKEN=$GATEWAY_TOKEN" >> ~/.openclaw/.env
chmod 600 ~/.openclaw/.env
```

### Step 2: Enable OS Keychain for Credentials

**macOS:**
```bash
# Set ANTHROPIC_API_KEY in your shell before running this command
security add-generic-password \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -w "$ANTHROPIC_API_KEY"
```

**Linux:**
```bash
# Install libsecret (Ubuntu/Debian)
sudo apt-get install libsecret-1-0

# Store in Secret Service
secret-tool store \
  --label="OpenClaw Anthropic API Key" \
  service ai.openclaw.anthropic \
  username $USER
# Paste your API key when prompted
```

**Windows:**
```powershell
# Set $env:ANTHROPIC_API_KEY for the current session first
cmdkey /generic:openclaw_anthropic /user:$env:USERNAME /pass:$env:ANTHROPIC_API_KEY
```

### Step 3: Configure Credential Storage

```bash
cat > ~/.openclaw/config/credentials.yml << 'EOF'
credentials:
  storage: "os_keychain"

  keychain:
    service_prefix: "ai.openclaw"
    providers:
      anthropic:
        service: "ai.openclaw.anthropic"
        account: "${USER}"
      openai:
        service: "ai.openclaw.openai"
        account: "${USER}"
EOF
```

### Step 4: Disable Skill Auto-Updates

```bash
cat > ~/.openclaw/config/skills.yml << 'EOF'
skills:
  autoUpdate: false
  autoInstall: false

  sources:
    allowedRepositories:
      - "https://github.com/your-approved-org/openclaw-skills"

  verification:
    requireSignature: true
    trustedKeys:
      - "anthropic-release-key.gpg"
EOF
```

---

## Verify Security Posture

Run the automated security verification:

```bash
# Run verification from the repository root
./scripts/verification/verify_openclaw_security.sh
```

**Verify:** Expected behavior:
- Output starts with `OpenClaw Security Verification` and seven checks (`[1/7]` through `[7/7]`).
- On a fresh clone without a running deployment, runtime sandboxing and TLS checks can warn and exit with code `2`.
- After a compatible hardened deployment is running and bound as expected, the script should exit `0` with all seven layers passing.

**If checks fail:**
- Review the error messages
- Fix issues before proceeding
- Re-run verification

---

## Test Your Deployment

### Test 1: Verify Localhost Binding

```bash
# Should succeed (localhost)
curl http://127.0.0.1:18789/health

# From another machine or by using a non-loopback host address,
# the same request should fail.
curl http://YOUR_HOST_IP:18789/health
# Expected: connection refused or timeout
```

### Test 2: Verify Credential Storage

```bash
# macOS
security find-generic-password -s "ai.openclaw.anthropic" >/dev/null && echo "Keychain entry exists"

# Linux
secret-tool lookup service ai.openclaw.anthropic username $USER >/dev/null && echo "Secret Service entry exists"
```

```powershell
# Windows
cmdkey /list:openclaw_anthropic
# Should list the stored credential target
```

### Test 3: Send Test Request

```bash
# Generate auth token (if using gateway auth)
AUTH_TOKEN=$GATEWAY_TOKEN

# Send test request
curl -X POST http://127.0.0.1:18789/v1/completions \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt": "What is 2+2?",
    "max_tokens": 50
  }'
```

**Expected:** JSON response with completion

---

## Next Steps

### Immediate (Next 30 Minutes)

1. **Set Up VPN Access** (if remote access needed)
   - Follow: [03-network-segmentation.md](03-network-segmentation.md)
   - Install Tailscale or WireGuard
   - Never expose to public internet

2. **Enable Logging**
   ```bash
   # Quick logging setup
   mkdir -p ~/.openclaw/logs
   cat > ~/.openclaw/config/logging.yml << 'EOF'
   logging:
     toolExecution:
       enabled: true
       path: "~/.openclaw/logs/tools.jsonl"

     auditLog:
       enabled: true
       path: "~/.openclaw/logs/audit.jsonl"
   EOF
   ```

3. **Review Allowed Tools**
   - Create allowlist: `~/.openclaw/config/tools.yml`
   - Start with read-only tools only
   - Add write tools as needed

### Short-Term (This Week)

1. **Deploy openclaw-telemetry** (Community Tool)
   - Enterprise-grade behavioral monitoring
   - Follow: [08-community-tools-integration.md](08-community-tools-integration.md#openclaw-telemetry)

2. **Implement Skill Integrity Monitoring**
   - Follow: [05-supply-chain-security.md](05-supply-chain-security.md)
   - Generate baseline manifest
   - Set up daily verification cron job

3. **Create Incident Response Plan**
   - Follow: [06-incident-response.md](06-incident-response.md)
   - Document escalation procedures
   - Test response playbooks

### Long-Term (This Month)

1. **Full Defense-in-Depth Implementation**
   - Layer 1: OS-Level Credential Isolation ✓ (Done in this guide)
   - Layer 2: Network Segmentation (See guide 03)
   - Layer 3: Runtime Sandboxing (See guide 04)
   - Layer 4: Runtime Security Enforcement (openclaw-shield)
   - Layer 5: Supply Chain Integrity (See guide 05)
   - Layer 6: Behavioral Monitoring (openclaw-telemetry)
   - Layer 7: Organizational Controls (See your org policies)

2. **Deploy openclaw-shield** (Community Tool)
   - 5-layer runtime security enforcement
   - Prompt injection guards
   - PII/secret redaction

3. **Shadow AI Discovery** (If Enterprise)
   - Deploy openclaw-detect via MDM
   - Inventory all AI agent installations
   - Enforce security policies

---

## Troubleshooting

### Gateway Won't Start

**Symptom:** Container exits immediately

**Solution:**
```bash
# Check logs
docker logs clawdbot-production

# Common issue: Missing credentials
# Verify the configured credential entry exists in your OS store.
```

### Cannot Access Gateway

**Symptom:** `curl: (7) Failed to connect`

**Solution:**
```bash
# Verify gateway is running
docker ps | grep clawdbot-production

# Check binding
docker port clawdbot-production 18789
# Should show: 127.0.0.1:18789
```

### Credential Storage Fails

**macOS Issue:** "User interaction required"

**Solution:**
```bash
# Update Keychain entry to allow access
security set-generic-password-partition-list \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -S
```

---

## Security Checklist

Before going to production, verify:

- [ ] Gateway bound to 127.0.0.1 (not 0.0.0.0)
- [ ] Credentials stored in OS keychain (not plaintext)
- [ ] No backup files with credentials exist
- [ ] Skill auto-update disabled
- [ ] Tool execution logging enabled
- [ ] Docker container uses security options
- [ ] Authentication enabled on gateway
- [ ] No public IP exposure
- [ ] Verification script passes all checks

---

## Quick Reference

### Start/Stop Commands

```bash
# Start
docker start clawdbot-production

# Stop
docker stop clawdbot-production

# Restart (after config changes)
docker restart clawdbot-production

# View logs
docker logs -f clawdbot-production
```

### Configuration Locations

- **Gateway:** `~/.openclaw/config/gateway.yml`
- **Credentials:** `~/.openclaw/config/credentials.yml`
- **Skills:** `~/.openclaw/config/skills.yml`
- **Logs:** `~/.openclaw/logs/`
- **Environment:** `~/.openclaw/.env`

### Important Commands

```bash
# Test localhost binding
curl http://127.0.0.1:18789/health

# View tool execution log
tail -f ~/.openclaw/logs/tools.jsonl | jq

# Rotate API key (macOS)
security delete-generic-password -s "ai.openclaw.anthropic"
security add-generic-password -s "ai.openclaw.anthropic" -a "$USER" -w "NEW_KEY"

# Check for security issues
./scripts/verification/verify_openclaw_security.sh
```

---

## Related Guides

- **Network Segmentation:** [03-network-segmentation.md](03-network-segmentation.md)
- **Credential Isolation:** [02-credential-isolation.md](02-credential-isolation.md)
- **Runtime Sandboxing:** [04-runtime-sandboxing.md](04-runtime-sandboxing.md)
- **Community Tools:** [08-community-tools-integration.md](08-community-tools-integration.md)

---

**Last Updated:** March 15, 2026  
**Tested On:** macOS 14.0+, Ubuntu 22.04+, Docker 24.0+ (Windows users should use WSL2 for shell-based steps)
