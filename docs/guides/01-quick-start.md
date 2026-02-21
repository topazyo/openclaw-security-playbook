---
title: Quick Start Guide
layer: Cross-layer
estimated_time: 15 minutes
difficulty: Beginner
---

# Quick Start Guide

**Estimated Time:** 15 minutes  
**Difficulty:** Beginner  
**Prerequisites:** Docker, basic command-line knowledge

This guide gets you from zero to a hardened AI agent deployment in 15 minutes.

## Platform Notes

### Linux
Use the commands as written.

### macOS
Use the commands as written; install GNU tools if a command differs from BSD behavior.

### Windows
Use PowerShell equivalents where needed, or run shell commands via WSL2.

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

## Install OpenClaw/ClawdBot

### Option A: Docker (Recommended)

```bash
# Create secure configuration directory
mkdir -p ~/.openclaw/{config,skills,logs}
chmod 700 ~/.openclaw

# Pull official image
docker pull anthropic/clawdbot:latest

# Run with security hardening
docker run -d \
  --name clawdbot-secure \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=100m \
  --security-opt no-new-privileges:true \
  --pids-limit=100 \
  -v ~/.openclaw/config:/app/config:ro \
  -v ~/.openclaw/skills:/app/skills:ro \
  -v ~/.openclaw/logs:/app/logs:rw \
  -p 127.0.0.1:18789:18789 \
  -e CREDENTIALS_STORE=keychain \
  anthropic/clawdbot:latest
```

**Security Notes:**
- `--cap-drop ALL`: Removes all Linux capabilities
- `--read-only`: Filesystem cannot be modified
- `--tmpfs`: Temporary files in memory only
- `-p 127.0.0.1:18789`: Binds to localhost only (not 0.0.0.0)

### Option B: Native Installation

```bash
# Install from package manager
npm install -g @anthropic/clawdbot
# OR
pip install clawdbot

# Create configuration
clawdbot init --secure
```

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
# Store Anthropic API key in Keychain
security add-generic-password \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -w "sk-ant-api03-..." \
  -T /usr/local/bin/clawdbot
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
# Store in Windows Credential Manager
cmdkey /generic:openclaw_anthropic /user:$env:USERNAME /pass:"sk-ant-api03-..."
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
      - "https://github.com/anthropic-ai/openclaw-skills"

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
# Download verification script
curl -fsSL https://raw.githubusercontent.com/YOUR-ORG/clawdbot-security-playbook/main/scripts/verification/verify_openclaw_security.sh -o verify.sh
chmod +x verify.sh

# Run verification
./verify.sh
```

**Verify:** Expected output:
```
[1/3] Checking network binding...
✓ Gateway bound to localhost only
  Binding: 127.0.0.1:18789

[2/3] Checking for backup files...
✓ No backup files found

[3/3] Checking logging configuration...
✓ Tool execution logging enabled

==============================
✓ All checks passed!
```

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

# Should fail (external access)
curl http://$(hostname -I | awk '{print $1}'):18789/health
# Expected: Connection refused
```

### Test 2: Verify Credential Storage

```bash
# macOS
security find-generic-password -s "ai.openclaw.anthropic" -w
# Should output your API key

# Linux
secret-tool lookup service ai.openclaw.anthropic username $USER
# Should output your API key
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
   - Follow: [07-community-tools-integration.md](07-community-tools-integration.md#openclaw-telemetry)

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
docker logs clawdbot-secure

# Common issue: Missing credentials
# Verify keychain entry exists:
security find-generic-password -s "ai.openclaw.anthropic"
```

### Cannot Access Gateway

**Symptom:** `curl: (7) Failed to connect`

**Solution:**
```bash
# Verify gateway is running
docker ps | grep clawdbot

# Check binding
docker exec clawdbot-secure netstat -tuln | grep 18789
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
docker start clawdbot-secure

# Stop
docker stop clawdbot-secure

# Restart (after config changes)
docker restart clawdbot-secure

# View logs
docker logs -f clawdbot-secure
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
- **Community Tools:** [07-community-tools-integration.md](07-community-tools-integration.md)

---

**Last Updated:** February 14, 2026  
**Tested On:** macOS 14.0+, Ubuntu 22.04+, Docker 24.0+
