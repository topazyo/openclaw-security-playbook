# Verification Failures Troubleshooting Guide

> **Quick Reference:** Common issues when verifying ClawdBot security configurations and how to resolve them

This guide covers troubleshooting for the `verify_openclaw_security.sh` script and manual verification procedures across all 7 security layers.

---

## Table of Contents

1. [Pre-Flight Verification Failures](#pre-flight-verification-failures)
2. [Layer 1: Credential Isolation Issues](#layer-1-credential-isolation-issues)
3. [Layer 2: Network Segmentation Issues](#layer-2-network-segmentation-issues)
4. [Layer 3: Runtime Sandboxing Issues](#layer-3-runtime-sandboxing-issues)
5. [Layer 4: Runtime Enforcement Issues](#layer-4-runtime-enforcement-issues)
6. [Layer 5: Supply Chain Security Issues](#layer-5-supply-chain-security-issues)
7. [Layer 6: Behavioral Monitoring Issues](#layer-6-behavioral-monitoring-issues)
8. [Layer 7: Organizational Controls Issues](#layer-7-organizational-controls-issues)
9. [Platform-Specific Issues](#platform-specific-issues)
10. [Getting Help](#getting-help)

---

## Pre-Flight Verification Failures

### Issue: Verification Script Not Found

**Symptom:**
```bash
$ ./scripts/verification/verify_openclaw_security.sh
bash: ./scripts/verification/verify_openclaw_security.sh: No such file or directory
```

**Cause:** Script not downloaded or wrong directory

**Solution:**
```bash
# Ensure you're in the repository root
cd ~/clawdbot-security-playbook

# Verify script exists
ls -la scripts/verification/verify_openclaw_security.sh

# If missing, download from repository
curl -O https://raw.githubusercontent.com/YOUR-ORG/clawdbot-security-playbook/main/scripts/verification/verify_openclaw_security.sh

# Make executable
chmod +x scripts/verification/verify_openclaw_security.sh
```

---

### Issue: Permission Denied

**Symptom:**
```bash
$ ./scripts/verification/verify_openclaw_security.sh
bash: ./scripts/verification/verify_openclaw_security.sh: Permission denied
```

**Cause:** Script not executable

**Solution:**
```bash
# Add execute permission
chmod +x scripts/verification/verify_openclaw_security.sh

# Verify permissions
ls -la scripts/verification/verify_openclaw_security.sh
# Should show: -rwxr-xr-x
```

---

### Issue: Unsupported Platform

**Symptom:**
```bash
ERROR: Unsupported platform: MINGW64_NT
```

**Cause:** Running on Windows Git Bash or unsupported OS

**Solution:**
```bash
# Option 1: Use WSL2 (Windows Subsystem for Linux)
wsl --install
wsl
cd /mnt/c/Users/YourName/clawdbot-security-playbook
./scripts/verification/verify_openclaw_security.sh

# Option 2: Use PowerShell (limited support)
# Manual verification required - follow platform-specific guides

# Option 3: Use Docker
docker run -it --rm -v $(pwd):/workspace ubuntu:22.04 bash
cd /workspace
./scripts/verification/verify_openclaw_security.sh
```

---

## Layer 1: Credential Isolation Issues

### Issue: OS Keychain Not Detected

**Symptom:**
```
❌ FAIL: OS keychain not available or not configured
```

**Platform-Specific Solutions:**

#### macOS
```bash
# Verify Keychain Access is running
ps aux | grep "Keychain Access"

# Check security command
security -h

# Test keychain access
security find-generic-password -s test 2>&1

# If keychain is locked, unlock it
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

#### Linux
```bash
# Install libsecret (Debian/Ubuntu)
sudo apt-get update
sudo apt-get install -y libsecret-1-0 libsecret-tools

# Install libsecret (Fedora/RHEL)
sudo dnf install -y libsecret libsecret-devel

# Verify installation
secret-tool -h

# Check if gnome-keyring is running
ps aux | grep gnome-keyring

# If not running, start it
gnome-keyring-daemon --start

# Test secret storage
echo "test" | secret-tool store --label='Test Secret' service test account testuser
secret-tool lookup service test account testuser
secret-tool clear service test account testuser
```

#### Windows
```powershell
# Test Credential Manager access
Get-Command *Credential*

# Test creating a credential
$cred = New-Object System.Management.Automation.PSCredential("test", (ConvertTo-SecureString "password" -AsPlainText -Force))
$cred | Export-Clixml -Path "$env:TEMP\test-cred.xml"

# Clean up test
Remove-Item "$env:TEMP\test-cred.xml"
```

---

### Issue: Credentials Found in Config Files

**Symptom:**
```
❌ FAIL: Found potential API keys in config files:
~/.openclaw/config/gateway.yml: ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}
```

**Cause:** Credentials hardcoded in configuration files

**Solution:**
```bash
# 1. Remove credentials from config files
vim ~/.openclaw/config/gateway.yml
# Replace: ANTHROPIC_API_KEY=sk-ant-...
# With: ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

# 2. Store credentials in OS keychain
# macOS
security add-generic-password -a "$USER" -s "ai.openclaw.anthropic" -w "${ANTHROPIC_API_KEY}" -U

# Linux
echo "${ANTHROPIC_API_KEY}" | secret-tool store --label='Anthropic API Key' service ai.openclaw.anthropic account "$USER"

# Windows (PowerShell)
$apikey = ConvertTo-SecureString "${env:ANTHROPIC_API_KEY}" -AsPlainText -Force
New-Object System.Management.Automation.PSCredential("ai.openclaw.anthropic", $apikey) | Export-Clixml -Path "$env:LOCALAPPDATA\openclaw\credentials\anthropic.xml"

# Generate key if needed:
# openssl rand -base64 32

# 3. Verify credentials removed
grep -rE "(sk-ant-|sk-proj-|AKIA[0-9A-Z]{16})" ~/.openclaw/config/
# Should return no results

# 4. Verify credentials accessible from keychain
# macOS
security find-generic-password -a "$USER" -s "ai.openclaw.anthropic" -w

# Linux
secret-tool lookup service ai.openclaw.anthropic account "$USER"
```

---

### Issue: Backup Files Containing Credentials

**Symptom:**
```
❌ FAIL: Found backup files that may contain credentials:
~/.openclaw/config/.gateway.yml.swp
~/.openclaw/config/gateway.yml~
```

**Cause:** Editor backup files not cleaned up

**Solution:**
```bash
# 1. Find all backup files
find ~/.openclaw -type f \( \
    -name "*.swp" -o \
    -name "*.swo" -o \
    -name "*~" -o \
    -name "*.bak" -o \
    -name "*.backup" \
\)

# 2. Review each file for credentials
for file in $(find ~/.openclaw -type f -name "*~"); do
    echo "=== $file ==="
    grep -i "api.*key\|secret\|password\|token" "$file"
done

# 3. Securely delete backup files
# macOS/Linux
find ~/.openclaw -type f \( \
    -name "*.swp" -o \
    -name "*.swo" -o \
    -name "*~" -o \
    -name "*.bak" \
\) -exec shred -vfz -n 3 {} \;

# If shred not available (macOS)
find ~/.openclaw -type f \( \
    -name "*.swp" -o \
    -name "*~" \
\) -exec rm -P {} \;

# 4. Configure editor to not create backup files
# Vim - add to ~/.vimrc
echo "set nobackup" >> ~/.vimrc
echo "set nowritebackup" >> ~/.vimrc
echo "set noswapfile" >> ~/.vimrc

# Nano - add to ~/.nanorc
echo "set nobackup" >> ~/.nanorc

# VS Code - add to settings.json
echo '{"files.hotExit": "off"}' >> ~/.config/Code/User/settings.json
```

---

### Issue: Credentials in Environment Variables

**Symptom:**
```
❌ FAIL: Found credentials in environment variables
```

**Cause:** API keys exported directly in shell

**Solution:**
```bash
# 1. List current environment variables with credentials
env | grep -E "API.*KEY|SECRET|TOKEN|PASSWORD"

# 2. Remove from current session
unset ANTHROPIC_API_KEY
unset OPENAI_API_KEY
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY

# 3. Check shell configuration files
grep -r "API.*KEY\|SECRET\|TOKEN" ~/.bashrc ~/.bash_profile ~/.zshrc ~/.profile

# 4. Remove from shell config (example for ~/.bashrc)
vim ~/.bashrc
# Delete lines like: export ANTHROPIC_API_KEY=sk-ant-...

# 5. Use keychain-based environment loading instead
# Add to ~/.bashrc (macOS)
echo 'export ANTHROPIC_API_KEY=$(security find-generic-password -a "$USER" -s "ai.openclaw.anthropic" -w 2>/dev/null)' >> ~/.bashrc

# Add to ~/.bashrc (Linux)
echo 'export ANTHROPIC_API_KEY=$(secret-tool lookup service ai.openclaw.anthropic account "$USER" 2>/dev/null)' >> ~/.bashrc

# 6. Reload shell configuration
source ~/.bashrc
```

---

## Layer 2: Network Segmentation Issues

### Issue: Gateway Bound to 0.0.0.0

**Symptom:**
```
❌ FAIL: ClawdBot gateway is exposed on 0.0.0.0 (all interfaces)
```

**Cause:** Default configuration or misconfiguration

**Solution:**
```bash
# 1. Stop ClawdBot
pkill -f clawdbot
# Or for Docker
docker stop clawdbot-production

# 2. Edit configuration
vim ~/.openclaw/config/gateway.yml

# Change:
# bind:
#   address: "0.0.0.0"
# To:
# bind:
#   address: "127.0.0.1"

# 3. Restart ClawdBot
clawdbot start
# Or for Docker
docker start clawdbot-production

# 4. Verify binding
netstat -tulpn | grep 18789
# Should show: 127.0.0.1:18789 (not 0.0.0.0:18789)

# Alternative verification
lsof -i :18789 | grep LISTEN
```

---

### Issue: Gateway Accessible from External Network

**Symptom:**
```
❌ FAIL: Gateway is accessible from external network
Testing from: 192.168.1.100
```

**Cause:** Firewall not configured or misconfigured

**Solution:**

#### UFW (Ubuntu/Debian)
```bash
# 1. Check current firewall status
sudo ufw status

# 2. If inactive, enable it
sudo ufw --force enable

# 3. Block ClawdBot port from external access
sudo ufw deny 18789/tcp

# 4. Allow only from localhost
sudo ufw allow from 127.0.0.1 to any port 18789

# 5. If using VPN, allow VPN subnet
# Tailscale
sudo ufw allow from 100.64.0.0/10 to any port 18789

# WireGuard
sudo ufw allow from 10.0.0.0/24 to any port 18789

# 6. Reload firewall
sudo ufw reload

# 7. Verify rules
sudo ufw status numbered
```

#### firewalld (Fedora/RHEL/CentOS)
```bash
# 1. Check firewall status
sudo firewall-cmd --state

# 2. Block ClawdBot port
sudo firewall-cmd --permanent --remove-port=18789/tcp
sudo firewall-cmd --reload

# 3. Create rich rule for localhost only
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="127.0.0.1" port port="18789" protocol="tcp" accept'

# 4. If using VPN, add VPN subnet
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="100.64.0.0/10" port port="18789" protocol="tcp" accept'

# 5. Reload
sudo firewall-cmd --reload

# 6. Verify
sudo firewall-cmd --list-all
```

#### iptables (Advanced)
```bash
# 1. Drop all incoming to port 18789
sudo iptables -A INPUT -p tcp --dport 18789 -j DROP

# 2. Allow from localhost
sudo iptables -I INPUT -s 127.0.0.1 -p tcp --dport 18789 -j ACCEPT

# 3. Allow from VPN subnet
sudo iptables -I INPUT -s 100.64.0.0/10 -p tcp --dport 18789 -j ACCEPT

# 4. Save rules
# Ubuntu/Debian
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# RHEL/CentOS
sudo service iptables save

# 5. Verify
sudo iptables -L -n -v | grep 18789
```

#### macOS (pf)
```bash
# 1. Create pf rules file
sudo vim /etc/pf.anchors/clawdbot

# Add:
# block drop in proto tcp from any to any port 18789
# pass in proto tcp from 127.0.0.1 to any port 18789
# pass in proto tcp from 100.64.0.0/10 to any port 18789

# 2. Load anchor in main pf.conf
sudo vim /etc/pf.conf

# Add before the last line:
# anchor "clawdbot"
# load anchor "clawdbot" from "/etc/pf.anchors/clawdbot"

# 3. Enable and reload pf
sudo pfctl -e -f /etc/pf.conf

# 4. Verify
sudo pfctl -s rules | grep 18789
```

---

### Issue: No Authentication Configured

**Symptom:**
```
❌ FAIL: Gateway authentication is disabled or set to 'optional'
```

**Cause:** Authentication mode not set to "required"

**Solution:**
```bash
# 1. Edit gateway configuration
vim ~/.openclaw/config/gateway.yml

# 2. Set authentication to required
auth:
  mode: "required"  # Change from "none" or "optional"
  token:
    enabled: true
    secret: "${GATEWAY_TOKEN}"  # Use environment variable
    expiration: 3600

# 3. Generate secure token
export GATEWAY_TOKEN=$(openssl rand -base64 32)

# 4. Store token securely
# macOS
security add-generic-password -a "$USER" -s "ai.openclaw.gateway_token" -w "$GATEWAY_TOKEN" -U

# Linux
echo "$GATEWAY_TOKEN" | secret-tool store --label='Gateway Token' service ai.openclaw.gateway_token account "$USER"

# 5. Restart ClawdBot
clawdbot restart

# 6. Test authentication
# Should fail without token
curl http://localhost:18789/health

# Should succeed with token
curl -H "Authorization: Bearer $GATEWAY_TOKEN" http://localhost:18789/health
```

---

### Issue: Weak Gateway Token

**Symptom:**
```
⚠️  WARNING: Gateway token appears weak (length < 32 characters)
```

**Cause:** Token too short or predictable

**Solution:**
```bash
# 1. Generate strong token
NEW_TOKEN=$(openssl rand -base64 48)
echo "Generated token: $NEW_TOKEN"

# 2. Update configuration
vim ~/.openclaw/config/gateway.yml
# Set: secret: "${GATEWAY_TOKEN}"

# 3. Store in environment (for current session)
export GATEWAY_TOKEN="$NEW_TOKEN"

# 4. Store in keychain (persistent)
# macOS
security add-generic-password -a "$USER" -s "ai.openclaw.gateway_token" -w "$NEW_TOKEN" -U

# Linux
echo "$NEW_TOKEN" | secret-tool store --label='Gateway Token' service ai.openclaw.gateway_token account "$USER"

# 5. Update any clients/scripts using the old token

# 6. Restart ClawdBot
clawdbot restart

# 7. Verify new token works
TOKEN=$(security find-generic-password -a "$USER" -s "ai.openclaw.gateway_token" -w)
curl -H "Authorization: Bearer $TOKEN" http://localhost:18789/health
```

---

## Layer 3: Runtime Sandboxing Issues

### Issue: Container Running as Root

**Symptom:**
```
❌ FAIL: Container is running as root user
```

**Cause:** Docker container not configured with non-root user

**Solution:**
```bash
# 1. Stop current container
docker stop clawdbot-production
docker rm clawdbot-production

# 2. Option A: Use --user flag
docker run -d \
  --name clawdbot-production \
  --user 1000:1000 \
  --cap-drop ALL \
  --read-only \
  -p 127.0.0.1:18789:18789 \
  anthropic/clawdbot:latest

# 3. Option B: Modify Dockerfile (if building custom image)
cat > Dockerfile << 'EOF'
FROM anthropic/clawdbot:latest

# Create non-root user
RUN adduser --system --uid 1000 --group clawdbot

# Change ownership
RUN chown -R clawdbot:clawdbot /app

# Switch to non-root user
USER clawdbot

CMD ["clawdbot", "start"]
EOF

docker build -t clawdbot-secure:latest .
docker run -d --name clawdbot-production clawdbot-secure:latest

# 4. Verify user
docker exec clawdbot-production id
# Should show: uid=1000(clawdbot) gid=1000(clawdbot)
```

---

### Issue: Container Has Excessive Capabilities

**Symptom:**
```
❌ FAIL: Container has unnecessary capabilities: NET_RAW, SYS_ADMIN
```

**Cause:** Default Docker capabilities not dropped

**Solution:**
```bash
# 1. Stop container
docker stop clawdbot-production
docker rm clawdbot-production

# 2. Start with minimal capabilities
docker run -d \
  --name clawdbot-production \
  --user 1000:1000 \
  --cap-drop ALL \
  --cap-add NET_BIND_SERVICE \
  --security-opt no-new-privileges:true \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  -p 127.0.0.1:18789:18789 \
  anthropic/clawdbot:latest

# 3. Verify capabilities
docker inspect clawdbot-production --format='{{.HostConfig.CapDrop}}'
# Should show: [ALL]

docker inspect clawdbot-production --format='{{.HostConfig.CapAdd}}'
# Should show: [NET_BIND_SERVICE] or empty

# 4. Test that container still works
curl http://localhost:18789/health
```

---

### Issue: Root Filesystem is Writable

**Symptom:**
```
❌ FAIL: Container root filesystem is writable
```

**Cause:** Container not started with --read-only flag

**Solution:**
```bash
# 1. Stop container
docker stop clawdbot-production
docker rm clawdbot-production

# 2. Identify directories that need write access
docker run --rm anthropic/clawdbot:latest find /app -type d -perm -200

# 3. Start with read-only root and tmpfs for writable dirs
docker run -d \
  --name clawdbot-production \
  --user 1000:1000 \
  --cap-drop ALL \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /app/logs:rw,nosuid,size=500m \
  --tmpfs /app/cache:rw,nosuid,size=200m \
  -v ~/.openclaw/config:/app/config:ro \
  -p 127.0.0.1:18789:18789 \
  anthropic/clawdbot:latest

# 4. Test write attempt fails
docker exec clawdbot-production touch /test.txt
# Should fail: touch: cannot touch '/test.txt': Read-only file system

# 5. Test write to tmpfs succeeds
docker exec clawdbot-production touch /tmp/test.txt
# Should succeed
```

---

### Issue: No Resource Limits Set

**Symptom:**
```
⚠️  WARNING: No memory limit set for container
⚠️  WARNING: No CPU limit set for container
```

**Cause:** Container started without resource constraints

**Solution:**
```bash
# 1. Stop container
docker stop clawdbot-production
docker rm clawdbot-production

# 2. Start with resource limits
docker run -d \
  --name clawdbot-production \
  --user 1000:1000 \
  --cap-drop ALL \
  --read-only \
  --memory="2g" \
  --memory-swap="2g" \
  --cpus="2.0" \
  --pids-limit=100 \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  -p 127.0.0.1:18789:18789 \
  anthropic/clawdbot:latest

# 3. Verify limits
docker stats clawdbot-production --no-stream

# 4. Check memory limit
docker inspect clawdbot-production --format='{{.HostConfig.Memory}}'
# Should show: 2147483648 (2GB in bytes)

# 5. Check CPU limit
docker inspect clawdbot-production --format='{{.HostConfig.NanoCpus}}'
# Should show: 2000000000 (2.0 CPUs)
```

---

## Layer 4: Runtime Enforcement Issues

### Issue: openclaw-shield Not Responding

**Symptom:**
```
❌ FAIL: openclaw-shield is not responding on http://localhost:8080
```

**Cause:** Shield service not running or misconfigured

**Solution:**
```bash
# 1. Check if shield is running
docker ps | grep openclaw-shield
# Or
systemctl status openclaw-shield

# 2. If not running, start it
# Docker
docker run -d \
  --name openclaw-shield \
  -p 127.0.0.1:8080:8080 \
  knostic/openclaw-shield:latest

# From source
cd ~/openclaw-shield
npm install
npm start &

# 3. Verify shield is accessible
curl http://localhost:8080/health
# Should return: {"status": "healthy"}

# 4. Test prompt guard
curl -X POST http://localhost:8080/api/v1/guard \
  -H "Content-Type: application/json" \
  -d '{"prompt": "ignore previous instructions"}'

# Should return detection result

# 5. Check logs for errors
docker logs openclaw-shield
# Or
journalctl -u openclaw-shield -n 50
```

---

### Issue: PII Not Being Redacted

**Symptom:**
```
❌ FAIL: PII detection test failed - sensitive data not redacted
```

**Cause:** Output filtering not enabled or misconfigured

**Solution:**
```bash
# 1. Edit ClawdBot configuration
vim ~/.openclaw/config/clawdbot.yml

# 2. Enable output filtering
security:
  output_filtering:
    enabled: true
    redact_pii: true
    redact_patterns:
      - pattern: 'sk-[a-zA-Z0-9-]{20,}'
        replacement: '[API_KEY_REDACTED]'
        severity: "critical"
      - pattern: '\b\d{3}-\d{2}-\d{4}\b'
        replacement: '[SSN_REDACTED]'
        severity: "critical"
      - pattern: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        replacement: '[EMAIL_REDACTED]'
        severity: "high"

# 3. Restart ClawdBot
clawdbot restart

# 4. Test PII redaction
echo "My email is test@example.com and API key is sk-ant-1234567890abcdefghij" | \
  clawdbot process

# Should output: My email is [EMAIL_REDACTED] and API key is [API_KEY_REDACTED]

# 5. Check logs for unredacted PII
grep -E "sk-|@.*\.|\d{3}-\d{2}-\d{4}" ~/.openclaw/logs/*.log
# Should return no matches in recent logs
```

---

## Layer 5: Supply Chain Security Issues

### Issue: GPG Not Installed

**Symptom:**
```
❌ FAIL: GPG not installed or not in PATH
```

**Cause:** GnuPG not installed on system

**Solution:**
```bash
# macOS
brew install gnupg

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y gnupg2

# Fedora/RHEL
sudo dnf install -y gnupg2

# Verify installation
gpg --version

# Configure GPG (first time)
gpg --gen-key
# Follow prompts to create a key (optional for verification only)
```

---

### Issue: Skill Signature Verification Failed

**Symptom:**
```
❌ FAIL: Skill 'web-search' failed signature verification
gpg: Signature made Tue 13 Feb 2024 10:15:23 AM PST
gpg: using RSA key 1234567890ABCDEF
gpg: BAD signature from "Unknown"
```

**Cause:** Skill signature invalid or trusted key not imported

**Solution:**
```bash
# 1. Import the official Anthropic release key
curl -fsSL https://keys.anthropic.com/release-key.gpg | gpg --import

# Or download and verify manually
curl -fsSL https://keys.anthropic.com/release-key.gpg -o anthropic-key.gpg
gpg --import anthropic-key.gpg

# 2. Verify key fingerprint
gpg --fingerprint security@anthropic.com
# Compare with official fingerprint from Anthropic documentation

# 3. Trust the key
gpg --edit-key security@anthropic.com
# In GPG prompt:
# gpg> trust
# Select: 5 (Ultimate trust)
# gpg> quit

# 4. Re-verify skill signature
gpg --verify ~/.openclaw/skills/web-search/signature.asc ~/.openclaw/skills/web-search/skill.py

# Should show: Good signature

# 5. If signature is genuinely invalid, remove the skill
rm -rf ~/.openclaw/skills/web-search

# 6. Re-download from official source only
clawdbot skill install web-search --verify-signature
```

---

### Issue: Skill Integrity Check Failed

**Symptom:**
```
❌ FAIL: Skill integrity check failed for 'file-reader'
Expected: a1b2c3d4e5f6...
Actual:   f6e5d4c3b2a1...
```

**Cause:** Skill files have been modified

**Solution:**
```bash
# 1. Check what changed
cd ~/.openclaw/skills/file-reader
git diff  # If skill is a git repo

# 2. View modification times
find . -type f -exec stat -f "%Sm %N" -t "%Y-%m-%d %H:%M:%S" {} \;
# Linux: find . -type f -exec stat -c "%y %n" {} \;

# 3. Check for unauthorized modifications
grep -r "eval\|exec\|os.system" .

# 4. If modifications are unauthorized, restore from backup
rm -rf ~/.openclaw/skills/file-reader

# 5. Re-install from official source
clawdbot skill install file-reader --verify-signature

# 6. Update baseline manifest
python3 scripts/supply-chain/skill_manifest.py \
  --skills-dir ~/.openclaw/skills \
  --manifest ~/.openclaw/manifests/skills-baseline.json \
  --update

# 7. Set up monitoring for future changes
# macOS
fswatch -o ~/.openclaw/skills | xargs -n1 -I{} ./scripts/supply-chain/skill_manifest.py --check

# Linux
inotifywait -m -r -e modify,create,delete ~/.openclaw/skills | \
  while read; do
    python3 scripts/supply-chain/skill_manifest.py --check
  done
```

---

## Layer 6: Behavioral Monitoring Issues

### Issue: Metrics Endpoint Not Accessible

**Symptom:**
```
❌ FAIL: Prometheus metrics endpoint not accessible
curl: (7) Failed to connect to localhost port 9090
```

**Cause:** Metrics not enabled or port conflict

**Solution:**
```bash
# 1. Check if metrics are enabled
grep -A5 "metrics:" ~/.openclaw/config/clawdbot.yml

# 2. Enable metrics if disabled
vim ~/.openclaw/config/clawdbot.yml

monitoring:
  metrics:
    enabled: true
    endpoint: "/metrics"
    bind:
      address: "127.0.0.1"
      port: 9090

# 3. Check for port conflicts
lsof -i :9090
# Or
netstat -tulpn | grep 9090

# 4. If port is taken, use different port
# Change port to 9091 in config

# 5. Restart ClawdBot
clawdbot restart

# 6. Verify metrics endpoint
curl http://localhost:9090/metrics

# Should return Prometheus metrics format
```

---

### Issue: No Audit Logs Being Generated

**Symptom:**
```
❌ FAIL: No audit log entries found in last 24 hours
```

**Cause:** Audit logging not enabled or misconfigured

**Solution:**
```bash
# 1. Check audit logging configuration
grep -A10 "audit:" ~/.openclaw/config/clawdbot.yml

# 2. Enable audit logging
vim ~/.openclaw/config/clawdbot.yml

logging:
  components:
    audit:
      enabled: true
      log_path: "~/.openclaw/logs/audit.jsonl"
      events:
        - "user_login"
        - "credential_access"
        - "skill_install"
        - "config_change"
        - "tool_execution"
        - "auth_failure"

# 3. Ensure log directory exists and is writable
mkdir -p ~/.openclaw/logs
chmod 755 ~/.openclaw/logs

# 4. Restart ClawdBot
clawdbot restart

# 5. Trigger an auditable event
clawdbot skill list

# 6. Verify audit log was created
ls -la ~/.openclaw/logs/audit.jsonl
tail -f ~/.openclaw/logs/audit.jsonl

# 7. Check log format
cat ~/.openclaw/logs/audit.jsonl | jq .
# Should show valid JSON entries
```

---

## Layer 7: Organizational Controls Issues

### Issue: Compliance Policy Check Failed

**Symptom:**
```
⚠️  WARNING: SOC2 compliance requirements not fully met
- Missing: Data retention policy
- Missing: Encryption at rest configuration
```

**Cause:** Compliance settings not configured

**Solution:**
```bash
# 1. Edit compliance configuration
vim ~/.openclaw/config/clawdbot.yml

# 2. Add compliance settings
compliance:
  frameworks:
    soc2: true
    iso27001: true
    gdpr: true

  retention:
    logs: 90  # days
    audit: 365  # days (1 year for compliance)
    metrics: 30  # days

  data_residency:
    allowed_regions:
      - "us-east-1"
      - "us-west-2"
      - "eu-west-1"

  privacy:
    anonymize_ips: true
    minimize_data_collection: true
    enable_data_deletion: true

# 3. Set up log rotation with retention
sudo vim /etc/logrotate.d/openclaw

# Add:
/home/USER/.openclaw/logs/*.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0640 USER USER
}

# 4. Test log rotation
sudo logrotate -f /etc/logrotate.d/openclaw

# 5. Configure encryption at rest (if required)
# For logs on encrypted volume
sudo cryptsetup luksFormat /dev/sdX
sudo cryptsetup open /dev/sdX openclaw_logs
sudo mkfs.ext4 /dev/mapper/openclaw_logs
sudo mount /dev/mapper/openclaw_logs ~/.openclaw/logs

# 6. Document compliance measures
cat > ~/.openclaw/COMPLIANCE.md << 'EOF'
# Compliance Documentation

## SOC2 Type II
- Log retention: 90 days
- Audit retention: 365 days
- Encryption: AES-256 (at rest and in transit)
- Access control: OS keychain + MFA

## ISO 27001
- Risk assessment: Completed [DATE]
- Security controls: 7-layer defense-in-depth
- Incident response: Documented in docs/guides/06-incident-response.md

## GDPR
- Data minimization: Enabled
- Right to deletion: Implemented
- Data residency: EU-only option available
- Privacy by design: Default secure configuration
EOF
```

---

## Platform-Specific Issues

### macOS: Keychain Prompt on Every Access

**Symptom:**
Every credential access triggers a keychain unlock prompt

**Solution:**
```bash
# 1. Allow ClawdBot to always access the keychain entry
security set-generic-password-partition-list \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -S

# 2. Or set access control to allow app access
security add-generic-password \
  -a "$USER" \
  -s "ai.openclaw.anthropic" \
  -w "sk-ant-..." \
  -T /usr/local/bin/clawdbot \
  -T /usr/bin/security \
  -U

# 3. For Docker, keychain access requires host bind mount
# Not recommended - use environment variables for Docker
```

---

### Linux: Secret Service Not Available

**Symptom:**
```
ERROR: Secret service not available
org.freedesktop.Secret.Error.IsLocked: Cannot create an item in a locked collection
```

**Solution:**
```bash
# 1. Install and start gnome-keyring
sudo apt-get install gnome-keyring

# 2. Start keyring daemon
eval $(gnome-keyring-daemon --start)
export $(gnome-keyring-daemon --start --components=secrets)

# 3. Unlock keyring
echo -n "password" | gnome-keyring-daemon --unlock

# 4. Add to session startup
echo 'eval $(gnome-keyring-daemon --start)' >> ~/.bashrc

# 5. For headless systems, use alternative
# Install and use pass (password store) instead
sudo apt-get install pass
gpg --gen-key
pass init "your-gpg-key-id"

# 6. Store credentials with pass
pass insert anthropic/api_key
# Enter your API key when prompted

# 7. Retrieve with pass
pass show anthropic/api_key
```

---

### Windows: PowerShell Execution Policy

**Symptom:**
```
The file cannot be loaded because running scripts is disabled on this system
```

**Solution:**
```powershell
# 1. Check current execution policy
Get-ExecutionPolicy

# 2. Set to RemoteSigned (recommended) or Unrestricted
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 3. If administrative rights needed
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# 4. Verify change
Get-ExecutionPolicy

# 5. Sign your scripts (optional, for RemoteSigned)
$cert = New-SelfSignedCertificate -CertStoreLocation Cert:\CurrentUser\My -Type CodeSigning -Subject "CN=PowerShell Code Signing"
Set-AuthenticodeSignature -FilePath .\script.ps1 -Certificate $cert
```

---

## Getting Help

### Still Having Issues?

#### 1. **Enable Debug Logging**
```bash
# Edit configuration
vim ~/.openclaw/config/clawdbot.yml

# Set log level to DEBUG
logging:
  level: "DEBUG"

# Restart
clawdbot restart

# Watch logs
tail -f ~/.openclaw/logs/clawdbot.log
```

#### 2. **Run Verification in Verbose Mode**
```bash
./scripts/verification/verify_openclaw_security.sh --verbose
```

#### 3. **Collect Diagnostic Information**
```bash
# Create diagnostic report
cat > diagnostic_report.txt << EOF
=== System Information ===
OS: $(uname -a)
Shell: $SHELL
User: $(whoami)

=== ClawdBot Version ===
$(clawdbot --version 2>&1)

=== Docker Info ===
$(docker --version 2>&1)
$(docker ps 2>&1)

=== Network ===
$(netstat -tulpn | grep 18789 2>&1)

=== Keychain ===
$(security find-generic-password -s "ai.openclaw" -g 2>&1 || echo "Not macOS")
$(secret-tool search service ai.openclaw 2>&1 || echo "Not Linux with libsecret")

=== Recent Errors ===
$(tail -50 ~/.openclaw/logs/clawdbot.log 2>&1)
EOF

cat diagnostic_report.txt
```

#### 4. **Community Support**
- **GitHub Issues:** https://github.com/YOUR-ORG/clawdbot-security-playbook/issues
- **Discussions:** https://github.com/YOUR-ORG/clawdbot-security-playbook/discussions
- **Security Contact:** security@company.com (for security vulnerabilities)

#### 5. **Professional Support**
For enterprise deployments requiring professional support:
- **Email:** support@company.com
- **Slack:** #openclaw-security
- **Office Hours:** Tuesdays 2-4 PM EST

---

## Quick Reference: Common Commands

```bash
# Full security verification
./scripts/verification/verify_openclaw_security.sh --all

# Check specific layer
./scripts/verification/verify_openclaw_security.sh --layer 1  # Credentials
./scripts/verification/verify_openclaw_security.sh --layer 2  # Network
./scripts/verification/verify_openclaw_security.sh --layer 5  # Supply chain

# Fix credential issues
security add-generic-password -s "ai.openclaw.anthropic" -w "YOUR_KEY"

# Fix network binding
grep -r "0.0.0.0" ~/.openclaw/config/ && echo "FOUND - Change to 127.0.0.1"

# Fix firewall
sudo ufw deny 18789/tcp && sudo ufw allow from 127.0.0.1 to any port 18789

# Check container security
docker inspect clawdbot-production | jq '.[].HostConfig | {CapDrop, ReadonlyRootfs, SecurityOpt}'

# Verify skill integrity
python3 scripts/supply-chain/skill_manifest.py --check

# Check logs for issues
tail -100 ~/.openclaw/logs/clawdbot.log | grep -i "error\|fail\|warn"
```

---

**Last Updated:** February 14, 2026  
**Version:** 1.0.0  
**Related Guides:**
- [Quick Start Guide](../guides/01-quick-start.md)
- [Credential Isolation](../guides/02-credential-isolation.md)
- [Network Segmentation](../guides/03-network-segmentation.md)
- [Runtime Sandboxing](../guides/04-runtime-sandboxing.md)
- [Supply Chain Security](../guides/05-supply-chain-security.md)
- [Incident Response](../guides/06-incident-response.md)
