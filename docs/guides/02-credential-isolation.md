# Credential Isolation Guide

**Layer 1 of 7-Layer Defense-in-Depth Model**

**Estimated Time:** 30 minutes  
**Difficulty:** Intermediate  
**Prerequisites:** Basic understanding of operating system security

This guide covers OS-level credential isolation to prevent plaintext credential exposure, the #1 attack vector in AI agent compromises.

## Table of Contents

1. [The Problem: Plaintext Credentials](#the-problem-plaintext-credentials)
2. [OS Keychain Architecture](#os-keychain-architecture)
3. [macOS Implementation](#macos-implementation)
4. [Linux Implementation](#linux-implementation)
5. [Windows Implementation](#windows-implementation)
6. [OpenClaw Configuration](#openclaw-configuration)
7. [Backup File Management](#backup-file-management)
8. [Verification and Testing](#verification-and-testing)
9. [Emergency Response](#emergency-response)

---

## The Problem: Plaintext Credentials

### Attack Vector: Backup File Persistence

**Scenario:**
```bash
# Developer stores API key in config
$ echo "anthropic_api_key: sk-ant-api03-..." > credentials.yml

# Later, they "rotate" the key
$ vim credentials.yml  # Update to new key

# But the editor created a backup
$ ls -a
credentials.yml
credentials.yml~      # ← OLD KEY STILL HERE
.credentials.yml.swp  # ← VIM SWAP FILE
```

**Impact:**
- Old credentials remain harvestable
- Text editors create 5+ backup file types
- Deleting files doesn't overwrite data
- File recovery tools can restore old versions

### Real-World Incident

In 2023-2024, researchers found **1,200+ exposed AI agent instances** with:
- Backup files containing rotated credentials
- Plaintext API keys in git history
- Credentials in container environment variables
- Old keys valid for 90+ days after "rotation"

**Result:** Full credential exfiltration despite rotation efforts

---

## OS Keychain Architecture

### How OS Keychains Work

```
┌─────────────────────────────────────────┐
│        Application (ClawdBot)           │
│   Requests: "Get anthropic_api_key"     │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│         OS Keychain Service             │
│  • Encrypted storage                    │
│  • User authentication required         │
│  • No plaintext files                   │
│  • Hardware-backed encryption (TPM/     │
│    Secure Enclave)                      │
└────────────────┬────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────┐
│      Encrypted Keychain Database        │
│   /Library/Keychains/login.keychain-db  │
│   (Binary format, encrypted at rest)    │
└─────────────────────────────────────────┘
```

**Benefits:**
- ✅ No plaintext files (no backup file risk)
- ✅ User authentication for access
- ✅ Hardware encryption (Secure Enclave/TPM)
- ✅ Audit logging
- ✅ Per-application access control

---

## macOS Implementation

### Step 1: Store Credentials in Keychain

```bash
# Anthropic API Key
security add-generic-password \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -w "sk-ant-api03-YOUR-KEY-HERE" \
  -T /usr/local/bin/clawdbot \
  -T /Applications/ClawdBot.app/Contents/MacOS/clawdbot

# OpenAI API Key
security add-generic-password \
  -s "ai.openclaw.openai" \
  -a "$USER" \
  -w "sk-proj-YOUR-KEY-HERE" \
  -T /usr/local/bin/clawdbot

# AWS Credentials
security add-generic-password \
  -s "ai.openclaw.aws.access_key" \
  -a "$USER" \
  -w "AKIAIOSFODNN7EXAMPLE" \
  -T /usr/local/bin/clawdbot

security add-generic-password \
  -s "ai.openclaw.aws.secret_key" \
  -a "$USER" \
  -w "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
  -T /usr/local/bin/clawdbot
```

**Parameters Explained:**
- `-s`: Service name (identifier for the credential)
- `-a`: Account name (usually your username)
- `-w`: Password/secret (the actual credential)
- `-T`: Trusted application (which apps can access without prompt)

### Step 2: Verify Storage

```bash
# List all OpenClaw credentials
security find-generic-password -s "ai.openclaw.anthropic"

# Output:
# keychain: "/Users/yourname/Library/Keychains/login.keychain-db"
# class: "genp"
# attributes:
#     "acct"<blob>="yourname"
#     "svce"<blob>="ai.openclaw.anthropic"
# ...
```

### Step 3: Retrieve Credentials (Test)

```bash
# Get credential value
security find-generic-password \
  -s "ai.openclaw.anthropic" \
  -w

# Output: sk-ant-api03-YOUR-KEY-HERE
```

**First time:** macOS will prompt for keychain password

### Step 4: Configure Application Access

```bash
# Allow access without user interaction
security set-generic-password-partition-list \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -S

# Enter your keychain password when prompted
```

### Step 5: Require Touch ID (Optional, Recommended)

```bash
# Add Touch ID requirement for high-sensitivity credentials
security add-generic-password \
  -s "ai.openclaw.anthropic.production" \
  -a "$USER" \
  -w "sk-ant-api03-PROD-KEY" \
  -T /usr/local/bin/clawdbot \
  -U  # ← Requires biometric authentication
```

---

## Linux Implementation

Linux uses **Secret Service** (libsecret) for credential management.

### Step 1: Install Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install libsecret-1-0 libsecret-tools
```

**Fedora/RHEL:**
```bash
sudo dnf install libsecret
```

**Arch:**
```bash
sudo pacman -S libsecret
```

### Step 2: Verify Secret Service is Running

```bash
# Check for gnome-keyring or KWallet
ps aux | grep -E 'gnome-keyring|kwalletd'

# If not running, start it (GNOME)
gnome-keyring-daemon --start --components=secrets

# Or for KDE
kwalletd5 &
```

### Step 3: Store Credentials

```bash
# Anthropic API Key
secret-tool store \
  --label="OpenClaw Anthropic API Key" \
  service ai.openclaw.anthropic \
  username $USER \
  environment production
# Paste your API key when prompted

# OpenAI API Key
secret-tool store \
  --label="OpenClaw OpenAI API Key" \
  service ai.openclaw.openai \
  username $USER \
  environment production
```

### Step 4: Verify Storage

```bash
# List credentials
secret-tool search service ai.openclaw.anthropic

# Output:
# [/org/freedesktop/secrets/collection/login/1]
# label = OpenClaw Anthropic API Key
# secret = sk-ant-api03-YOUR-KEY-HERE
# ...
```

### Step 5: Retrieve Credentials (Test)

```bash
# Get credential
secret-tool lookup \
  service ai.openclaw.anthropic \
  username $USER \
  environment production

# Output: sk-ant-api03-YOUR-KEY-HERE
```

### Step 6: Automatic Unlocking (Optional)

For headless servers, you can create an unencrypted keyring:

**⚠️ WARNING:** This reduces security but enables automation

```bash
# Create unencrypted keyring (use only on secure servers)
dbus-run-session -- bash << 'EOF'
echo -n "default" | gnome-keyring-daemon --unlock
EOF

# Store credential
secret-tool store \
  --label="OpenClaw Anthropic API Key (Auto)" \
  service ai.openclaw.anthropic \
  username $USER \
  environment production \
  keyring default
```

**Better Alternative:** Use environment-based secrets for servers:
- AWS Secrets Manager
- HashiCorp Vault
- Kubernetes Secrets

---

## Windows Implementation

Windows uses **Credential Manager** for secure credential storage.

### Step 1: Store Credentials via Command Line

```powershell
# Anthropic API Key
cmdkey /generic:openclaw_anthropic /user:$env:USERNAME /pass:"sk-ant-api03-YOUR-KEY-HERE"

# OpenAI API Key
cmdkey /generic:openclaw_openai /user:$env:USERNAME /pass:"sk-proj-YOUR-KEY-HERE"

# AWS Access Key
cmdkey /generic:openclaw_aws_access /user:$env:USERNAME /pass:"AKIAIOSFODNN7EXAMPLE"

# AWS Secret Key
cmdkey /generic:openclaw_aws_secret /user:$env:USERNAME /pass:"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

### Step 2: Verify in Credential Manager

```powershell
# List credentials
cmdkey /list | findstr openclaw

# Output:
# Target: LegacyGeneric:target=openclaw_anthropic
# Type: Generic
# User: youruser
```

**Or use GUI:**
1. Press `Win + R`
2. Type: `control /name Microsoft.CredentialManager`
3. Click "Windows Credentials"
4. Verify "Generic Credentials" section

### Step 3: Retrieve Credentials (PowerShell)

```powershell
# Load credential
$cred = cmdkey /list | findstr openclaw_anthropic

# For programmatic access, use Windows API
Add-Type -AssemblyName System.Security
$credMan = New-Object System.Net.NetworkCredential("", "")
$credMan.Password = (cmdkey /generic:openclaw_anthropic /user:$env:USERNAME)
```

### Step 4: Using .NET CredentialManager

For better integration, use `CredentialManagement` library:

```powershell
# Install library
Install-Package CredentialManagement -Scope CurrentUser

# C# code to retrieve (in ClawdBot)
using CredentialManagement;

var cm = new Credential();
cm.Target = "openclaw_anthropic";
cm.Type = CredentialType.Generic;

if (cm.Load())
{
    string apiKey = cm.Password;
    // Use apiKey
}
```

---

## OpenClaw Configuration

### Configure ClawdBot to Use OS Keychain

Create `~/.openclaw/config/credentials.yml`:

```yaml
credentials:
  # Use OS keychain instead of plaintext files
  storage: "os_keychain"

  # Fallback to environment variables if keychain fails
  fallback: "environment"

  keychain:
    # Service name prefix
    service_prefix: "ai.openclaw"

    # Provider configurations
    providers:
      anthropic:
        service: "ai.openclaw.anthropic"
        account: "${USER}"
        required: true

      openai:
        service: "ai.openclaw.openai"
        account: "${USER}"
        required: false

      aws:
        service: "ai.openclaw.aws"
        access_key_service: "ai.openclaw.aws.access_key"
        secret_key_service: "ai.openclaw.aws.secret_key"
        account: "${USER}"
        required: false

  # Platform-specific settings
  platform:
    macos:
      use_secure_enclave: true
      require_touch_id: false  # Set to true for high security
      keychain_path: "~/Library/Keychains/login.keychain-db"

    linux:
      backend: "libsecret"  # or "kwallet" for KDE
      unlock_timeout: 3600  # seconds

    windows:
      use_dpapi: true  # Data Protection API

  # Security policies
  rotation:
    require_rotation_days: 90
    warn_before_expiry_days: 7

  audit:
    log_access: true
    log_path: "~/.openclaw/logs/credential-access.log"
```

### Environment Variable Fallback (Optional)

For CI/CD or containerized environments:

```bash
# .env file (for non-production only)
OPENCLAW_ANTHROPIC_API_KEY=sk-ant-api03-...
OPENCLAW_OPENAI_API_KEY=sk-proj-...

# Configure fallback
cat >> ~/.openclaw/config/credentials.yml << 'EOF'

  environment:
    anthropic_key: "OPENCLAW_ANTHROPIC_API_KEY"
    openai_key: "OPENCLAW_OPENAI_API_KEY"
EOF
```

---

## Backup File Management

### The Backup File Problem

Text editors create backup files automatically:

| Editor | Backup File Patterns |
|--------|---------------------|
| Vim | `*.swp`, `*.swo`, `.*.swp`, `*~` |
| Emacs | `*~`, `#*#` |
| Nano | `.*.swp` |
| VS Code | `.vscode/*`, `*.code-workspace~` |
| Sublime | `*.sublime-*` |
| macOS | `.DS_Store` |
| Windows | `Thumbs.db`, `desktop.ini` |

### Step 1: Find Existing Backup Files

```bash
# Comprehensive search
find ~/.openclaw ~/.clawdbot ~/.moltbot ~/clawd \
  -type f \( \
    -name "*.bak*" -o \
    -name "*~" -o \
    -name "*.swp" -o \
    -name "*.swo" -o \
    -name ".*.swp" -o \
    -name "#*#" -o \
    -name "credentials*.yml" -o \
    -name "secrets*.yml" -o \
    -name ".env*" \
  \) 2>/dev/null

# Check git history
cd ~/.openclaw
git log --all --full-history -- '*credentials*' '*secrets*' '*.env*'
```

### Step 2: Secure Deletion

**⚠️ CRITICAL:** Rotate credentials BEFORE deleting backups

```bash
# 1. FIRST: Rotate all credentials at providers
# - Anthropic: https://console.anthropic.com/settings/keys
# - OpenAI: https://platform.openai.com/api-keys
# - AWS: https://console.aws.amazon.com/iam/

# 2. THEN: Securely delete backups (3-pass overwrite)
find ~/.openclaw -name "*.bak*" -type f -exec shred -vfz -n 3 {} \;

# For entire directory
shred -vfz -n 3 ~/.openclaw/old_config/*
```

**Explanation:**
- `shred`: Overwrites file data
- `-v`: Verbose output
- `-f`: Force (change permissions if needed)
- `-z`: Final overwrite with zeros
- `-n 3`: 3 passes (DoD 5220.22-M standard)

### Step 3: Configure .gitignore

Prevent credentials from entering git:

```bash
cat >> ~/.openclaw/.gitignore << 'EOF'
# Credentials (never commit)
credentials.yml
secrets.yml
.env
.env.*
*.key
*.pem
*.p12

# Backup files
*.bak
*.bak.*
*~
*.swp
*.swo
.*.swp
#*#

# Logs (may contain credentials)
logs/
*.log
EOF

git add .gitignore
git commit -m "Add gitignore for credentials"
```

### Step 4: git-secrets Integration

Install git-secrets to prevent credential commits:

```bash
# Install
git clone https://github.com/awslabs/git-secrets
cd git-secrets
sudo make install

# Configure for repository
cd ~/.openclaw
git secrets --install
git secrets --register-aws

# Add custom patterns
git secrets --add 'sk-ant-api03-[A-Za-z0-9]{93}'  # Anthropic keys
git secrets --add 'sk-proj-[A-Za-z0-9]{48}'        # OpenAI keys
git secrets --add 'AKIA[0-9A-Z]{16}'               # AWS access keys

# Scan existing history
git secrets --scan-history
```

---

## Verification and Testing

### Test 1: Verify Keychain Storage

**macOS:**
```bash
security find-generic-password -s "ai.openclaw.anthropic" -w
# Should output your API key
```

**Linux:**
```bash
secret-tool lookup service ai.openclaw.anthropic username $USER
# Should output your API key
```

**Windows:**
```powershell
cmdkey /list | findstr openclaw_anthropic
# Should show credential entry
```

### Test 2: Verify No Plaintext Files

```bash
# Search for plaintext credentials
grep -r "sk-ant-api03" ~/.openclaw/ 2>/dev/null
grep -r "sk-proj" ~/.openclaw/ 2>/dev/null
grep -r "AKIA" ~/.openclaw/ 2>/dev/null

# Expected: No matches (empty output)
```

### Test 3: Application Access

```bash
# Start ClawdBot with keychain configuration
clawdbot start --config ~/.openclaw/config/credentials.yml

# Check logs for keychain access
tail -f ~/.openclaw/logs/clawdbot.log | grep -i keychain

# Expected: "Loaded credentials from OS keychain"
```

### Test 4: Backup File Cleanup

```bash
# Verify no backup files remain
find ~/.openclaw -name "*.bak*" -o -name "*~" -o -name "*.swp"

# Expected: Empty output
```

---

## Emergency Response

### Scenario: Credentials Exposed

**Immediate Actions (First 5 Minutes):**

1. **Rotate compromised credentials immediately:**
   ```bash
   # Generate new API key at provider
   # Update keychain with new key
   security delete-generic-password -s "ai.openclaw.anthropic"
   security add-generic-password -s "ai.openclaw.anthropic" -a "$USER" -w "NEW-KEY"
   ```

2. **Revoke old credentials:**
   - Anthropic: https://console.anthropic.com/settings/keys → Revoke
   - OpenAI: https://platform.openai.com/api-keys → Revoke
   - AWS: IAM Console → Deactivate access key

3. **Check for unauthorized usage:**
   ```bash
   # Anthropic usage logs
   curl https://api.anthropic.com/v1/usage \
     -H "x-api-key: $NEW_API_KEY"

   # Look for:
   # - Unusual timestamps
   # - Unexpected IP addresses
   # - High token usage
   ```

### Investigation Checklist

- [ ] Identify exposure vector (backup file, git history, logs)
- [ ] Determine exposure timeline
- [ ] Review audit logs for credential access
- [ ] Check provider usage logs for unauthorized activity
- [ ] Document findings for incident report
- [ ] Update security procedures to prevent recurrence

---

## Best Practices

1. **Never store credentials in plaintext files**
   - Use OS keychain exclusively
   - Environment variables only for CI/CD

2. **Rotate credentials regularly**
   - Set reminders for 90-day rotation
   - Use provider rotation features where available

3. **Monitor for backup files**
   - Run weekly scans: `find ~/.openclaw -name "*.bak*"`
   - Set up automated alerts

4. **Use separate credentials per environment**
   - Development: Limited permissions
   - Staging: Read-only production access
   - Production: Full permissions, audit logged

5. **Enable audit logging**
   - Log all keychain access attempts
   - Forward logs to SIEM
   - Alert on unusual access patterns

---

## Related Guides

- **Quick Start:** [01-quick-start.md](01-quick-start.md)
- **Network Segmentation:** [03-network-segmentation.md](03-network-segmentation.md)
- **Incident Response:** [06-incident-response.md](06-incident-response.md)

---

**Last Updated:** February 14, 2026  
**Tested On:** macOS 14.0+, Ubuntu 22.04+, Windows 11
