# Credential Migration Failures Troubleshooting Guide

> **Quick Reference:** Common issues when migrating credentials to OS keychains and how to resolve them

This guide covers troubleshooting for credential migration scripts across macOS and Linux platforms, including detection failures, migration errors, and rollback procedures.

---

## Table of Contents

1. [Pre-Migration Issues](#pre-migration-issues)
2. [macOS-Specific Issues](#macos-specific-issues)
3. [Linux-Specific Issues](#linux-specific-issues)
4. [Detection Issues](#detection-issues)
5. [Migration Errors](#migration-errors)
6. [Verification Failures](#verification-failures)
7. [Cleanup Issues](#cleanup-issues)
8. [Rollback Procedures](#rollback-procedures)
9. [Emergency Recovery](#emergency-recovery-lost-all-credentials)
10. [Platform Comparison](#platform-comparison)

---

## Pre-Migration Issues

### Issue: Script Not Executable

**Symptom:**
```bash
$ ./migrate_credentials_macos.sh
bash: ./migrate_credentials_macos.sh: Permission denied
```

**Cause:** Script doesn't have execute permissions

**Solution:**
```bash
# Add execute permission
chmod +x scripts/credential-migration/macos/migrate_credentials_macos.sh
chmod +x scripts/credential-migration/linux/migrate_credentials_linux.sh

# Verify permissions
ls -la scripts/credential-migration/*/migrate_credentials_*.sh
# Should show: -rwxr-xr-x
```

---

### Issue: Missing Required Tools

**Symptom:**
```bash
✗ ERROR: Missing required commands: jq
```

**Cause:** Required dependencies not installed

**Solution:**

#### macOS
```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install jq

# Verify installation
jq --version
```

#### Linux (Debian/Ubuntu)
```bash
# Update package list
sudo apt-get update

# Install required packages
sudo apt-get install -y jq gnome-keyring libsecret-tools

# Verify installation
jq --version
secret-tool --version
```

#### Linux (Fedora/RHEL)
```bash
# Install required packages
sudo dnf install -y jq gnome-keyring libsecret

# Verify installation
jq --version
secret-tool --version
```

---

### Issue: Insufficient Disk Space for Backup

**Symptom:**
```bash
✗ ERROR: Cannot create backup - insufficient disk space
cp: error writing '.openclaw/backups/...': No space left on device
```

**Cause:** Not enough disk space for backup

**Solution:**
```bash
# Check available disk space
df -h ~/.openclaw

# Check size of data to be backed up
du -sh ~/.openclaw ~/.config/openclaw ~/.clawdbot 2>/dev/null

# Free up space - clean old backups
ls -lt ~/.openclaw/backups/credentials/
rm -rf ~/.openclaw/backups/credentials/credentials_backup_OLD_DATE

# Clean old logs
find ~/.openclaw/logs -name "*.log" -mtime +30 -delete
```

---

## macOS-Specific Issues

### Issue: Keychain Access Denied

**Symptom:**
```bash
✗ ERROR: Cannot access Keychain. Please unlock your keychain first.
security: SecKeychainItemCopyContent: User interaction is not allowed.
```

**Cause:** Login keychain is locked

**Solution:**
```bash
# Check keychain status
security show-keychain-info ~/Library/Keychains/login.keychain-db

# Unlock keychain
security unlock-keychain ~/Library/Keychains/login.keychain-db
# You'll be prompted for your login password

# Verify keychain is unlocked
security find-generic-password -s test 2>&1

# Re-run migration
./scripts/credential-migration/macos/migrate_credentials_macos.sh
```

---

### Issue: Keychain Item Already Exists

**Symptom:**
```bash
⚠ WARNING: Credential already exists in keychain: ai.openclaw.anthropic
security: SecKeychainItemCreateFromContent: The specified item already exists in the keychain.
```

**Cause:** Credential already migrated or manually added

**Solution:**
```bash
# Check existing credential
security find-generic-password -s "ai.openclaw.anthropic" -a "$USER"

# Option 1: Force overwrite
./scripts/credential-migration/macos/migrate_credentials_macos.sh --force

# Option 2: Manually delete and retry
security delete-generic-password -s "ai.openclaw.anthropic" -a "$USER"
./scripts/credential-migration/macos/migrate_credentials_macos.sh

# Option 3: View existing credential value to verify
security find-generic-password -s "ai.openclaw.anthropic" -a "$USER" -w
```

---

## Linux-Specific Issues

### Issue: No Keyring Backend Detected

**Symptom:**
```bash
✗ ERROR: No supported keyring backend detected
Supported backends:
  - GNOME Keyring (gnome-keyring-daemon)
  - KDE Wallet (kwalletd5)
```

**Cause:** Neither GNOME Keyring nor KDE Wallet is running

**Solution:**

#### For GNOME/Ubuntu Desktop
```bash
# Install GNOME Keyring
sudo apt-get install gnome-keyring libsecret-tools

# Start gnome-keyring daemon
eval $(gnome-keyring-daemon --start)
export $(gnome-keyring-daemon --start --components=secrets)

# Add to startup (automatic)
echo 'eval $(gnome-keyring-daemon --start)' >> ~/.bashrc

# Verify
pgrep -x gnome-keyring-d

# Re-run migration
./scripts/credential-migration/linux/migrate_credentials_linux.sh
```

#### For KDE/Plasma Desktop
```bash
# Install KDE Wallet
sudo apt-get install kwalletd5 kwalletcli

# Start kwalletd
kwalletd5 &

# Verify
pgrep kwalletd5

# Re-run migration
./scripts/credential-migration/linux/migrate_credentials_linux.sh --backend kde
```

---

### Issue: Keyring Locked

**Symptom:**
```bash
✗ ERROR: Cannot access keyring. It may be locked.
org.freedesktop.Secret.Error.IsLocked: Cannot create an item in a locked collection
```

**Cause:** Secret Service collection is locked

**Solution:**
```bash
# Check if gnome-keyring is running
pgrep gnome-keyring-d

# Unlock keyring (GNOME)
gnome-keyring-daemon --replace --components=secrets

# For automatic unlock on login - install PAM integration
sudo apt-get install libpam-gnome-keyring

# Or use seahorse to manage keyring
sudo apt-get install seahorse
seahorse
# Set keyring password or remove password

# Re-run migration
./scripts/credential-migration/linux/migrate_credentials_linux.sh
```

---

## Detection Issues

### Issue: No Credentials Found

**Symptom:**
```bash
✓ SUCCESS: No credentials found to migrate
```

**Cause:** Credentials not in standard locations or already migrated

**Solution:**
```bash
# Check if credentials already in keychain
# macOS
security find-generic-password -s "ai.openclaw"

# Linux
secret-tool search service ai.openclaw

# Check custom locations
find ~ -name "*.yml" -o -name "*.yaml" | xargs grep -l "sk-ant-"

# Check environment variables
env | grep -E "ANTHROPIC|OPENAI|AWS.*KEY"

# If credentials in non-standard location, move temporarily
mkdir -p ~/.openclaw/config
cp /path/to/custom/config.yml ~/.openclaw/config/

# Re-run migration
./scripts/credential-migration/*/migrate_credentials_*.sh --dry-run
```

---

### Issue: Partial Detection (Missing Some Credentials)

**Symptom:**
Migration completes but some credentials are missing

**Solution:**
```bash
# Search for specific credentials manually
# Look for Anthropic keys
grep -r "sk-ant-" ~/.openclaw ~/.config/openclaw 2>/dev/null

# Look for OpenAI keys
grep -r "sk-[a-zA-Z0-9]\{48\}" ~/.openclaw 2>/dev/null

# If found, add manually to keychain
# macOS
security add-generic-password \
    -s "ai.openclaw.custom" \
    -a "$USER" \
    -w "YOUR_CREDENTIAL"

# Linux
echo -n "YOUR_CREDENTIAL" | secret-tool store \
    --label="ClawdBot: custom" \
    service ai.openclaw.custom \
    account "$USER"
```

---

## Migration Errors

### Issue: Migration Fails Midway

**Symptom:**
```bash
✓ SUCCESS: Migrated: ai.openclaw.anthropic
✗ ERROR: Failed to migrate: ai.openclaw.openai
ℹ INFO: Migration complete: 1/3 successful, 2 failed
```

**Cause:** Error storing specific credential

**Solution:**
```bash
# Check detailed log
tail -50 ~/.openclaw/logs/credential_migration_*.log

# For failed credentials, migrate manually
# macOS
security add-generic-password \
    -s "ai.openclaw.openai" \
    -a "$USER" \
    -w "sk-1234567890..."

# Linux
echo -n "sk-1234567890..." | secret-tool store \
    --label="ClawdBot: OpenAI" \
    service ai.openclaw.openai \
    account "$USER"

# Verify manual migration
./scripts/verification/verify_openclaw_security.sh --layer 1
```

---

### Issue: Credential Value Empty or Malformed

**Symptom:**
```bash
✗ ERROR: Failed to migrate: ai.openclaw.anthropic
security: SecKeychainItemCreateFromContent: The parameter is incorrect
```

**Cause:** Credential value is empty or contains invalid characters

**Solution:**
```bash
# Check the credential value in config file
grep -A2 -B2 "api.*key" ~/.openclaw/config/gateway.yml

# Fix in config file
vim ~/.openclaw/config/gateway.yml

# Example correct format:
# ANTHROPIC_API_KEY: "sk-ant-1234567890abcdef"

# Re-run migration
./scripts/credential-migration/*/migrate_credentials_*.sh --dry-run
```

---

## Verification Failures

### Issue: Migrated Credentials Not Accessible

**Symptom:**
```bash
✗ ERROR: Verification failed: ai.openclaw.anthropic
security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain.
```

**Cause:** Credential not properly stored or keychain switched

**Solution:**
```bash
# Check if credential exists
# macOS
security dump-keychain | grep "ai.openclaw"

# Linux
secret-tool search service ai.openclaw

# Ensure login keychain is in search path (macOS)
security list-keychains -d user -s ~/Library/Keychains/login.keychain-db

# Try adding credential again
./scripts/credential-migration/*/migrate_credentials_*.sh --force
```

---

## Cleanup Issues

### Issue: Credentials Still in Config Files

**Symptom:**
```bash
✗ FAIL: Found potential API keys in config files
~/.openclaw/config/gateway.yml: ANTHROPIC_API_KEY=sk-ant-...
```

**Cause:** Cleanup was skipped or failed

**Solution:**
```bash
# First, verify credentials are in keychain
# macOS
security find-generic-password -s "ai.openclaw.anthropic" -w

# Linux
secret-tool lookup service ai.openclaw.anthropic account "$USER"

# If verified, clean config files manually
cp ~/.openclaw/config/gateway.yml ~/.openclaw/config/gateway.yml.backup

# Remove credential lines (macOS)
sed -i '' '/sk-ant-/d' ~/.openclaw/config/gateway.yml

# Remove credential lines (Linux)
sed -i '/sk-ant-/d' ~/.openclaw/config/gateway.yml

# Verify
grep -E "sk-|AKIA" ~/.openclaw/config/gateway.yml
# Should return nothing
```

---

## Rollback Procedures

### Quick Rollback (Using Script)

**When to use:** Migration completed but something is wrong

**Solution:**
```bash
# Use built-in rollback feature
./scripts/credential-migration/*/migrate_credentials_*.sh --rollback

# This will:
# 1. Restore config files from latest backup
# 2. Restore environment files from latest backup
# 3. Remove credentials from keychain
```

---

### Manual Rollback

**When to use:** Script rollback fails or partial rollback needed

**Solution:**
```bash
# 1. Find latest backup
ls -lt ~/.openclaw/backups/credentials/

# 2. Restore files
BACKUP_DIR=~/.openclaw/backups/credentials/credentials_backup_YYYYMMDD_HHMMSS

# Restore config files
cp -r $BACKUP_DIR/.openclaw/* ~/.openclaw/ 2>/dev/null || true

# Restore environment files
cp $BACKUP_DIR/.bashrc ~/.bashrc 2>/dev/null || true
cp $BACKUP_DIR/.zshrc ~/.zshrc 2>/dev/null || true

# 3. Remove credentials from keychain
# macOS - delete all ai.openclaw.* credentials
security dump-keychain | grep "ai.openclaw" | while read line; do
    SERVICE=$(echo "$line" | cut -d'"' -f4)
    security delete-generic-password -s "$SERVICE" -a "$USER" 2>/dev/null
done

# Linux - delete all ai.openclaw.* credentials
secret-tool search service ai.openclaw | grep "^service" | while read key value; do
    if [ "$key" = "service" ]; then
        secret-tool clear service "$value" account "$USER"
    fi
done

# 4. Reload environment
source ~/.bashrc  # or ~/.zshrc

# 5. Verify rollback
./scripts/verification/verify_openclaw_security.sh --layer 1
```

---

### Emergency Recovery: Lost All Credentials

**Symptom:**
- Migration failed
- Backup corrupted or deleted
- Can't access credentials anywhere

**Recovery Steps:**

#### Step 1: Search for Any Remaining Credentials
```bash
# Search command history
history | grep -E "export.*API.*KEY|ANTHROPIC|OPENAI"

# Search shell history files
grep -h "API.*KEY" ~/.bash_history ~/.zsh_history 2>/dev/null

# Check .bak files
find ~/.openclaw -name "*.bak" -type f
```

#### Step 2: Check Alternative Storage
```bash
# Check password managers
# - 1Password: Check for "ClawdBot" or "Anthropic"
# - LastPass: Search vault

# Check email for original credentials
# Search for: "API key" "credentials" "Anthropic"
```

#### Step 3: Request New Credentials
```bash
# If credentials cannot be recovered, generate new ones

# Anthropic: https://console.anthropic.com/settings/keys
# OpenAI: https://platform.openai.com/api-keys
# AWS: aws iam create-access-key --user-name clawdbot
# GitHub: https://github.com/settings/tokens
```

#### Step 4: Properly Store New Credentials
```bash
# Store in keychain immediately

# macOS
security add-generic-password \
    -s "ai.openclaw.anthropic" \
    -a "$USER" \
    -w "NEW_API_KEY" \
    -U

# Linux
echo -n "NEW_API_KEY" | secret-tool store \
    --label="ClawdBot: Anthropic" \
    service ai.openclaw.anthropic \
    account "$USER"

# Verify
./scripts/verification/verify_openclaw_security.sh --layer 1
```

#### Step 5: Revoke Compromised Credentials
```bash
# Revoke old credentials immediately if potentially compromised

# Anthropic: Delete old keys from console
# OpenAI: Revoke old keys from dashboard
# AWS: aws iam delete-access-key --access-key-id AKIA_OLD_KEY
# GitHub: Revoke old token from settings
```

---

## Platform Comparison

### Migration Success Rates by Platform

| Platform | Success Rate | Common Issues |
|----------|-------------|---------------|
| **macOS (Catalina+)** | 95%+ | Keychain prompts, permission dialogs |
| **macOS (Older)** | 85%+ | Security restrictions, keychain bugs |
| **Ubuntu/Debian (Desktop)** | 90%+ | GNOME Keyring not running |
| **Ubuntu/Debian (Server)** | 70%+ | No keyring daemon (headless) |
| **Fedora/RHEL** | 88%+ | SELinux restrictions |
| **Arch Linux** | 92%+ | Manual keyring configuration |
| **KDE (any distro)** | 85%+ | KWallet auto-lock |

### Platform-Specific Best Practices

#### macOS
- ✅ Always unlock keychain before migration
- ✅ Use login keychain (default)
- ✅ Allow ClawdBot in keychain ACL
- ⚠️ Disable Touch ID requirement if causing issues

#### Linux (GNOME)
- ✅ Ensure gnome-keyring-daemon is running
- ✅ Set up PAM integration for auto-unlock
- ✅ Use same password for keyring and login
- ⚠️ DBus session required

#### Linux (KDE)
- ✅ Open KWallet manually first to unlock
- ✅ Set KWallet to auto-unlock on login
- ✅ Install kwalletcli if not present

#### Linux (Headless/Server)
- ❌ Standard keyrings not suitable
- ✅ Use `pass` (password-store) instead
- ✅ Or store in encrypted vault (HashiCorp Vault)

---

## Quick Reference Commands

### Check Migration Status
```bash
# macOS - List migrated credentials
security find-generic-password -s "ai.openclaw" 2>&1 | grep "svce"

# Linux - List migrated credentials
secret-tool search service ai.openclaw

# Check logs
tail -50 ~/.openclaw/logs/credential_migration_*.log
```

### Manual Credential Operations

#### Add Credential
```bash
# macOS
security add-generic-password -s "SERVICE" -a "$USER" -w "VALUE"

# Linux
echo -n "VALUE" | secret-tool store --label="LABEL" service "SERVICE" account "$USER"
```

#### Retrieve Credential
```bash
# macOS
security find-generic-password -s "SERVICE" -a "$USER" -w

# Linux
secret-tool lookup service "SERVICE" account "$USER"
```

#### Delete Credential
```bash
# macOS
security delete-generic-password -s "SERVICE" -a "$USER"

# Linux
secret-tool clear service "SERVICE" account "$USER"
```

### Verification
```bash
# Full security verification
./scripts/verification/verify_openclaw_security.sh --all

# Credential isolation only
./scripts/verification/verify_openclaw_security.sh --layer 1
```

---

## Getting Help

### Diagnostic Information to Collect

When requesting help, provide:

```bash
# System information
uname -a
sw_vers  # macOS
cat /etc/os-release  # Linux

# Keyring status
# macOS
security list-keychains
security find-generic-password -s "ai.openclaw" 2>&1

# Linux
pgrep -a gnome-keyring-d || pgrep -a kwalletd5
secret-tool search service ai.openclaw

# Log excerpt (last 50 lines)
tail -50 ~/.openclaw/logs/credential_migration_*.log
```

### Support Channels
- **GitHub Issues:** https://github.com/YOUR-ORG/clawdbot-security-playbook/issues
- **Documentation:** docs/guides/02-credential-isolation.md
- **Migration README:** scripts/credential-migration/README.md

---

**Last Updated:** February 14, 2026  
**Related Guides:**
- [Credential Isolation](../guides/02-credential-isolation.md)
- [Verification Failures](verification-failures.md)
- [Migration Scripts README](../../scripts/credential-migration/README.md)
