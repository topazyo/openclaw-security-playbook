# Credential Migration Scripts

Comprehensive automated migration tools for moving ClawdBot credentials from insecure storage locations to OS-native secure keychains.

---

## Overview

These scripts automate the complete migration of credentials from:
- ❌ **Configuration files** (YAML, JSON, ENV)
- ❌ **Environment variables** (shell RC files)
- ❌ **Running environment** (exported variables)

To:
- ✅ **macOS Keychain** (Hardware-backed encryption)
- ✅ **Linux Secret Service** (GNOME Keyring / KDE Wallet)

---

## Scripts

### 1. macOS Migration Script
**Location:** `scripts/credential-migration/macos/migrate_credentials_macos.sh`

**Features:**
- macOS Keychain integration with security command
- Support for Secure Enclave (hardware encryption)
- Touch ID integration capability
- Automatic credential detection in 10+ locations
- Comprehensive backup before migration
- Verification of successful migration
- Rollback capability
- Dry-run mode

**Requirements:**
- macOS 10.14+ (Mojave or later)
- `security` command-line tool (built-in)
- `jq` (install: `brew install jq`)

### 2. Linux Migration Script
**Location:** `scripts/credential-migration/linux/migrate_credentials_linux.sh`

**Features:**
- GNOME Keyring support (secret-tool)
- KDE Wallet support (kwalletcli)
- Auto-detection of available backend
- Secret Service API integration
- Automatic credential detection in 10+ locations
- Comprehensive backup before migration
- Verification of successful migration
- Rollback capability
- Dry-run mode

**Requirements:**
- Linux with Secret Service API
- `libsecret-tools` (GNOME) or `kwalletcli` (KDE)
- `jq` for JSON parsing

**Installation:**
```bash
# Debian/Ubuntu
sudo apt-get install gnome-keyring libsecret-tools jq

# Fedora/RHEL
sudo dnf install gnome-keyring libsecret jq

# Arch Linux
sudo pacman -S gnome-keyring libsecret jq
```

---

## Features Comparison

| Feature | macOS | Linux |
|---------|-------|-------|
| **Secure Storage** | Keychain | Secret Service |
| **Hardware Encryption** | Secure Enclave | TPM (if available) |
| **Backend Support** | 1 (Keychain) | 2 (GNOME/KDE) |
| **Credential Detection** | ✅ | ✅ |
| **Backup Creation** | ✅ | ✅ |
| **Verification** | ✅ | ✅ |
| **Rollback** | ✅ | ✅ |
| **Dry-Run Mode** | ✅ | ✅ |
| **Cleanup** | ✅ | ✅ |
| **Logging** | ✅ | ✅ |
| **Color Output** | ✅ | ✅ |
| **Auto-Detection** | ✅ | ✅ |

---

## Detection Capabilities

Both scripts detect credentials in:

### File Locations
- `~/.openclaw/**/*.{yml,yaml,json,conf,env}`
- `~/.config/openclaw/**/*.{yml,yaml,json,conf,env}`
- `~/.clawdbot/**/*.{yml,yaml,json,conf,env}`

### Environment Files
- `~/.bashrc`
- `~/.bash_profile`
- `~/.zshrc`
- `~/.zprofile`
- `~/.profile`

### Credential Types
- ✅ Anthropic API keys (`sk-ant-...`)
- ✅ OpenAI API keys (`sk-...`)
- ✅ AWS credentials (`AKIA...`)
- ✅ GitHub tokens (`ghp_...`)
- ✅ Slack tokens (`xoxb-...`)
- ✅ Custom patterns (extensible)

---

## Usage

### Basic Usage

#### macOS
```bash
# Dry run (see what will be migrated)
./scripts/credential-migration/macos/migrate_credentials_macos.sh --dry-run

# Full migration
./scripts/credential-migration/macos/migrate_credentials_macos.sh

# Verbose migration
./scripts/credential-migration/macos/migrate_credentials_macos.sh --verbose

# Force migration (skip confirmations)
./scripts/credential-migration/macos/migrate_credentials_macos.sh --force
```

#### Linux
```bash
# Dry run (see what will be migrated)
./scripts/credential-migration/linux/migrate_credentials_linux.sh --dry-run

# Full migration
./scripts/credential-migration/linux/migrate_credentials_linux.sh

# Verbose migration
./scripts/credential-migration/linux/migrate_credentials_linux.sh --verbose

# Specify backend explicitly
./scripts/credential-migration/linux/migrate_credentials_linux.sh --backend gnome
```

### Advanced Usage

#### Backup Only
```bash
# Create backup without migrating
./migrate_credentials_*.sh --backup-only
```

#### Migration Without Cleanup
```bash
# Migrate but keep old credentials (for testing)
./migrate_credentials_*.sh --no-cleanup
```

#### Rollback
```bash
# Restore from most recent backup
./migrate_credentials_*.sh --rollback
```

#### Combination
```bash
# Verbose, force, no cleanup
./migrate_credentials_*.sh --verbose --force --no-cleanup
```

---

## Command-Line Options

### Common Options (Both Platforms)

| Option | Description |
|--------|-------------|
| `--dry-run` | Show what would be migrated without making changes |
| `--backup-only` | Create backups without migrating |
| `--skip-backup` | Skip backup creation (⚠️ not recommended) |
| `--no-cleanup` | Don't remove credentials from old locations |
| `--force` | Skip all confirmation prompts |
| `--verbose` | Enable verbose output with detailed logging |
| `--rollback` | Restore from most recent backup |
| `--help` | Show help message with examples |

### Linux-Specific Options

| Option | Description |
|--------|-------------|
| `--backend BACKEND` | Specify keyring backend: `gnome`, `kde`, or `auto` |

---

## Migration Process

### Step-by-Step Flow

```
1. Pre-Flight Checks
   ├─ Verify OS version
   ├─ Check required tools
   └─ Validate keychain/keyring access

2. Credential Detection
   ├─ Scan configuration files
   ├─ Scan environment files
   └─ Check running environment

3. Backup Creation
   ├─ Copy all configuration files
   ├─ Copy all environment files
   ├─ Create manifest.json
   └─ Set restrictive permissions (700)

4. Migration to Keychain/Keyring
   ├─ For each detected credential:
   │  ├─ Check if already exists
   │  ├─ Store in secure keychain
   │  └─ Log migration status
   └─ Generate migration report

5. Verification
   ├─ Test retrieval of each credential
   └─ Confirm successful migration

6. Cleanup (Optional)
   ├─ Remove credentials from config files
   ├─ Remove credentials from env files
   └─ Keep .bak files for safety

7. Reporting
   ├─ Generate detailed report
   ├─ Log all actions
   └─ Provide next steps
```

---

## Output Examples

### Successful Migration

```
========================================
ClawdBot Credential Migration for macOS
Version: 1.0.0
========================================

ℹ INFO: Checking requirements...
✓ SUCCESS: All requirements met (macOS 14.2)
ℹ INFO: Checking Keychain access...
✓ SUCCESS: Keychain access verified
ℹ INFO: Scanning configuration files for credentials...
⚠ WARNING: Found credential in: /Users/user/.openclaw/config/gateway.yml
ℹ INFO: Found 3 credential(s) to migrate
ℹ INFO: Creating backup of current credentials...
✓ SUCCESS: Backup created: ~/.openclaw/backups/credentials/credentials_backup_20260214_142630

⚠ WARNING: This will migrate credentials to the macOS Keychain
Continue? [y/N] y

ℹ INFO: Processing detected credentials...
✓ SUCCESS: Migrated: ai.openclaw.anthropic
✓ SUCCESS: Migrated: ai.openclaw.openai
✓ SUCCESS: Migrated: ai.openclaw.github
ℹ INFO: Migration complete: 3/3 successful, 0 failed

ℹ INFO: Verifying migrated credentials...
✓ SUCCESS: All credentials verified (3/3)

ℹ INFO: Cleaning up old credential storage...
✓ SUCCESS: Cleaned: /Users/user/.openclaw/config/gateway.yml
✓ SUCCESS: Cleaned: /Users/user/.bashrc

✓ SUCCESS: Migration complete!
ℹ INFO: Backup location: ~/.openclaw/backups/credentials/credentials_backup_20260214_142630
ℹ INFO: Log file: ~/.openclaw/logs/credential_migration_20260214_142630.log
```

### Dry Run Output

```
ℹ INFO: Found 3 credential(s) to migrate
ℹ INFO: [DRY RUN] Would migrate: ai.openclaw.anthropic for account user (from ~/.openclaw/config/gateway.yml)
ℹ INFO: [DRY RUN] Would migrate: ai.openclaw.openai for account user (from ~/.bashrc)
ℹ INFO: [DRY RUN] Would migrate: ai.openclaw.github for account user (from environment)
ℹ INFO: [DRY RUN] Would clean up old credentials
```

---

## Generated Files

### Backup Structure
```
~/.openclaw/backups/credentials/credentials_backup_YYYYMMDD_HHMMSS/
├── manifest.json
├── .openclaw/
│   └── config/
│       ├── gateway.yml
│       └── clawdbot.yml
├── .bashrc
├── .zshrc
└── .profile
```

### manifest.json Example
```json
{
  "timestamp": "2026-02-14T14:26:30Z",
  "hostname": "macbook-pro",
  "user": "username",
  "backup_name": "credentials_backup_20260214_142630",
  "script_version": "1.0.0"
}
```

### Log Files
```
~/.openclaw/logs/
├── credential_migration_20260214_142630.log    (Detailed log)
└── migration_report_20260214_142630.txt        (Summary report)
```

### Migration Report Example
```
================================================================================
ClawdBot Credential Migration Report
================================================================================

Date: Wed Feb 14 14:26:30 IST 2026
User: username
Hostname: macbook-pro
Script Version: 1.0.0

SUMMARY
------------------------------------------------------------------------
Dry Run: No
Backup Created: Yes
Cleanup Performed: Yes

CREDENTIALS FOUND
------------------------------------------------------------------------
3

FILE|/Users/user/.openclaw/config/gateway.yml|sk-ant-1234...
ENV|/Users/user/.bashrc|ANTHROPIC_API_KEY|sk-ant-1234...
RUNENV|GITHUB_TOKEN|ghp_5678...

MIGRATION RESULTS
------------------------------------------------------------------------
SUCCESS|ai.openclaw.anthropic|/Users/user/.openclaw/config/gateway.yml
SUCCESS|ai.openclaw.openai|/Users/user/.bashrc
SUCCESS|ai.openclaw.github|environment

NEXT STEPS
------------------------------------------------------------------------
1. Update ClawdBot configuration to use keychain:
   credentials:
     storage: "os_keychain"

2. Test credential access:
   security find-generic-password -s "ai.openclaw.anthropic" -w

3. Review backup location:
   ~/.openclaw/backups/credentials/credentials_backup_20260214_142630

4. Review full log:
   ~/.openclaw/logs/credential_migration_20260214_142630.log
```

---

## Post-Migration Steps

### 1. Update ClawdBot Configuration

Edit `~/.openclaw/config/clawdbot.yml`:

```yaml
credentials:
  # Change from: storage: "file" or "environment"
  # To:
  storage: "os_keychain"

  keychain:
    service_prefix: "ai.openclaw"
    account: "${USER}"
```

### 2. Test Credential Access

#### macOS
```bash
# Test retrieval
security find-generic-password -s "ai.openclaw.anthropic" -w

# Test with ClawdBot
clawdbot config test-credentials
```

#### Linux
```bash
# Test retrieval
secret-tool lookup service ai.openclaw.anthropic account "$USER"

# Test with ClawdBot
clawdbot config test-credentials
```

### 3. Verify Migration

Run the security verification script:
```bash
./scripts/verification/verify_openclaw_security.sh --layer 1
```

Expected output:
```
✓ PASS: OS keychain available and configured
✓ PASS: No credentials found in config files
✓ PASS: No credentials found in environment files
```

### 4. Delete Old Backup Files (Optional)

After confirming everything works:
```bash
# Review backups
ls -la ~/.openclaw/backups/credentials/

# Delete old backups (keep latest)
rm -rf ~/.openclaw/backups/credentials/credentials_backup_YYYYMMDD_HHMMSS
```

---

## Troubleshooting

### macOS Issues

#### Issue: Keychain Prompt on Every Access
**Solution:**
```bash
# Allow ClawdBot to always access the credential
security set-generic-password-partition-list \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -S
```

#### Issue: "security: SecKeychainItemCreateFromContent: User interaction is not allowed"
**Solution:**
```bash
# Unlock keychain first
security unlock-keychain ~/Library/Keychains/login.keychain-db
```

### Linux Issues

#### Issue: "org.freedesktop.Secret.Error.IsLocked"
**Solution:**
```bash
# Start and unlock gnome-keyring
eval $(gnome-keyring-daemon --start)
export $(gnome-keyring-daemon --start --components=secrets)
```

#### Issue: "Cannot find secret service"
**Solution:**
```bash
# Install required packages
sudo apt-get install gnome-keyring libsecret-tools

# Start gnome-keyring
gnome-keyring-daemon --start
```

#### Issue: KDE Wallet not accessible
**Solution:**
```bash
# Check if kwalletd is running
pgrep kwalletd5

# Start if not running
kwalletd5 &

# Install kwalletcli if missing
sudo apt-get install kwalletcli
```

### General Issues

#### Issue: "No credentials found to migrate"
**Cause:** Credentials already in keychain or not in standard locations

**Solution:**
```bash
# Check if already migrated
security find-generic-password -s "ai.openclaw" (macOS)
secret-tool search service ai.openclaw (Linux)

# Specify custom search paths (edit script)
CONFIG_DIRS=(
    "$HOME/.openclaw"
    "$HOME/custom/path"
)
```

#### Issue: Migration fails partway through
**Solution:**
```bash
# Use rollback to restore original state
./migrate_credentials_*.sh --rollback

# Review log for errors
tail -50 ~/.openclaw/logs/credential_migration_*.log

# Fix issues and retry
./migrate_credentials_*.sh --verbose
```

---

## Security Considerations

### Backup Security
- ✅ Backups stored with 700 permissions (owner-only)
- ✅ Files within backups have 600 permissions
- ✅ Backups contain plaintext credentials (secure deletion recommended)
- ✅ Automatic backup on every migration

### Credential Storage
- ✅ macOS Keychain uses hardware encryption (Secure Enclave)
- ✅ Linux Secret Service uses OS-level encryption
- ✅ Credentials never written to disk in plaintext (after migration)
- ✅ Access controlled by OS authentication

### Cleanup Safety
- ✅ Original files backed up as `.bak`
- ✅ Verification before cleanup
- ✅ Optional cleanup (can be skipped)
- ✅ Rollback available

### Best Practices
1. ✅ Always use `--dry-run` first
2. ✅ Never use `--skip-backup` in production
3. ✅ Review migration report
4. ✅ Test credential access after migration
5. ✅ Securely delete old backups after verification
6. ✅ Keep logs for audit trail

---

## Integration with Security Playbook

These migration scripts are part of **Layer 1: Credential Isolation** in the ClawdBot Security Playbook.

### Related Documentation
- [Credential Isolation Guide](../../docs/guides/02-credential-isolation.md)
- [Quick Start Guide](../../docs/guides/01-quick-start.md)
- [Verification Failures](../../docs/troubleshooting/verification-failures.md)

### Verification
Run full security verification after migration:
```bash
./scripts/verification/verify_openclaw_security.sh --all
```

---

## Contributing

### Adding Support for New Credential Types

Edit the `patterns` array in either script:

```bash
# Add new pattern
local patterns=(
    'sk-ant-[a-zA-Z0-9_-]{20,}'
    'your-custom-pattern-here'
)
```

### Adding Support for New Locations

Edit the `CONFIG_DIRS` array:

```bash
CONFIG_DIRS=(
    "$HOME/.openclaw"
    "$HOME/.custom/location"
)
```

---

## Version History

### v1.0.0 (2026-02-14)
- ✅ Initial release
- ✅ macOS Keychain support
- ✅ Linux Secret Service support (GNOME/KDE)
- ✅ Multi-location credential detection
- ✅ Backup and rollback capability
- ✅ Comprehensive logging and reporting

---

## License

Part of the ClawdBot Security Playbook
See: [../../LICENSE](../../LICENSE)

---

## Support

For issues or questions:
- **GitHub Issues:** https://github.com/YOUR-ORG/clawdbot-security-playbook/issues
- **Documentation:** docs/guides/02-credential-isolation.md
- **Troubleshooting:** docs/troubleshooting/verification-failures.md

---

**Last Updated:** February 14, 2026  
**Script Versions:** macOS v1.0.0 | Linux v1.0.0
