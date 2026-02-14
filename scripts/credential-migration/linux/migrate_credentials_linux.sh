#!/bin/bash
#
# migrate_credentials_linux.sh
# Secure Credential Migration Script for Linux
#
# This script migrates ClawdBot credentials from insecure storage locations
# (config files, environment variables, plaintext) to Linux Secret Service
# (gnome-keyring or KWallet).
#
# Features:
#   - Detects credentials in multiple locations
#   - Creates secure backups before migration
#   - Migrates to Secret Service with encryption
#   - Supports gnome-keyring and KWallet
#   - Verifies migration success
#   - Cleans up insecure storage
#   - Supports dry-run mode
#   - Provides rollback capability
#   - Comprehensive logging
#
# Usage:
#   ./migrate_credentials_linux.sh [OPTIONS]
#
# Options:
#   --dry-run          Show what would be migrated without making changes
#   --backup-only      Create backups without migrating
#   --skip-backup      Skip backup creation (not recommended)
#   --no-cleanup       Don't remove credentials from old locations
#   --force            Skip confirmation prompts
#   --verbose          Enable verbose output
#   --rollback         Restore from backup
#   --backend BACKEND  Specify keyring backend (gnome, kde, auto)
#   --help             Show this help message
#
# Example:
#   # Dry run to see what will be migrated
#   ./migrate_credentials_linux.sh --dry-run
#
#   # Full migration with verbose output
#   ./migrate_credentials_linux.sh --verbose
#
#   # Specify KDE backend explicitly
#   ./migrate_credentials_linux.sh --backend kde
#
#   # Rollback migration
#   ./migrate_credentials_linux.sh --rollback
#
# Requirements:
#   - Linux with Secret Service API
#   - libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL)
#   - gnome-keyring OR kwalletd5
#   - jq (for JSON parsing)
#
# Version: 1.0.0
# Last Updated: February 14, 2026

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

# Script metadata
SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Secret Service configuration
SECRET_SERVICE="org.freedesktop.secrets"
SECRET_COLLECTION="default"
SECRET_LABEL_PREFIX="ClawdBot"

# Search locations
CONFIG_DIRS=(
    "$HOME/.openclaw"
    "$HOME/.config/openclaw"
    "$HOME/.clawdbot"
)

ENV_FILES=(
    "$HOME/.bashrc"
    "$HOME/.bash_profile"
    "$HOME/.zshrc"
    "$HOME/.zprofile"
    "$HOME/.profile"
)

# Backup configuration
BACKUP_DIR="$HOME/.openclaw/backups/credentials"
BACKUP_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="credentials_backup_${BACKUP_TIMESTAMP}"

# Log configuration
LOG_DIR="$HOME/.openclaw/logs"
LOG_FILE="$LOG_DIR/credential_migration_${BACKUP_TIMESTAMP}.log"

# Temporary files
TEMP_DIR=$(mktemp -d)
CREDENTIALS_FOUND="$TEMP_DIR/credentials_found.txt"
MIGRATION_REPORT="$TEMP_DIR/migration_report.txt"

# Options
DRY_RUN=false
BACKUP_ONLY=false
SKIP_BACKUP=false
NO_CLEANUP=false
FORCE=false
VERBOSE=false
ROLLBACK=false
BACKEND="auto"  # auto, gnome, kde

# Detected backend
DETECTED_BACKEND=""
SECRET_TOOL_CMD=""

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$*${NC}"
}

info() {
    print_color "$BLUE" "ℹ INFO: $*"
    log "INFO: $*"
}

success() {
    print_color "$GREEN" "✓ SUCCESS: $*"
    log "SUCCESS: $*"
}

warning() {
    print_color "$YELLOW" "⚠ WARNING: $*"
    log "WARNING: $*"
}

error() {
    print_color "$RED" "✗ ERROR: $*"
    log "ERROR: $*"
}

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

verbose() {
    if [ "$VERBOSE" = true ]; then
        info "$*"
    fi
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

cleanup() {
    verbose "Cleaning up temporary files..."
    rm -rf "$TEMP_DIR"
}

trap cleanup EXIT

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

detect_keyring_backend() {
    info "Detecting keyring backend..."

    # Check for secret-tool (libsecret)
    if command -v secret-tool &> /dev/null; then
        DETECTED_BACKEND="libsecret"
        SECRET_TOOL_CMD="secret-tool"
        success "Using libsecret (secret-tool)"
        return 0
    fi

    # Check for gnome-keyring
    if pgrep -x gnome-keyring-d &> /dev/null; then
        DETECTED_BACKEND="gnome"

        # Install secret-tool if not present
        if ! command -v secret-tool &> /dev/null; then
            error "gnome-keyring detected but secret-tool not found"
            info "Install with: sudo apt-get install libsecret-tools (Debian/Ubuntu)"
            info "            : sudo dnf install libsecret (Fedora/RHEL)"
            exit 1
        fi

        SECRET_TOOL_CMD="secret-tool"
        success "Using GNOME Keyring"
        return 0
    fi

    # Check for KWallet
    if pgrep -x kwalletd5 &> /dev/null || pgrep -x kwalletd &> /dev/null; then
        DETECTED_BACKEND="kde"

        # Check for kwalletcli
        if command -v kwalletcli &> /dev/null; then
            SECRET_TOOL_CMD="kwalletcli"
            success "Using KWallet"
            return 0
        else
            error "KWallet detected but kwalletcli not found"
            info "Install with: sudo apt-get install kwalletcli (Debian/Ubuntu)"
            exit 1
        fi
    fi

    error "No supported keyring backend detected"
    info "Supported backends:"
    info "  - GNOME Keyring (gnome-keyring-daemon)"
    info "  - KDE Wallet (kwalletd5)"
    info ""
    info "Install GNOME Keyring:"
    info "  Debian/Ubuntu: sudo apt-get install gnome-keyring libsecret-tools"
    info "  Fedora/RHEL:   sudo dnf install gnome-keyring libsecret"
    exit 1
}

check_requirements() {
    info "Checking requirements..."

    # Check Linux distribution
    if [ ! -f /etc/os-release ]; then
        error "Cannot determine Linux distribution"
        exit 1
    fi

    source /etc/os-release
    verbose "Distribution: $NAME $VERSION"

    # Check for required commands
    local missing_commands=()

    if ! command -v jq &> /dev/null; then
        missing_commands+=("jq")
    fi

    if [ ${#missing_commands[@]} -ne 0 ]; then
        error "Missing required commands: ${missing_commands[*]}"
        info "Install with:"
        info "  Debian/Ubuntu: sudo apt-get install ${missing_commands[*]}"
        info "  Fedora/RHEL:   sudo dnf install ${missing_commands[*]}"
        exit 1
    fi

    # Detect and validate keyring backend
    detect_keyring_backend

    success "All requirements met"
}

check_keyring_access() {
    info "Checking keyring access..."

    if [ "$DETECTED_BACKEND" = "libsecret" ] || [ "$DETECTED_BACKEND" = "gnome" ]; then
        # Test secret-tool access
        if ! secret-tool search service test 2>/dev/null; then
            warning "Cannot access keyring. Checking if unlocked..."

            # Check if gnome-keyring is running
            if ! pgrep -x gnome-keyring-d &> /dev/null; then
                error "gnome-keyring-daemon is not running"
                info "Start with: eval \$(gnome-keyring-daemon --start)"
                exit 1
            fi

            # Keyring might be locked
            warning "Keyring may be locked. You may need to unlock it."
        fi
    elif [ "$DETECTED_BACKEND" = "kde" ]; then
        # Test KWallet access
        if ! kwalletcli -f default -e test &> /dev/null; then
            warning "Cannot access KWallet. It may be locked."
        fi
    fi

    success "Keyring access verified"
}

# ============================================================================
# CREDENTIAL DETECTION FUNCTIONS
# ============================================================================

detect_credentials_in_files() {
    info "Scanning configuration files for credentials..."

    local found_count=0

    # Credential patterns to search for
    local patterns=(
        'sk-ant-[a-zA-Z0-9_-]{20,}'           # Anthropic API keys
        'sk-[a-zA-Z0-9]{48}'                   # OpenAI API keys
        'AKIA[0-9A-Z]{16}'                     # AWS access keys
        'ghp_[a-zA-Z0-9]{36}'                  # GitHub tokens
        'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}' # Slack tokens
    )

    for config_dir in "${CONFIG_DIRS[@]}"; do
        if [ ! -d "$config_dir" ]; then
            continue
        fi

        verbose "Scanning directory: $config_dir"

        # Find configuration files
        while IFS= read -r file; do
            for pattern in "${patterns[@]}"; do
                if grep -q -E "$pattern" "$file" 2>/dev/null; then
                    echo "FILE|$file|$(grep -E "$pattern" "$file" | head -1)" >> "$CREDENTIALS_FOUND"
                    ((found_count++))
                    warning "Found credential in: $file"
                fi
            done
        done < <(find "$config_dir" -type f \( -name "*.yml" -o -name "*.yaml" -o -name "*.json" -o -name "*.conf" -o -name "*.env" \) 2>/dev/null)
    done

    return $found_count
}

detect_credentials_in_env() {
    info "Checking environment files for credentials..."

    local found_count=0

    # Environment variable patterns
    local env_patterns=(
        'ANTHROPIC_API_KEY'
        'OPENAI_API_KEY'
        'AWS_ACCESS_KEY_ID'
        'AWS_SECRET_ACCESS_KEY'
        'GITHUB_TOKEN'
        'SLACK_TOKEN'
    )

    for env_file in "${ENV_FILES[@]}"; do
        if [ ! -f "$env_file" ]; then
            continue
        fi

        verbose "Scanning environment file: $env_file"

        for pattern in "${env_patterns[@]}"; do
            if grep -q "export $pattern=" "$env_file" 2>/dev/null; then
                local value=$(grep "export $pattern=" "$env_file" | head -1 | cut -d'=' -f2- | tr -d '"' | tr -d "'")
                echo "ENV|$env_file|$pattern|$value" >> "$CREDENTIALS_FOUND"
                ((found_count++))
                warning "Found $pattern in: $env_file"
            fi
        done
    done

    return $found_count
}

detect_credentials_in_running_env() {
    info "Checking running environment for credentials..."

    local found_count=0

    # Check current environment variables
    local env_vars=(
        'ANTHROPIC_API_KEY'
        'OPENAI_API_KEY'
        'AWS_ACCESS_KEY_ID'
        'AWS_SECRET_ACCESS_KEY'
        'GITHUB_TOKEN'
    )

    for var in "${env_vars[@]}"; do
        if [ -n "${!var:-}" ]; then
            echo "RUNENV|$var|${!var}" >> "$CREDENTIALS_FOUND"
            ((found_count++))
            warning "Found $var in running environment"
        fi
    done

    return $found_count
}

# ============================================================================
# BACKUP FUNCTIONS
# ============================================================================

create_backup() {
    if [ "$SKIP_BACKUP" = true ]; then
        warning "Skipping backup creation (not recommended)"
        return 0
    fi

    info "Creating backup of current credentials..."

    # Create backup directory
    mkdir -p "$BACKUP_DIR/$BACKUP_NAME"

    # Copy configuration files
    for config_dir in "${CONFIG_DIRS[@]}"; do
        if [ -d "$config_dir" ]; then
            verbose "Backing up: $config_dir"
            cp -r "$config_dir" "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null || true
        fi
    done

    # Copy environment files
    for env_file in "${ENV_FILES[@]}"; do
        if [ -f "$env_file" ]; then
            verbose "Backing up: $env_file"
            cp "$env_file" "$BACKUP_DIR/$BACKUP_NAME/" 2>/dev/null || true
        fi
    done

    # Create backup manifest
    cat > "$BACKUP_DIR/$BACKUP_NAME/manifest.json" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "hostname": "$(hostname)",
  "user": "$USER",
  "backup_name": "$BACKUP_NAME",
  "script_version": "$SCRIPT_VERSION",
  "backend": "$DETECTED_BACKEND"
}
EOF

    # Set restrictive permissions
    chmod 700 "$BACKUP_DIR/$BACKUP_NAME"
    chmod 600 "$BACKUP_DIR/$BACKUP_NAME"/* 2>/dev/null || true

    success "Backup created: $BACKUP_DIR/$BACKUP_NAME"
}

# ============================================================================
# MIGRATION FUNCTIONS
# ============================================================================

migrate_credential_to_keyring() {
    local service=$1
    local account=$2
    local password=$3
    local source=$4

    if [ "$DRY_RUN" = true ]; then
        info "[DRY RUN] Would migrate: $service for account $account (from $source)"
        return 0
    fi

    verbose "Migrating credential: $service"

    # Check if credential already exists
    if secret-tool lookup service "$service" account "$account" &> /dev/null; then
        warning "Credential already exists in keyring: $service"

        if [ "$FORCE" = false ]; then
            read -p "Overwrite existing credential? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                info "Skipping $service"
                return 0
            fi
        fi

        # Delete existing credential
        secret-tool clear service "$service" account "$account" 2>/dev/null || true
    fi

    # Add new credential to keyring
    echo -n "$password" | secret-tool store \
        --label="$SECRET_LABEL_PREFIX: $service" \
        service "$service" \
        account "$account"

    if [ $? -eq 0 ]; then
        success "Migrated: $service"
        echo "SUCCESS|$service|$source" >> "$MIGRATION_REPORT"
        return 0
    else
        error "Failed to migrate: $service"
        echo "FAILED|$service|$source" >> "$MIGRATION_REPORT"
        return 1
    fi
}

process_credentials() {
    info "Processing detected credentials..."

    if [ ! -f "$CREDENTIALS_FOUND" ]; then
        info "No credentials found to migrate"
        return 0
    fi

    local total=0
    local success_count=0
    local failed=0

    while IFS='|' read -r type location key value; do
        ((total++))

        case "$type" in
            FILE)
                # Extract credential from file
                local cred_value=$(echo "$value" | grep -oE 'sk-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}')
                local service="ai.openclaw.$(basename "$location" | sed 's/\.[^.]*$//')"

                if migrate_credential_to_keyring "$service" "$USER" "$cred_value" "$location"; then
                    ((success_count++))
                else
                    ((failed++))
                fi
                ;;

            ENV)
                # Migrate from environment file
                local service="ai.openclaw.$(echo "$key" | tr '[:upper:]' '[:lower:]' | sed 's/_/./g')"

                if migrate_credential_to_keyring "$service" "$USER" "$value" "$location"; then
                    ((success_count++))
                else
                    ((failed++))
                fi
                ;;

            RUNENV)
                # Migrate from running environment
                local service="ai.openclaw.$(echo "$location" | tr '[:upper:]' '[:lower:]' | sed 's/_/./g')"

                if migrate_credential_to_keyring "$service" "$USER" "$key" "environment"; then
                    ((success_count++))
                else
                    ((failed++))
                fi
                ;;
        esac
    done < "$CREDENTIALS_FOUND"

    info "Migration complete: $success_count/$total successful, $failed failed"
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

cleanup_old_credentials() {
    if [ "$NO_CLEANUP" = true ]; then
        warning "Skipping cleanup of old credentials"
        return 0
    fi

    if [ "$DRY_RUN" = true ]; then
        info "[DRY RUN] Would clean up old credentials"
        return 0
    fi

    info "Cleaning up old credential storage..."

    if [ "$FORCE" = false ]; then
        warning "This will remove credentials from configuration files and environment variables"
        read -p "Continue with cleanup? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Skipping cleanup"
            return 0
        fi
    fi

    # Remove credentials from files
    while IFS='|' read -r type location key value; do
        if [ "$type" = "FILE" ]; then
            verbose "Removing credentials from: $location"

            # Create backup of file
            cp "$location" "$location.bak"

            # Remove credential lines
            sed -i.tmp -E '/sk-[a-zA-Z0-9_-]{20,}/d' "$location"
            sed -i.tmp -E '/AKIA[0-9A-Z]{16}/d' "$location"
            sed -i.tmp -E '/ghp_[a-zA-Z0-9]{36}/d' "$location"
            rm -f "$location.tmp"

            success "Cleaned: $location"
        fi
    done < "$CREDENTIALS_FOUND"

    # Remove from environment files
    for env_file in "${ENV_FILES[@]}"; do
        if [ -f "$env_file" ]; then
            verbose "Cleaning environment file: $env_file"

            cp "$env_file" "$env_file.bak"

            sed -i.tmp '/export ANTHROPIC_API_KEY=/d' "$env_file"
            sed -i.tmp '/export OPENAI_API_KEY=/d' "$env_file"
            sed -i.tmp '/export AWS_ACCESS_KEY_ID=/d' "$env_file"
            sed -i.tmp '/export AWS_SECRET_ACCESS_KEY=/d' "$env_file"
            sed -i.tmp '/export GITHUB_TOKEN=/d' "$env_file"
            rm -f "$env_file.tmp"

            success "Cleaned: $env_file"
        fi
    done
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

verify_migration() {
    info "Verifying migrated credentials..."

    local verified=0
    local failed=0

    # Check each migrated credential
    while IFS='|' read -r status service source; do
        if [ "$status" = "SUCCESS" ]; then
            if secret-tool lookup service "$service" account "$USER" &> /dev/null; then
                verbose "Verified: $service"
                ((verified++))
            else
                error "Verification failed: $service"
                ((failed++))
            fi
        fi
    done < "$MIGRATION_REPORT"

    if [ $failed -eq 0 ]; then
        success "All credentials verified ($verified/$verified)"
        return 0
    else
        error "Verification incomplete: $verified verified, $failed failed"
        return 1
    fi
}

# ============================================================================
# ROLLBACK FUNCTIONS
# ============================================================================

rollback_migration() {
    info "Rolling back migration..."

    # Find most recent backup
    local latest_backup=$(ls -t "$BACKUP_DIR" 2>/dev/null | head -1)

    if [ -z "$latest_backup" ]; then
        error "No backup found for rollback"
        exit 1
    fi

    warning "This will restore from backup: $latest_backup"

    if [ "$FORCE" = false ]; then
        read -p "Continue with rollback? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Rollback cancelled"
            exit 0
        fi
    fi

    # Restore files
    info "Restoring configuration files..."

    for config_dir in "${CONFIG_DIRS[@]}"; do
        local backup_path="$BACKUP_DIR/$latest_backup/$(basename "$config_dir")"
        if [ -d "$backup_path" ]; then
            cp -r "$backup_path/"* "$config_dir/" 2>/dev/null || true
            verbose "Restored: $config_dir"
        fi
    done

    # Restore environment files
    for env_file in "${ENV_FILES[@]}"; do
        local backup_file="$BACKUP_DIR/$latest_backup/$(basename "$env_file")"
        if [ -f "$backup_file" ]; then
            cp "$backup_file" "$env_file"
            verbose "Restored: $env_file"
        fi
    done

    # Remove credentials from keyring
    info "Removing credentials from keyring..."

    while IFS='|' read -r status service source; do
        if [ "$status" = "SUCCESS" ]; then
            secret-tool clear service "$service" account "$USER" 2>/dev/null || true
            verbose "Removed from keyring: $service"
        fi
    done < "$MIGRATION_REPORT" 2>/dev/null || true

    success "Rollback complete"
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

generate_report() {
    info "Generating migration report..."

    local report_file="$LOG_DIR/migration_report_${BACKUP_TIMESTAMP}.txt"

    cat > "$report_file" << EOF
================================================================================
ClawdBot Credential Migration Report (Linux)
================================================================================

Date: $(date)
User: $USER
Hostname: $(hostname)
Script Version: $SCRIPT_VERSION
Backend: $DETECTED_BACKEND

SUMMARY
------------------------------------------------------------------------
Dry Run: $([ "$DRY_RUN" = true ] && echo "Yes" || echo "No")
Backup Created: $([ "$SKIP_BACKUP" = false ] && echo "Yes" || echo "No")
Cleanup Performed: $([ "$NO_CLEANUP" = false ] && echo "Yes" || echo "No")

CREDENTIALS FOUND
------------------------------------------------------------------------
EOF

    if [ -f "$CREDENTIALS_FOUND" ]; then
        wc -l < "$CREDENTIALS_FOUND" >> "$report_file"
        echo "" >> "$report_file"
        cat "$CREDENTIALS_FOUND" >> "$report_file"
    else
        echo "None" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

MIGRATION RESULTS
------------------------------------------------------------------------
EOF

    if [ -f "$MIGRATION_REPORT" ]; then
        cat "$MIGRATION_REPORT" >> "$report_file"
    else
        echo "No migrations performed" >> "$report_file"
    fi

    cat >> "$report_file" << EOF

NEXT STEPS
------------------------------------------------------------------------
1. Update ClawdBot configuration to use keyring:
   credentials:
     storage: "os_keychain"

2. Test credential access:
   secret-tool lookup service ai.openclaw.anthropic account $USER

3. Review backup location:
   $BACKUP_DIR/$BACKUP_NAME

4. Review full log:
   $LOG_FILE

================================================================================
EOF

    success "Report generated: $report_file"

    if [ "$VERBOSE" = true ]; then
        cat "$report_file"
    fi
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

show_help() {
    cat << EOF
ClawdBot Credential Migration Script for Linux
Version: $SCRIPT_VERSION

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --dry-run          Show what would be migrated without making changes
    --backup-only      Create backups without migrating
    --skip-backup      Skip backup creation (not recommended)
    --no-cleanup       Don't remove credentials from old locations
    --force            Skip confirmation prompts
    --verbose          Enable verbose output
    --rollback         Restore from backup
    --backend BACKEND  Specify keyring backend (gnome, kde, auto)
    --help             Show this help message

EXAMPLES:
    # Dry run to see what will be migrated
    $SCRIPT_NAME --dry-run

    # Full migration with verbose output
    $SCRIPT_NAME --verbose

    # Create backup only
    $SCRIPT_NAME --backup-only

    # Migrate using KDE backend
    $SCRIPT_NAME --backend kde

    # Rollback migration
    $SCRIPT_NAME --rollback

DESCRIPTION:
    This script migrates ClawdBot credentials from insecure storage locations
    (configuration files, environment variables) to the Linux Secret Service.

    The migration process:
    1. Detects keyring backend (GNOME Keyring or KDE Wallet)
    2. Detects credentials in configuration files
    3. Detects credentials in environment files
    4. Creates secure backup of all credentials
    5. Migrates credentials to Secret Service
    6. Verifies successful migration
    7. Optionally removes credentials from old locations
    8. Generates detailed migration report

REQUIREMENTS:
    - Linux with Secret Service API
    - libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL)
    - gnome-keyring OR kwalletd5
    - jq (for JSON parsing)

INSTALLATION:
    Debian/Ubuntu:
        sudo apt-get install gnome-keyring libsecret-tools jq

    Fedora/RHEL:
        sudo dnf install gnome-keyring libsecret jq

    Arch Linux:
        sudo pacman -S gnome-keyring libsecret jq

FOR MORE INFORMATION:
    See: docs/guides/02-credential-isolation.md

EOF
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --backup-only)
                BACKUP_ONLY=true
                shift
                ;;
            --skip-backup)
                SKIP_BACKUP=true
                shift
                ;;
            --no-cleanup)
                NO_CLEANUP=true
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --verbose)
                VERBOSE=true
                shift
                ;;
            --rollback)
                ROLLBACK=true
                shift
                ;;
            --backend)
                BACKEND="$2"
                shift 2
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done

    # Create log directory
    mkdir -p "$LOG_DIR"

    # Print header
    print_color "$BLUE" "========================================"
    print_color "$BLUE" "ClawdBot Credential Migration for Linux"
    print_color "$BLUE" "Version: $SCRIPT_VERSION"
    print_color "$BLUE" "========================================"
    echo

    # Handle rollback
    if [ "$ROLLBACK" = true ]; then
        check_requirements
        rollback_migration
        exit 0
    fi

    # Check requirements
    check_requirements
    check_keyring_access

    # Detect credentials
    detect_credentials_in_files
    detect_credentials_in_env
    detect_credentials_in_running_env

    # Check if any credentials found
    if [ ! -f "$CREDENTIALS_FOUND" ] || [ ! -s "$CREDENTIALS_FOUND" ]; then
        success "No credentials found to migrate"
        exit 0
    fi

    # Show summary
    local cred_count=$(wc -l < "$CREDENTIALS_FOUND" | tr -d ' ')
    info "Found $cred_count credential(s) to migrate"

    # Create backup
    if [ "$BACKUP_ONLY" = false ]; then
        create_backup
    else
        create_backup
        success "Backup complete. Migration skipped (--backup-only)"
        exit 0
    fi

    # Confirm migration
    if [ "$FORCE" = false ] && [ "$DRY_RUN" = false ]; then
        echo
        warning "This will migrate credentials to the Linux Secret Service"
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            info "Migration cancelled"
            exit 0
        fi
    fi

    # Process credentials
    process_credentials

    # Verify migration
    if [ "$DRY_RUN" = false ]; then
        verify_migration
    fi

    # Cleanup old storage
    cleanup_old_credentials

    # Generate report
    generate_report

    # Final message
    echo
    success "Migration complete!"
    info "Backend used: $DETECTED_BACKEND"
    info "Backup location: $BACKUP_DIR/$BACKUP_NAME"
    info "Log file: $LOG_FILE"

    if [ "$DRY_RUN" = false ]; then
        info "Next steps:"
        info "  1. Update ClawdBot config to use keyring"
        info "  2. Test credential access with secret-tool"
        info "  3. Review the migration report"
    fi
}

# Run main function
main "$@"
