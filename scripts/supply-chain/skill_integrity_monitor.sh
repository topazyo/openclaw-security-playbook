#!/bin/bash
#
# skill_integrity_monitor.sh
# Continuous Skill Integrity Monitoring for ClawdBot
#
# This script monitors and validates MCP skills in real-time, enforcing
# security policies and detecting tampering or unauthorized modifications.
#
# Features:
#   - Continuous monitoring of skill directories
#   - Manifest validation and signature verification
#   - Policy enforcement (allowlists, dangerous patterns)
#   - Integrity checking (hash verification)
#   - Automated alerting on violations
#   - Quarantine of suspicious skills
#   - Comprehensive logging and reporting
#   - Cleanup and recovery procedures
#
# Usage:
#   ./skill_integrity_monitor.sh [OPTIONS]
#
# Options:
#   --start             Start monitoring daemon
#   --stop              Stop monitoring daemon
#   --scan              Run one-time scan
#   --validate FILE     Validate specific skill manifest
#   --quarantine ID     Quarantine skill by ID
#   --restore ID        Restore quarantined skill
#   --cleanup           Clean up old logs and quarantine
#   --status            Show monitoring status
#   --report            Generate security report
#   --help              Show this help message
#
# Examples:
#   # Start monitoring
#   ./skill_integrity_monitor.sh --start
#
#   # Run one-time scan
#   ./skill_integrity_monitor.sh --scan
#
#   # Validate specific skill
#   ./skill_integrity_monitor.sh --validate /path/to/skill-manifest.json
#
#   # Generate report
#   ./skill_integrity_monitor.sh --report
#
# Configuration:
#   Edit ~/.openclaw/config/skill-policies/ for policy customization
#
# Version: 1.0.0
# Last Updated: February 14, 2026

set -euo pipefail

# ============================================================================
# CONFIGURATION
# ============================================================================

SCRIPT_VERSION="1.0.0"
SCRIPT_NAME="$(basename "$0")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Paths
CONFIG_DIR="${OPENCLAW_CONFIG:-$HOME/.openclaw/config}"
SKILLS_DIR="${OPENCLAW_SKILLS:-$HOME/.openclaw/skills}"
QUARANTINE_DIR="${OPENCLAW_QUARANTINE:-$HOME/.openclaw/quarantine}"
LOG_DIR="${OPENCLAW_LOGS:-$HOME/.openclaw/logs}"
POLICY_DIR="${CONFIG_DIR}/skill-policies"
STATE_DIR="${HOME}/.openclaw/state"

# Files
PIDFILE="${STATE_DIR}/skill_monitor.pid"
LOG_FILE="${LOG_DIR}/skill_monitor.log"
AUDIT_LOG="${LOG_DIR}/skill_audit.log"
REPORT_FILE="${LOG_DIR}/skill_report_$(date +%Y%m%d_%H%M%S).json"

# Policy files
ALLOWLIST_FILE="${POLICY_DIR}/allowlist.json"
PATTERNS_FILE="${POLICY_DIR}/dangerous-patterns.json"
SCHEMA_FILE="${POLICY_DIR}/manifest-schema.json"
POLICY_FILE="${POLICY_DIR}/enforcement-policy.json"

# Monitoring settings
SCAN_INTERVAL="${SKILL_SCAN_INTERVAL:-300}"  # 5 minutes
MAX_LOG_SIZE="${MAX_LOG_SIZE:-104857600}"    # 100MB
LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-30}"
QUARANTINE_RETENTION_DAYS="${QUARANTINE_RETENTION_DAYS:-90}"

# Statistics
STATS_TOTAL=0
STATS_VALID=0
STATS_INVALID=0
STATS_QUARANTINED=0
STATS_WARNINGS=0

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

print_color() {
    local color=$1
    shift
    echo -e "${color}$*${NC}"
}

info() {
    print_color "$BLUE" "ℹ INFO: $*"
    log "INFO" "$*"
}

success() {
    print_color "$GREEN" "✓ SUCCESS: $*"
    log "SUCCESS" "$*"
}

warning() {
    print_color "$YELLOW" "⚠ WARNING: $*"
    log "WARNING" "$*"
    ((STATS_WARNINGS++))
}

error() {
    print_color "$RED" "✗ ERROR: $*"
    log "ERROR" "$*"
}

audit() {
    local level=$1
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $*" >> "$AUDIT_LOG"
}

log() {
    local level=$1
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $*" >> "$LOG_FILE"
}

escape_regex() {
    local value=$1
    printf '%s' "$value" | sed 's/[.[\*^$()+?{}|\\]/\\&/g'
}

is_valid_ere() {
    local pattern=$1
    grep -E -- "$pattern" /dev/null >/dev/null 2>&1
    local status=$?
    if [ $status -eq 2 ]; then
        return 1
    fi
    return 0
}

# ============================================================================
# INITIALIZATION
# ============================================================================

initialize() {
    info "Initializing Skill Integrity Monitor v${SCRIPT_VERSION}..."

    # Create directories
    mkdir -p "$CONFIG_DIR" "$SKILLS_DIR" "$QUARANTINE_DIR" \
             "$LOG_DIR" "$POLICY_DIR" "$STATE_DIR"

    # Check for required commands
    local missing_cmds=()
    for cmd in jq sha256sum curl; do
        if ! command -v "$cmd" &> /dev/null; then
            missing_cmds+=("$cmd")
        fi
    done

    if [ ${#missing_cmds[@]} -gt 0 ]; then
        error "Missing required commands: ${missing_cmds[*]}"
        info "Install with: sudo apt-get install ${missing_cmds[*]}"
        exit 1
    fi

    # Initialize policy files if not present
    if [ ! -f "$ALLOWLIST_FILE" ]; then
        create_default_allowlist
    fi

    if [ ! -f "$PATTERNS_FILE" ]; then
        warning "Dangerous patterns file not found: $PATTERNS_FILE"
        info "Creating default patterns file"
        cp "${POLICY_DIR}/dangerous-patterns.json" "$PATTERNS_FILE" 2>/dev/null || true
    fi

    if [ ! -f "$SCHEMA_FILE" ]; then
        warning "Schema file not found: $SCHEMA_FILE"
    fi

    success "Initialization complete"
}

create_default_allowlist() {
    info "Creating default allowlist..."
    cat > "$ALLOWLIST_FILE" << 'EOF'
{
  "version": "1.0.0",
  "last_updated": "2026-02-14T12:00:00Z",
  "sources": {
    "trusted": [
      "https://github.com/anthropics/",
      "https://github.com/modelcontextprotocol/"
    ],
    "approved": []
  },
  "skills": {
    "approved": [],
    "deprecated": [],
    "blocked": []
  }
}
EOF
    success "Default allowlist created: $ALLOWLIST_FILE"
}

# ============================================================================
# VALIDATION FUNCTIONS
# ============================================================================

validate_manifest() {
    local manifest_file=$1

    if [ ! -f "$manifest_file" ]; then
        error "Manifest file not found: $manifest_file"
        return 1
    fi

    info "Validating manifest: $manifest_file"
    ((STATS_TOTAL++))

    # Check JSON syntax
    if ! jq empty "$manifest_file" 2>/dev/null; then
        error "Invalid JSON syntax in manifest"
        ((STATS_INVALID++))
        return 1
    fi

    # Validate required fields
    local required_fields=("name" "version" "type" "author")
    for field in "${required_fields[@]}"; do
        if ! jq -e ".$field" "$manifest_file" &>/dev/null; then
            error "Missing required field: $field"
            ((STATS_INVALID++))
            return 1
        fi
    done

    # Validate against schema if available
    if [ -f "$SCHEMA_FILE" ]; then
        if command -v ajv &>/dev/null; then
            if ! ajv validate -s "$SCHEMA_FILE" -d "$manifest_file" 2>/dev/null; then
                error "Manifest does not conform to schema"
                ((STATS_INVALID++))
                return 1
            fi
        fi
    fi

    # Check version format
    local version=$(jq -r '.version' "$manifest_file")
    if ! [[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        warning "Invalid version format: $version (expected semver)"
    fi

    # Validate source repository
    if jq -e '.repository' "$manifest_file" &>/dev/null; then
        local repo=$(jq -r '.repository' "$manifest_file")
        if ! validate_source "$repo"; then
            warning "Untrusted source repository: $repo"
        fi
    fi

    success "Manifest validation passed: $manifest_file"
    ((STATS_VALID++))
    return 0
}

validate_source() {
    local source=$1

    if [ ! -f "$ALLOWLIST_FILE" ]; then
        return 0  # Pass if no allowlist
    fi

    # Check if source matches trusted patterns
    local trusted_sources=$(jq -r '.sources.trusted[]' "$ALLOWLIST_FILE" 2>/dev/null || echo "")

    for trusted in $trusted_sources; do
        if [[ "$source" == "$trusted"* ]]; then
            return 0
        fi
    done

    # Check approved sources
    local approved_sources=$(jq -r '.sources.approved[]' "$ALLOWLIST_FILE" 2>/dev/null || echo "")

    for approved in $approved_sources; do
        if [ "$source" = "$approved" ]; then
            return 0
        fi
    done

    return 1
}

check_integrity() {
    local manifest_file=$1

    info "Checking integrity: $manifest_file"

    # Get expected hash from manifest
    if ! jq -e '.integrity' "$manifest_file" &>/dev/null; then
        warning "No integrity hash in manifest"
        return 0
    fi

    local expected_hash=$(jq -r '.integrity.hash' "$manifest_file")
    local hash_algo=$(jq -r '.integrity.algorithm // "sha256"' "$manifest_file")

    # Get skill directory
    local skill_dir=$(dirname "$manifest_file")

    # Calculate actual hash
    local actual_hash=""
    case "$hash_algo" in
        sha256)
            actual_hash=$(find "$skill_dir" -type f ! -name "skill-manifest.json" -exec sha256sum {} \; | \
                         sort | sha256sum | awk '{print $1}')
            ;;
        sha512)
            actual_hash=$(find "$skill_dir" -type f ! -name "skill-manifest.json" -exec sha512sum {} \; | \
                         sort | sha512sum | awk '{print $1}')
            ;;
        *)
            warning "Unknown hash algorithm: $hash_algo"
            return 0
            ;;
    esac

    if [ "$expected_hash" != "$actual_hash" ]; then
        error "Integrity check failed!"
        error "Expected: $expected_hash"
        error "Actual:   $actual_hash"
        audit "INTEGRITY_FAILURE" "Skill: $manifest_file | Expected: $expected_hash | Actual: $actual_hash"
        return 1
    fi

    success "Integrity check passed"
    return 0
}

verify_signature() {
    local manifest_file=$1
    local signature_required="true"
    local verify_pgp="true"

    if [ -f "$POLICY_FILE" ]; then
        signature_required=$(jq -r '.validation.signature.required // true' "$POLICY_FILE" 2>/dev/null || echo "true")
        verify_pgp=$(jq -r '.validation.signature.verify_pgp // true' "$POLICY_FILE" 2>/dev/null || echo "true")
    fi

    if ! jq -e '.signature' "$manifest_file" &>/dev/null; then
        if [ "$signature_required" = "true" ]; then
            error "No signature present but signature validation is required"
            audit "SIGNATURE_MISSING" "Skill: $manifest_file"
            return 1
        fi

        info "No signature present (optional mode)"
        return 0
    fi

    if [ "$verify_pgp" != "true" ]; then
        warning "PGP verification disabled by policy"
        audit "SIGNATURE_BYPASS" "Skill: $manifest_file | verify_pgp=false"
        return 0
    fi

    info "Verifying signature..."

    if ! command -v gpg &>/dev/null; then
        error "gpg is required for signature verification"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | gpg_missing=true"
        return 1
    fi

    local signature_value=$(jq -r '.signature.value // empty' "$manifest_file")
    local public_key=$(jq -r '.signature.public_key // empty' "$manifest_file")
    local trusted_keys
    trusted_keys=$(jq -r '.validation.signature.trusted_keys[]?' "$POLICY_FILE" 2>/dev/null || true)

    if [ -z "$signature_value" ]; then
        error "Signature block present but signature.value is missing"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=missing_signature_value"
        return 1
    fi

    if [ -z "$public_key" ]; then
        error "Signature block present but signature.public_key is missing"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=missing_public_key"
        return 1
    fi

    if [ -n "$trusted_keys" ]; then
        local key_trusted="false"
        while IFS= read -r trusted_key; do
            if [ -n "$trusted_key" ] && [ "$public_key" = "$trusted_key" ]; then
                key_trusted="true"
                break
            fi
        done <<< "$trusted_keys"

        if [ "$key_trusted" != "true" ]; then
            error "Signing key is not in policy trusted_keys allowlist"
            audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=untrusted_key"
            return 1
        fi
    fi

    local temp_sig temp_payload
    temp_sig=$(mktemp)
    temp_payload=$(mktemp)

    if ! echo "$signature_value" | base64 --decode > "$temp_sig" 2>/dev/null; then
        if ! echo "$signature_value" | base64 -d > "$temp_sig" 2>/dev/null; then
            rm -f "$temp_sig" "$temp_payload"
            error "Invalid signature encoding (expected base64)"
            audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=invalid_base64"
            return 1
        fi
    fi

    if ! jq -c 'del(.signature)' "$manifest_file" > "$temp_payload" 2>/dev/null; then
        rm -f "$temp_sig" "$temp_payload"
        error "Failed to prepare canonical payload for signature verification"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=canonicalization_failed"
        return 1
    fi

    if ! gpg --list-keys "$public_key" &>/dev/null; then
        rm -f "$temp_sig" "$temp_payload"
        error "Public key not found in GPG keyring: $public_key"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=key_not_found"
        return 1
    fi

    if gpg --list-keys "$public_key" 2>&1 | grep -qi "revoked"; then
        rm -f "$temp_sig" "$temp_payload"
        error "Signing key is revoked: $public_key"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=key_revoked"
        return 1
    fi

    local verify_ok="false"
    if gpg --verify "$temp_sig" "$temp_payload" &>/dev/null; then
        verify_ok="true"
    elif gpg --verify "$temp_sig" "$manifest_file" &>/dev/null; then
        verify_ok="true"
    fi

    rm -f "$temp_sig" "$temp_payload"

    if [ "$verify_ok" != "true" ]; then
        error "GPG signature verification failed"
        audit "SIGNATURE_FAILURE" "Skill: $manifest_file | reason=verify_failed"
        return 1
    fi

    success "Signature verification passed"
    audit "SIGNATURE_OK" "Skill: $manifest_file | key=$public_key"
    return 0
}

scan_dangerous_patterns() {
    local skill_dir=$1

    if [ ! -f "$PATTERNS_FILE" ]; then
        return 0
    fi

    info "Scanning for dangerous patterns..."

    local patterns=$(jq -r '.patterns[].pattern // empty' "$PATTERNS_FILE" 2>/dev/null || echo "")
    local exceptions=$(jq -r '.exceptions[]? // empty' "$PATTERNS_FILE" 2>/dev/null || echo "")
    local found_issues=0

    while IFS= read -r pattern; do
        if [ -n "$pattern" ]; then
            if ! is_valid_ere "$pattern"; then
                warning "Skipping invalid regex pattern: $pattern"
                audit "PATTERN_INVALID" "Pattern: $pattern"
                continue
            fi

            local matches
            matches=$(grep -r -E -- "$pattern" "$skill_dir" 2>/dev/null || true)

            if [ -n "$exceptions" ] && [ -n "$matches" ]; then
                while IFS= read -r exception; do
                    if [ -n "$exception" ]; then
                        local escaped_exception
                        escaped_exception=$(escape_regex "$exception")
                        matches=$(echo "$matches" | grep -E -v -- "\\b${escaped_exception}\\s*\\(" || true)
                    fi
                done <<< "$exceptions"
            fi

            if [ -n "$matches" ]; then
                warning "Dangerous pattern detected: $pattern"
                echo "$matches" | head -5
                ((found_issues++))
                audit "DANGEROUS_PATTERN" "Skill: $skill_dir | Pattern: $pattern"
            fi
        fi
    done <<< "$patterns"

    if [ $found_issues -gt 0 ]; then
        error "Found $found_issues dangerous pattern(s)"
        return 1
    fi

    success "No dangerous patterns detected"
    return 0
}

check_permissions() {
    local manifest_file=$1

    info "Checking requested permissions..."

    if ! jq -e '.permissions' "$manifest_file" &>/dev/null; then
        info "No permissions declared"
        return 0
    fi

    local permissions=$(jq -r '.permissions[]' "$manifest_file")
    local dangerous_perms=("filesystem:write" "network:unrestricted" "process:exec" "secrets:read")

    while IFS= read -r perm; do
        for dangerous in "${dangerous_perms[@]}"; do
            if [ "$perm" = "$dangerous" ]; then
                warning "Dangerous permission requested: $perm"
                audit "DANGEROUS_PERMISSION" "Skill: $manifest_file | Permission: $perm"
            fi
        done
    done <<< "$permissions"

    return 0
}

# ============================================================================
# ENFORCEMENT FUNCTIONS
# ============================================================================

quarantine_skill() {
    local skill_path=$1
    local reason=${2:-"Policy violation"}

    warning "Quarantining skill: $skill_path"
    audit "QUARANTINE" "Skill: $skill_path | Reason: $reason"

    local skill_name=$(basename "$skill_path")
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local quarantine_path="${QUARANTINE_DIR}/${skill_name}_${timestamp}"

    # Move skill to quarantine
    if mv "$skill_path" "$quarantine_path"; then
        success "Skill quarantined: $quarantine_path"

        # Create quarantine metadata
        cat > "${quarantine_path}/QUARANTINE_INFO.txt" << EOF
Quarantine Information
======================
Skill: $skill_name
Original Path: $skill_path
Quarantined: $(date '+%Y-%m-%d %H:%M:%S')
Reason: $reason
Quarantine ID: ${skill_name}_${timestamp}

To restore:
  $SCRIPT_NAME --restore ${skill_name}_${timestamp}
EOF

        ((STATS_QUARANTINED++))
        return 0
    else
        error "Failed to quarantine skill"
        return 1
    fi
}

restore_skill() {
    local quarantine_id=$1

    local quarantine_path="${QUARANTINE_DIR}/${quarantine_id}"

    if [ ! -d "$quarantine_path" ]; then
        error "Quarantined skill not found: $quarantine_id"
        return 1
    fi

    info "Restoring skill: $quarantine_id"

    # Read original path
    local original_path=$(grep "Original Path:" "${quarantine_path}/QUARANTINE_INFO.txt" | cut -d' ' -f3)

    if [ -z "$original_path" ]; then
        error "Could not determine original path"
        return 1
    fi

    # Restore skill
    if mv "$quarantine_path" "$original_path"; then
        success "Skill restored: $original_path"
        audit "RESTORE" "Skill: $quarantine_id | Restored to: $original_path"
        return 0
    else
        error "Failed to restore skill"
        return 1
    fi
}

# ============================================================================
# SCANNING FUNCTIONS
# ============================================================================

scan_all_skills() {
    info "Scanning all skills in: $SKILLS_DIR"

    if [ ! -d "$SKILLS_DIR" ]; then
        error "Skills directory not found: $SKILLS_DIR"
        return 1
    fi

    # Find all skill manifests
    local manifests=$(find "$SKILLS_DIR" -name "skill-manifest.json" 2>/dev/null)

    if [ -z "$manifests" ]; then
        warning "No skill manifests found"
        return 0
    fi

    local total=0
    local passed=0
    local failed=0

    while IFS= read -r manifest; do
        ((total++))

        echo ""
        info "═══════════════════════════════════════════════════════════"
        info "Scanning skill #$total: $manifest"
        info "═══════════════════════════════════════════════════════════"

        local issues=0

        # Validate manifest
        if ! validate_manifest "$manifest"; then
            ((issues++))
        fi

        # Check integrity
        if ! check_integrity "$manifest"; then
            ((issues++))
        fi

        # Verify signature
        if ! verify_signature "$manifest"; then
            ((issues++))
        fi

        # Scan for dangerous patterns
        local skill_dir=$(dirname "$manifest")
        if ! scan_dangerous_patterns "$skill_dir"; then
            ((issues++))
        fi

        # Check permissions
        check_permissions "$manifest"

        # Enforce policy
        if [ $issues -gt 0 ]; then
            error "Skill failed validation with $issues issue(s)"
            ((failed++))

            # Quarantine if configured
            if [ "${AUTO_QUARANTINE:-false}" = "true" ]; then
                quarantine_skill "$skill_dir" "Failed validation with $issues issue(s)"
            fi
        else
            success "Skill passed all checks"
            ((passed++))
        fi

    done <<< "$manifests"

    echo ""
    info "═══════════════════════════════════════════════════════════"
    info "Scan Summary"
    info "═══════════════════════════════════════════════════════════"
    info "Total Skills:    $total"
    success "Passed:         $passed"
    if [ $failed -gt 0 ]; then
        error "Failed:         $failed"
    else
        info "Failed:         $failed"
    fi
    info "Quarantined:     $STATS_QUARANTINED"

    return 0
}

# ============================================================================
# MONITORING FUNCTIONS
# ============================================================================

start_monitoring() {
    if is_running; then
        warning "Monitor already running (PID: $(cat "$PIDFILE"))"
        return 1
    fi

    info "Starting skill integrity monitor..."

    # Start monitor in background
    (monitor_loop) &
    local pid=$!

    echo $pid > "$PIDFILE"

    success "Monitor started (PID: $pid)"
    info "Scan interval: ${SCAN_INTERVAL}s"
    info "Log file: $LOG_FILE"

    audit "MONITOR_START" "PID: $pid | Interval: ${SCAN_INTERVAL}s"
}

stop_monitoring() {
    if ! is_running; then
        warning "Monitor not running"
        return 1
    fi

    local pid=$(cat "$PIDFILE")

    info "Stopping monitor (PID: $pid)..."

    if kill "$pid" 2>/dev/null; then
        rm -f "$PIDFILE"
        success "Monitor stopped"
        audit "MONITOR_STOP" "PID: $pid"
        return 0
    else
        error "Failed to stop monitor"
        return 1
    fi
}

is_running() {
    if [ -f "$PIDFILE" ]; then
        local pid=$(cat "$PIDFILE")
        if kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            # Stale PID file
            rm -f "$PIDFILE"
        fi
    fi
    return 1
}

monitor_loop() {
    info "Monitor loop started"

    while true; do
        log "INFO" "Running periodic scan..."

        # Run scan
        scan_all_skills >> "$LOG_FILE" 2>&1

        # Rotate logs if needed
        rotate_logs

        # Sleep until next scan
        sleep "$SCAN_INTERVAL"
    done
}

# ============================================================================
# REPORTING FUNCTIONS
# ============================================================================

generate_report() {
    info "Generating security report..."

    # Run scan to collect data
    scan_all_skills > /dev/null 2>&1

    # Generate JSON report
    cat > "$REPORT_FILE" << EOF
{
  "report_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "version": "$SCRIPT_VERSION",
  "statistics": {
    "total_skills": $STATS_TOTAL,
    "valid": $STATS_VALID,
    "invalid": $STATS_INVALID,
    "quarantined": $STATS_QUARANTINED,
    "warnings": $STATS_WARNINGS
  },
  "quarantine": {
    "count": $(find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l),
    "path": "$QUARANTINE_DIR"
  },
  "policies": {
    "allowlist": "$ALLOWLIST_FILE",
    "patterns": "$PATTERNS_FILE",
    "schema": "$SCHEMA_FILE"
  }
}
EOF

    success "Report generated: $REPORT_FILE"

    # Display summary
    echo ""
    info "═══════════════════════════════════════════════════════════"
    info "Security Report Summary"
    info "═══════════════════════════════════════════════════════════"
    jq '.' "$REPORT_FILE"
}

# ============================================================================
# CLEANUP FUNCTIONS
# ============================================================================

cleanup() {
    info "Running cleanup..."

    # Rotate old logs
    rotate_logs

    # Clean up old quarantine
    clean_quarantine

    success "Cleanup complete"
}

rotate_logs() {
    if [ -f "$LOG_FILE" ]; then
        local size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)

        if [ "$size" -gt "$MAX_LOG_SIZE" ]; then
            info "Rotating log file (size: $size bytes)"
            mv "$LOG_FILE" "${LOG_FILE}.$(date +%Y%m%d_%H%M%S)"
            gzip "${LOG_FILE}".* 2>/dev/null || true
        fi
    fi

    # Delete old logs
    find "$LOG_DIR" -name "*.log.*.gz" -mtime +$LOG_RETENTION_DAYS -delete 2>/dev/null || true
}

clean_quarantine() {
    info "Cleaning up old quarantine..."

    local count=$(find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +$QUARANTINE_RETENTION_DAYS 2>/dev/null | wc -l)

    if [ $count -gt 0 ]; then
        info "Removing $count old quarantined skill(s)"
        find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type d -mtime +$QUARANTINE_RETENTION_DAYS -exec rm -rf {} \; 2>/dev/null || true
    fi
}

# ============================================================================
# MAIN FUNCTION
# ============================================================================

show_help() {
    cat << EOF
Skill Integrity Monitor for ClawdBot
Version: $SCRIPT_VERSION

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --start              Start monitoring daemon
    --stop               Stop monitoring daemon
    --scan               Run one-time scan
    --validate FILE      Validate specific skill manifest
    --quarantine ID      Quarantine skill by ID
    --restore ID         Restore quarantined skill
    --cleanup            Clean up old logs and quarantine
    --status             Show monitoring status
    --report             Generate security report
    --help               Show this help message

EXAMPLES:
    # Start continuous monitoring
    $SCRIPT_NAME --start

    # Run immediate scan
    $SCRIPT_NAME --scan

    # Validate specific skill
    $SCRIPT_NAME --validate /path/to/skill-manifest.json

    # Check status
    $SCRIPT_NAME --status

    # Generate report
    $SCRIPT_NAME --report

CONFIGURATION:
    Config directory: $CONFIG_DIR/skill-policies/
    Skills directory: $SKILLS_DIR
    Log file:         $LOG_FILE

    Policy files:
      - allowlist.json
      - dangerous-patterns.json
      - manifest-schema.json
      - enforcement-policy.json

ENVIRONMENT VARIABLES:
    OPENCLAW_CONFIG              Configuration directory
    OPENCLAW_SKILLS              Skills directory
    OPENCLAW_LOGS                Logs directory
    SKILL_SCAN_INTERVAL          Scan interval in seconds (default: 300)
    MAX_LOG_SIZE                 Max log size in bytes (default: 104857600)
    LOG_RETENTION_DAYS           Log retention period (default: 30)
    QUARANTINE_RETENTION_DAYS    Quarantine retention (default: 90)
    AUTO_QUARANTINE              Auto-quarantine on failure (true/false)

For more information, see: docs/guides/06-supply-chain-security.md

EOF
}

show_status() {
    echo "Skill Integrity Monitor Status"
    echo "══════════════════════════════"
    echo ""

    if is_running; then
        local pid=$(cat "$PIDFILE")
        print_color "$GREEN" "Status: RUNNING (PID: $pid)"
    else
        print_color "$YELLOW" "Status: STOPPED"
    fi

    echo ""
    echo "Configuration:"
    echo "  Skills Dir:    $SKILLS_DIR"
    echo "  Policy Dir:    $POLICY_DIR"
    echo "  Quarantine:    $QUARANTINE_DIR"
    echo "  Log File:      $LOG_FILE"
    echo ""

    local skill_count=$(find "$SKILLS_DIR" -name "skill-manifest.json" 2>/dev/null | wc -l)
    local quarantine_count=$(find "$QUARANTINE_DIR" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l)

    echo "Statistics:"
    echo "  Total Skills:     $skill_count"
    echo "  Quarantined:      $quarantine_count"
    echo "  Scan Interval:    ${SCAN_INTERVAL}s"
}

main() {
    # Parse arguments
    if [ $# -eq 0 ]; then
        show_help
        exit 0
    fi

    local action=""
    local arg=""

    case "$1" in
        --start)
            action="start"
            ;;
        --stop)
            action="stop"
            ;;
        --scan)
            action="scan"
            ;;
        --validate)
            action="validate"
            arg="${2:-}"
            ;;
        --quarantine)
            action="quarantine"
            arg="${2:-}"
            ;;
        --restore)
            action="restore"
            arg="${2:-}"
            ;;
        --cleanup)
            action="cleanup"
            ;;
        --status)
            action="status"
            ;;
        --report)
            action="report"
            ;;
        --help)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac

    # Initialize
    initialize

    # Execute action
    case "$action" in
        start)
            start_monitoring
            ;;
        stop)
            stop_monitoring
            ;;
        scan)
            scan_all_skills
            ;;
        validate)
            if [ -z "$arg" ]; then
                error "Manifest file required"
                exit 1
            fi
            validate_manifest "$arg"
            ;;
        quarantine)
            if [ -z "$arg" ]; then
                error "Skill path required"
                exit 1
            fi
            quarantine_skill "$arg" "Manual quarantine"
            ;;
        restore)
            if [ -z "$arg" ]; then
                error "Quarantine ID required"
                exit 1
            fi
            restore_skill "$arg"
            ;;
        cleanup)
            cleanup
            ;;
        status)
            show_status
            ;;
        report)
            generate_report
            ;;
    esac
}

main "$@"
