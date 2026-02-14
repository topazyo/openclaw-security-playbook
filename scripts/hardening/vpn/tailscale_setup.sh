#!/bin/bash
#
# tailscale_setup.sh
# Complete Tailscale Setup for ClawdBot Network Isolation
#
# This script automates Tailscale installation, configuration, and ACL setup
# to enable secure network isolation for ClawdBot deployments.
#
# Features:
#   - Automated Tailscale installation (macOS, Linux)
#   - Device authentication and registration
#   - ACL configuration with principle of least privilege
#   - Device allowlisting and tags
#   - Subnet routing configuration
#   - DNS configuration for ClawdBot services
#   - Exit node setup (optional)
#   - Multi-user access control
#   - Verification and testing
#   - Comprehensive troubleshooting
#
# Usage:
#   ./tailscale_setup.sh [OPTIONS]
#
# Options:
#   --install          Install Tailscale (if not present)
#   --configure        Configure Tailscale for ClawdBot
#   --acl-file FILE    Path to custom ACL configuration file
#   --tag TAG          Device tag (default: tag:clawdbot)
#   --subnet CIDR      Advertise subnet routes
#   --exit-node        Configure as exit node
#   --dns DOMAINS      Configure MagicDNS domains
#   --verify           Verify Tailscale setup
#   --troubleshoot     Run troubleshooting checks
#   --uninstall        Remove Tailscale configuration
#   --help             Show this help message
#
# Example:
#   # Install and configure with default settings
#   ./tailscale_setup.sh --install --configure
#
#   # Configure with custom ACL and subnet routing
#   ./tailscale_setup.sh --configure --acl-file custom_acl.json --subnet 10.0.0.0/24
#
#   # Verify setup
#   ./tailscale_setup.sh --verify
#
# Requirements:
#   - macOS 10.13+ or Linux (Ubuntu, Debian, Fedora, Arch)
#   - sudo/root access for installation
#   - Tailscale account (free tier supported)
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
NC='\033[0m'

# Tailscale configuration
TAILSCALE_TAG="${TAILSCALE_TAG:-tag:clawdbot}"
TAILSCALE_ACL_FILE="${TAILSCALE_ACL_FILE:-}"
TAILSCALE_SUBNET="${TAILSCALE_SUBNET:-}"
TAILSCALE_EXIT_NODE="${TAILSCALE_EXIT_NODE:-false}"
TAILSCALE_DNS_DOMAINS="${TAILSCALE_DNS_DOMAINS:-}"

# Paths
CONFIG_DIR="$HOME/.openclaw/config"
LOG_DIR="$HOME/.openclaw/logs"
LOG_FILE="$LOG_DIR/tailscale_setup_$(date +%Y%m%d_%H%M%S).log"

# Options
DO_INSTALL=false
DO_CONFIGURE=false
DO_VERIFY=false
DO_TROUBLESHOOT=false
DO_UNINSTALL=false

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

# ============================================================================
# DETECTION FUNCTIONS
# ============================================================================

detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ -f /etc/os-release ]]; then
        source /etc/os-release
        echo "$ID"
    else
        echo "unknown"
    fi
}

check_tailscale_installed() {
    if command -v tailscale &> /dev/null; then
        return 0
    else
        return 1
    fi
}

check_tailscale_running() {
    if tailscale status &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

install_tailscale_macos() {
    info "Installing Tailscale on macOS..."

    # Check if Homebrew is installed
    if ! command -v brew &> /dev/null; then
        error "Homebrew not found. Install from: https://brew.sh"
        exit 1
    fi

    # Install Tailscale
    brew install tailscale

    # Start Tailscale service
    sudo brew services start tailscale

    success "Tailscale installed on macOS"
}

install_tailscale_ubuntu() {
    info "Installing Tailscale on Ubuntu/Debian..."

    # Add Tailscale repository
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).gpg | sudo apt-key add -
    curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/$(lsb_release -cs).list | sudo tee /etc/apt/sources.list.d/tailscale.list

    # Update and install
    sudo apt-get update
    sudo apt-get install -y tailscale

    success "Tailscale installed on Ubuntu/Debian"
}

install_tailscale_fedora() {
    info "Installing Tailscale on Fedora/RHEL..."

    # Add Tailscale repository
    sudo dnf config-manager --add-repo https://pkgs.tailscale.com/stable/fedora/tailscale.repo

    # Install
    sudo dnf install -y tailscale

    # Enable and start service
    sudo systemctl enable --now tailscaled

    success "Tailscale installed on Fedora/RHEL"
}

install_tailscale_arch() {
    info "Installing Tailscale on Arch Linux..."

    # Install from official repository
    sudo pacman -S --noconfirm tailscale

    # Enable and start service
    sudo systemctl enable --now tailscaled

    success "Tailscale installed on Arch Linux"
}

install_tailscale() {
    if check_tailscale_installed; then
        success "Tailscale already installed"
        tailscale version
        return 0
    fi

    local os=$(detect_os)

    case "$os" in
        macos)
            install_tailscale_macos
            ;;
        ubuntu|debian)
            install_tailscale_ubuntu
            ;;
        fedora|rhel|centos)
            install_tailscale_fedora
            ;;
        arch)
            install_tailscale_arch
            ;;
        *)
            error "Unsupported OS: $os"
            info "Visit https://tailscale.com/download for manual installation"
            exit 1
            ;;
    esac
}

# ============================================================================
# AUTHENTICATION FUNCTIONS
# ============================================================================

authenticate_tailscale() {
    info "Authenticating with Tailscale..."

    if check_tailscale_running; then
        success "Already authenticated"
        tailscale status --json | jq -r '.Self.HostName'
        return 0
    fi

    # Build authentication command
    local auth_cmd="sudo tailscale up"

    # Add tag if specified
    if [ -n "$TAILSCALE_TAG" ]; then
        auth_cmd="$auth_cmd --advertise-tags=$TAILSCALE_TAG"
    fi

    # Add subnet routes if specified
    if [ -n "$TAILSCALE_SUBNET" ]; then
        auth_cmd="$auth_cmd --advertise-routes=$TAILSCALE_SUBNET"
    fi

    # Add exit node if specified
    if [ "$TAILSCALE_EXIT_NODE" = true ]; then
        auth_cmd="$auth_cmd --advertise-exit-node"
    fi

    # Execute authentication
    info "Running: $auth_cmd"
    info "Please follow the authentication link that will be displayed..."

    eval "$auth_cmd"

    if check_tailscale_running; then
        success "Authentication successful"
        tailscale status
        return 0
    else
        error "Authentication failed"
        return 1
    fi
}

# ============================================================================
# ACL CONFIGURATION FUNCTIONS
# ============================================================================

generate_default_acl() {
    local acl_file="$1"

    info "Generating default ACL configuration..."

    cat > "$acl_file" << 'EOF'
{
  // ClawdBot Tailscale ACL Configuration
  // Version: 1.0.0
  // Last Updated: 2026-02-14

  // Tags define logical groups of devices
  "tagOwners": {
    "tag:clawdbot": ["autogroup:admin"],
    "tag:clawdbot-prod": ["autogroup:admin"],
    "tag:clawdbot-dev": ["autogroup:admin"],
    "tag:clawdbot-gateway": ["autogroup:admin"]
  },

  // ACLs define who can access what
  "acls": [
    // Allow all ClawdBot devices to communicate with each other
    {
      "action": "accept",
      "src": ["tag:clawdbot"],
      "dst": ["tag:clawdbot:*"]
    },

    // Allow production gateway to access all ClawdBot services
    {
      "action": "accept",
      "src": ["tag:clawdbot-gateway"],
      "dst": [
        "tag:clawdbot-prod:443",  // HTTPS
        "tag:clawdbot-prod:8443", // Gateway
        "tag:clawdbot-prod:9090"  // Metrics
      ]
    },

    // Allow dev environment isolated access
    {
      "action": "accept",
      "src": ["tag:clawdbot-dev"],
      "dst": ["tag:clawdbot-dev:*"]
    },

    // Allow admin users full access
    {
      "action": "accept",
      "src": ["autogroup:admin"],
      "dst": ["tag:clawdbot:*"]
    },

    // Deny all other traffic (implicit deny)
  ],

  // SSH access control
  "ssh": [
    {
      "action": "accept",
      "src": ["autogroup:admin"],
      "dst": ["tag:clawdbot"],
      "users": ["autogroup:nonroot", "root"]
    }
  ],

  // DNS configuration
  "dnsConfig": {
    "domains": ["clawdbot.internal"],
    "nameservers": ["8.8.8.8"],
    "magicDNS": true,
    "overrideLocalDNS": false
  },

  // Auto-approvers for subnet routes and exit nodes
  "autoApprovers": {
    "routes": {
      "10.0.0.0/8": ["tag:clawdbot-gateway"],
      "172.16.0.0/12": ["tag:clawdbot-gateway"]
    },
    "exitNode": ["tag:clawdbot-gateway"]
  },

  // Device posture checks (requires Business plan)
  "postures": {
    "postureDisableFileSharing": [
      "autogroup:admin"
    ]
  }
}
EOF

    success "Default ACL configuration generated: $acl_file"
}

upload_acl_configuration() {
    local acl_file="$1"

    if [ ! -f "$acl_file" ]; then
        error "ACL file not found: $acl_file"
        return 1
    fi

    info "Uploading ACL configuration..."
    warning "ACL must be uploaded via Tailscale admin console"
    info "1. Visit: https://login.tailscale.com/admin/acls"
    info "2. Copy the contents of: $acl_file"
    info "3. Paste into ACL editor and save"

    cat "$acl_file"

    read -p "Press Enter after uploading ACL configuration..."
}

# ============================================================================
# DNS CONFIGURATION FUNCTIONS
# ============================================================================

configure_dns() {
    info "Configuring MagicDNS..."

    if [ -z "$TAILSCALE_DNS_DOMAINS" ]; then
        info "No custom DNS domains specified, using defaults"
        TAILSCALE_DNS_DOMAINS="clawdbot.internal"
    fi

    info "DNS domains: $TAILSCALE_DNS_DOMAINS"
    warning "MagicDNS configuration must be done via admin console"
    info "1. Visit: https://login.tailscale.com/admin/dns"
    info "2. Enable MagicDNS"
    info "3. Add search domains: $TAILSCALE_DNS_DOMAINS"

    read -p "Press Enter after configuring DNS..."

    success "DNS configuration completed"
}

# ============================================================================
# DEVICE MANAGEMENT FUNCTIONS
# ============================================================================

list_devices() {
    info "Listing Tailscale devices..."

    if ! check_tailscale_running; then
        error "Tailscale not running"
        return 1
    fi

    tailscale status
}

tag_device() {
    local device_name="$1"
    local tag="$2"

    info "Tagging device $device_name with $tag..."
    warning "Device tagging must be done via admin console"
    info "1. Visit: https://login.tailscale.com/admin/machines"
    info "2. Find device: $device_name"
    info "3. Edit > Tags > Add: $tag"

    read -p "Press Enter after tagging device..."
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

verify_installation() {
    info "Verifying Tailscale installation..."

    local issues=0

    # Check if Tailscale is installed
    if check_tailscale_installed; then
        success "Tailscale binary found"
        tailscale version
    else
        error "Tailscale not installed"
        ((issues++))
    fi

    # Check if Tailscale is running
    if check_tailscale_running; then
        success "Tailscale is running"
    else
        error "Tailscale is not running"
        ((issues++))
    fi

    # Check authentication status
    local status=$(tailscale status --json 2>/dev/null || echo '{}')
    local backend_state=$(echo "$status" | jq -r '.BackendState // "unknown"')

    if [ "$backend_state" = "Running" ]; then
        success "Authenticated and connected"
    else
        error "Not authenticated (state: $backend_state)"
        ((issues++))
    fi

    # Check IP address
    local ip=$(tailscale ip -4 2>/dev/null)
    if [ -n "$ip" ]; then
        success "Tailscale IP: $ip"
    else
        warning "No Tailscale IP assigned"
        ((issues++))
    fi

    # Check DNS
    if tailscale status --json | jq -e '.MagicDNSSuffix' &>/dev/null; then
        local dns_suffix=$(tailscale status --json | jq -r '.MagicDNSSuffix')
        success "MagicDNS enabled: $dns_suffix"
    else
        info "MagicDNS not configured"
    fi

    return $issues
}

verify_connectivity() {
    info "Verifying Tailscale connectivity..."

    if ! check_tailscale_running; then
        error "Tailscale not running"
        return 1
    fi

    # Get list of peers
    local peers=$(tailscale status --json | jq -r '.Peer | keys[]' 2>/dev/null)

    if [ -z "$peers" ]; then
        warning "No peers found. This may be the first device."
        return 0
    fi

    # Test connectivity to each peer
    info "Testing connectivity to peers..."
    while IFS= read -r peer; do
        local peer_ip=$(tailscale status --json | jq -r ".Peer[\"$peer\"].TailscaleIPs[0]")
        local peer_name=$(tailscale status --json | jq -r ".Peer[\"$peer\"].HostName")

        if [ -n "$peer_ip" ]; then
            if ping -c 1 -W 2 "$peer_ip" &>/dev/null; then
                success "Connectivity OK: $peer_name ($peer_ip)"
            else
                warning "Cannot ping: $peer_name ($peer_ip)"
            fi
        fi
    done <<< "$peers"
}

verify_acl_compliance() {
    info "Verifying ACL compliance..."

    warning "ACL verification must be done via admin console"
    info "1. Visit: https://login.tailscale.com/admin/acls"
    info "2. Click 'Test' to validate ACL syntax"
    info "3. Review access rules for tag:$TAILSCALE_TAG"

    # Check device tags
    local tags=$(tailscale status --json | jq -r '.Self.Tags[]?' 2>/dev/null)

    if [ -n "$tags" ]; then
        success "Device tags:"
        echo "$tags"
    else
        warning "No tags assigned to this device"
        info "Expected tag: $TAILSCALE_TAG"
    fi
}

# ============================================================================
# TROUBLESHOOTING FUNCTIONS
# ============================================================================

troubleshoot_connection() {
    info "Running connection troubleshooting..."

    # Check Tailscale daemon status
    info "Checking Tailscale daemon..."
    if pgrep -f tailscaled &>/dev/null; then
        success "tailscaled is running"
    else
        error "tailscaled is not running"
        info "Start with: sudo systemctl start tailscaled (Linux)"
        info "           : sudo brew services start tailscale (macOS)"
    fi

    # Check firewall
    info "Checking firewall configuration..."
    local os=$(detect_os)

    case "$os" in
        macos)
            if sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate | grep -q "enabled"; then
                warning "macOS firewall is enabled"
                info "Ensure Tailscale is allowed in System Preferences > Security & Privacy > Firewall"
            fi
            ;;
        ubuntu|debian)
            if command -v ufw &>/dev/null && sudo ufw status | grep -q "active"; then
                warning "UFW firewall is active"
                info "Allow Tailscale: sudo ufw allow in on tailscale0"
            fi
            ;;
        fedora|rhel|centos)
            if command -v firewall-cmd &>/dev/null && sudo firewall-cmd --state 2>/dev/null | grep -q "running"; then
                warning "firewalld is running"
                info "Allow Tailscale: sudo firewall-cmd --add-interface=tailscale0 --zone=trusted --permanent"
            fi
            ;;
    esac

    # Check network connectivity
    info "Checking network connectivity..."
    if ping -c 1 -W 2 login.tailscale.com &>/dev/null; then
        success "Can reach Tailscale servers"
    else
        error "Cannot reach Tailscale servers"
        info "Check internet connection and firewall rules"
    fi

    # Check UDP port 41641
    info "Checking Tailscale UDP port..."
    if nc -uz -w1 login.tailscale.com 41641 2>/dev/null; then
        success "UDP port 41641 accessible"
    else
        warning "UDP port 41641 may be blocked"
        info "Tailscale uses UDP 41641 for peer connections"
    fi

    # Check logs
    info "Recent Tailscale logs:"
    if [ "$os" = "macos" ]; then
        log show --predicate 'process == "tailscaled"' --last 5m --info 2>/dev/null || echo "Cannot access system logs"
    else
        sudo journalctl -u tailscaled --since "5 minutes ago" --no-pager | tail -20
    fi
}

troubleshoot_auth() {
    info "Troubleshooting authentication..."

    # Check authentication status
    local status=$(tailscale status --json 2>/dev/null || echo '{}')
    local backend_state=$(echo "$status" | jq -r '.BackendState // "unknown"')

    info "Backend state: $backend_state"

    case "$backend_state" in
        "Running")
            success "Authenticated and running"
            ;;
        "NeedsLogin")
            error "Authentication required"
            info "Run: sudo tailscale up"
            ;;
        "NoState")
            error "Tailscale not started"
            info "Start daemon first"
            ;;
        *)
            warning "Unknown state: $backend_state"
            ;;
    esac

    # Check for auth key
    if [ -n "${TAILSCALE_AUTHKEY:-}" ]; then
        info "Auth key found in environment"
        info "Attempting automatic authentication..."
        sudo tailscale up --authkey="$TAILSCALE_AUTHKEY"
    else
        info "No TAILSCALE_AUTHKEY environment variable found"
        info "Generate auth key: https://login.tailscale.com/admin/settings/keys"
    fi
}

# ============================================================================
# UNINSTALL FUNCTIONS
# ============================================================================

uninstall_tailscale() {
    warning "Uninstalling Tailscale configuration..."

    read -p "This will disconnect from Tailscale network. Continue? [y/N] " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Uninstall cancelled"
        return 0
    fi

    # Logout from Tailscale
    info "Logging out from Tailscale..."
    sudo tailscale logout

    # Stop Tailscale service
    info "Stopping Tailscale service..."
    local os=$(detect_os)

    case "$os" in
        macos)
            sudo brew services stop tailscale
            ;;
        *)
            sudo systemctl stop tailscaled
            ;;
    esac

    success "Tailscale disconnected"
    info "To fully remove Tailscale:"
    info "  macOS: brew uninstall tailscale"
    info "  Linux: sudo apt remove tailscale (Ubuntu/Debian)"
    info "        sudo dnf remove tailscale (Fedora/RHEL)"
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

show_help() {
    cat << EOF
Tailscale Setup for ClawdBot Network Isolation
Version: $SCRIPT_VERSION

USAGE:
    $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --install          Install Tailscale (if not present)
    --configure        Configure Tailscale for ClawdBot
    --acl-file FILE    Path to custom ACL configuration file
    --tag TAG          Device tag (default: tag:clawdbot)
    --subnet CIDR      Advertise subnet routes
    --exit-node        Configure as exit node
    --dns DOMAINS      Configure MagicDNS domains
    --verify           Verify Tailscale setup
    --troubleshoot     Run troubleshooting checks
    --uninstall        Remove Tailscale configuration
    --help             Show this help message

EXAMPLES:
    # Install and configure with defaults
    $SCRIPT_NAME --install --configure

    # Configure with custom tag and subnet
    $SCRIPT_NAME --configure --tag tag:clawdbot-prod --subnet 10.0.0.0/24

    # Configure as exit node with custom ACL
    $SCRIPT_NAME --configure --exit-node --acl-file custom_acl.json

    # Verify setup
    $SCRIPT_NAME --verify

    # Troubleshoot connection issues
    $SCRIPT_NAME --troubleshoot

WORKFLOW:
    1. Install Tailscale: $SCRIPT_NAME --install
    2. Configure: $SCRIPT_NAME --configure
    3. Upload ACL via admin console
    4. Verify: $SCRIPT_NAME --verify

For more information:
    - Tailscale docs: https://tailscale.com/kb/
    - ClawdBot security: docs/guides/03-network-isolation.md

EOF
}

main() {
    # Create log directory
    mkdir -p "$LOG_DIR"

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install)
                DO_INSTALL=true
                shift
                ;;
            --configure)
                DO_CONFIGURE=true
                shift
                ;;
            --acl-file)
                TAILSCALE_ACL_FILE="$2"
                shift 2
                ;;
            --tag)
                TAILSCALE_TAG="$2"
                shift 2
                ;;
            --subnet)
                TAILSCALE_SUBNET="$2"
                shift 2
                ;;
            --exit-node)
                TAILSCALE_EXIT_NODE=true
                shift
                ;;
            --dns)
                TAILSCALE_DNS_DOMAINS="$2"
                shift 2
                ;;
            --verify)
                DO_VERIFY=true
                shift
                ;;
            --troubleshoot)
                DO_TROUBLESHOOT=true
                shift
                ;;
            --uninstall)
                DO_UNINSTALL=true
                shift
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
    done

    # Print header
    print_color "$BLUE" "========================================"
    print_color "$BLUE" "Tailscale Setup for ClawdBot"
    print_color "$BLUE" "Version: $SCRIPT_VERSION"
    print_color "$BLUE" "========================================"
    echo

    # Handle uninstall
    if [ "$DO_UNINSTALL" = true ]; then
        uninstall_tailscale
        exit 0
    fi

    # Handle troubleshoot
    if [ "$DO_TROUBLESHOOT" = true ]; then
        troubleshoot_connection
        troubleshoot_auth
        exit 0
    fi

    # Install Tailscale
    if [ "$DO_INSTALL" = true ]; then
        install_tailscale
    fi

    # Configure Tailscale
    if [ "$DO_CONFIGURE" = true ]; then
        # Generate ACL if not provided
        if [ -z "$TAILSCALE_ACL_FILE" ]; then
            TAILSCALE_ACL_FILE="$CONFIG_DIR/tailscale_acl.json"
            mkdir -p "$CONFIG_DIR"
            generate_default_acl "$TAILSCALE_ACL_FILE"
        fi

        # Authenticate
        authenticate_tailscale

        # Upload ACL
        upload_acl_configuration "$TAILSCALE_ACL_FILE"

        # Configure DNS
        configure_dns

        success "Tailscale configuration complete"
    fi

    # Verify setup
    if [ "$DO_VERIFY" = true ]; then
        verify_installation
        verify_connectivity
        verify_acl_compliance
    fi

    # Final status
    echo
    info "Tailscale status:"
    tailscale status 2>/dev/null || error "Tailscale not running"

    echo
    info "Log file: $LOG_FILE"
    success "Setup complete!"
}

main "$@"
