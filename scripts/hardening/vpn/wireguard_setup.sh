#!/bin/bash
#
# wireguard_setup.sh
# Complete WireGuard Setup for ClawdBot Network Isolation
#
# This script automates WireGuard installation and configuration for secure
# network isolation without third-party coordination servers.
#
# Features:
#   - Automated WireGuard installation (macOS, Linux)
#   - Server and client mode configuration
#   - Automatic key generation and management
#   - Firewall rules (iptables/nftables/pf)
#   - NAT traversal and port forwarding
#   - Multi-peer support
#   - DNS configuration
#   - Connection verification
#   - Comprehensive troubleshooting
#   - QR code generation for mobile clients
#
# Usage:
#   ./wireguard_setup.sh [OPTIONS]
#
# Options:
#   --install          Install WireGuard (if not present)
#   --mode MODE        Mode: server or client (required for --configure)
#   --configure        Configure WireGuard
#   --server-ip IP     Server public IP or domain
#   --server-port PORT Server listening port (default: 51820)
#   --network CIDR     VPN network CIDR (default: 10.66.66.0/24)
#   --dns SERVERS      DNS servers (default: 1.1.1.1,1.0.0.1)
#   --add-peer         Add a new peer configuration
#   --peer-name NAME   Peer name for identification
#   --show-qr          Show QR code for peer config
#   --verify           Verify WireGuard setup
#   --troubleshoot     Run troubleshooting checks
#   --stop             Stop WireGuard
#   --start            Start WireGuard
#   --uninstall        Remove WireGuard configuration
#   --help             Show this help message
#
# Example:
#   # Install and configure as server
#   ./wireguard_setup.sh --install --mode server --configure
#
#   # Configure as client connecting to server
#   ./wireguard_setup.sh --mode client --configure --server-ip 1.2.3.4
#
#   # Add a new peer (from server)
#   ./wireguard_setup.sh --add-peer --peer-name laptop-alice --show-qr
#
#   # Verify connection
#   ./wireguard_setup.sh --verify
#
# Requirements:
#   - macOS 10.14+ or Linux (Ubuntu, Debian, Fedora, Arch)
#   - sudo/root access for installation and configuration
#   - Open UDP port (default: 51820) on server
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

# WireGuard configuration
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PORT="${WG_PORT:-51820}"
WG_NETWORK="${WG_NETWORK:-10.66.66.0/24}"
WG_SERVER_IP="${WG_SERVER_IP:-}"
WG_DNS="${WG_DNS:-1.1.1.1,1.0.0.1}"
WG_MODE=""  # server or client

# Paths
CONFIG_DIR="/etc/wireguard"
KEYS_DIR="$CONFIG_DIR/keys"
PEERS_DIR="$CONFIG_DIR/peers"
LOG_DIR="/var/log/wireguard"
LOG_FILE="$LOG_DIR/setup_$(date +%Y%m%d_%H%M%S).log"

# Runtime paths (user-specific)
USER_CONFIG_DIR="$HOME/.openclaw/wireguard"
USER_LOG="$HOME/.openclaw/logs/wireguard_setup_$(date +%Y%m%d_%H%M%S).log"

# Options
DO_INSTALL=false
DO_CONFIGURE=false
DO_ADD_PEER=false
DO_VERIFY=false
DO_TROUBLESHOOT=false
DO_STOP=false
DO_START=false
DO_UNINSTALL=false
DO_SHOW_QR=false
PEER_NAME=""

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
    mkdir -p "$(dirname "$USER_LOG")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$USER_LOG"
}

require_root() {
    if [ "$EUID" -ne 0 ]; then
        error "This operation requires root privileges"
        info "Run with: sudo $SCRIPT_NAME $*"
        exit 1
    fi
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

check_wireguard_installed() {
    if command -v wg &> /dev/null; then
        return 0
    else
        return 1
    fi
}

check_wireguard_running() {
    if wg show "$WG_INTERFACE" &> /dev/null; then
        return 0
    else
        return 1
    fi
}

# ============================================================================
# INSTALLATION FUNCTIONS
# ============================================================================

install_wireguard_macos() {
    info "Installing WireGuard on macOS..."

    if ! command -v brew &> /dev/null; then
        error "Homebrew not found. Install from: https://brew.sh"
        exit 1
    fi

    # Install WireGuard tools
    brew install wireguard-tools

    # Install WireGuard app (GUI)
    brew install --cask wireguard

    success "WireGuard installed on macOS"
    info "WireGuard app available in Applications"
}

install_wireguard_ubuntu() {
    info "Installing WireGuard on Ubuntu/Debian..."

    sudo apt-get update
    sudo apt-get install -y wireguard wireguard-tools qrencode

    success "WireGuard installed on Ubuntu/Debian"
}

install_wireguard_fedora() {
    info "Installing WireGuard on Fedora/RHEL..."

    sudo dnf install -y wireguard-tools qrencode

    success "WireGuard installed on Fedora/RHEL"
}

install_wireguard_arch() {
    info "Installing WireGuard on Arch Linux..."

    sudo pacman -S --noconfirm wireguard-tools qrencode

    success "WireGuard installed on Arch Linux"
}

install_wireguard() {
    if check_wireguard_installed; then
        success "WireGuard already installed"
        wg --version
        return 0
    fi

    local os=$(detect_os)

    case "$os" in
        macos)
            install_wireguard_macos
            ;;
        ubuntu|debian)
            install_wireguard_ubuntu
            ;;
        fedora|rhel|centos)
            install_wireguard_fedora
            ;;
        arch)
            install_wireguard_arch
            ;;
        *)
            error "Unsupported OS: $os"
            info "Visit https://www.wireguard.com/install/ for manual installation"
            exit 1
            ;;
    esac
}

# ============================================================================
# KEY MANAGEMENT FUNCTIONS
# ============================================================================

generate_keys() {
    local name=$1
    local private_key_file="$KEYS_DIR/${name}_private.key"
    local public_key_file="$KEYS_DIR/${name}_public.key"

    info "Generating keys for: $name"

    # Create keys directory
    mkdir -p "$KEYS_DIR"
    chmod 700 "$KEYS_DIR"

    # Generate private key
    wg genkey > "$private_key_file"
    chmod 600 "$private_key_file"

    # Generate public key
    wg pubkey < "$private_key_file" > "$public_key_file"
    chmod 644 "$public_key_file"

    success "Keys generated:"
    info "  Private: $private_key_file"
    info "  Public:  $public_key_file"
}

get_or_create_keys() {
    local name=$1
    local private_key_file="$KEYS_DIR/${name}_private.key"
    local public_key_file="$KEYS_DIR/${name}_public.key"

    if [ ! -f "$private_key_file" ] || [ ! -f "$public_key_file" ]; then
        generate_keys "$name"
    fi

    echo "$private_key_file"
}

# ============================================================================
# NETWORK FUNCTIONS
# ============================================================================

get_server_public_ip() {
    # Try multiple methods to get public IP
    local public_ip=""

    # Method 1: ip API
    public_ip=$(curl -s https://api.ipify.org 2>/dev/null || true)

    # Method 2: ifconfig.me
    if [ -z "$public_ip" ]; then
        public_ip=$(curl -s https://ifconfig.me 2>/dev/null || true)
    fi

    # Method 3: dig
    if [ -z "$public_ip" ]; then
        public_ip=$(dig +short myip.opendns.com @resolver1.opendns.com 2>/dev/null || true)
    fi

    if [ -n "$public_ip" ]; then
        echo "$public_ip"
    else
        warning "Could not detect public IP automatically"
        read -p "Enter server public IP or domain: " public_ip
        echo "$public_ip"
    fi
}

allocate_ip_address() {
    # Allocate next available IP in the VPN network
    local network_prefix=$(echo "$WG_NETWORK" | cut -d'/' -f1 | cut -d'.' -f1-3)
    local existing_ips=$(wg show "$WG_INTERFACE" allowed-ips 2>/dev/null | awk '{print $2}' | cut -d'/' -f1 | cut -d'.' -f4 | sort -n || echo "")

    local next_ip=2

    while echo "$existing_ips" | grep -q "^${next_ip}$"; do
        ((next_ip++))
    done

    echo "${network_prefix}.${next_ip}"
}

# ============================================================================
# SERVER CONFIGURATION FUNCTIONS
# ============================================================================

configure_server() {
    require_root

    info "Configuring WireGuard server..."

    # Get or create server keys
    local server_private_key_file=$(get_or_create_keys "server")
    local server_private_key=$(cat "$server_private_key_file")

    # Get server public IP
    if [ -z "$WG_SERVER_IP" ]; then
        WG_SERVER_IP=$(get_server_public_ip)
    fi

    # Server IP in VPN network
    local server_vpn_ip=$(echo "$WG_NETWORK" | sed 's|0/24|1/24|')

    # Create server configuration
    info "Creating server configuration: $CONFIG_DIR/${WG_INTERFACE}.conf"

    cat > "$CONFIG_DIR/${WG_INTERFACE}.conf" << EOF
# WireGuard Server Configuration
# ClawdBot Network Isolation
# Generated: $(date)

[Interface]
# Server private key
PrivateKey = $server_private_key

# Server VPN IP address
Address = $server_vpn_ip

# Listening port
ListenPort = $WG_PORT

# Post-up rules (NAT and forwarding)
PostUp = iptables -A FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i $WG_INTERFACE -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Alternative for multiple interfaces
# PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
# PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Peers will be added below by add-peer command
EOF

    chmod 600 "$CONFIG_DIR/${WG_INTERFACE}.conf"

    # Enable IP forwarding
    info "Enabling IP forwarding..."
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -p > /dev/null

    # Configure firewall
    configure_firewall_server

    success "Server configured successfully"
    info "Server public IP: $WG_SERVER_IP"
    info "Server VPN IP: $server_vpn_ip"
    info "Listening port: $WG_PORT"

    # Save server info
    cat > "$USER_CONFIG_DIR/server_info.txt" << EOF
WireGuard Server Information
============================
Public IP: $WG_SERVER_IP
VPN Network: $WG_NETWORK
VPN IP: $server_vpn_ip
Port: $WG_PORT
Interface: $WG_INTERFACE
Public Key: $(cat "$KEYS_DIR/server_public.key")
EOF
}

configure_firewall_server() {
    info "Configuring firewall for WireGuard server..."

    local os=$(detect_os)

    case "$os" in
        ubuntu|debian)
            if command -v ufw &>/dev/null; then
                info "Configuring UFW..."
                sudo ufw allow "$WG_PORT/udp"
                sudo ufw reload
            elif command -v iptables &>/dev/null; then
                info "Configuring iptables..."
                sudo iptables -A INPUT -p udp --dport "$WG_PORT" -j ACCEPT
            fi
            ;;
        fedora|rhel|centos)
            if command -v firewall-cmd &>/dev/null; then
                info "Configuring firewalld..."
                sudo firewall-cmd --add-port="${WG_PORT}/udp" --permanent
                sudo firewall-cmd --add-masquerade --permanent
                sudo firewall-cmd --reload
            fi
            ;;
        macos)
            info "Configuring pf firewall..."
            warning "macOS firewall configuration may require manual setup"
            info "Allow UDP port $WG_PORT in System Preferences > Security & Privacy > Firewall"
            ;;
    esac

    success "Firewall configured"
}

# ============================================================================
# CLIENT CONFIGURATION FUNCTIONS
# ============================================================================

configure_client() {
    require_root

    info "Configuring WireGuard client..."

    # Validate server IP
    if [ -z "$WG_SERVER_IP" ]; then
        error "Server IP required for client configuration"
        info "Use: --server-ip <IP_OR_DOMAIN>"
        exit 1
    fi

    # Get or create client keys
    local client_name="client-$(hostname)"
    local client_private_key_file=$(get_or_create_keys "$client_name")
    local client_private_key=$(cat "$client_private_key_file")
    local client_public_key=$(cat "$KEYS_DIR/${client_name}_public.key")

    # Client IP in VPN network
    local client_vpn_ip=$(echo "$WG_NETWORK" | sed 's|0/24|2/32|')

    info "Requesting server public key..."
    warning "You need the server's public key to configure the client"
    read -p "Enter server public key: " server_public_key

    # Create client configuration
    info "Creating client configuration: $CONFIG_DIR/${WG_INTERFACE}.conf"

    cat > "$CONFIG_DIR/${WG_INTERFACE}.conf" << EOF
# WireGuard Client Configuration
# ClawdBot Network Isolation
# Generated: $(date)

[Interface]
# Client private key
PrivateKey = $client_private_key

# Client VPN IP address
Address = $client_vpn_ip

# DNS servers
DNS = $WG_DNS

[Peer]
# Server public key
PublicKey = $server_public_key

# Server endpoint
Endpoint = $WG_SERVER_IP:$WG_PORT

# Allowed IPs (routes through VPN)
# Use 0.0.0.0/0 to route all traffic through VPN
# Use $WG_NETWORK to route only VPN network traffic
AllowedIPs = $WG_NETWORK

# Keep connection alive (25 seconds)
PersistentKeepalive = 25
EOF

    chmod 600 "$CONFIG_DIR/${WG_INTERFACE}.conf"

    success "Client configured successfully"
    info "Your public key (share with server admin):"
    echo "$client_public_key"

    # Save client info
    mkdir -p "$USER_CONFIG_DIR"
    cat > "$USER_CONFIG_DIR/client_info.txt" << EOF
WireGuard Client Information
============================
Server: $WG_SERVER_IP:$WG_PORT
VPN IP: $client_vpn_ip
Interface: $WG_INTERFACE
Public Key: $client_public_key
EOF

    warning "Next steps:"
    info "1. Share your public key with the server admin"
    info "2. Ask admin to run: sudo $SCRIPT_NAME --add-peer --peer-name $(hostname)"
    info "3. Start WireGuard: sudo $SCRIPT_NAME --start"
}

# ============================================================================
# PEER MANAGEMENT FUNCTIONS
# ============================================================================

add_peer() {
    require_root

    if [ -z "$PEER_NAME" ]; then
        error "Peer name required"
        info "Use: --peer-name <NAME>"
        exit 1
    fi

    info "Adding peer: $PEER_NAME"

    # Generate keys for peer
    local peer_private_key_file=$(get_or_create_keys "$PEER_NAME")
    local peer_private_key=$(cat "$peer_private_key_file")
    local peer_public_key=$(cat "$KEYS_DIR/${PEER_NAME}_public.key")

    # Allocate IP for peer
    local peer_ip=$(allocate_ip_address)
    local peer_ip_cidr="${peer_ip}/32"

    info "Peer IP: $peer_ip"

    # Add peer to server configuration
    info "Adding peer to server configuration..."

    cat >> "$CONFIG_DIR/${WG_INTERFACE}.conf" << EOF

# Peer: $PEER_NAME
[Peer]
PublicKey = $peer_public_key
AllowedIPs = $peer_ip_cidr
EOF

    # Create peer configuration file
    mkdir -p "$PEERS_DIR"
    local peer_config="$PEERS_DIR/${PEER_NAME}.conf"

    # Get server info
    local server_public_key=$(cat "$KEYS_DIR/server_public.key")
    local server_vpn_ip=$(echo "$WG_NETWORK" | sed 's|0/24|1/24|')

    cat > "$peer_config" << EOF
# WireGuard Client Configuration
# Peer: $PEER_NAME
# Generated: $(date)

[Interface]
PrivateKey = $peer_private_key
Address = $peer_ip/24
DNS = $WG_DNS

[Peer]
PublicKey = $server_public_key
Endpoint = $WG_SERVER_IP:$WG_PORT
AllowedIPs = $WG_NETWORK
PersistentKeepalive = 25
EOF

    chmod 600 "$peer_config"

    success "Peer added successfully"
    info "Configuration saved: $peer_config"

    # Reload WireGuard
    if check_wireguard_running; then
        info "Reloading WireGuard configuration..."
        wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_INTERFACE")
    fi

    # Show QR code if requested
    if [ "$DO_SHOW_QR" = true ]; then
        show_qr_code "$peer_config"
    fi

    info "Share configuration with peer:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat "$peer_config"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

show_qr_code() {
    local config_file=$1

    if ! command -v qrencode &>/dev/null; then
        warning "qrencode not installed. Cannot generate QR code."
        return 1
    fi

    info "QR Code for mobile device:"
    echo
    qrencode -t ansiutf8 < "$config_file"
    echo
}

# ============================================================================
# START/STOP FUNCTIONS
# ============================================================================

start_wireguard() {
    require_root

    info "Starting WireGuard interface: $WG_INTERFACE"

    if check_wireguard_running; then
        warning "WireGuard already running"
        return 0
    fi

    # Start WireGuard
    wg-quick up "$WG_INTERFACE"

    if check_wireguard_running; then
        success "WireGuard started successfully"
        wg show "$WG_INTERFACE"
    else
        error "Failed to start WireGuard"
        return 1
    fi
}

stop_wireguard() {
    require_root

    info "Stopping WireGuard interface: $WG_INTERFACE"

    if ! check_wireguard_running; then
        warning "WireGuard not running"
        return 0
    fi

    # Stop WireGuard
    wg-quick down "$WG_INTERFACE"

    success "WireGuard stopped"
}

enable_autostart() {
    require_root

    info "Enabling WireGuard autostart..."

    local os=$(detect_os)

    case "$os" in
        macos)
            warning "macOS autostart requires WireGuard app or LaunchDaemon"
            info "Use WireGuard app for automatic connection"
            ;;
        *)
            systemctl enable "wg-quick@${WG_INTERFACE}.service"
            success "WireGuard will start automatically on boot"
            ;;
    esac
}

# ============================================================================
# VERIFICATION FUNCTIONS
# ============================================================================

verify_installation() {
    info "Verifying WireGuard installation..."

    local issues=0

    # Check if WireGuard is installed
    if check_wireguard_installed; then
        success "WireGuard installed"
        wg --version
    else
        error "WireGuard not installed"
        ((issues++))
    fi

    # Check if configuration exists
    if [ -f "$CONFIG_DIR/${WG_INTERFACE}.conf" ]; then
        success "Configuration file exists"
    else
        error "Configuration file not found: $CONFIG_DIR/${WG_INTERFACE}.conf"
        ((issues++))
    fi

    # Check if WireGuard is running
    if check_wireguard_running; then
        success "WireGuard interface is up"
    else
        warning "WireGuard interface is down"
        ((issues++))
    fi

    return $issues
}

verify_connectivity() {
    info "Verifying WireGuard connectivity..."

    if ! check_wireguard_running; then
        error "WireGuard not running"
        return 1
    fi

    # Show interface status
    info "Interface status:"
    wg show "$WG_INTERFACE"

    # Get peers
    local peers=$(wg show "$WG_INTERFACE" peers 2>/dev/null || true)

    if [ -z "$peers" ]; then
        warning "No peers configured"
        return 0
    fi

    # Test connectivity to each peer
    info "Testing peer connectivity..."

    while IFS= read -r peer_pubkey; do
        local peer_ip=$(wg show "$WG_INTERFACE" allowed-ips | grep "$peer_pubkey" | awk '{print $2}' | cut -d'/' -f1)

        if [ -n "$peer_ip" ]; then
            if ping -c 1 -W 2 "$peer_ip" &>/dev/null; then
                success "Peer reachable: $peer_ip"
            else
                warning "Cannot reach peer: $peer_ip"
            fi
        fi
    done <<< "$peers"
}

# ============================================================================
# TROUBLESHOOTING FUNCTIONS
# ============================================================================

troubleshoot_connection() {
    info "Running WireGuard troubleshooting..."

    # Check if interface exists
    if ip link show "$WG_INTERFACE" &>/dev/null; then
        success "Interface $WG_INTERFACE exists"
    else
        error "Interface $WG_INTERFACE not found"
        info "Check configuration and start WireGuard"
    fi

    # Check IP forwarding (server)
    local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "0")
    if [ "$ip_forward" = "1" ]; then
        success "IP forwarding enabled"
    else
        warning "IP forwarding disabled (required for server)"
        info "Enable with: echo 1 > /proc/sys/net/ipv4/ip_forward"
    fi

    # Check firewall rules
    info "Checking firewall..."

    if command -v iptables &>/dev/null; then
        local fw_rules=$(sudo iptables -L -n | grep -i wireguard || true)
        if [ -n "$fw_rules" ]; then
            success "WireGuard firewall rules present"
        else
            warning "No WireGuard firewall rules found"
        fi
    fi

    # Check listening port
    if sudo netstat -ulnp 2>/dev/null | grep -q ":${WG_PORT}.*wireguard\|wg"; then
        success "WireGuard listening on UDP port $WG_PORT"
    elif sudo ss -ulnp 2>/dev/null | grep -q ":${WG_PORT}.*wireguard\|wg"; then
        success "WireGuard listening on UDP port $WG_PORT"
    else
        warning "WireGuard not listening on UDP port $WG_PORT"
    fi

    # Check handshake
    if check_wireguard_running; then
        info "Checking peer handshakes..."
        wg show "$WG_INTERFACE" latest-handshakes
    fi

    # Check logs
    info "Recent system logs:"
    if command -v journalctl &>/dev/null; then
        sudo journalctl -u "wg-quick@${WG_INTERFACE}" --since "5 minutes ago" --no-pager | tail -20
    else
        tail -20 /var/log/syslog | grep -i wireguard || echo "No recent logs"
    fi
}

# ============================================================================
# UNINSTALL FUNCTIONS
# ============================================================================

uninstall_wireguard() {
    require_root

    warning "Uninstalling WireGuard configuration..."

    read -p "This will stop WireGuard and remove configuration. Continue? [y/N] " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Uninstall cancelled"
        return 0
    fi

    # Stop WireGuard
    if check_wireguard_running; then
        stop_wireguard
    fi

    # Disable autostart
    local os=$(detect_os)
    if [ "$os" != "macos" ]; then
        systemctl disable "wg-quick@${WG_INTERFACE}.service" 2>/dev/null || true
    fi

    # Backup configuration
    if [ -f "$CONFIG_DIR/${WG_INTERFACE}.conf" ]; then
        local backup_dir="$HOME/.openclaw/wireguard_backup_$(date +%Y%m%d_%H%M%S)"
        mkdir -p "$backup_dir"
        cp -r "$CONFIG_DIR" "$backup_dir/"
        info "Configuration backed up to: $backup_dir"
    fi

    # Remove configuration
    rm -f "$CONFIG_DIR/${WG_INTERFACE}.conf"

    success "WireGuard configuration removed"
    info "WireGuard package still installed (remove manually if desired)"
}

# ============================================================================
# MAIN FUNCTIONS
# ============================================================================

show_help() {
    cat << EOF
WireGuard Setup for ClawdBot Network Isolation
Version: $SCRIPT_VERSION

USAGE:
    sudo $SCRIPT_NAME [OPTIONS]

OPTIONS:
    --install          Install WireGuard (if not present)
    --mode MODE        Mode: server or client (required for --configure)
    --configure        Configure WireGuard
    --server-ip IP     Server public IP or domain
    --server-port PORT Server listening port (default: 51820)
    --network CIDR     VPN network CIDR (default: 10.66.66.0/24)
    --dns SERVERS      DNS servers (default: 1.1.1.1,1.0.0.1)
    --add-peer         Add a new peer configuration
    --peer-name NAME   Peer name for identification
    --show-qr          Show QR code for peer config
    --verify           Verify WireGuard setup
    --troubleshoot     Run troubleshooting checks
    --stop             Stop WireGuard
    --start            Start WireGuard
    --uninstall        Remove WireGuard configuration
    --help             Show this help message

EXAMPLES:
    # Install WireGuard
    sudo $SCRIPT_NAME --install

    # Configure as server
    sudo $SCRIPT_NAME --mode server --configure

    # Configure as client
    sudo $SCRIPT_NAME --mode client --configure --server-ip 1.2.3.4

    # Add peer and show QR code
    sudo $SCRIPT_NAME --add-peer --peer-name laptop-alice --show-qr

    # Start WireGuard
    sudo $SCRIPT_NAME --start

    # Verify setup
    sudo $SCRIPT_NAME --verify

WORKFLOW (Server):
    1. Install: sudo $SCRIPT_NAME --install
    2. Configure: sudo $SCRIPT_NAME --mode server --configure
    3. Start: sudo $SCRIPT_NAME --start
    4. Add peers: sudo $SCRIPT_NAME --add-peer --peer-name client1

WORKFLOW (Client):
    1. Install: sudo $SCRIPT_NAME --install
    2. Configure: sudo $SCRIPT_NAME --mode client --configure --server-ip <SERVER_IP>
    3. Share public key with server admin
    4. Start: sudo $SCRIPT_NAME --start

For more information:
    - WireGuard docs: https://www.wireguard.com/
    - ClawdBot security: docs/guides/03-network-isolation.md

EOF
}

main() {
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install)
                DO_INSTALL=true
                shift
                ;;
            --mode)
                WG_MODE="$2"
                shift 2
                ;;
            --configure)
                DO_CONFIGURE=true
                shift
                ;;
            --server-ip)
                WG_SERVER_IP="$2"
                shift 2
                ;;
            --server-port)
                WG_PORT="$2"
                shift 2
                ;;
            --network)
                WG_NETWORK="$2"
                shift 2
                ;;
            --dns)
                WG_DNS="$2"
                shift 2
                ;;
            --add-peer)
                DO_ADD_PEER=true
                shift
                ;;
            --peer-name)
                PEER_NAME="$2"
                shift 2
                ;;
            --show-qr)
                DO_SHOW_QR=true
                shift
                ;;
            --verify)
                DO_VERIFY=true
                shift
                ;;
            --troubleshoot)
                DO_TROUBLESHOOT=true
                shift
                ;;
            --stop)
                DO_STOP=true
                shift
                ;;
            --start)
                DO_START=true
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
    print_color "$BLUE" "WireGuard Setup for ClawdBot"
    print_color "$BLUE" "Version: $SCRIPT_VERSION"
    print_color "$BLUE" "========================================"
    echo

    # Handle non-root operations first
    if [ "$DO_INSTALL" = false ] && [ "$DO_CONFIGURE" = false ] && \
       [ "$DO_ADD_PEER" = false ] && [ "$DO_START" = false ] && \
       [ "$DO_STOP" = false ] && [ "$DO_UNINSTALL" = false ]; then
        # These can run without root
        if [ "$DO_VERIFY" = true ]; then
            verify_installation
            if check_wireguard_running; then
                verify_connectivity
            fi
        fi

        if [ "$DO_TROUBLESHOOT" = true ]; then
            troubleshoot_connection
        fi

        exit 0
    fi

    # Handle uninstall
    if [ "$DO_UNINSTALL" = true ]; then
        uninstall_wireguard
        exit 0
    fi

    # Install WireGuard
    if [ "$DO_INSTALL" = true ]; then
        install_wireguard
    fi

    # Stop WireGuard
    if [ "$DO_STOP" = true ]; then
        stop_wireguard
        exit 0
    fi

    # Start WireGuard
    if [ "$DO_START" = true ]; then
        start_wireguard
        enable_autostart
        exit 0
    fi

    # Configure WireGuard
    if [ "$DO_CONFIGURE" = true ]; then
        if [ "$WG_MODE" = "server" ]; then
            configure_server
            start_wireguard
            enable_autostart
        elif [ "$WG_MODE" = "client" ]; then
            configure_client
            info "Start WireGuard with: sudo $SCRIPT_NAME --start"
        else
            error "Invalid mode. Use --mode server or --mode client"
            exit 1
        fi
    fi

    # Add peer
    if [ "$DO_ADD_PEER" = true ]; then
        add_peer
    fi

    # Verify
    if [ "$DO_VERIFY" = true ]; then
        verify_installation
        verify_connectivity
    fi

    echo
    info "Log file: $USER_LOG"
    success "Setup complete!"
}

main "$@"
