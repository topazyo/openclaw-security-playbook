# VPN Setup Scripts for ClawdBot Network Isolation

Complete automated VPN setup scripts implementing **Layer 2: Network Isolation** from the ClawdBot Security Playbook.

---

## Overview

These scripts provide two VPN solutions for securing ClawdBot deployments:

1. **Tailscale** - Zero-configuration mesh VPN with centralized management
2. **WireGuard** - Self-hosted VPN with complete infrastructure control

Both scripts automate installation, configuration, and verification across macOS and Linux platforms.

---

## Scripts

### 1. Tailscale Setup (`tailscale_setup.sh`)

**Purpose:** Easy-to-use mesh VPN with automatic NAT traversal and centralized ACL management

**Best For:**
- Teams distributed across multiple networks
- Dynamic IP addresses (laptops, mobile devices)
- Users who want zero-configuration setup
- Environments with strict firewall rules
- Need for centralized access control

**Features:**
- ✅ Automatic NAT traversal (no port forwarding needed)
- ✅ Centralized ACL configuration
- ✅ MagicDNS for device discovery
- ✅ Device tagging and grouping
- ✅ Multi-user access control
- ✅ Free tier available (20 devices)
- ✅ Subnet routing support
- ✅ Exit node capabilities

### 2. WireGuard Setup (`wireguard_setup.sh`)

**Purpose:** Self-hosted VPN with complete control and maximum privacy

**Best For:**
- Users who want fully open-source solutions
- Self-hosted infrastructure requirements
- Maximum privacy (no third-party servers)
- Static server IP addresses
- Full control over encryption and routing

**Features:**
- ✅ Fully open-source (client and server)
- ✅ No third-party coordination servers
- ✅ Self-hosted infrastructure
- ✅ Automatic key generation
- ✅ QR code generation for mobile
- ✅ Server and client modes
- ✅ Multi-peer support
- ✅ Firewall auto-configuration

---

## Feature Comparison

| Feature | Tailscale | WireGuard |
|---------|-----------|-----------|
| **Setup Complexity** | Very Easy | Moderate |
| **NAT Traversal** | Automatic | Manual (port forward) |
| **Third-Party Server** | Yes (Tailscale) | No |
| **Open Source** | Client only | Fully |
| **ACL Management** | Centralized web UI | Manual config files |
| **MagicDNS** | Yes | Manual setup |
| **Device Tagging** | Yes | No |
| **Cost** | Free (≤20 devices) | Free |
| **Mobile Apps** | Excellent | Good |
| **Key Management** | Automatic | Automatic (via script) |
| **Peer Discovery** | Automatic | Manual |
| **Performance** | Excellent | Excellent |
| **Security** | WireGuard protocol | WireGuard protocol |

---

## Installation

### Prerequisites

#### Both Scripts
- macOS 10.14+ or Linux (Ubuntu, Debian, Fedora, Arch)
- `sudo`/root access
- Internet connection

#### Tailscale Additional
- Tailscale account (free: https://login.tailscale.com/start)

#### WireGuard Additional
- Server with public IP or port forwarding
- `qrencode` for mobile QR codes (optional)

---

## Usage

### Tailscale Setup

#### Quick Start
```bash
# Install and configure
sudo ./scripts/hardening/vpn/tailscale_setup.sh --install --configure

# Follow authentication link in browser
# Upload ACL via admin console

# Verify setup
./scripts/hardening/vpn/tailscale_setup.sh --verify
```

#### Full Workflow
```bash
# 1. Install Tailscale
sudo ./tailscale_setup.sh --install

# 2. Configure with custom settings
sudo ./tailscale_setup.sh --configure \
    --tag tag:clawdbot-prod \
    --subnet 10.0.0.0/24 \
    --dns clawdbot.internal

# 3. Authenticate (opens browser)
# Click link and authenticate with Tailscale account

# 4. Upload ACL configuration
# File generated at: ~/.openclaw/config/tailscale_acl.json
# Upload via: https://login.tailscale.com/admin/acls

# 5. Verify connectivity
./tailscale_setup.sh --verify

# 6. Check status
tailscale status
```

#### Custom ACL Configuration
```bash
# Use custom ACL file
./tailscale_setup.sh --configure \
    --acl-file /path/to/custom_acl.json
```

#### Troubleshooting
```bash
# Run diagnostics
./tailscale_setup.sh --troubleshoot

# Check connection issues
./tailscale_setup.sh --verify
```

---

### WireGuard Setup

#### Server Setup (Typical Workflow)
```bash
# 1. Install WireGuard
sudo ./scripts/hardening/vpn/wireguard_setup.sh --install

# 2. Configure as server
sudo ./wireguard_setup.sh --mode server --configure

# Server will:
# - Generate keys automatically
# - Detect public IP
# - Configure firewall
# - Set up NAT forwarding

# 3. Start WireGuard
sudo ./wireguard_setup.sh --start

# 4. Add first client peer
sudo ./wireguard_setup.sh \
    --add-peer \
    --peer-name laptop-alice \
    --show-qr

# QR code and config file will be displayed
# Share with client

# 5. Verify server
sudo ./wireguard_setup.sh --verify
```

#### Client Setup (Typical Workflow)
```bash
# 1. Install WireGuard
sudo ./scripts/hardening/vpn/wireguard_setup.sh --install

# 2. Configure as client
sudo ./wireguard_setup.sh --mode client --configure \
    --server-ip 1.2.3.4

# You'll be prompted for server's public key

# 3. Share your public key with server admin
# (displayed during configuration)

# 4. Wait for server admin to add you as peer

# 5. Start WireGuard
sudo ./wireguard_setup.sh --start

# 6. Verify connection
sudo ./wireguard_setup.sh --verify
ping 10.66.66.1  # Server VPN IP
```

#### Add Additional Peers (Server)
```bash
# Add peer with QR code
sudo ./wireguard_setup.sh \
    --add-peer \
    --peer-name phone-bob \
    --show-qr

# Scan QR code with mobile WireGuard app
```

#### Advanced Configuration
```bash
# Custom network range
sudo ./wireguard_setup.sh --mode server --configure \
    --network 192.168.100.0/24 \
    --server-port 443

# Custom DNS servers
sudo ./wireguard_setup.sh --mode client --configure \
    --server-ip vpn.example.com \
    --dns 8.8.8.8,8.8.4.4
```

---

## Configuration Examples

### Tailscale ACL Configuration

Default ACL generated by script (`~/.openclaw/config/tailscale_acl.json`):

```json
{
  "tagOwners": {
    "tag:clawdbot": ["autogroup:admin"],
    "tag:clawdbot-prod": ["autogroup:admin"],
    "tag:clawdbot-dev": ["autogroup:admin"]
  },

  "acls": [
    {
      "action": "accept",
      "src": ["tag:clawdbot"],
      "dst": ["tag:clawdbot:*"]
    },
    {
      "action": "accept",
      "src": ["tag:clawdbot-gateway"],
      "dst": [
        "tag:clawdbot-prod:443",
        "tag:clawdbot-prod:8443"
      ]
    }
  ],

  "dnsConfig": {
    "domains": ["clawdbot.internal"],
    "magicDNS": true
  }
}
```

**Usage:**
1. Upload via: https://login.tailscale.com/admin/acls
2. Modify tags and rules as needed
3. Test ACL syntax before saving

---

### WireGuard Configuration

#### Server Configuration (`/etc/wireguard/wg0.conf`)
```ini
[Interface]
PrivateKey = SERVER_PRIVATE_KEY
Address = 10.66.66.1/24
ListenPort = 51820
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

[Peer]
PublicKey = CLIENT_PUBLIC_KEY
AllowedIPs = 10.66.66.2/32
```

#### Client Configuration (`/etc/wireguard/wg0.conf`)
```ini
[Interface]
PrivateKey = CLIENT_PRIVATE_KEY
Address = 10.66.66.2/24
DNS = 1.1.1.1, 1.0.0.1

[Peer]
PublicKey = SERVER_PUBLIC_KEY
Endpoint = SERVER_IP:51820
AllowedIPs = 10.66.66.0/24
PersistentKeepalive = 25
```

---

## Network Architecture

### Tailscale Mesh Network

```
                     Tailscale
                  Coordination Server
                  login.tailscale.com
                          |
        ╭─────────────────┼─────────────────╮
        |                 |                 |
   [Device A]        [Device B]        [Device C]
   tag:clawdbot      tag:clawdbot      tag:clawdbot-dev
   100.64.1.1        100.64.1.2        100.64.1.3
        |                 |                 |
        └─────────────────┴─────────────────┘
          Direct P2P connections
          (automatic NAT traversal)
```

**Benefits:**
- Automatic NAT traversal
- Direct P2P connections when possible
- DERP relay fallback
- Centralized ACL management

---

### WireGuard Star Topology

```
                   WireGuard Server
                   vpn.example.com
                   (10.66.66.1)
                   UDP Port 51820
                          |
        ╭─────────────────┼─────────────────╮
        |                 |                 |
   [Client A]        [Client B]        [Client C]
   10.66.66.2        10.66.66.3        10.66.66.4
   (Laptop)          (Phone)           (Desktop)
```

**Benefits:**
- Full control over infrastructure
- No third-party servers
- Self-hosted privacy
- Simple topology

---

## Security Considerations

### Tailscale

**Advantages:**
- ✅ Automatic certificate management
- ✅ Centralized ACL enforcement
- ✅ Device authentication via OAuth
- ✅ Regular security audits

**Considerations:**
- ⚠️ Coordination server knows network topology
- ⚠️ Requires trust in Tailscale Inc.
- ⚠️ Some client code is proprietary

**Mitigation:**
- Use self-hosted Headscale (open-source Tailscale control server)
- Review ACLs regularly
- Monitor device connections

### WireGuard

**Advantages:**
- ✅ Fully open-source
- ✅ No third-party servers
- ✅ Complete infrastructure control
- ✅ Audited cryptography

**Considerations:**
- ⚠️ Manual key management
- ⚠️ Requires secure key distribution
- ⚠️ Server IP exposure

**Mitigation:**
- Secure key exchange (out-of-band)
- Regular key rotation
- Monitor server logs
- Use DDoS protection

---

## ClawdBot Integration

### Network Isolation Strategy

Both VPN solutions implement **Layer 2: Network Isolation** by:

1. **Restricting Access** - Only VPN-connected devices can reach ClawdBot services
2. **Segmentation** - Separate production and development environments
3. **Encryption** - All traffic encrypted in transit
4. **Access Control** - Fine-grained rules for service access

### Example: Production Deployment

#### Tailscale Approach
```bash
# Tag production gateway
./tailscale_setup.sh --configure --tag tag:clawdbot-prod

# ACL restricts access to production services
# Only devices with tag:clawdbot-prod can connect
```

#### WireGuard Approach
```bash
# Server hosts ClawdBot gateway
sudo ./wireguard_setup.sh --mode server --configure

# Only peers with valid keys can connect
# Firewall rules block non-VPN traffic
```

### ClawdBot Configuration

Update `~/.openclaw/config/gateway.yml`:

```yaml
server:
  # Listen only on VPN interface
  host: "10.66.66.1"  # WireGuard
  # or
  host: "100.64.1.1"  # Tailscale

  port: 8443

security:
  # Allow connections only from VPN network
  allowed_networks:
    - "10.66.66.0/24"     # WireGuard
    - "100.64.0.0/10"     # Tailscale
```

---

## Verification

### Tailscale Verification
```bash
# Check status
tailscale status

# Expected output:
# 100.64.1.1   hostname     username@   linux   active; direct [IP]:port

# Test connectivity to peer
ping 100.64.1.2

# Verify ACL
# Visit: https://login.tailscale.com/admin/acls
```

### WireGuard Verification
```bash
# Check interface
sudo wg show wg0

# Expected output shows:
# - interface public key
# - listening port
# - peers with latest handshake

# Test connectivity to server
ping 10.66.66.1

# Check logs
sudo journalctl -u wg-quick@wg0
```

### Security Verification

Run the ClawdBot security verification:
```bash
./scripts/verification/verify_openclaw_security.sh --layer 2
```

Expected results:
- ✅ VPN interface is up
- ✅ ClawdBot listening only on VPN interface
- ✅ Firewall rules block non-VPN access
- ✅ Encryption is active

---

## Troubleshooting

### Tailscale Issues

#### Issue: Cannot Authenticate
```bash
# Check authentication status
tailscale status

# Re-authenticate
sudo tailscale up

# Check logs
# macOS: Console app > "tailscale"
# Linux: sudo journalctl -u tailscaled
```

#### Issue: No Connectivity to Peers
```bash
# Run diagnostics
./tailscale_setup.sh --troubleshoot

# Check firewall (allow UDP 41641)
sudo ufw allow 41641/udp

# Check NAT traversal
tailscale netcheck
```

#### Issue: ACL Denying Access
```bash
# Review ACLs
# Visit: https://login.tailscale.com/admin/acls

# Test ACL syntax
# Use "Test" button in ACL editor

# Check device tags
tailscale status --json | jq '.Self.Tags'
```

---

### WireGuard Issues

#### Issue: Cannot Connect to Server
```bash
# Check if server is listening
sudo netstat -ulnp | grep 51820

# Test firewall
nc -uz SERVER_IP 51820

# Check routing
ip route show

# Verify keys
sudo wg show wg0
```

#### Issue: No Internet Through VPN
```bash
# Check IP forwarding (server)
cat /proc/sys/net/ipv4/ip_forward
# Should be: 1

# Check NAT rules (server)
sudo iptables -t nat -L -n

# Check DNS (client)
cat /etc/resolv.conf
```

#### Issue: Handshake Failing
```bash
# Check peer public keys match
# Server: cat /etc/wireguard/wg0.conf
# Client: cat /etc/wireguard/wg0.conf

# Verify endpoint reachable
ping SERVER_IP

# Check time sync (required for handshake)
timedatectl
```

---

## Advanced Topics

### Tailscale: Subnet Routing

Expose local network to VPN:

```bash
# On gateway device
./tailscale_setup.sh --configure --subnet 192.168.1.0/24

# Approve in admin console
# Settings > Subnet routes > Approve

# From other devices
ping 192.168.1.100  # Local network device
```

### Tailscale: Exit Nodes

Route all traffic through exit node:

```bash
# Configure as exit node
./tailscale_setup.sh --configure --exit-node

# Approve in admin console
# Machines > Edit > Use as exit node

# Use exit node (client)
sudo tailscale up --exit-node=DEVICE_NAME
```

### WireGuard: Full Tunnel

Route all traffic through VPN:

**Client Configuration:**
```ini
[Peer]
AllowedIPs = 0.0.0.0/0  # Route ALL traffic
```

**Server Requirements:**
- IP forwarding enabled
- NAT masquerading configured
- DNS resolver running

### WireGuard: Site-to-Site VPN

Connect two networks:

**Site A Server:**
```ini
[Interface]
Address = 10.66.66.1/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = SITE_B_PUBLIC_KEY
AllowedIPs = 10.66.77.0/24, 192.168.2.0/24
```

**Site B Server:**
```ini
[Interface]
Address = 10.66.77.1/24
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = SITE_A_PUBLIC_KEY
AllowedIPs = 10.66.66.0/24, 192.168.1.0/24
```

---

## Performance Tuning

### WireGuard Optimization

```ini
# Reduce MTU for better compatibility
[Interface]
MTU = 1420

# Increase keepalive for unreliable connections
[Peer]
PersistentKeepalive = 15

# Use DNS load balancing
DNS = 1.1.1.1, 1.0.0.1, 8.8.8.8
```

### Tailscale Optimization

```bash
# Prefer direct connections
sudo tailscale up --accept-routes=false

# Disable key expiry for stable connections
# Admin console > Settings > Keys > Disable expiry

# Use nearest DERP relay
tailscale netcheck  # Shows latency to relays
```

---

## Cost Comparison

| Aspect | Tailscale | WireGuard |
|--------|-----------|-----------|
| **Software** | Free | Free |
| **Hosting** | Free (≤20 devices) | VPS: $5-10/month |
| **Bandwidth** | Included | VPS-dependent |
| **Support** | Community + Paid | Community only |
| **Enterprise** | Custom pricing | DIY or paid support |

---

## Migration Guide

### From Tailscale to WireGuard

```bash
# 1. Note Tailscale IP addresses
tailscale status > tailscale_ips.txt

# 2. Set up WireGuard server
sudo ./wireguard_setup.sh --install --mode server --configure

# 3. Add peers matching Tailscale devices
for peer in device1 device2 device3; do
    sudo ./wireguard_setup.sh --add-peer --peer-name $peer
done

# 4. Update ClawdBot configs with new IPs

# 5. Test WireGuard connectivity

# 6. Logout from Tailscale
sudo tailscale logout
```

### From WireGuard to Tailscale

```bash
# 1. Note WireGuard peer IPs
sudo wg show wg0 > wireguard_peers.txt

# 2. Install and configure Tailscale
./tailscale_setup.sh --install --configure

# 3. Add all peers to Tailscale network

# 4. Update ClawdBot configs with Tailscale IPs

# 5. Test Tailscale connectivity

# 6. Stop WireGuard
sudo ./wireguard_setup.sh --stop
```

---

## Best Practices

### General

1. **Regular Updates** - Keep VPN software updated
2. **Key Rotation** - Rotate keys periodically (WireGuard)
3. **Monitoring** - Monitor connection logs
4. **Documentation** - Document network topology
5. **Backups** - Backup VPN configurations

### Tailscale

1. **Review ACLs** - Audit ACL rules regularly
2. **Device Management** - Remove unused devices
3. **Tags** - Use tags for access control
4. **MagicDNS** - Use MagicDNS for device discovery
5. **Subnet Routes** - Minimize exposed subnets

### WireGuard

1. **Key Security** - Never share private keys
2. **Firewall Rules** - Restrict server access
3. **Log Monitoring** - Monitor handshake failures
4. **Backup Configs** - Backup peer configurations
5. **IP Management** - Document peer IP assignments

---

## Quick Reference

### Tailscale Commands
```bash
# Status
tailscale status

# Connect/disconnect
sudo tailscale up
sudo tailscale down

# Show IP
tailscale ip -4

# List peers
tailscale status --json | jq '.Peer | keys'

# Network diagnostics
tailscale netcheck
```

### WireGuard Commands
```bash
# Status
sudo wg show wg0

# Start/stop
sudo wg-quick up wg0
sudo wg-quick down wg0

# Add peer dynamically
sudo wg set wg0 peer PUBLIC_KEY allowed-ips 10.66.66.x/32

# Show interface
ip addr show wg0

# Check handshake
sudo wg show wg0 latest-handshakes
```

---

## Support and Resources

### Documentation
- **Tailscale Docs:** https://tailscale.com/kb/
- **WireGuard Docs:** https://www.wireguard.com/
- **ClawdBot Security:** `docs/guides/03-network-isolation.md`

### Community
- **Tailscale Forum:** https://forum.tailscale.com/
- **WireGuard Mailing List:** https://lists.zx2c4.com/mailman/listinfo/wireguard

### Issues
- **ClawdBot Issues:** https://github.com/YOUR-ORG/clawdbot-security-playbook/issues
- **Script Issues:** Include output from `--troubleshoot` flag

---

**Version:** 1.0.0  
**Last Updated:** February 14, 2026  
**Maintained by:** ClawdBot Security Team
