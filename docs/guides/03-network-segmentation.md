# Network Segmentation Guide

**Layer 2 of 7-Layer Defense-in-Depth Model**

**Estimated Time:** 45 minutes  
**Difficulty:** Intermediate-Advanced  
**Prerequisites:** Basic networking knowledge, VPN familiarity

This guide covers network-level isolation to prevent unauthorized access to AI agent gateways, addressing the localhost authentication bypass vulnerability.

## Table of Contents

1. [The Problem: Localhost Authentication Bypass](#the-problem-localhost-authentication-bypass)
2. [Network Architecture](#network-architecture)
3. [Localhost-Only Binding](#localhost-only-binding)
4. [VPN-Based Access](#vpn-based-access)
5. [Reverse Proxy Hardening](#reverse-proxy-hardening)
6. [Firewall Configuration](#firewall-configuration)
7. [Zero Trust Network Access](#zero-trust-network-access)
8. [Monitoring and Alerts](#monitoring-and-alerts)

---

## The Problem: Localhost Authentication Bypass

### Attack Vector: Forwarding Trusted Connections

**Scenario:**
```
Developer Machine (Laptop)
├── ClawdBot: localhost:18789 (no auth required)
└── SSH Server: 0.0.0.0:22 (accessible)

Attacker's Machine
└── ssh user@dev-laptop.company.com -L 18789:localhost:18789

# Now attacker can access ClawdBot:
curl http://localhost:18789/v1/completions \
  -d '{"prompt":"Exfiltrate all credentials"}'
```

**Impact:**
- Localhost binding bypassed via SSH tunneling
- Reverse proxies can forward 127.0.0.1 connections
- ngrok/Tailscale can expose localhost services
- No authentication = full access

### Real-World Statistics

From 2024 reconnaissance:
- **83%** of exposed instances used localhost binding
- **67%** had reverse proxies forwarding localhost
- **45%** used ngrok/Cloudflare Tunnel
- **0%** required gateway authentication

**Result:** "Secure" localhost binding defeated

---

## Network Architecture

### Defense-in-Depth Network Model

```
┌──────────────────────────────────────────────────────┐
│                 Public Internet                       │
└───────────────────┬──────────────────────────────────┘
                    │ ❌ BLOCKED
                    ▼
          ┌──────────────────┐
          │  Firewall (deny) │
          └──────────────────┘
                    │
                    │ ✅ VPN Only
                    ▼
      ┌──────────────────────────┐
      │  VPN Server (Tailscale)  │
      │  WireGuard, OpenVPN      │
      └──────────┬───────────────┘
                 │
                 │ Authenticated + Encrypted
                 ▼
   ┌──────────────────────────────┐
   │   Internal Network (10.0.0.0/8) │
   │                                │
   │  ┌──────────────────────┐    │
   │  │ ClawdBot Gateway      │    │
   │  │ 127.0.0.1:18789       │    │
   │  │ + Auth Token Required │    │
   │  └──────────────────────┘    │
   └──────────────────────────────┘
```

**Key Principles:**
1. **Never expose directly to internet**
2. **VPN-only access** for remote connections
3. **Localhost binding** as first barrier
4. **Gateway authentication** as second barrier
5. **Rate limiting** as third barrier

---

## Localhost-Only Binding

### Step 1: Configure Localhost Binding

**Gateway Configuration (`~/.openclaw/config/gateway.yml`):**

```yaml
gateway:
  bind:
    # ⚠️ CRITICAL: localhost only (not 0.0.0.0)
    address: "127.0.0.1"
    port: 18789

  # NEVER use these:
  # address: "0.0.0.0"    # ❌ Binds to all interfaces
  # address: ""           # ❌ Defaults to 0.0.0.0
  # address: "::1"        # ⚠️ IPv6 localhost (use with caution)
```

### Step 2: Verify Binding

```bash
# Check listening sockets
ss -tlnp | grep 18789
# Expected: 127.0.0.1:18789 (NOT 0.0.0.0:18789)

# Alternative: netstat
netstat -tuln | grep 18789
# Expected: 127.0.0.1:18789

# Alternative: lsof
lsof -iTCP:18789 -sTCP:LISTEN
# Expected: localhost:18789
```

**What to look for:**
- ✅ `127.0.0.1:18789` — Correct (localhost only)
- ❌ `0.0.0.0:18789` — DANGER (all interfaces)
- ❌ `*:18789` — DANGER (all interfaces)
- ⚠️ `:::18789` — IPv6 all interfaces (if no IPv4 binding)

### Step 3: Test External Access

```bash
# Should FAIL (connection refused)
curl http://$(hostname -I | awk '{print $1}'):18789/health
# OR
curl http://your-server-ip:18789/health

# Expected: curl: (7) Failed to connect to ... Connection refused
```

If this succeeds, your gateway is EXPOSED — fix immediately.

### Step 4: Docker Localhost Binding

**Correct Docker port mapping:**
```bash
docker run -d \
  --name clawdbot \
  -p 127.0.0.1:18789:18789 \  # ← localhost only
  anthropic/clawdbot:latest

# NEVER use:
# -p 18789:18789            # ❌ Binds to 0.0.0.0
# -p 0.0.0.0:18789:18789    # ❌ Explicit all interfaces
```

---

## VPN-Based Access

### Option 1: Tailscale (Recommended for Simplicity)

**What is Tailscale?**
- WireGuard-based mesh VPN
- Zero-config peer-to-peer networking
- Automatic NAT traversal
- SSO integration (Google, GitHub, Okta)

**Installation:**

```bash
# macOS
brew install tailscale
sudo tailscale up

# Linux
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up

# Windows
# Download from https://tailscale.com/download/windows
```

**Configuration:**

```bash
# Connect to Tailscale network
sudo tailscale up --authkey=YOUR-AUTH-KEY

# Get your Tailscale IP
tailscale ip -4
# Output: 100.x.y.z

# Configure ClawdBot to listen on Tailscale interface (optional)
cat >> ~/.openclaw/config/gateway.yml << 'EOF'
gateway:
  bind:
    address: "100.x.y.z"  # Your Tailscale IP
    port: 18789

  acl:
    allowed_ips:
      - "100.0.0.0/8"  # Tailscale subnet
EOF
```

**Access Control:**

```json
// Tailscale ACL (Admin Console → Access Controls)
{
  "acls": [
    {
      "action": "accept",
      "src": ["group:engineering"],
      "dst": ["tag:clawdbot:18789"]
    }
  ],
  "groups": {
    "group:engineering": [
      "user1@company.com",
      "user2@company.com"
    ]
  },
  "tagOwners": {
    "tag:clawdbot": ["group:engineering-leads"]
  }
}
```

**Benefits:**
- ✅ Automatic encryption (WireGuard)
- ✅ No firewall configuration needed
- ✅ Works behind NAT
- ✅ SSO integration
- ✅ Free for personal use (up to 20 devices)

### Option 2: WireGuard (Recommended for Customization)

**Server Setup (Ubuntu):**

```bash
# Install WireGuard
sudo apt-get update
sudo apt-get install wireguard

# Generate server keys
umask 077
wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key

# Create server configuration
sudo cat > /etc/wireguard/wg0.conf << 'EOF'
[Interface]
PrivateKey = <SERVER_PRIVATE_KEY>
Address = 10.0.0.1/24
ListenPort = 51820
SaveConfig = true

# Enable IP forwarding
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# Client 1
[Peer]
PublicKey = <CLIENT1_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32

# Client 2
[Peer]
PublicKey = <CLIENT2_PUBLIC_KEY>
AllowedIPs = 10.0.0.3/32
EOF

# Start WireGuard
sudo systemctl enable wg-quick@wg0
sudo systemctl start wg-quick@wg0
```

**Client Configuration:**

```bash
# Generate client keys
wg genkey | tee client_private.key | wg pubkey > client_public.key

# Create client configuration
cat > ~/.config/wireguard/clawdbot.conf << 'EOF'
[Interface]
PrivateKey = <CLIENT_PRIVATE_KEY>
Address = 10.0.0.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = <SERVER_PUBLIC_KEY>
Endpoint = clawdbot-server.company.com:51820
AllowedIPs = 10.0.0.0/24  # Only route VPN subnet
PersistentKeepalive = 25
EOF

# Connect
sudo wg-quick up clawdbot
```

**Verify Connection:**

```bash
# Check WireGuard status
sudo wg show

# Test connectivity
ping 10.0.0.1

# Access ClawdBot via VPN
curl http://10.0.0.1:18789/health
```

### Option 3: OpenVPN

**Server Setup:**

```bash
# Install OpenVPN
sudo apt-get install openvpn easy-rsa

# Generate certificates
make-cadir ~/openvpn-ca
cd ~/openvpn-ca
./easyrsa init-pki
./easyrsa build-ca
./easyrsa gen-req server nopass
./easyrsa sign-req server server
./easyrsa gen-dh

# Create server configuration
sudo cat > /etc/openvpn/server.conf << 'EOF'
port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem

server 10.8.0.0 255.255.255.0
push "route 10.0.0.0 255.255.255.0"

keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun

status /var/log/openvpn-status.log
log-append /var/log/openvpn.log
verb 3
EOF

# Start OpenVPN
sudo systemctl enable openvpn@server
sudo systemctl start openvpn@server
```

---

## Reverse Proxy Hardening

### When Reverse Proxy is Required

Use cases:
- HTTPS termination
- Load balancing multiple agents
- Centralized authentication
- Compliance requirements (TLS everywhere)

**⚠️ WARNING:** Reverse proxies introduce risk — harden carefully

### Nginx Configuration

```nginx
# /etc/nginx/sites-available/clawdbot

upstream clawdbot_backend {
    # Use Unix socket (more secure than TCP)
    server unix:/var/run/clawdbot.sock;

    # OR use localhost TCP (less secure)
    # server 127.0.0.1:18789;

    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name clawdbot.company.internal;

    # TLS Configuration
    ssl_certificate /etc/nginx/ssl/clawdbot.crt;
    ssl_certificate_key /etc/nginx/ssl/clawdbot.key;
    ssl_protocols TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Client certificate authentication (mTLS)
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=clawdbot_limit:10m rate=10r/s;
    limit_req zone=clawdbot_limit burst=20 nodelay;

    # IP whitelist (VPN subnet only)
    allow 10.0.0.0/8;       # WireGuard
    allow 100.0.0.0/8;      # Tailscale
    deny all;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    # Disable logging of sensitive data
    access_log /var/log/nginx/clawdbot-access.log combined if=$loggable;
    map $request_uri $loggable {
        ~*"api_key|token|password" 0;
        default 1;
    }

    location / {
        # Proxy headers
        proxy_pass http://clawdbot_backend;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Security: Don't pass original client IP to backend
        # (prevents IP-based auth bypass)
        proxy_set_header X-Original-Client-IP "";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;

        # Buffering (prevent memory exhaustion)
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
        proxy_max_temp_file_size 0;
    }

    # Health check endpoint (no auth required)
    location = /health {
        access_log off;
        proxy_pass http://clawdbot_backend/health;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name clawdbot.company.internal;
    return 301 https://$server_name$request_uri;
}
```

**Enable Configuration:**

```bash
# Test configuration
sudo nginx -t

# Enable site
sudo ln -s /etc/nginx/sites-available/clawdbot /etc/nginx/sites-enabled/

# Reload Nginx
sudo systemctl reload nginx
```

---

## Firewall Configuration

### UFW (Ubuntu)

```bash
# Reset to defaults
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (from specific IP only)
sudo ufw allow from 203.0.113.0/24 to any port 22 proto tcp

# Allow VPN (WireGuard)
sudo ufw allow 51820/udp

# Allow VPN traffic to ClawdBot
sudo ufw allow from 10.0.0.0/24 to any port 18789 proto tcp

# Enable firewall
sudo ufw enable

# Verify rules
sudo ufw status verbose
```

### iptables (Advanced)

```bash
# Flush existing rules
sudo iptables -F
sudo iptables -X

# Default policies
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT ACCEPT

# Allow loopback
sudo iptables -A INPUT -i lo -j ACCEPT

# Allow established connections
sudo iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH from specific subnet
sudo iptables -A INPUT -p tcp -s 203.0.113.0/24 --dport 22 -j ACCEPT

# Allow WireGuard
sudo iptables -A INPUT -p udp --dport 51820 -j ACCEPT

# Allow VPN subnet to ClawdBot
sudo iptables -A INPUT -p tcp -s 10.0.0.0/24 --dport 18789 -j ACCEPT

# Log dropped packets
sudo iptables -A INPUT -j LOG --log-prefix "iptables-dropped: "

# Save rules
sudo iptables-save > /etc/iptables/rules.v4
```

### macOS (pf)

```bash
# Create firewall ruleset
sudo cat > /etc/pf.anchors/clawdbot << 'EOF'
# Block all incoming by default
block in all

# Allow localhost
pass in quick on lo0

# Allow established connections
pass in quick proto tcp from any to any flags S/SA keep state

# Allow VPN (Tailscale subnet)
pass in quick on utun3 proto tcp from 100.0.0.0/8 to any port 18789

# Allow SSH from specific IP
pass in quick proto tcp from 203.0.113.0/24 to any port 22
EOF

# Load ruleset
sudo pfctl -ef /etc/pf.anchors/clawdbot

# Verify rules
sudo pfctl -sr
```

---

## Zero Trust Network Access

### Cloudflare Access Integration

```yaml
# ~/.openclaw/config/auth.yml

auth:
  providers:
    cloudflare_access:
      enabled: true
      team_domain: "yourcompany.cloudflareaccess.com"
      audience_tag: "clawdbot-production"

      # Validate JWT tokens
      jwt_validation:
        algorithms: ["RS256"]
        jwks_url: "https://yourcompany.cloudflareaccess.com/cdn-cgi/access/certs"

      # Require specific groups
      required_groups:
        - "engineering"
        - "security-team"
```

### Okta Integration

```yaml
auth:
  providers:
    okta:
      enabled: true
      issuer: "https://yourcompany.okta.com/oauth2/default"
      client_id: "0oa1234567890abcdef"
      client_secret: "${OKTA_CLIENT_SECRET}"  # From keychain

      # PKCE for additional security
      pkce: true

      # Require MFA
      require_mfa: true
```

---

## Monitoring and Alerts

### Network Access Logging

```yaml
# ~/.openclaw/config/logging.yml

logging:
  network:
    enabled: true
    log_path: "~/.openclaw/logs/network-access.jsonl"

    # Log all connection attempts
    log_connections: true
    log_failed_auth: true

    # Alert on suspicious activity
    alerts:
      - type: "unexpected_source_ip"
        condition: "ip NOT IN vpn_subnet"
        action: "log_and_alert"

      - type: "failed_auth_threshold"
        condition: "failed_attempts > 5 in 60 seconds"
        action: "block_ip"

      - type: "off_hours_access"
        condition: "hour < 6 OR hour > 22"
        action: "log_and_alert"
```

### Prometheus Metrics

```yaml
# Export metrics for monitoring
metrics:
  enabled: true
  bind: "127.0.0.1:9090"

  exposed_metrics:
    - "clawdbot_connections_total"
    - "clawdbot_connection_duration_seconds"
    - "clawdbot_auth_failures_total"
    - "clawdbot_requests_by_source_ip"
```

### Alert Configuration (Grafana)

```yaml
# grafana/alerts/network-security.yml

alerts:
  - name: "Unexpected Source IP"
    expr: |
      rate(clawdbot_requests_by_source_ip{ip!~"10.0.0.*|100.*"}[5m]) > 0
    severity: critical
    annotations:
      summary: "ClawdBot accessed from non-VPN IP"

  - name: "High Failed Auth Rate"
    expr: |
      rate(clawdbot_auth_failures_total[1m]) > 10
    severity: high
    annotations:
      summary: "Potential brute force attack on ClawdBot"
```

---

## Testing and Verification

### Test 1: External Access Blocked

```bash
# From external network (should FAIL)
curl -v http://clawdbot-server.company.com:18789/health

# Expected: Connection refused or timeout
```

### Test 2: VPN Access Allowed

```bash
# Connect to VPN first
sudo wg-quick up clawdbot
# OR
tailscale up

# Access via VPN IP (should SUCCEED)
curl http://10.0.0.1:18789/health

# Expected: {"status":"healthy"}
```

### Test 3: Rate Limiting

```bash
# Test rate limiting (from VPN)
for i in {1..100}; do
  curl -s -o /dev/null -w "%{http_code}\n" http://10.0.0.1:18789/health
done

# Expected: First ~20 requests: 200, then: 429 (Too Many Requests)
```

---

## Best Practices

1. **Never expose directly to internet**
   - Always use VPN for remote access
   - No public IP binding

2. **Defense in depth**
   - Localhost binding + VPN + Auth token + Rate limiting
   - Multiple layers prevent single point of failure

3. **Monitor access patterns**
   - Log all connections
   - Alert on unexpected IPs
   - Track failed authentication attempts

4. **Regular security audits**
   - Weekly: Check for exposed ports (`nmap`)
   - Monthly: Review firewall rules
   - Quarterly: Penetration testing

5. **Incident response readiness**
   - Document VPN credentials rotation procedure
   - Test firewall rule rollback
   - Practice emergency shutdown

---

## Related Guides

- **Quick Start:** [01-quick-start.md](01-quick-start.md)
- **Credential Isolation:** [02-credential-isolation.md](02-credential-isolation.md)
- **Incident Response:** [06-incident-response.md](06-incident-response.md)

---

**Last Updated:** February 14, 2026  
**Tested On:** Ubuntu 22.04+, macOS 14.0+, Tailscale 1.50+, WireGuard 1.0+
