# Zero-Trust Security Design for AI Agents

**Estimated Time:** 45 minutes  
**Difficulty:** Advanced  
**Prerequisites:** Understanding of zero-trust principles, network security, identity and access management

This document describes the **zero-trust security architecture** for AI agent deployments, specifically ClawdBot/OpenClaw. Zero-trust assumes no implicit trust based on network location, requiring continuous verification of identity, device, and context for every access request.

---

## Table of Contents

1. [Zero-Trust Principles](#zero-trust-principles)
2. [Architecture Overview](#architecture-overview)
3. [Identity Verification](#identity-verification)
4. [Device Trust](#device-trust)
5. [Least Privilege Access](#least-privilege-access)
6. [Micro-Segmentation](#micro-segmentation)
7. [Continuous Monitoring](#continuous-monitoring)
8. [Implementation Guide](#implementation-guide)
9. [References](#references)

---

## Zero-Trust Principles

### Traditional Perimeter Security (Castle-and-Moat)

**Problem with traditional approach:**
```
Internet ─────► Firewall ─────► [Trusted Internal Network]
                 (Hard Shell)     │
                                  ├─ All internal systems trust each other
                                  ├─ Once inside, lateral movement is easy
                                  └─ Breach = game over
```

**Failure scenarios:**
- VPN credentials stolen → full network access
- Compromised laptop inside network → lateral movement
- Malicious insider → no detection
- SSH tunnel bypasses firewall → localhost trust exploited

### Zero-Trust Model (Never Trust, Always Verify)

**Core tenets:**

1. **Assume Breach**: Treat every access request as potentially hostile
2. **Verify Explicitly**: Authenticate and authorize based on all available data
3. **Least Privilege**: Minimum access needed for the task
4. **Micro-Segmentation**: Isolate resources, limit blast radius
5. **Continuous Monitoring**: Real-time threat detection and response

```
Internet ─────► VPN Gateway ─────► mTLS Gateway ─────► Agent
                 (Identity)         (Authorization)      │
                     │                    │              │
                     v                    v              v
                Device Check         API Key Check   Skill Sandbox
                Network Context      IP Allowlist    Permission Boundaries
                MFA Required         Rate Limits     Resource Limits
```

**Key difference**: Every step requires independent verification. VPN access doesn't imply gateway access doesn't imply skill execution permission.

---

## Architecture Overview

### Zero-Trust Control Plane

```
┌─────────────────────────────────────────────────────────────────┐
│                        User / Device                             │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────────────┐
│  Identity Provider (IdP)                                         │
│  • User authentication (SSO, MFA)                               │
│  • Device posture check                                         │
│  • Context evaluation (location, time, risk score)              │
└────────────────────────┬────────────────────────────────────────┘
                         │ JWT/SAML token
                         v
┌─────────────────────────────────────────────────────────────────┐
│  Policy Decision Point (PDP)                                     │
│  • Evaluate access policies                                     │
│  • Check compliance (device encryption, patch level)            │
│  • Risk-based authentication (step-up auth)                     │
└────────────────────────┬────────────────────────────────────────┘
                         │ Access decision (allow/deny)
                         v
┌─────────────────────────────────────────────────────────────────┐
│  Policy Enforcement Point (PEP)                                  │
│  • VPN gateway (Tailscale, WireGuard)                           │
│  • HTTP gateway (mTLS, API key validation)                      │
│  • Agent runtime (tool allowlist, sandbox)                      │
└─────────────────────────────────────────────────────────────────┘
```

### Trust Zones

**Zone 0: Public Internet**
- No trust
- All traffic treated as hostile
- Rate limiting, DDoS protection

**Zone 1: Authenticated User**
- Identity verified (MFA, SSO)
- Device posture checked
- Access to VPN only

**Zone 2: Authorized API Access**
- API key validated
- IP allowlisted
- Rate limit applied
- Access to gateway endpoints

**Zone 3: Agent Runtime**
- Request authenticated + authorized
- Input sanitized
- Actions logged
- Access to agent capabilities

**Zone 4: Privileged Operations**
- Credential access
- Skill installation
- Configuration changes
- Requires additional verification (step-up auth, admin approval)

---

## Identity Verification

### Principle: Verify Explicitly

Every access request must prove identity using multiple factors.

### User Identity

**Multi-Factor Authentication (MFA) Required:**

```yaml
# configs/mcp-server-config/authentication.yaml
authentication:
  methods:
    - name: "api_key"
      required: true
      validation:
        key_prefix: "openclaw_"
        min_length: 32
        rotation_days: 90
        
    - name: "mtls"
      required: false  # Optional second factor
      client_cert:
        ca_path: "/etc/ssl/certs/ca.crt"
        verify_depth: 2
        required_extensions:
          - "keyUsage: digitalSignature"
          - "extendedKeyUsage: clientAuth"
```

**Identity Providers Supported:**
- **API Keys**: Generated per user, scoped to specific agent
- **mTLS Client Certificates**: Device-specific, short-lived (30 days)
- **SSO Integration**: Okta, Azure AD, Google Workspace (via OIDC)
- **VPN Authentication**: Tailscale (device identity), WireGuard (public key)

### Device Identity

**Device Posture Checks:**

```yaml
# Tailscale ACL: tailnet-policy.hujson
{
  "groups": {
    "group:approved-devices": ["user1@example.com", "user2@example.com"]
  },
  
  "tagOwners": {
    "tag:openclaw-client": ["group:approved-devices"]
  },
  
  "acls": [
    {
      "action": "accept",
      "src": ["tag:openclaw-client"],
      "dst": ["tag:openclaw-server:18789"],
      "checks": [
        "device-authorized",
        "device-encrypted",
        "security-patches-current"
      ]
    }
  ]
}
```

**Required Device Security:**
- Disk encryption enabled (FileVault, LUKS, BitLocker)
- OS patches current (< 30 days old)
- Endpoint protection running (antivirus, EDR)
- No jailbreak/root detected
- Managed by MDM (for enterprise deployments)

### Service Identity

**Mutual TLS (mTLS) for Service-to-Service:**

```nginx
# configs/examples/nginx-advanced.conf
server {
    listen 443 ssl http2;
    server_name openclaw.internal;
    
    # Server certificate
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    
    # Client certificate verification (mTLS)
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;
    
    # Only allow specific client DNs
    if ($ssl_client_s_dn !~ "CN=(agent|gateway|telemetry)\.openclaw\.internal") {
        return 403;
    }
    
    location / {
        proxy_pass http://127.0.0.1:18789;
        proxy_set_header X-Client-Cert $ssl_client_cert;
        proxy_set_header X-Client-DN $ssl_client_s_dn;
    }
}
```

---

## Device Trust

### Device Compliance Verification

**Pre-Access Checks:**

```python
# Example device posture check
def verify_device_posture(device_id: str) -> bool:
    """Verify device meets security requirements before granting access."""
    checks = {
        "disk_encryption": check_disk_encryption(device_id),
        "os_patches": check_os_patches(device_id, max_age_days=30),
        "antivirus": check_antivirus_running(device_id),
        "firewall": check_firewall_enabled(device_id),
        "mdm_enrolled": check_mdm_status(device_id),
    }
    
    required_checks = ["disk_encryption", "os_patches", "antivirus"]
    return all(checks[check] for check in required_checks)
```

**Continuous Verification:**

Devices are re-checked every 15 minutes. If compliance lapses:
1. Device loses access immediately (VPN disconnected)
2. Alert sent to security team
3. User notified with remediation steps
4. Access restored automatically once compliant

### Network Context

**Risk-Based Access:**

```yaml
# configs/organization-policies/security-policy.json (excerpt)
{
  "network_policies": {
    "trusted_networks": {
      "policy": "Allow access from corporate networks with reduced MFA",
      "networks": ["10.0.0.0/8", "172.16.0.0/12"],
      "mfa_required": false
    },
    "untrusted_networks": {
      "policy": "Require MFA for all access from public networks",
      "networks": ["0.0.0.0/0"],
      "mfa_required": true,
      "step_up_auth": true
    }
  }
}
```

**Context Variables:**
- **Source IP**: Corporate office, home, public Wi-Fi, VPN
- **Time of Day**: Business hours vs off-hours (elevated risk)
- **Geolocation**: Expected country vs anomalous location
- **Device Risk Score**: Clean vs recently infected/suspicious activity

---

## Least Privilege Access

### Principle: Minimum Necessary Access

Grant only the permissions required for the specific task, for only the duration needed.

### Role-Based Access Control (RBAC)

```yaml
# configs/agent-config/skill-permissions.yaml
roles:
  - name: "viewer"
    description: "Read-only access to agent status"
    permissions:
      - "agent:read"
      - "logs:read"
    
  - name: "operator"
    description: "Execute approved skills, no config changes"
    permissions:
      - "agent:read"
      - "agent:execute_skill"
      - "logs:read"
    allowed_skills:
      - "openclaw-http-skill"
      - "openclaw-file-reader"
    
  - name: "administrator"
    description: "Full access including config and skill installation"
    permissions:
      - "agent:*"
      - "config:write"
      - "skills:install"
      - "credentials:rotate"
    requires_approval: true
    mfa_required: true

user_assignments:
  - user: "engineer@example.com"
    role: "operator"
    
  - user: "security@example.com"
    role: "administrator"
    approval_workflow: "jira-ticket-required"
```

### Attribute-Based Access Control (ABAC)

**Fine-grained policies based on attributes:**

```python
# Example ABAC policy
def authorize_request(user, resource, action, context):
    """Attribute-based access control decision."""
    
    # Policy 1: Credential access requires admin role + approved device
    if resource == "credentials" and action == "read":
        return (
            user.role == "administrator" and
            context.device.is_approved and
            context.device.encryption_enabled and
            context.time.is_business_hours()
        )
    
    # Policy 2: Skill execution requires operator role + network allowlist
    if resource == "skills" and action == "execute":
        return (
            user.role in ["operator", "administrator"] and
            context.network.ip in ALLOWED_IP_RANGES and
            context.request.rate_limit_ok()
        )
    
    # Policy 3: Config changes require admin + step-up auth
    if resource == "config" and action == "write":
        return (
            user.role == "administrator" and
            user.mfa_verified and
            user.approval_granted and
            context.audit_log.enabled
        )
    
    return False  # Deny by default
```

### Just-in-Time (JIT) Access

**Temporary privilege elevation:**

1. **Request**: User requests admin access for specific task
2. **Approval**: Manager/security approves via Slack/PagerDuty
3. **Grant**: Admin role granted for 1 hour
4. **Audit**: All actions logged
5. **Revoke**: Access automatically revoked after time expires

```bash
# Request temporary admin access
$ openclaw-access request --role admin --duration 1h --reason "Emergency credential rotation"

# Approval notification sent to security team
# If approved, user gets temporary admin token
$ export OPENCLAW_TOKEN="temp_admin_..."

# After 1 hour, token expires automatically
```

---

## Micro-Segmentation

### Principle: Isolate Resources, Limit Blast Radius

Segment the network and application architecture so compromise of one component doesn't cascade.

### Network Micro-Segmentation

```
┌─────────────────────────────────────────────────────────────────┐
│  Segment 1: User Workstations                                   │
│  VLAN: 10.1.0.0/24                                              │
│  Allowed Outbound: VPN gateway only                             │
└────────────────────────┬────────────────────────────────────────┘
                         │ VPN tunnel
                         v
┌─────────────────────────────────────────────────────────────────┐
│  Segment 2: VPN Gateway                                         │
│  VLAN: 10.2.0.0/24                                              │
│  Firewall Rules:                                                │
│    • Allow: Segments 1 → 2 (VPN handshake)                     │
│    • Allow: Segment 2 → 3 (authenticated traffic)              │
│    • Deny: All other traffic                                    │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         v
┌─────────────────────────────────────────────────────────────────┐
│  Segment 3: Application Tier (HTTP Gateway)                     │
│  VLAN: 10.3.0.0/24                                              │
│  Firewall Rules:                                                │
│    • Allow: Segment 2 → 3 port 18789 (gateway)                 │
│    • Allow: Segment 3 → 4 Unix socket (agent IPC)              │
│    • Deny: Segment 3 → Internet (no outbound except APIs)      │
└────────────────────────┬────────────────────────────────────────┘
                         │ Unix socket / loopback
                         v
┌─────────────────────────────────────────────────────────────────┐
│  Segment 4: Agent Runtime                                       │
│  VLAN: 10.4.0.0/24                                              │
│  Firewall Rules:                                                │
│    • Allow: Segment 4 → Anthropic API (443)                    │
│    • Allow: Segment 4 → Approved MCP servers (allowlist)       │
│    • Deny: Segment 4 → 4 (no lateral movement)                 │
└────────────────────────┬────────────────────────────────────────┘
                         │ Restricted API access
                         v
        ┌────────────────┴────────────────┐
        v                                  v
    Anthropic API                   MCP Servers
    (External)                      (Allowlisted)
```

### Application Micro-Segmentation

**Container Network Policies (Kubernetes):**

```yaml
# configs/examples/production-k8s.yml (excerpt)
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: clawdbot-network-policy
spec:
  podSelector:
    matchLabels:
      app: clawdbot
  policyTypes:
    - Ingress
    - Egress
  
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app: gateway
      ports:
        - protocol: TCP
          port: 8080
  
  egress:
    # Allow DNS
    - to:
        - namespaceSelector:
            matchLabels:
              name: kube-system
      ports:
        - protocol: UDP
          port: 53
    
    # Allow Anthropic API
    - to:
        - ipBlock:
            cidr: 0.0.0.0/0
      ports:
        - protocol: TCP
          port: 443
      # Note: Further restrict to Anthropic IP ranges in production
```

**Skill Isolation:**

Each skill executes in its own sandbox with explicit network policies:

```yaml
# Skill execution policy
skill_sandbox:
  network:
    allow_outbound: false  # Deny by default
    allowlist:
      - domain: "api.example.com"
        ports: [443]
        reason: "Required for HTTP skill functionality"
  
  filesystem:
    read_only: true
    writable_dirs:
      - "/tmp"  # Size-limited tmpfs
    
  resources:
    max_memory: "512Mi"
    max_cpu: "0.5"
    max_pids: 50
```

---

## Continuous Monitoring

### Principle: Trust, But Verify Continuously

Identity and authorization decisions are point-in-time. Continuous monitoring ensures compliance and detects anomalies.

### Real-Time Threat Detection

**Key Metrics Monitored (using openclaw-telemetry):**

```yaml
# configs/examples/with-community-tools.yml (excerpt)
services:
  openclaw-telemetry:
    image: knostic/openclaw-telemetry:latest
    environment:
      # Behavioral monitoring
      BASELINE_PERIOD: "7d"
      ANOMALY_THRESHOLD: "3sigma"
      
      # Metrics tracked
      MONITORED_METRICS: |
        - request_rate_per_user
        - token_consumption_per_request
        - tool_invocation_frequency
        - credential_access_frequency
        - network_connection_destinations
        - error_rate
      
      # Alerting
      ALERT_ON_ANOMALY: "true"
      ALERT_WEBHOOK: "${SLACK_WEBHOOK_URL}"
      SIEM_INTEGRATION: "splunk"
```

**Anomaly Detection Examples:**

| Metric | Baseline | Observed | Anomaly? | Action |
|--------|----------|----------|----------|--------|
| Token usage/request | 1,500 avg | 15,000 | ✅ Yes (10x) | Alert + Rate limit |
| Requests/min | 5 avg | 4 | ❌ No | None |
| Credential access | 1/day | 50/hour | ✅ Yes | Alert + Block |
| Tool invocations | 10/hour | 100/hour | ✅ Yes (10x) | Review + Step-up auth |

### Audit Logging

**Immutable Audit Trail:**

```yaml
# configs/examples/monitoring-stack.yml (excerpt)
audit_logging:
  destination: "siem"  # Splunk, Elasticsearch, S3
  retention: "2y"
  
  events_logged:
    - authentication_attempts
    - authorization_decisions
    - credential_access
    - configuration_changes
    - skill_installations
    - tool_executions
    - network_connections
    - anomalies_detected
  
  log_format: "json"
  include_context:
    - user_id
    - device_id
    - source_ip
    - timestamp
    - request_id
    - outcome (success/failure)
    - reason (for denials)
```

**Sample Audit Log Entry:**

```json
{
  "timestamp": "2026-02-14T15:23:41Z",
  "event_type": "credential_access",
  "user": "engineer@example.com",
  "device_id": "device-abc123",
  "source_ip": "10.1.5.42",
  "request_id": "req-xyz789",
  "resource": "credentials.anthropic_api_key",
  "action": "read",
  "outcome": "success",
  "authorization_policy": "RBAC:administrator",
  "compliance_checks": [
    "device_encrypted: true",
    "os_patches: current",
    "mfa_verified: true"
  ]
}
```

### Compliance Monitoring

**Automated Compliance Checks:**

```bash
#!/bin/bash
# scripts/compliance/policy-audit.sh

# Check all deployments for compliance
violations=0

# Policy: No plaintext credentials
if find ~/.openclaw -type f -exec grep -l "sk-ant-" {} \; | grep -q .; then
    echo "❌ VIOLATION: Plaintext credentials found"
    ((violations++))
fi

# Policy: VPN required for gateway access
if netstat -tulpn | grep 18789 | grep -q "0.0.0.0"; then
    echo "❌ VIOLATION: Gateway bound to 0.0.0.0 (should be 127.0.0.1)"
    ((violations++))
fi

# Policy: All skills must have GPG signatures
unsigned=$(find ~/.openclaw/skills -name "*.sig" -o -name "*.asc" | wc -l)
total=$(find ~/.openclaw/skills -type d -d 1 | wc -l)
if [ "$unsigned" -lt "$total" ]; then
    echo "❌ VIOLATION: Unsigned skills detected"
    ((violations++))
fi

echo ""
echo "Compliance scan complete: $violations violations"
exit $violations
```

---

## Implementation Guide

### Step 1: Identity Foundation (Week 1)

**Objective**: Establish strong identity verification

1. **Deploy VPN with device identity**:
   ```bash
   # Tailscale setup
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo tailscale up --auth-key="${TAILSCALE_AUTH_KEY}"
   ```

2. **Enable MFA for all users**:
   - Configure API key authentication in [gateway.hardened.yml](../../configs/templates/gateway.hardened.yml)
   - Optionally deploy mTLS client certificates

3. **Device posture checks**:
   - Enable Tailscale device authorization
   - Require disk encryption, current patches

**Verification**:
```bash
# Confirm VPN access required
curl http://localhost:18789/health
# Should fail without VPN connection
```

### Step 2: Least Privilege (Week 2)

**Objective**: Implement RBAC and minimize permissions

1. **Define roles**:
   - Create [skill-permissions.yaml](../../configs/agent-config/skill-permissions.yaml)
   - Map users to roles

2. **Implement authorization checks**:
   - Update gateway to enforce RBAC
   - Log all authorization decisions

3. **Skill sandboxing**:
   - Deploy hardened Docker config from [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md)
   - Restrict skill network access via [allowlist.json](../../configs/skill-policies/allowlist.json)

**Verification**:
```bash
# Test authorization
curl -H "Authorization: Bearer ${OPERATOR_TOKEN}" \
  http://localhost:18789/admin
# Should return: 403 Forbidden
```

### Step 3: Micro-Segmentation (Week 3)

**Objective**: Isolate components to limit blast radius

1. **Network segmentation**:
   - Deploy firewall rules from [03-network-segmentation.md](../guides/03-network-segmentation.md)
   - Use Kubernetes NetworkPolicies if on K8s

2. **Application segmentation**:
   - Run gateway, agent, MCP servers in separate containers/VMs
   - Restrict inter-process communication to Unix sockets or localhost

**Verification**:
```bash
# Test network isolation
docker exec clawdbot ping 10.0.0.1
# Should fail: Network unreachable
```

### Step 4: Continuous Monitoring (Week 4)

**Objective**: Gain visibility and detect anomalies

1. **Deploy openclaw-telemetry**:
   ```bash
   docker-compose -f configs/examples/with-community-tools.yml up -d openclaw-telemetry
   ```

2. **Configure alerts**:
   - Set up Slack/PagerDuty webhooks
   - Define anomaly thresholds

3. **Integrate SIEM**:
   - Forward logs to Splunk/Elastic
   - Deploy detection rules from [examples/monitoring/siem-rules/](../../examples/monitoring/siem-rules/)

**Verification**:
```bash
# Check telemetry
curl http://localhost:9090/metrics | grep openclaw
```

---

## References

### Internal Documentation
- [Threat Model](./threat-model.md) - STRIDE analysis
- [Security Layers](./security-layers.md) - Defense-in-depth architecture
- [Network Segmentation Guide](../guides/03-network-segmentation.md)
- [Runtime Sandboxing Guide](../guides/04-runtime-sandboxing.md)

### Configuration Examples
- [Gateway Config (Hardened)](../../configs/templates/gateway.hardened.yml)
- [Nginx Advanced Config](../../configs/examples/nginx-advanced.conf)
- [Production Kubernetes](../../configs/examples/production-k8s.yml)
- [Skill Permissions](../../configs/agent-config/skill-permissions.yaml)

### External Resources
- [Google BeyondCorp](https://cloud.google.com/beyondcorp) - Zero-trust case study
- [NIST Zero Trust Architecture (SP 800-207)](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [Forrester Zero Trust eXtended (ZTX) Framework](https://www.forrester.com/report/the-zero-trust-extended-ztx-ecosystem/RES176315)
- [Tailscale Zero Trust Networking](https://tailscale.com/blog/how-tailscale-works/)

---

**Document Version**: 1.0.0  
**Last Updated**: February 14, 2026  
**Next Review**: May 14, 2026 (quarterly)
