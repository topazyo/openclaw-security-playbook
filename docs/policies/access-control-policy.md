# Access Control Policy

**Policy ID**: SEC-002  
**Version**: 1.0.0  
**Effective Date**: 2026-01-15  
**Last Updated**: 2026-02-14  
**Owner**: Security Team (security@company.com)  
**Approval**: CISO, CTO  
**Review Frequency**: Quarterly

This policy defines access control requirements for AI agent systems (ClawdBot/OpenClaw), including identity management, authentication, authorization, and privilege management.

---

## Table of Contents

1. [Purpose](#purpose)
2. [Scope](#scope)
3. [Policy Statements](#policy-statements)
4. [Roles and Responsibilities](#roles-and-responsibilities)
5. [Access Control Framework](#access-control-framework)
6. [Authentication Requirements](#authentication-requirements)
7. [Authorization Model](#authorization-model)
8. [Privileged Access Management](#privileged-access-management)
9. [Access Reviews](#access-reviews)
10. [Compliance](#compliance)
11. [References](#references)

---

## Purpose

This policy ensures:
- Only authorized users and systems can access AI agent resources
- Access is granted based on least privilege principles
- Authentication and authorization are continuously verified
- Access decisions are logged and auditable
- Compliance with regulatory requirements (SOC 2, ISO 27001, GDPR)

---

## Scope

**In Scope:**
- All ClawdBot/OpenClaw deployments (development, staging, production)
- User access to agent gateways and management interfaces
- Service-to-service authentication (agent-to-MCP, agent-to-LLM API)
- Privileged operations (credential access, config changes, skill installation)
- Third-party integrations and MCP servers

**Out of Scope**:
- End-user device management (covered by Device Management Policy)
- Physical security controls (covered by Physical Security Policy)
- Anthropic Claude API access control (external, managed by Anthropic)

---

## Policy Statements

### 1. Authentication

**Policy**: All access to AI agent resources MUST be authenticated.

**Requirements**:
- Multi-factor authentication (MFA) required for all human users
- API keys required for programmatic access (min 32 characters, rotated every 90 days)
- Mutual TLS (mTLS) required for service-to-service communication
- Default usernames and passwords MUST be changed immediately
- Password must meet complexity requirements (12+ characters, mixed case, numbers, symbols)
- Failed authentication attempts logged and monitored (5 failures = account lockout)

**Rationale**: Prevents unauthorized access and credential-based attacks.

**Compliance Mapping**:
- **SOC 2**: CC6.1 (Logical and physical access controls)
- **ISO 27001**: A.9.2.1 (User registration and de-registration), A.9.4.2 (Secure log-on procedures)
- **NIST CSF**: PR.AC-1 (Identities and credentials are issued, managed, verified, revoked, and audited)

**Implementation**: See [configs/templates/gateway.hardened.yml](../../configs/templates/gateway.hardened.yml) and [docs/guides/03-network-segmentation.md](../guides/03-network-segmentation.md)

---

### 2. Authorization

**Policy**: Access permissions MUST follow the principle of least privilege.

**Requirements**:
- Role-Based Access Control (RBAC) with predefined roles: viewer, operator, administrator
- Users granted minimum permissions necessary for their job function
- Privileged operations (credential access, skill installation) require additional approval
- Service accounts use scoped API keys with explicit permission boundaries
- Authorization decisions logged with user, resource, action, and outcome

**Rationale**: Limits blast radius of compromised accounts and insider threats.

**Compliance Mapping**:
- **SOC 2**: CC6.2 (Authorization), CC6.3 (Restrictions on access to logical and physical assets)
- **ISO 27001**: A.9.1.2 (Access to networks and network services)
- **GDPR**: Article 32 (Security of processing - access control)

**Implementation**: See [configs/agent-config/skill-permissions.yaml](../../configs/agent-config/skill-permissions.yaml)

---

### 3. Credential Storage

**Policy**: Credentials MUST be stored in OS-provided secure storage; plaintext storage is PROHIBITED.

**Requirements**:
- All API keys, passwords, tokens stored in OS keychain (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- Zero plaintext credentials in config files, environment variables, or logs
- Backup files (.yml~, .bak, .swp) automatically cleaned up
- Credentials encrypted in transit (TLS 1.3+) and at rest
- Emergency credential rotation procedures documented and tested

**Rationale**: Prevents credential exfiltration, the highest-risk attack vector (90% exposure rate).

**Compliance Mapping**:
- **SOC 2**: CC6.1 (Logical access controls), CC6.7 (Encryption of data at rest)
- **ISO 27001**: A.10.1.1 (Policy on use of cryptographic controls), A.9.4.3 (Password management system)
- **PCI DSS**: Requirement 8.2.1 (Render all authentication credentials unreadable during transmission and storage)

**Implementation**: See [docs/guides/02-credential-isolation.md](../guides/02-credential-isolation.md) and [configs/templates/credentials.yml](../../configs/templates/credentials.yml)

---

### 4. Network Access

**Policy**: AI agent gateways MUST NOT be exposed to the public internet; VPN access is REQUIRED.

**Requirements**:
- Gateway binds to localhost (127.0.0.1) only, never 0.0.0.0
- VPN (Tailscale, WireGuard, OpenVPN) required for remote access
- Firewall rules block non-VPN traffic to gateway ports
- IP allowlisting for additional defense-in-depth
- Rate limiting enforced (100 requests/minute per user)

**Rationale**: Prevents authentication bypass via SSH tunneling and unauthorized access.

**Compliance Mapping**:
- **SOC 2**: CC6.6 (Logical access controls), CC6.7 (Cryptographic protection of data in transit)
- **ISO 27001**: A.13.1.1 (Network controls), A.13.1.3 (Segregation in networks)
- **NIST CSF**: PR.AC-5 (Network integrity is protected)

**Implementation**: See [docs/guides/03-network-segmentation.md](../guides/03-network-segmentation.md) and [scripts/hardening/vpn/](../../scripts/hardening/vpn/)

---

### 5. Privileged Access

**Policy**: Privileged operations require just-in-time (JIT) access with additional approval and MFA.

**Requirements**:
- Administrator role requires manager approval + MFA
- Privileged access granted for specific time period (max 4 hours)
- All privileged actions logged with full context (user, timestamp, justification)
- Automated revocation after time expires
- Break-glass procedures documented for emergencies

**Rationale**: Limits standing privileges and insider threat risk.

**Compliance Mapping**:
- **SOC 2**: CC6.2 (Authorization for privileged access)
- **ISO 27001**: A.9.2.3 (Management of privileged access rights)
- **NIST CSF**: PR.AC-4 (Access permissions and authorizations are managed)

**Implementation**: See [Privileged Access Management](#privileged-access-management) section below

---

### 6. Device Security

**Policy**: Only compliant devices may access AI agent resources.

**Requirements**:
- Disk encryption enabled (FileVault, LUKS, BitLocker)
- OS patches current (less than 30 days old)
- Endpoint protection running (antivirus, EDR)
- Device managed by MDM (for enterprise deployments)
- Device posture checked continuously (every 15 minutes)
- Non-compliant devices lose access immediately

**Rationale**: Prevents compromised devices from accessing systems.

**Compliance Mapping**:
- **SOC 2**: CC6.6 (Logical and physical access controls)
- **ISO 27001**: A.8.1.3 (Acceptable use of assets), A.12.5.1 (Installation of software on operational systems)
- **NIST CSF**: PR.IP-3 (Configuration change control processes are in place)

**Implementation**: See [docs/architecture/zero-trust-design.md](../architecture/zero-trust-design.md#device-trust)

---

### 7. Access Reviews

**Policy**: Access permissions MUST be reviewed quarterly and recertified.

**Requirements**:
- Quarterly access review by resource owners
- All users, their roles, and permissions listed
- Manager approval required to retain access
- Unused accounts deactivated after 90 days of inactivity
- Contractor access revoked immediately upon contract end
- Service account access reviewed annually

**Rationale**: Ensures access remains appropriate and removes orphaned accounts.

**Compliance Mapping**:
- **SOC 2**: CC6.2 (Periodic review of access rights)
- **ISO 27001**: A.9.2.5 (Review of user access rights)
- **NIST CSF**: PR.AC-1 (Access is granted based on need-to-know)

**Implementation**: See [docs/procedures/access-review.md](../procedures/access-review.md)

---

## Roles and Responsibilities

### Security Team
- Define and maintain access control policies
- Review access logs for anomalies
- Conduct quarterly access reviews
- Approve privileged access requests
- Respond to incidents involving unauthorized access

### Engineering Team
- Implement technical access controls
- Configure RBAC roles and permissions
- Maintain VPN infrastructure
- Deploy authentication/authorization systems
- Document service account usage

### IT Operations
- Provision and deprovision user accounts
- Manage device compliance checks
- Monitor authentication failures
- Respond to account lockouts
- Maintain MDM and endpoint protection

### Managers
- Approve privileged access requests for their reports
- Recertify access during quarterly reviews
- Report access violations or security concerns

### End Users
- Protect authentication credentials
- Enable MFA on all accounts
- Report suspicious authentication attempts
- Follow device security requirements

---

## Access Control Framework

### Identity and Access Management (IAM) Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     Identity Provider (IdP)                   │
│  • User directory (Okta, Azure AD, Google Workspace)         │
│  • MFA enforcement                                           │
│  • SSO/SAML integration                                      │
└────────────────────────┬─────────────────────────────────────┘
                         │ SAML/OIDC
                         v
┌──────────────────────────────────────────────────────────────┐
│              Policy Decision Point (PDP)                      │
│  • RBAC/ABAC policy evaluation                               │
│  • Device posture check                                      │
│  • Risk-based authentication                                 │
└────────────────────────┬─────────────────────────────────────┘
                         │ Access decision (allow/deny)
                         v
┌──────────────────────────────────────────────────────────────┐
│           Policy Enforcement Points (PEP)                     │
│  • VPN Gateway (Tailscale, WireGuard)                        │
│  • HTTP Gateway (API key + mTLS validation)                  │
│  • Agent Runtime (skill permission boundaries)               │
└──────────────────────────────────────────────────────────────┘
```

### Trust Zones

| Zone | Description | Authentication Required | Authorization Model |
|------|-------------|------------------------|---------------------|
| **Internet** | Public | None | Deny all |
| **VPN** | Authenticated users | MFA + device posture | Identity-based |
| **Gateway** | API access | API key + IP allowlist | RBAC |
| **Agent** | Tool execution | Service auth | Skill allowlist |
| **Privileged** | Admin operations | MFA + approval + audit | ABAC + JIT |

---

## Authentication Requirements

### User Authentication

**Primary Methods**:
1. **Username + Password + MFA** (humans)
2. **API Key** (services, automation)
3. **mTLS Client Certificate** (service-to-service)

**MFA Options**:
- TOTP (Google Authenticator, Authy)
- WebAuthn (YubiKey, Touch ID, Windows Hello)
- Push notification (Okta Verify, Duo)

**Configuration Example**:
```yaml
# configs/mcp-server-config/authentication.yaml
authentication:
  mfa:
    required: true
    methods: ["totp", "webauthn", "push"]
    backup_codes: true
    
  api_keys:
    required: trueformat: "openclaw_<32-char-random>"
    rotation_days: 90
    scopes: ["read", "execute", "admin"]
    
  session:
    timeout_minutes: 60
    absolute_timeout_hours: 8
    concurrent_sessions_max: 3
```

### Service Authentication

**API Key Management**:
```bash
# Generate API key
openclaw-admin api-key create \
  --user automation@company.com \
  --role operator \
  --scope "agent:execute_skill" \
  --expires-in 90d

# Rotate API key
openclaw-admin api-key rotate --key-id abc123
```

**mTLS Configuration**:
```bash
# Generate client certificate
openssl req -new -x509 -days 30 \
  -keyout client.key \
  -out client.crt \
  -subj "/CN=gateway.openclaw.internal/O=Company/C=US"

# Configure in nginx (see configs/examples/nginx-advanced.conf)
```

---

## Authorization Model

### Role Definitions

**Viewer**:
- View agent status, logs
- Read-only access
- No execution permissions

**Operator**:
- Execute approved skills
- View logs and metrics
- No config or admin access

**Administrator**:
- Full access to agent
- Config changes, skill installation
- Credential rotation
- Requires additional approval + MFA

### RBAC Implementation

```yaml
# configs/agent-config/skill-permissions.yaml
roles:
  viewer:
    permissions:
      - "agent:read-status"
      - "logs:read"
      - "metrics:read"
    
  operator:
    permissions:
      - "agent:read-status"
      - "agent:execute-skill"
      - "logs:read"
      - "metrics:read"
    allowed_skills:
      - "openclaw-http-skill"
      - "openclaw-file-reader"
    max_requests_per_minute: 100
    
  administrator:
    permissions:
      - "agent:*"
      - "config:write"
      - "skills:install"
      - "credentials:rotate"
    requires_approval: true
    mfa_required: true
    session_timeout_minutes: 60
```

### Permission Inheritance

```
viewer
  └─ operator (inherits viewer permissions)
      └─ administrator (inherits operator permissions)
```

---

## Privileged Access Management

### Just-in-Time (JIT) Access

**Workflow**:
1. **Request**: User requests temporary admin access
   ```bash
   openclaw-access request \
     --role administrator \
     --duration 1h \
     --reason "Emergency credential rotation - INC-2026-001"
   ```

2. **Approval**: Manager approves via Slack/email
   - Approval notification sent
   - Manager reviews justification
   - Approval valid for requested duration only

3. **Grant**: Temporary admin token issued
   ```bash
   export OPENCLAW_ADMIN_TOKEN="temp_admin_ab...xyz"
   # Valid for 1 hour
   ```

4. **Audit**: All actions logged
   ```json
   {
     "event": "privileged_access_granted",
     "user": "engineer@company.com",
     "role": "administrator",
     "approver": "manager@company.com",
     "duration": "1h",
     "reason": "Emergency credential rotation - INC-2026-001",
     "timestamp": "2026-02-14T10:30:00Z"
   }
   ```

5. **Revoke**: Access expires automatically
   - Token invalidated after 1 hour
   - User returned to operator role
   - Final actions summary emailed

### Break-Glass Procedures

**Emergency Access** (when normal approval not possible):

1. Use emergency admin account (`emergency-admin@company.com`)
2. Stored password in physical safe (CFO office)
3. Video surveillance of safe access
4. Security team notified immediately
5. Full audit conducted post-incident

**Conditions for Break-Glass**:
- Production outage affecting customers
- Security incident requiring immediate containment
- Normal approval process unavailable (off-hours, manager unavailable)

---

## Access Reviews

### Quarterly Review Process

**Timeline**:
- **Week 1**: Security team generates access report
- **Week 2-3**: Managers review and recertify
- **Week 4**: Security team processes changes, revokes uncertified access

**Review Checklist**:
- [ ] User still employed/contractor active?
- [ ] Role still appropriate for job function?
- [ ] Unused access (>90 days no logins)?
- [ ] Service accounts still needed?
- [ ] API keys rotated per policy?

**Report Example**:
| User | Role | Last Login | Resources | Certify? |
|------|------|------------|-----------|----------|
| alice@company.com | operator | 2026-02-13 | agent-prod-1 | ✅ |
| bob@company.com | administrator | 2025-11-05 (90+ days) | agent-prod-1 | ❌ Revoke |
| contractor@vendor.com | viewer | 2026-01-20 (contract ended) | agent-dev-1 | ❌ Revoke |

**Implementation**: See [docs/procedures/access-review.md](../procedures/access-review.md)

---

## Compliance

### Regulatory Mappings

**SOC 2 Type II**:
- CC6.1: Logical and physical access controls restrict unauthorized access
- CC6.2: Identify and authenticate users prior to granting access
- CC6.3: Authorization for additions, modifications, and deletions

**ISO 27001:2022**:
- A.9.1.1: Access control policy
- A.9.2.1: User registration and de-registration
- A.9.2.3: Management of privileged access rights
- A.9.4.3: Password management system

**GDPR**:
- Article 32: Security of processing (access control)
- Article 5: Principles (integrity and confidentiality)

**NIST CSF**:
- PR.AC-1: Identities and credentials managed
- PR.AC-4: Access permissions managed
- PR.AC-7: Users, devices, and assets authenticated

### Audit Evidence

Access control compliance demonstrated through:
- Authentication logs (MFA events, failed logins)
- Authorization decision logs (RBAC policy evaluations)
- Access review reports (quarterly recertifications)
- Credential storage verification (OS keychain, zero plaintext)
- Device compliance reports (encryption, patches, EDR)
- Privileged access audit trails (JIT approvals, actions taken)

**Storage**: All audit evidence retained for 2 years in immutable SIEM (Splunk, S3).

---

## References

### Internal Documentation
- [Credential Isolation Guide](../guides/02-credential-isolation.md)
- [Network Segmentation Guide](../guides/03-network-segmentation.md)
- [Zero-Trust Design](../architecture/zero-trust-design.md)
- [Access Review Procedures](../procedures/access-review.md)

### Configuration Templates
- [Gateway Authentication](../../configs/templates/gateway.hardened.yml)
- [Skill Permissions (RBAC)](../../configs/agent-config/skill-permissions.yaml)
- [mTLS Configuration](../../configs/examples/nginx-advanced.conf)

### Related Policies
- [Incident Response Policy](./incident-response-policy.md)
- [Data Classification Policy](./data-classification.md)
- [Acceptable Use Policy](./acceptable-use-policy.md)

### External Standards
- [NIST SP 800-63B: Digital Identity Guidelines (Authentication)](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)

---

**Policy Owner**: Security Team  
**Approved By**: CISO, CTO  
**Next Review Date**: May 14, 2026  
**Questions**: security@company.com
