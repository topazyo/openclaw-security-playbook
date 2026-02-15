# Security Review Checklist

**Document Type**: Pre-Deployment Checklist  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Security Team

Use this checklist before deploying ClawdBot/OpenClaw to production or making security-relevant changes.

---

## 1. Credential Security

### 1.1 Credential Storage
- [ ] **All API keys stored in OS keychain** (no plaintext in configs)
  - macOS: Keychain Access
  - Linux: GNOME Keyring / KWallet
  - Windows: Credential Manager
- [ ] **No credentials in environment variables** (except `${VAR}` placeholders)
- [ ] **No credentials in version control** (check Git history: `git log -p | grep -i "api.key"`)
- [ ] **Backup credentials excluded** from regular backups (use secure vault)

**Verification**:
```bash
./scripts/verification/verify_openclaw_security.sh | grep "Credential isolation"
# Expected: ✅ All checks passed
```

**Reference**: [Credential Isolation Guide](../guides/02-credential-isolation.md)

---

### 1.2 Credential Rotation
- [ ] **API keys rotated** within last 90 days (check: `aws iam list-access-keys`)
- [ ] **Old keys revoked** after rotation
- [ ] **Rotation procedure documented** (see [Credential Migration Scripts](../../scripts/credential-migration/))

---

## 2. Network Security

### 2.1 Network Segmentation
- [ ] **Gateway binds to localhost only** (`127.0.0.1:18789`, NOT `0.0.0.0`)
- [ ] **VPN required for remote access** (Tailscale or WireGuard configured)
- [ ] **No public internet exposure** (firewall rules verified)
- [ ] **Internal-only communication** between services (Docker network or K8s NetworkPolicy)

**Verification**:
```bash
# Check network binding
netstat -tuln | grep 18789
# Expected: tcp 127.0.0.1:18789 (NOT 0.0.0.0:18789)

# Check firewall rules
sudo iptables -L | grep 18789
# Expected: No ACCEPT rules from 0.0.0.0/0
```

**Reference**: [Network Segmentation Guide](../guides/03-network-segmentation.md)

---

### 2.2 TLS Configuration
- [ ] **TLS 1.2+ enforced** (no SSLv3, TLS 1.0, TLS 1.1)
- [ ] **Strong ciphers only** (ECDHE-RSA-AES256-GCM-SHA384 or better)
- [ ] **Valid certificates** (not self-signed for production, expiry >30 days)
- [ ] **HSTS enabled** (Strict-Transport-Security header)

**Verification**:
```bash
# Test TLS configuration
nmap --script ssl-enum-ciphers -p 18789 localhost
# Expected: Grade A or A+
```

---

## 3. Runtime Sandboxing

### 3.1 Docker Configuration
- [ ] **Non-root user** (`user: "1000:1000"` in docker-compose.yml)
- [ ] **Capabilities dropped** (`cap_drop: [ALL]`, only add back essentials)
- [ ] **Read-only filesystem** (`read_only: true`, tmpfs for writable paths)
- [ ] **No new privileges** (`security_opt: ["no-new-privileges:true"]`)
- [ ] **Seccomp profile applied** (see [seccomp-profiles/clawdbot.json](../../scripts/hardening/docker/seccomp-profiles/clawdbot.json))

**Verification**:
```bash
# Check container security
docker inspect clawdbot | jq '.[0].HostConfig' | grep -E "(User|CapDrop|ReadonlyRootfs|SecurityOpt)"

# Expected output:
# "User": "1000:1000"
# "CapDrop": ["ALL"]
# "ReadonlyRootfs": true
# "SecurityOpt": ["no-new-privileges=true", "seccomp=/path/to/profile.json"]
```

**Reference**: [Runtime Sandboxing Guide](../guides/04-runtime-sandboxing.md)

---

### 3.2 Resource Limits
- [ ] **CPU limits** defined (`cpus: "2"` or equivalent)
- [ ] **Memory limits** defined (`memory: "4g"`)
- [ ] **PID limits** defined (`pids_limit: 200`)
- [ ] **Restart policy** appropriate (`restart: on-failure:3`, NOT `always`)

**Verification**:
```bash
# Check resource usage
docker stats --no-stream clawdbot

# Limits should show (not unlimited)
```

---

## 4. Supply Chain Security

### 4.1 Container Images
- [ ] **Base image from trusted source** (official image or internal registry)
- [ ] **Image pinned by digest** (not `latest`, use `image@sha256:...`)
- [ ] **Vulnerability scan passed** (Trivy/Grype: 0 critical, <5 high)
- [ ] **SBOM generated** (Software Bill of Materials for audit)

**Verification**:
```bash
# Scan image
trivy image openclaw/clawdbot:1.2.3 --severity CRITICAL,HIGH
# Expected: 0 vulnerabilities

# Generate SBOM
syft openclaw/clawdbot:1.2.3 -o cyclonedx-json > sbom.json
```

**Reference**: [Supply Chain Security Guide](../guides/05-supply-chain-security.md)

---

### 4.2 Skills and Dependencies
- [ ] **Skill allowlist enforced** (see [allowlist.json](../../configs/skill-policies/allowlist.json))
- [ ] **Signature verification enabled** (`requireSignature: true`)
- [ ] **Auto-install disabled** (`autoInstall: false`)
- [ ] **Auto-update disabled** (`autoUpdate: false`)
- [ ] **Dependencies scanned** (`pip-audit`, `npm audit` with 0 critical)

**Verification**:
```bash
# Check skill integrity
./scripts/supply-chain/skill_manifest.py --skills-dir ~/.openclaw/skills --verify

# Check dependencies
pip-audit --format json
npm audit --json
```

---

## 5. Access Control

### 5.1 Authentication
- [ ] **MFA enabled** for all user accounts
- [ ] **Strong passwords enforced** (12+ characters, complexity requirements)
- [ ] **Password rotation** within last 90 days (for service accounts)
- [ ] **No default credentials** (admin/admin, root/root, etc.)

---

### 5.2 Authorization
- [ ] **RBAC configured** (roles: Admin, Developer, Operator)
- [ ] **Least privilege enforced** (users have minimum necessary permissions)
- [ ] **Privileged access is JIT** (Just-In-Time, 4-hour grants, not standing)
- [ ] **Access reviews up-to-date** (quarterly reviews completed)

**Reference**: [Access Control Policy](../policies/access-control-policy.md)

---

## 6. Monitoring and Logging

### 6.1 Logging
- [ ] **Audit logs enabled** (who, what, when, where for all actions)
- [ ] **Log retention configured** (7 years for compliance, 90 days for operational)
- [ ] **Logs centralized** (SIEM integration or log aggregation)
- [ ] **Sensitive data redacted** (no PII, credentials in logs)

**Verification**:
```bash
# Check audit log
tail /var/log/openclaw/audit.log
# Expected: Timestamps, user IDs, actions (no credentials)
```

---

### 6.2 Monitoring
- [ ] **Health checks configured** (HTTP /health endpoint returns 200)
- [ ] **Resource monitoring** (CPU, memory, disk usage tracked)
- [ ] **Security monitoring** (openclaw-telemetry or SIEM alerts)
- [ ] **Anomaly detection** (behavioral baseline established)

**Reference**: [Community Tools Integration](../guides/07-community-tools-integration.md)

---

## 7. Data Protection

### 7.1 Data Classification
- [ ] **Data classified** per [Data Classification Policy](../policies/data-classification.md)
- [ ] **PII redaction enabled** (for Confidential data processed by AI)
- [ ] **Restricted data NOT processed** by AI agents (manual review only)
- [ ] **Backup encryption enabled** (GPG + S3 server-side encryption)

---

### 7.2 Data Retention
- [ ] **Conversation history retention policy** (90 days production, 30 days dev)
- [ ] **Audit logs retained** per compliance (7 years for SOC 2 / ISO 27001)
- [ ] **Backup retention policy** (hourly: 24h, daily: 30d, monthly: 7y)

**Reference**: [Backup and Recovery Procedure](../procedures/backup-recovery.md)

---

## 8. Compliance

### 8.1 SOC 2 Type II
- [ ] **Security policy** acknowledged by all users
- [ ] **Access control** policy enforced (CC6.1)
- [ ] **Change management** followed for production changes (CC8.1)
- [ ] **Incident response** tested (tabletop exercise annually)

---

### 8.2 ISO 27001:2022
- [ ] **Risk assessment** completed (Annex A controls mapped)
- [ ] **Security controls** implemented per [Security Layers](../architecture/security-layers.md)
- [ ] **Vulnerability management** process documented (A.12.6.1)
- [ ] **Cryptography policy** followed (A.10.1)

---

### 8.3 GDPR
- [ ] **Data processing agreement** in place (if processing EU data)
- [ ] **Privacy by design** (PII redaction, data minimization)
- [ ] **Breach notification process** ready (72-hour SLA per Article 33)
- [ ] **Data subject rights** workflow (access, deletion, portability)

**Reference**: [Compliance Documentation](../compliance/)

---

## 9. Incident Preparedness

### 9.1 Backups
- [ ] **Backups tested** within last 30 days (restore successful)
- [ ] **Backup integrity verified** (checksums match)
- [ ] **DR site ready** (secondary region can take over within 8 hours)
- [ ] **Backup encryption keys** accessible (key escrow documented)

---

### 9.2 Response Plans
- [ ] **Incident response playbooks** ready (see [examples/incident-response/](../../examples/incident-response/))
- [ ] **On-call rotation** configured (PagerDuty or equivalent)
- [ ] **Contact list** up-to-date (Security, Legal, CISO)
- [ ] **Escalation matrix** documented (see [Incident Response Policy](../policies/incident-response-policy.md))

---

## 10. Configuration Management

### 10.1 Infrastructure as Code
- [ ] **All configs in version control** (Git)
- [ ] **No manual changes** to production (deploy via CI/CD only)
- [ ] **Configuration drift detection** enabled (check quarterly)
- [ ] **Secrets NOT in Git** (use `.gitignore` for credentials, checked: `git secrets --scan`)

---

### 10.2 Change Management
- [ ] **Change request approved** (CAB approval for production)
- [ ] **Rollback plan documented** (can revert within 15 minutes)
- [ ] **Maintenance window scheduled** (off-peak hours, stakeholders notified)
- [ ] **Post-change verification** (smoke tests pass)

---

## 11. Documentation

- [ ] **Deployment runbook updated** (see [Quick Start Guide](../guides/01-quick-start.md))
- [ ] **Architecture diagrams current** (see [Security Layers](../architecture/security-layers.md))
- [ ] **Incident playbooks reflect current environment**
- [ ] **CHANGELOG.md updated** (security-relevant changes documented)

---

## 12. Testing

### 12.1 Security Testing
- [ ] **Vulnerability scan completed** (within last 7 days, 0 critical)
- [ ] **Penetration test passed** (annually, or after major changes)
- [ ] **Security verification script passed**:
  ```bash
  ./scripts/verification/verify_openclaw_security.sh
  # Expected: 0 critical findings
  ```

---

### 12.2 Functional Testing
- [ ] **Integration tests passed** (all 247 tests green)
- [ ] **Smoke tests passed** (critical paths verified)
- [ ] **Performance tests passed** (RPS targets met, latency <100ms)

---

## Sign-Off

**Reviewed By**: ______________________________ (Security Team)  
**Date**: ______________________________  

**Approved By**: ______________________________ (Engineering Lead)  
**Date**: ______________________________  

**Deployed By**: ______________________________ (DevOps)  
**Date**: ______________________________  

**Deployment ID**: ______________________________ (Git SHA or release tag)  
**Environment**: Production / Staging / Development (circle one)

---

**Related Documentation**:
- [Production Deployment Checklist (PDF)](./Production-Deployment-Checklist.pdf) - Detailed version
- [Onboarding Checklist](./onboarding-checklist.md) - For new users
- [Quick Start Guide](../guides/01-quick-start.md) - Initial setup
- [Security Verification Script](../../scripts/verification/verify_openclaw_security.sh) - Automated checks
