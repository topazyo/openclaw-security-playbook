# Onboarding Checklist

**Document Type**: New User Onboarding  
**Version**: 1.0.1  
**Last Updated**: 2026-02-21  
**Owner**: Security Team + HR

This checklist ensures new employees/contractors receive proper access and training for ClawdBot/OpenClaw systems.

---

## Pre-Day 1: HR Processing

### Account Creation
- [ ] **User account created** in identity system (Azure AD, Okta, etc.)
- [ ] **Employee ID assigned** (unique identifier)
- [ ] **Role determined** (Admin, Developer, Operator - see [Access Control Policy](../policies/access-control-policy.md))
- [ ] **Manager assigned** (for access approvals)
- [ ] **Department assigned** (Engineering, Operations, etc.)

### Device Provisioning
- [ ] **Company laptop issued** (macOS, Linux, or Windows with MDM enrollment)
- [ ] **MDM profile installed** (Mobile Device Management for security policies)
- [ ] **Full disk encryption enabled** (FileVault, LUKS, BitLocker)
- [ ] **Endpoint detection installed** (EDR agent: CrowdStrike, SentinelOne, etc.)
- [ ] **OS patches applied** (fully updated before handoff)

### Background Checks
- [ ] **Background check completed** (if accessing sensitive data)
- [ ] **NDA signed** (Non-Disclosure Agreement)
- [ ] **Acceptable Use Policy signed** (see [Acceptable Use Policy](../policies/acceptable-use-policy.md))

---

## Day 1: Initial Setup

### Welcome Package
- [ ] **Welcome email sent** with:
  - IT Helpdesk contact: it@company.com
  - Security Team contact: security@company.com
  - Emergency contacts (after-hours support)
  - Building access (badge, parking, keys)
- [ ] **Manager introductions** (team meeting scheduled)
- [ ] **Buddy assigned** (peer mentor for first 30 days)

### Account Activation
- [ ] **User logged in** to corporate network (VPN configured)
- [ ] **MFA enrolled** (mandatory):
  - Method 1: Authenticator app (Microsoft Authenticator, Google Authenticator)
  - Method 2: Hardware token (YubiKey preferred) or SMS (fallback)
- [ ] **Email account accessible** (user@company.com)
- [ ] **Slack/Teams invited** to relevant channels (#engineering, #security)

---

## Week 1: System Access

### Core Tools Access
- [ ] **GitHub/GitLab access** (added to `openclaw` organization)
- [ ] **JIRA/Project Management** (assigned to relevant projects)
- [ ] **Documentation access** (Confluence, Notion, internal wiki)
- [ ] **VPN configured**:
  - macOS/Linux: [Tailscale Setup](../../scripts/hardening/vpn/tailscale_setup.sh)
  - All platforms: [WireGuard Setup](../../scripts/hardening/vpn/wireguard_setup.sh)

### OpenClaw Access (Role-Based)

#### All Users
- [ ] **Quick Start Guide reviewed** (see [01-quick-start.md](../guides/01-quick-start.md))
- [ ] **Development environment access** (can deploy to personal dev instance)
- [ ] **Staging environment access** (read-only for Operators, read-write for Developers)

#### Developers
- [ ] **Staging write access** (can deploy to staging)
- [ ] **Skill repository access** (can submit PRs for new skills)
- [ ] **CI/CD pipeline access** (can trigger builds)

#### Operators
- [ ] **Production read access** (monitoring, logs)
- [ ] **On-call rotation** (added to PagerDuty schedule if applicable)

#### Admins
- [ ] **Production admin access** (via Just-In-Time request, not standing privilege)
- [ ] **Infrastructure access** (Kubernetes, Docker hosts)
- [ ] **Secrets management access** (HashiCorp Vault, AWS Secrets Manager)

**Access Request Process**:
```bash
# Submit access request
jira create \
  --project ACCESS \
  --type "Access Request" \
  --summary "OpenClaw Production Access - Jane Doe" \
  --description "Role: Operator; Justification: On-call rotation" \
  --assignee security-team

# Approval required: Manager + Security Team
```

---

## Week 1-2: Training

### Mandatory Training (All Users)
- [ ] **Security Awareness Training** (1 hour, annual renewal required)
  - Topics: Phishing, password security, data classification, incident reporting
  - Provider: KnowBe4, SANS, or internal training
  - Completion tracked in LMS (Learning Management System)
- [ ] **Acceptable Use Policy training** (30 minutes)
  - Review [Acceptable Use Policy](../policies/acceptable-use-policy.md)
  - Quiz: 10 questions, 80% pass required
- [ ] **Data Classification Training** (30 minutes)
  - Review [Data Classification Policy](../policies/data-classification.md)
  - Understand Public/Internal/Confidential/Restricted levels

### Role-Specific Training

#### Developers
- [ ] **AI Security Training** (2 hours)
  - Prompt injection risks (see [Scenario 001](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md))
  - Credential management (see [02-credential-isolation.md](../guides/02-credential-isolation.md))
  - Secure coding practices (no secrets in Git, input validation)
- [ ] **Supply Chain Security Training** (1 hour)
  - Skill vetting process (see [05-supply-chain-security.md](../guides/05-supply-chain-security.md))
  - Dependency scanning (Trivy, pip-audit)
  - SBOM generation (Syft)

#### Operators
- [ ] **Incident Response Training** (2 hours)
  - Review [Incident Response Policy](../policies/incident-response-policy.md)
  - Practice with [Incident Response Playbooks](../../examples/incident-response/)
  - On-call responsibilities (response SLA, escalation)

#### Admins
- [ ] **Advanced Security Training** (4 hours)
  - Threat modeling (see [Threat Model](../architecture/threat-model.md))
  - Runtime sandboxing (see [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md))
  - Network segmentation (see [03-network-segmentation.md](../guides/03-network-segmentation.md))

---

## Week 2: Hands-On Setup

### Development Environment

#### Step 1: Install Prerequisites
```bash
# macOS
brew install docker docker-compose git jq

# Linux
sudo apt update && sudo apt install -y docker.io docker-compose git jq
sudo usermod -aG docker $USER  # Add user to docker group

# Windows (PowerShell as Admin)
choco install docker-desktop git jq
```

#### Step 2: Clone Repository
```bash
git clone git@github.com:company/openclaw-security-playbook.git
cd openclaw-security-playbook
```

#### Step 3: Configure Credentials
```bash
# macOS
./scripts/credential-migration/macos/migrate_credentials_macos.sh

# Linux
./scripts/credential-migration/linux/migrate_credentials_linux.sh

# Verify credentials stored securely
security find-generic-password -s "ai.openclaw.anthropic"  # macOS
secret-tool lookup service "ai.openclaw.anthropic"         # Linux
```

**Reference**: [Credential Isolation Guide](../guides/02-credential-isolation.md)

#### Step 4: Deploy Development Instance
```bash
# Use hardened Docker Compose configuration
docker-compose -f configs/examples/docker-compose-full-stack.yml up -d

# Wait for health check
docker-compose -f configs/examples/docker-compose-full-stack.yml ps

# Verify deployment
./scripts/verification/verify_openclaw_security.sh
# Expected: 0 critical findings
```

**Reference**: [Quick Start Guide](../guides/01-quick-start.md)

#### Step 5: Run Tests
```bash
# Integration tests
pytest tests/integration

# Smoke tests
pytest tests/unit/test_tools_help_smoke.py
```

---

## Week 2-4: Shadowing and Practice

### Pair Programming (Developers)
- [ ] **Shadow senior developer** (1 week)
- [ ] **Code review participation** (review 5 PRs)
- [ ] **First PR submitted** (small bug fix or documentation improvement)
- [ ] **Security review passed** (PR approved by Security Team)

### On-Call Shadowing (Operators)
- [ ] **Shadow on-call engineer** (1 week)
- [ ] **Incident response practice** (tabletop exercise)
- [ ] **Runbook review** (practice with 3 incident playbooks)
- [ ] **First on-call shift** (with backup support)

### Infrastructure Review (Admins)
- [ ] **Architecture walkthrough** (2-hour session with Security Team)
- [ ] **Threat model review** (see [Threat Model](../architecture/threat-model.md))
- [ ] **Disaster recovery drill** (participate in quarterly DR test)
- [ ] **Privileged access practice** (JIT access approval workflow)

---

## Week 4: Final Certification

### Knowledge Check
- [ ] **Security quiz completed** (20 questions, 85% pass required)
  - Credential management (5 questions)
  - Incident response (5 questions)
  - Data classification (5 questions)
  - Acceptable use (5 questions)

### Practical Assessment

#### Developers
- [ ] **Deploy to staging** (end-to-end deployment)
- [ ] **Identify security issue** (in sample code, find 3 vulnerabilities)
- [ ] **Fix vulnerability** (apply proper remediation)

#### Operators
- [ ] **Respond to simulated incident** (P2 incident, follow playbook)
- [ ] **Analyze logs** (identify anomaly in audit logs)
- [ ] **Escalate properly** (know when to page Security On-Call)

#### Admins
- [ ] **Perform access review** (review 10 user accounts, identify 2 issues)
- [ ] **Harden deployment** (apply seccomp profile, verify configuration)
- [ ] **Backup/restore test** (restore from backup to staging)

---

## Sign-Off

### Manager Sign-Off
**I certify that [Employee Name] has completed all onboarding requirements and is ready for independent work.**

Manager Name: ______________________________  
Signature: ______________________________  
Date: ______________________________

### Security Team Sign-Off
**I certify that [Employee Name] has completed security training and passed assessments.**

Security Team Member: ______________________________  
Signature: ______________________________  
Date: ______________________________

### Employee Acknowledgment
**I acknowledge that I have completed onboarding and understand my security responsibilities.**

Employee Name: ______________________________  
Signature: ______________________________  
Date: ______________________________

---

## Post-Onboarding

### 30-Day Check-In
- [ ] **Manager 1:1 scheduled** (how is onboarding going?)
- [ ] **Security Team check-in** (any questions about security policies?)
- [ ] **Buddy feedback session** (peer mentor provides feedback)

### 90-Day Review
- [ ] **Performance review** (manager evaluates progress)
- [ ] **Access review** (verify user still needs current access level)
- [ ] **Training refresh** (re-take security quiz if <85% on first attempt)

---

## Off-Boarding (When Employee Departs)

**IMMEDIATE** (within 1 hour of termination):
- [ ] **Revoke all access** (see [Access Review Procedure](../procedures/access-review.md))
- [ ] **Disable accounts** (Azure AD, VPN, SSH keys)
- [ ] **Rotate credentials** (if employee had Admin access)
- [ ] **Collect company assets** (laptop, badge, hardware tokens)

**Within 24 Hours**:
- [ ] **Remove from documentation** (update runbooks, remove from on-call rotation)
- [ ] **Knowledge transfer** (if critical role, document handoff)
- [ ] **Exit interview** (HR + Security if sensitive role)

**Within 1 Week**:
- [ ] **Archive user data** (email, files per retention policy)
- [ ] **Final access review** (ensure no orphaned permissions)
- [ ] **Update compliance records** (SOC 2, ISO 27001 audit trail)

---

**Document Owner**: Security Team + HR  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-08-14 (semi-annual)  
**Questions**: hr@company.com, security@company.com

**Related Documentation**:
- [Access Control Policy](../policies/access-control-policy.md)
- [Acceptable Use Policy](../policies/acceptable-use-policy.md)
- [Data Classification Policy](../policies/data-classification.md)
- [Quick Start Guide](../guides/01-quick-start.md)
- [Training Materials](../../training/)
