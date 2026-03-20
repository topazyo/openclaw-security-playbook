# Access Review Procedure

**Document Type**: Operational Runbook  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Security Team + HR  
**Related Policy**: [Access Control Policy](../policies/access-control-policy.md)

> ⚠️ **Automation Notice:** The `scripts/access-management/` directory referenced throughout this runbook does not yet exist. All shell commands invoking those scripts are placeholder templates for planned future automation. For each phase, follow the **manual procedure steps** described in the accompanying prose. Track all review and remediation actions via your incident-tracking system (GitHub Issues, Jira, etc.).

This runbook defines the quarterly access review process to ensure least privilege and prevent unauthorized access to ClawdBot/OpenClaw systems.

---

## Table of Contents

1. [Overview](#overview)
2. [Schedule](#schedule)
3. [Review Process](#review-process)
4. [Role-Based Reviews](#role-based-reviews)
5. [Remediation](#remediation)
6. [Reporting](#reporting)
7. [Tools and Scripts](#tools-and-scripts)

---

## Overview

### Purpose

- **Verify** users still require their current access (role changes, terminations)
- **Detect** privilege creep (accumulation of permissions over time)
- **Enforce** least privilege (remove unnecessary access)
- **Comply** with regulations (SOC 2 CC6.1, ISO 27001 A.9.2.5, GDPR Article 32)

### Scope

**Systems Reviewed**:
- ClawdBot/OpenClaw deployments (production, staging, development)
- MCP server access
- Gateway API access
- Skill repositories
- Infrastructure (Docker hosts, Kubernetes clusters)
- Monitoring and logging systems
- Administrative interfaces (SIEM, VPN, secrets management)

---

## Schedule

### Quarterly Reviews

| Quarter | Review Month | Due Date | Review Owner |
|---------|--------------|----------|--------------|
| Q1 | January | January 31 | Security Team |
| Q2 | April | April 30 | Security Team |
| Q3 | July | July 31 | Security Team |
| Q4 | October | October 31 | Security Team |

**Kickoff**: First business day of review month  
**Deadline**: Last business day of review month  
**Escalation**: Outstanding reviews escalated to CISO on deadline day

---

### Event-Driven Reviews

**Trigger**: Immediate review required within 24 hours

- **Employee Termination**: Revoke all access immediately
- **Role Change**: Adjust permissions to match new role
- **Security Incident**: Review access for affected systems/users
- **Extended Leave**: Suspend access for leaves >30 days

**Process**: Follow the procedure in [Phase 4: Remediation](#remediation) immediately. File a ticket in your incident-tracking system recording the user, event type, and effective date before end of business.

---

## Review Process

### Phase 1: Data Collection (Days 1-5)

#### Step 1.1: Extract Current Access

Export a user access report from your identity provider (Okta, Azure AD, Google Workspace, etc.) and save as `access-report-YYYY-QX.csv`. Include: User ID, Name, Email, Role, Systems, LastLogin, GrantedDate, and GrantedBy.

**Example Output**:
```csv
UserID,Name,Email,Role,Systems,LastLogin,GrantedDate,GrantedBy
1001,Alice Johnson,alice@company.com,Admin,"prod,staging,dev",2026-02-10,2025-06-15,CISO
1002,Bob Smith,bob@company.com,Developer,"staging,dev",2026-02-12,2025-09-01,EngineeringLead
1003,Carol Chen,carol@company.com,Operator,"prod",2025-11-20,2025-08-10,SecurityLead
```

#### Step 1.2: Identify Inactive Users

Filter `access-report-YYYY-QX.csv` by the `LastLogin` column. Flag users with no login activity in the past 90 days, save the filtered list to `inactive-users.csv`, and note a recommendation for each (contact to confirm continued need, or flag for revocation).

#### Step 1.3: Check for Privilege Creep

Cross-reference the access report against your role matrix. Record findings in `privilege-creep-report.csv` and flag:
- Users with both Developer and Admin roles
- Production access granted to users in non-production roles
- Orphaned access (approver no longer employed)

---

### Phase 2: Manager Review (Days 6-15)

#### Step 2.1: Send Review Requests

Email the exported access report to each manager using your standard email system. Attach the relevant team subset of `access-report-YYYY-QX.csv`. Use the email wording from the certification template in Step 2.2 as the message body. Set the reply-to address to your access review tracking mailbox and include the certification deadline.

#### Step 2.2: Manager Certification

**Managers Must Certify**:
1. User still requires access (employment continues, role unchanged)
2. Access level is appropriate (least privilege)
3. No excessive permissions detected

**Certification Form**:
```markdown
# Access Review Certification: Q1 2026

Manager: Alice Johnson  
Department: Engineering  
Review Date: 2026-01-10

| User | Current Access | Certification | Notes |
|------|----------------|---------------|-------|
| Bob Smith | Developer (staging, dev) | ✅ KEEP | Actively working on project X |
| Carol Chen | Operator (prod) | ❌ REMOVE | Transferred to Marketing team |
| Dave Lee | Developer (prod, staging, dev) | 🔄 MODIFY | Remove prod access (no longer on-call) |

Signature: Alice Johnson  
Date: 2026-01-10
```

#### Step 2.3: Track Responses

Track completion in a shared spreadsheet or your incident-tracking system. For each manager record: department, submission date, and status (Pending / Complete / Escalated). Update the tracking sheet daily during the review window.

**Escalation** (if overdue): Send a manual reminder email to outstanding managers once overdue. Open a CISO escalation ticket if still outstanding after 7 days.

---

### Phase 3: Security Review (Days 16-20)

#### Step 3.1: Validate Manager Decisions

**Security Team Checks**:
1. **Terminations**: Were all terminated employees' access revoked?
2. **Compliance**: Do certifications comply with policies?
3. **Anomalies**: Investigate flagged accounts (privilege creep, inactive users with production access)

Cross-check manager certifications against HR records and current IdP role assignments. Flag any KEEP decision for a terminated employee, or any role mismatch between the certification and actual IdP role. Record all findings in `validation-report.txt` with supporting evidence.

#### Step 3.2: Review Privileged Access

**Special Scrutiny for**:
- **Admin Role**: Should be <5% of users
- **Production Access**: Requires business justification
- **Standing Privileges**: Should use JIT access instead

Query your identity provider for all users with the Admin role. For each, verify documented executive approval, active employment, and a current business justification on file. Record findings with counts and justifications.

---

### Phase 4: Remediation (Days 21-28)

#### Step 4.1: Revoke Unnecessary Access

For each user marked REMOVE in manager certifications, work through every item in the [Revocation Checklist](#revocation-checklist) below. Log each revocation in your incident-tracking system with the user, reason, and effective date.

**Revocation Actions**:
1. **API Keys**: Rotate and delete old keys
2. **VPN Access**: Remove from VPN user list
3. **Docker/K8s**: Delete kubeconfig, revoke certificates
4. **Skills**: Remove from authorized users list
5. **Monitoring**: Remove from Grafana, SIEM

**Notification**:
```
Subject: Access Revocation Notice

Your access to the following systems has been revoked per Q1 2026 Access Review:
- ClawdBot Production Environment
- Kubernetes Production Cluster

If you believe this is an error, contact your manager.

This action is effective immediately.
```

#### Step 4.2: Modify Access Levels

Update the user's role via your identity provider admin console or Kubernetes RBAC configuration. Confirm the change in the IdP and verify that any previously granted system access matches the new role. Log the old role, new role, approver, and effective date in the tracking ticket.

---

### Phase 5: Reporting (Days 29-31)

#### Step 5.1: Generate Compliance Report

Compile the quarterly compliance report using the **Report Contents** template below. Run `python tools/compliance-reporter.py` for SOC 2 / ISO 27001 evidence generation. Export to PDF and obtain CISO sign-off before the review deadline.

**Report Contents**:
1. **Executive Summary**: Total users reviewed, actions taken
2. **Certifications**: Manager sign-offs (attached)
3. **Revocations**: Users whose access was removed (with justification)
4. **Modifications**: Users whose access was changed
5. **Findings**: Anomalies detected and resolved
6. **Compliance**: SOC 2, ISO 27001, GDPR attestation

**Example Summary**:
```
Q1 2026 Access Review - Executive Summary

Total Users Reviewed: 247
Manager Certifications: 15/15 (100% completion)

Actions Taken:
- Revocations: 12 users (terminated employees, role changes)
- Modifications: 8 users (downgraded from Admin to Developer)
- Unchanged: 227 users (access still required)

Findings:
- 3 inactive users detected (>90 days no login) → Access revoked
- 1 privilege creep case (user had Admin + Developer roles) → Resolved
- 0 terminated employees with active access (compliance ✅)

Compliance Status: PASS
- SOC 2 CC6.1: Access review completed quarterly ✅
- ISO 27001 A.9.2.5: Access rights reviewed ✅
- GDPR Article 32: Least privilege enforced ✅

Report Date: 2026-01-31
Prepared By: Security Team
Approved By: CISO
```

#### Step 5.2: Audit Trail

**Preserve Evidence** (for SOC 2 / ISO 27001 audits):
- Manager certifications (signed PDFs)
- Access reports (before and after)
- Revocation logs (timestamped)
- Compliance report (signed by CISO)

**Storage**: Archive all artifacts (certifications, reports, revocation logs) into `/compliance/access-reviews/YYYY-QX/` with a minimum 7-year retention policy. Confirm archival is complete in the quarterly report before closing the review cycle.

---

## Role-Based Reviews

### Admin Role

**Criteria**:
- Executive approval required (CISO, CTO)
- MFA mandatory
- Annual background check (for sensitive data access)
- Just-In-Time (JIT) access preferred (4-hour grants)

**Review Questions**:
1. Does user still require admin privileges?
2. Can we downgrade to Developer + JIT for production access?
3. Has user completed annual security training?

---

### Developer Role

**Criteria**:
- Engineering manager approval
- Production access requires business justification
- Code review required for production deployments

**Review Questions**:
1. Is user actively developing AI agent features?
2. Does user still need staging/dev access?
3. Is production access justified? (on-call rotation, critical fixes)

---

### Operator Role

**Criteria**:
- Operations manager approval
- Read-only access to production (unless on-call)
- Monitoring and log access only

**Review Questions**:
1. Is user actively monitoring systems?
2. Is write access to production justified?
3. Can we use JIT access for modifications?

---

## Remediation

### Revocation Checklist

For each user whose access is revoked:

- [ ] **API Keys**: Rotate Anthropic API keys, revoke old keys
- [ ] **VPN**: Remove user from Tailscale/WireGuard
- [ ] **Credentials**: Delete from OS keychain (if company device)
- [ ] **Certificates**: Revoke mTLS client certificates
- [ ] **Kubernetes**: Delete user's kubeconfig, RoleBindings
- [ ] **Docker**: Remove from allowed users (docker socket access)
- [ ] **Skills**: Remove from skill repository collaborators
- [ ] **Monitoring**: Remove from Grafana, Prometheus, SIEM
- [ ] **Documentation**: Update runbooks if user was on-call
- [ ] **Notification**: Inform user and manager

Complete the **Revocation Checklist** above for each affected system in sequence. Record each completed item in a remediation ticket that includes the user, reason, and effective date.

---

## Reporting

### Quarterly Report to Security Leadership

**To**: CISO, VP Engineering, VP Operations  
**Format**: PDF + Excel spreadsheet

**Metrics**:
- Total users reviewed
- Certifications completed on time (%)
- Access revoked (count, %)
- Access modified (count, %)
- Inactive users detected and removed
- Privilege creep cases resolved

**Trend Analysis**:
```
Q1 2026 vs Q4 2025:
- Total Users: 247 (+12 from Q4)
- Revocations: 12 (-3 from Q4)
- Admin Accounts: 3 (unchanged from Q4)
- Compliance: 100% (maintained from Q4)
```

---

### Audit Evidence

**For SOC 2 / ISO 27001 auditors**:

**Provide**:
1. Quarterly access review reports (4 per year)
2. Manager certifications (with signatures)
3. Revocation logs (audit trail)
4. Policy acknowledgments (users signed Access Control Policy)

**Location**: `/compliance/access-reviews/YYYY-QX/`

---

## Tools and Scripts

> ⚠️ **Automation placeholder:** The `scripts/access-management/` directory does not yet exist in this repository. The commands shown throughout this runbook are proposals for future automation and **will fail if run**. Follow the manual procedures in each phase above instead.
>
> **Available tools that support access review work:**
> - [`tools/compliance-reporter.py`](../../tools/compliance-reporter.py) — SOC 2 / ISO 27001 compliance report generation
> - [`scripts/verification/verify_openclaw_security.sh`](../../scripts/verification/verify_openclaw_security.sh) — Security posture verification

---

**Document Owner**: Security Team + HR  
**Last Review**: Q4 2025 (October 2025)  
**Next Review**: Q2 2026 (April 2026)  
**Questions**: security@company.com  
**Manager Training**: Required annually (see [Training Materials](../../training/security-training.md))
