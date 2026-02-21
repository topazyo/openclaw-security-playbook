# SOC 2 Controls Mapping

**Document Type**: Compliance Mapping  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Compliance Team + Security Team  
**Framework**: SOC 2 Type II (2017 Trust Services Criteria)

This document maps ClawdBot/OpenClaw security controls to SOC 2 Type II Trust Services Criteria.

---

## Table of Contents

1. [Overview](#overview)
2. [Control Environment (CC1)](#control-environment-cc1)
3. [Communication and Information (CC2)](#communication-and-information-cc2)
4. [Risk Assessment (CC3)](#risk-assessment-cc3)
5. [Monitoring Activities (CC4)](#monitoring-activities-cc4)
6. [Control Activities (CC5)](#control-activities-cc5)
7. [Logical and Physical Access Controls (CC6)](#logical-and-physical-access-controls-cc6)
8. [System Operations (CC7)](#system-operations-cc7)
9. [Change Management (CC8)](#change-management-cc8)
10. [Risk Mitigation (CC9)](#risk-mitigation-cc9)
11. [Audit Evidence](#audit-evidence)

---

## Overview

### SOC 2 Type II Scope

**In-Scope Systems**:
- ClawdBot/OpenClaw AI agent runtime
- MCP (Model Context Protocol) servers
- Gateway API (HTTP interface)
- Credential management systems
- Monitoring and logging infrastructure

**Out-of-Scope**:
- Anthropic Claude API (third-party service)
- End-user devices (customer responsibility)
- Public internet infrastructure

---

### Audit Period

**Current Audit Period**: January 1, 2026 - December 31, 2026  
**Audit Firm**: [Audit Firm Name]  
**Last Audit**: Q4 2025 (Report dated January 15, 2026)  
**Audit Opinion**: Unqualified (clean opinion)

---

### Compliance Status Dashboard

| Category | Total Controls | Implemented | In Progress | Not Applicable | Compliance % |
|----------|----------------|-------------|-------------|----------------|--------------|
| CC1 (Control Environment) | 5 | 5 | 0 | 0 | 100% |
| CC2 (Communication) | 2 | 2 | 0 | 0 | 100% |
| CC3 (Risk Assessment) | 4 | 4 | 0 | 0 | 100% |
| CC4 (Monitoring) | 2 | 2 | 0 | 0 | 100% |
| CC5 (Control Activities) | 4 | 4 | 0 | 0 | 100% |
| CC6 (Access Controls) | 8 | 8 | 0 | 0 | 100% |
| CC7 (System Operations) | 5 | 5 | 0 | 0 | 100% |
| CC8 (Change Management) | 3 | 3 | 0 | 0 | 100% |
| CC9 (Risk Mitigation) | 3 | 3 | 0 | 0 | 100% |
| **TOTAL** | **36** | **36** | **0** | **0** | **100%** |

**Last Updated**: 2026-02-14

---

## Control Environment (CC1)

### CC1.1: Integrity and Ethical Values

**Control Objective**: The entity demonstrates a commitment to integrity and ethical values.

**Implementation**:
- [Security Policy](../../configs/organization-policies/security-policy.json) (SEC-001) defines ethical use of AI agents
- [Acceptable Use Policy](../policies/acceptable-use-policy.md) (SEC-005) signed by all employees annually
- Code of Conduct prohibits misuse (credential sharing, data exfiltration, unauthorized access)
- Whistleblower hotline for reporting violations (anonymous reporting available)

**Evidence**:
- Policy acknowledgment records (100% of employees signed)
- Annual ethics training completion records (100% completion)
- Disciplinary action records (for policy violations)

**Reference**: [Organization Policy - Security](../../configs/organization-policies/security-policy.json)

---

### CC1.2: Board Independence and Oversight

**Control Objective**: The board of directors demonstrates independence from management and exercises oversight.

**Implementation**:
- Board audit committee reviews security posture quarterly
- Independent directors (3 of 5 board members)
- CISO reports directly to CEO and board audit committee
- Annual board training on AI security risks

**Evidence**:
- Board meeting minutes (quarterly security reviews)
- Audit committee charter
- CISO direct reporting structure (org chart)

---

### CC1.3: Organizational Structure and Authority

**Control Objective**: Management establishes structures, reporting lines, and appropriate authorities and responsibilities.

**Implementation**:
- Security organization chart defines roles (CISO → Security Team → DevSecOps)
- [Access Control Policy](../policies/access-control-policy.md) defines authority levels (Admin, Developer, Operator)
- Escalation matrix documented (see [Incident Response Procedure](../procedures/incident-response.md))

**Evidence**:
- Organizational chart (updated quarterly)
- Job descriptions (security roles)
- Access control matrix (who can approve what)

---

### CC1.4: Commitment to Competence

**Control Objective**: The entity demonstrates a commitment to attract, develop, and retain competent individuals.

**Implementation**:
- [Onboarding Checklist](../checklists/onboarding-checklist.md) includes mandatory security training
- Annual security awareness training (100% completion required)
- AI security training for developers (see [Training Materials](../../training/))
- Certifications encouraged (CISSP, CEH, OSCP for security team)

**Evidence**:
- Training completion records (LMS)
- Certification tracking (security team)
- Performance review documentation

---

### CC1.5: Accountability

**Control Objective**: The entity holds individuals accountable for their internal control responsibilities.

**Implementation**:
- Annual performance reviews include security responsibilities
- Security KPIs tracked (vulnerability remediation SLA, incident response time)
- [Acceptable Use Policy](../policies/acceptable-use-policy.md) violations result in disciplinary action
- Quarterly access reviews ensure accountability (see [Access Review Procedure](../procedures/access-review.md))

**Evidence**:
- Performance review templates (security section)
- Disciplinary action records
- Access review reports (quarterly)

---

## Communication and Information (CC2)

### CC2.1: Internal Communication

**Control Objective**: The entity obtains or generates and uses relevant, quality information to support internal control.

**Implementation**:
- Security incident notifications (Slack #security-incidents, email security@company.com)
- Monthly security newsletter (threat intelligence, policy updates)
- Weekly vulnerability reports (to development and operations teams)
- Quarterly security town halls (CISO presents to all employees)

**Evidence**:
- Slack message archives
- Email distribution lists
- Newsletter archives
- Town hall attendance records

---

### CC2.2: External Communication

**Control Objective**: The entity communicates with external parties regarding matters affecting internal control.

**Implementation**:
- Customer breach notifications per GDPR Article 33 (72-hour SLA)
- Security advisory publication (for disclosed vulnerabilities)
- SOC 2 report shared with customers (upon request with NDA)
- Regulatory reporting (data protection authorities as required)

**Evidence**:
- Breach notification records (timestamps, recipients)
- Security advisories (published on security@company.com)
- SOC 2 report distribution log

---

## Risk Assessment (CC3)

### CC3.1: Risk Identification

**Control Objective**: The entity specifies objectives with sufficient clarity to enable identification of risks.

**Implementation**:
- [Threat Model](../architecture/threat-model.md) catalogs AI-specific risks (prompt injection, credential exfiltration, supply chain attacks)
- Annual risk assessment (STRIDE methodology)
- Real-world attack scenarios documented (see [examples/scenarios/](../../examples/scenarios/))

**Evidence**:
- Risk register (updated quarterly)
- Threat model document (version controlled)
- Risk assessment reports (annual)

---

### CC3.2: Risk Analysis

**Control Objective**: The entity identifies and analyzes risk to the achievement of objectives.

**Implementation**:
- Risk scoring matrix (Risk = Severity × Exploitability × Exposure)
- Prioritization: P0 (24h SLA) → P1 (7d) → P2 (30d) → P3 (90d)
- [Vulnerability Management Procedure](../procedures/vulnerability-management.md) implements risk-based remediation

**Evidence**:
- Risk scores (CVSS + contextual factors)
- Remediation prioritization records
- SLA compliance metrics

---

### CC3.3: Fraud Risk Assessment

**Control Objective**: The entity considers the potential for fraud in assessing risks.

**Implementation**:
- Fraud risk assessment includes:
  - **Insider threat**: Credential exfiltration by employees (see [Scenario 005](../../examples/scenarios/scenario-005-credential-theft-via-skill.md))
  - **Impersonation**: Unauthorized use of AI agent
  - **Data exfiltration**: Conversation history theft (see [Scenario 006](../../examples/scenarios/scenario-006-credential-theft-conversation-history.md))
- Behavioral monitoring (openclaw-telemetry detects anomalies)
- Audit logs immutable (cannot be deleted by users)

**Evidence**:
- Fraud risk scenarios (documented)
- Anomaly detection alerts
- Audit log retention (7 years)

---

### CC3.4: Significant Changes

**Control Objective**: The entity identifies and assesses changes that could significantly impact internal control.

**Implementation**:
- Change Advisory Board (CAB) reviews all production changes
- [Production Deployment Checklist](../checklists/production-deployment.md) includes risk assessment
- Architecture review for major changes (new services, external integrations)

**Evidence**:
- CAB meeting minutes
- Deployment checklists (signed)
- Architecture review approvals

---

## Monitoring Activities (CC4)

### CC4.1: Ongoing and Periodic Evaluations

**Control Objective**: The entity selects, develops, and performs ongoing and/or separate evaluations.

**Implementation**:
- **Real-time**: openclaw-telemetry, SIEM alerts (see [monitoring-stack.yml](../../configs/examples/monitoring-stack.yml))
- **Daily**: Security analyst log review
- **Weekly**: Vulnerability scan results
- **Quarterly**: Access reviews, configuration audits
- **Annually**: Penetration testing, SOC 2 audit

**Evidence**:
- Monitoring dashboards (Grafana)
- Log review records (daily sign-off)
- Vulnerability scan reports (weekly)
- Access review reports (quarterly)
- Penetration test reports (annual)

---

### CC4.2: Evaluation of Deficiencies

**Control Objective**: The entity evaluates and communicates internal control deficiencies.

**Implementation**:
- Audit findings tracked in JIRA (severity: Critical, High, Medium, Low)
- Remediation plans with owners and deadlines
- Escalation to CISO for overdue critical findings
- Quarterly board reporting (open audit findings, remediation progress)

**Evidence**:
- Audit finding tracker (JIRA)
- Remediation status reports
- Board presentations (quarterly)

---

## Control Activities (CC5)

### CC5.1: Selection and Development of Control Activities

**Control Objective**: The entity selects and develops control activities that contribute to mitigation of risks.

**Implementation**:
- 7-layer defense-in-depth model (see [Security Layers](../architecture/security-layers.md))
- Technical controls: Credential isolation, network segmentation, runtime sandboxing, supply chain security
- Administrative controls: Policies, procedures, training
- Monitoring controls: Behavioral monitoring, audit logging

**Evidence**:
- Security architecture diagrams
- Control implementation documentation (guides 02-07)
- Configuration files (hardened docker-compose.yml, K8s manifests)

---

### CC5.2: Technology Controls

**Control Objective**: The entity selects and develops general control activities over technology.

**Implementation**:
- **Authentication**: MFA required for all users
- **Authorization**: RBAC with 3 roles (Admin, Developer, Operator)
- **Encryption**: TLS 1.2+ for data in transit, AES-256 for data at rest
- **Logging**: Immutable audit logs (tamper-evident)
- **Backup**: 3-2-1 backup strategy (see [Backup and Recovery Procedure](../procedures/backup-recovery.md))

**Evidence**:
- Authentication logs (MFA usage)
- Authorization matrix
- Encryption configuration (tested)
- Backup test results (monthly)

---

### CC5.3: Deployment Through Policies and Procedures

**Control Objective**: The entity deploys control activities through policies and procedures.

**Implementation**:
- Policies: [Access Control](../policies/access-control-policy.md), [Data Classification](../policies/data-classification.md), [Incident Response](../policies/incident-response-policy.md), [Acceptable Use](../policies/acceptable-use-policy.md)
- Procedures: [Incident Response](../procedures/incident-response.md), [Vulnerability Management](../procedures/vulnerability-management.md), [Access Review](../procedures/access-review.md), [Backup and Recovery](../procedures/backup-recovery.md)
- Checklists: [Security Review](../checklists/security-review.md), [Production Deployment](../checklists/production-deployment.md), [Onboarding](../checklists/onboarding-checklist.md)

**Evidence**:
- Policy acknowledgments (100% signed)
- Procedure execution records (tickets, logs)
- Checklist completions (signed)

---

### CC5.4: Restrictive Actions

**Control Objective**: The entity establishes restrictive actions.

**Implementation**:
- **Technical restrictions**:
  - Network binding: `127.0.0.1:18789` (localhost only, see [Network Segmentation](../guides/03-network-segmentation.md))
  - Capabilities: `cap_drop: [ALL]` (see [Runtime Sandboxing](../guides/04-runtime-sandboxing.md))
  - Filesystem: `read_only: true` (immutable containers)
  - Skill allowlist: Only approved skills installable (see [Supply Chain Security](../guides/05-supply-chain-security.md))
- **Administrative restrictions**:
  - Least privilege: Users have minimum necessary permissions
  - JIT access: Admin privileges granted for 4 hours only
  - Quarterly access reviews: Revoke unnecessary access

**Evidence**:
- Configuration audits (network binding, capabilities)
- Access control lists (RBAC roles)
- JIT access logs (time-limited grants)
- Access review reports (revocations documented)

---

## Logical and Physical Access Controls (CC6)

### CC6.1: Logical Access

**Control Objective**: The entity authorizes, modifies, or removes access to data and infrastructure.

**Implementation**:
- Access request process (see [Onboarding Checklist](../checklists/onboarding-checklist.md))
- Manager approval + Security Team approval required
- Access provisioning automated (JIRA ticket triggers Terraform/Ansible)
- Deprovisioning within 1 hour of termination

**Evidence**:
- Access request tickets (JIRA)
- Provisioning logs (IAM changes)
- Deprovisioning records (termination checklist)

---

### CC6.2: Authentication

**Control Objective**: The entity uses authentication mechanisms.

**Implementation**:
- MFA mandatory (no exceptions, see [Access Control Policy](../policies/access-control-policy.md))
- Password policy: 12+ characters, complexity requirements, 90-day rotation
- API key management: OS keychain storage (see [Credential Isolation](../guides/02-credential-isolation.md))
- Certificate-based auth for services (mTLS)

**Evidence**:
- MFA enrollment logs (100% of users)
- Password compliance reports
- API key audit (no plaintext credentials)
- Certificate inventory

---

### CC6.3: Authorization

**Control Objective**: The entity authorizes access to assets.

**Implementation**:
- RBAC with 3 roles:
  - **Admin**: Production write access, JIT only
  - **Developer**: Staging write, production read-only
  - **Operator**: Production read-only, limited write for on-call
- Authorization matrix documents allowed actions per role
- Enforcement: Technical (RBAC) + Administrative (quarterly reviews)

**Evidence**:
- RBAC configuration (K8s RoleBindings, IAM policies)
- Authorization matrix
- Access denial logs (unauthorized attempts)

---

### CC6.4: Privileged Access

**Control Objective**: The entity restricts access to programs, data, and infrastructure based on roles.

**Implementation**:
- Privileged access is JIT: 4-hour grants, auto-revoke
- Approval workflow: JIRA ticket → Manager approval → Security approval
- All privileged actions logged (immutable audit trail)
- Privileged accounts never used for daily work (separate admin accounts)

**Evidence**:
- JIT access logs (granted, used, revoked)
- Approval records (JIRA tickets)
- Privileged action audit logs

---

### CC6.5: Credential Management

**Control Objective**: The entity uses encrypted connections and authenticates to systems.

**Implementation**:
- All credentials in OS keychain (no plaintext)
- API keys rotated every 90 days
- Credential backup encrypted (GPG + S3 server-side encryption)
- No credentials in Git (enforced by git-secrets hook)

**Evidence**:
- Credential storage verification ([verify_openclaw_security.sh](../../scripts/verification/verify_openclaw_security.sh))
- Rotation logs (last rotation date)
- Git history scan (no secrets)

---

### CC6.6: Physical Access

**Control Objective**: The entity restricts physical access to facilities and equipment.

**Implementation**:
- **Cloud-hosted**: AWS/Azure/GCP data centers (SOC 2 compliant)
- **Office**: Badge access, visitor logs, security cameras
- **Laptop security**: Full disk encryption, screen lock (5 minutes), no shared devices

**Evidence**:
- Cloud provider SOC 2 reports
- Badge access logs
- Laptop encryption verification (MDM reports)

---

### CC6.7: Transmission of Data

**Control Objective**: The entity restricts the transmission, movement, and removal of data.

**Implementation**:
- TLS 1.2+ for all network communication
- VPN required for remote access (see [Network Segmentation](../guides/03-network-segmentation.md))
- Data Loss Prevention (DLP): openclaw-shield blocks credential exfiltration
- Backup encryption: AES-256 + GPG (see [Backup and Recovery](../procedures/backup-recovery.md))

**Evidence**:
- TLS configuration audits
- VPN connection logs
- DLP alerts (blocked exfiltration attempts)
- Backup encryption verification

---

### CC6.8: Removal and Recycle of Equipment

**Control Objective**: The entity securely disposes of data and equipment.

**Implementation**:
- Laptop wiping: NIST 800-88 media sanitization (3-pass overwrite)
- Hard drive destruction: Physical shredding (certificate of destruction)
- Data retention policy: 7 years for compliance data, then secure deletion
- Cloud data: Cryptographic erasure (delete encryption keys)

**Evidence**:
- Destruction certificates (shredded drives)
- Data deletion logs (timestamps)
- NIST 800-88 compliance reports

---

## System Operations (CC7)

### CC7.1: Detection of System Vulnerabilities

**Control Objective**: The entity detects system vulnerabilities and promptly remediates them.

**Implementation**:
- Automated vulnerability scanning: Daily (Trivy on containers), Weekly (dependencies), Monthly (infrastructure)
- [Vulnerability Management Procedure](../procedures/vulnerability-management.md) defines SLA: P0 (24h), P1 (7d), P2 (30d), P3 (90d)
- Patch management: Security patches applied within SLA

**Evidence**:
- Vulnerability scan reports (daily/weekly/monthly)
- Remediation tickets (JIRA with SLA tracking)
- Patch logs (applied updates)

---

### CC7.2: Monitoring of System Operations

**Control Objective**: The entity monitors system components and the operation of those components.

**Implementation**:
- Real-time monitoring: openclaw-telemetry, SIEM (see [monitoring-stack.yml](../../configs/examples/monitoring-stack.yml))
- Metrics: CPU, memory, disk, API usage, error rates, latency
- Alerting: PagerDuty for P0/P1 issues, email for P2/P3
- Dashboards: Grafana (accessible to operations team)

**Evidence**:
- Monitoring dashboards (screenshots)
- Alert history (PagerDuty logs)
- Incident tickets (triggered by alerts)

---

### CC7.3: Incident Detection and Response

**Control Objective**: The entity responds to identified incidents.

**Implementation**:
- [Incident Response Policy](../policies/incident-response-policy.md) defines procedures, SLA, roles
- [Incident Response Procedure](../procedures/incident-response.md) provides runbook
- Incident playbooks for common attacks (see [examples/incident-response/](../../examples/incident-response/))
- Response tested: Tabletop exercises quarterly, full DR drill annually

**Evidence**:
- Incident tickets (JIRA with timeline)
- Post-incident review reports
- Tabletop exercise records (quarterly)
- DR drill results (annual)

---

### CC7.4: Incident Analysis

**Control Objective**: The entity analyzes security incidents to identify root cause.

**Implementation**:
- Post-Incident Review (PIR) within 5 business days
- Root cause analysis (5 Whys methodology)
- Lessons learned documented, action items tracked
- Runbooks updated with learnings

**Evidence**:
- PIR reports (see [reporting-template.md](../../examples/incident-response/reporting-template.md))
- Action item tracking (JIRA)
- Updated runbooks (version control)

---

### CC7.5: Incident Remediation

**Control Objective**: The entity takes corrective actions to remediate incidents.

**Implementation**:
- Action items from PIR assigned to owners with deadlines
- Verification: Re-test exploits to confirm fix
- Communication: Notify stakeholders of remediation completion
- Metrics: Track Mean Time To Remediate (MTTR)

**Evidence**:
- Action item completion records
- Remediation verification tests
- MTTR metrics (target: <24h for P0, <7d for P1)

---

## Change Management (CC8)

### CC8.1: Change Management Process

**Control Objective**: The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.

**Implementation**:
- Change Advisory Board (CAB) reviews all production changes
- [Production Deployment Checklist](../checklists/production-deployment.md) mandatory
- Rollback plan required (tested in staging)
- Post-change verification (smoke tests)

**Evidence**:
- CAB meeting minutes
- Deployment checklists (signed)
- Rollback test results (staging)
- Post-change verification logs

---

### CC8.2: Development and Deployment

**Control Objective**: The entity manages changes made through its system development life cycle.

**Implementation**:
- Infrastructure as Code (Terraform, Ansible) - all configs in Git
- CI/CD pipeline: Automated testing (unit, integration, security)
- Canary deployments: 10% → 50% → 100% traffic gradual rollout
- Immutable infrastructure: Containers rebuilt from Dockerfile, not patched in place

**Evidence**:
- Git commit history (all changes tracked)
- CI/CD logs (test results)
- Deployment metrics (canary rollout)
- Container image tags (versioned)

---

### CC8.3: Emergency Changes

**Control Objective**: The entity authorizes, tests, and documents emergency changes.

**Implementation**:
- Emergency change process: CISO or CTO verbal approval, written approval within 24 hours
- Hotfix procedure: Deploy to staging first (even in emergency), rollback plan ready
- Post-emergency review: PIR within 48 hours, action items for process improvement

**Evidence**:
- Emergency change approvals (email, Slack)
- Hotfix deployment logs
- Post-emergency PIR reports

---

## Risk Mitigation (CC9)

### CC9.1: Vendor Management

**Control Objective**: The entity identifies, evaluates, and manages risks related to vendors.

**Implementation**:
- Anthropic (Claude API): Reviewed SOC 2 report, signed Data Processing Agreement (DPA)
- Cloud providers (AWS/Azure/GCP): SOC 2 compliant, ISO 27001 certified
- Skill vendors: Security review required (see [Supply Chain Security](../guides/05-supply-chain-security.md))

**Evidence**:
- Vendor risk assessments (annual)
- Vendor SOC 2 reports (on file)
- DPAs (signed)

---

### CC9.2: Business Continuity and Disaster Recovery

**Control Objective**: The entity designs, develops, and implements activities to prevent, detect, and mitigate threats.

**Implementation**:
- [Backup and Recovery Procedure](../procedures/backup-recovery.md) defines RPO/RTO
- 3-2-1 backup strategy: 3 copies, 2 media types, 1 off-site
- DR site: Secondary AWS region (eu-west-1)
- DR testing: Monthly backup restore test, annual full DR drill

**Evidence**:
- Backup test results (monthly)
- DR drill reports (annual)
- RPO/RTO metrics (actual vs target)

---

### CC9.3: Cybersecurity Insurance

**Control Objective**: The entity maintains cybersecurity insurance coverage.

**Implementation**:
- Cybersecurity insurance policy: $5M coverage
- Policy covers: Data breach response, regulatory fines, business interruption, cyber extortion
- Annual renewal, premium based on security posture

**Evidence**:
- Insurance policy (certificate of coverage)
- Premium invoices (paid annually)

---

## Audit Evidence

### Evidence Archive Location

**Path**: `/compliance/soc2-audit-evidence/2026/`

**Contents**:
- Policy documents (signed versions)
- Procedure execution records
- Training completion records
- Access review reports
- Vulnerability scan results
- Incident response records
- Change management approvals
- Backup test results
- Monitoring screenshots

**Retention**: 7 years (SOC 2 requirement)

---

### Auditor Access

**Audit Firm**: [Audit Firm Name]  
**Lead Auditor**: [Name], [Email]  
**Audit Fieldwork**: October 1-31, 2026  
**Evidence Request Portal**: [URL]

**Point of Contact**:
- Compliance Officer: compliance@company.com
- CISO: ciso@company.com
- Audit Liaison: [Name], [Email]

---

**Document Owner**: Compliance Team + Security Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-08-14 (semi-annual)  
**SOC 2 Report Requests**: compliance@company.com  
**Questions**: security@company.com

**Related Documentation**:
- [SOC 2 Compliance Mapping JSON](../../configs/organization-policies/soc2-compliance-mapping.json) - Machine-readable mapping
- [ISO 27001 Controls Mapping](./iso27001-controls.md) - ISO 27001 crosswalk
- [GDPR Compliance](./gdpr-compliance.md) - GDPR requirements
- [Audit Configuration](./audit-configuration.md) - Technical audit settings
