# ISO 27001:2022 Controls Mapping

**Document Type**: Compliance Mapping  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Compliance Team + Security Team  
**Framework**: ISO/IEC 27001:2022 Annex A

This document maps ClawdBot/OpenClaw security controls to ISO 27001:2022 Annex A control objectives.

---

## Table of Contents

1. [Overview](#overview)
2. [Organizational Controls (A.5)](#organizational-controls-a5)
3. [People Controls (A.6)](#people-controls-a6)
4. [Physical Controls (A.7)](#physical-controls-a7)
5. [Technological Controls (A.8)](#technological-controls-a8)
6. [Audit Evidence](#audit-evidence)

---

## Overview

### ISO 27001:2022 Scope

**Information Security Management System (ISMS) Scope**:
- ClawdBot/OpenClaw AI agent operations
- AI model API integrations (Anthropic Claude)
- Credential management infrastructure
- Network segmentation and gateway services
- Runtime sandboxing (Docker/Kubernetes)
- Supply chain security (skills, MCP servers)
- Monitoring and incident response systems

**Certification Status**: ISO 27001:2022 Certified  
**Certificate Number**: ISO27K-2026-001234  
**Certification Body**: [Certification Body Name]  
**Certification Date**: January 15, 2026  
**Valid Until**: January 14, 2029 (3 years)  
**Surveillance Audits**: Annually (January 2027, January 2028)

---

### Compliance Dashboard

| Annex A Section | Total Controls | Implemented | Evidence Available | Compliance % |
|-----------------|----------------|-------------|-------------------|--------------|
| A.5 (Organizational) | 37 | 37 | 37 | 100% |
| A.6 (People) | 8 | 8 | 8 | 100% |
| A.7 (Physical) | 14 | 14 | 14 | 100% |
| A.8 (Technological) | 34 | 34 | 34 | 100% |
| **TOTAL** | **93** | **93** | **93** | **100%** |

**Last Audit**: January 2026 (Certification Audit)  
**Next Audit**: January 2027 (Surveillance Audit)  
**Non-Conformities**: 0  
**Opportunities for Improvement**: 3 (documented in CAR tracker)

---

## Organizational Controls (A.5)

### A.5.1: Policies for Information Security

**Control Objective**: Management direction and support for information security in accordance with business requirements and relevant laws and regulations.

**Implementation**:
- [Security Policy](../../configs/organization-policies/security-policy.json) (SEC-001) - Overarching security policy, board-approved
- [Access Control Policy](../policies/access-control-policy.md) (SEC-002) - Identity and access management
- [Data Classification Policy](../policies/data-classification.md) (SEC-003) - Data handling requirements
- [Incident Response Policy](../policies/incident-response-policy.md) (SEC-004) - Security incident management
- [Acceptable Use Policy](../policies/acceptable-use-policy.md) (SEC-005) - User responsibilities

**Policy Review**: Annually or when significant changes occur  
**Approval**: CISO (draft) → Executive Team (review) → Board of Directors (approval)  
**Communication**: All policies published on internal wiki, signed acknowledgment required

**Evidence**:
- Policy documents (version controlled, approved signatures)
- Policy acknowledgment records (100% of employees)
- Annual policy review meeting minutes

**Reference**: [Organization Policy - Security](../../configs/organization-policies/security-policy.json)

---

### A.5.2: Information Security Roles and Responsibilities

**Control Objective**: Information security roles and responsibilities are defined and allocated according to organization needs.

**Implementation**:
- **CISO**: Overall security strategy, board reporting, compliance oversight
- **Security Team**: Implement controls, incident response, vulnerability management
- **DevSecOps Engineers**: Secure development, infrastructure hardening, CI/CD security
- **Data Protection Officer (DPO)**: GDPR compliance, privacy by design
- **All Employees**: Report incidents, follow policies, complete training

**Roles documented**: Job descriptions, RACI matrix, escalation paths

**Evidence**:
- Organizational chart (security team structure)
- Job descriptions (security responsibilities)
- RACI matrix (who is Responsible, Accountable, Consulted, Informed)

---

### A.5.3: Segregation of Duties

**Control Objective**: Conflicting duties and conflicting areas of responsibility are segregated to reduce opportunities for unauthorized or unintentional modification or misuse.

**Implementation**:
- Developer cannot approve own code (peer review required)
- Security team cannot deploy own changes (operations team deploys)
- CISO reports to CEO (independent from engineering)
- No single person has all admin privileges (dual control for critical actions)

**Examples**:
- Code review: Developer writes code → Peer approves → CI/CD deploys
- Production access: Engineer requests JIT access → Manager approves → Security approves → Auto-granted for 4 hours

**Evidence**:
- Pull request approvals (GitHub history)
- JIT access approval logs (dual approval)
- Deployment logs (who deployed, who approved)

---

### A.5.4: Management Responsibilities

**Control Objective**: Management requires personnel to apply information security in accordance with established policies, procedures.

**Implementation**:
- Security responsibilities in performance reviews
- Annual security training mandatory (100% completion)
- Security KPIs tracked (vulnerability remediation, incident response time)
- Managers certify team access during quarterly access reviews

**Evidence**:
- Performance review templates (security section)
- Training completion records
- KPI dashboards (Grafana)
- Access review certifications (manager signatures)

---

### A.5.5: Contact with Authorities

**Control Objective**: Appropriate contacts with relevant authorities are maintained.

**Implementation**:
- **Law enforcement**: Local police cybercrime unit (pre-established contact for major incidents)
- **Data Protection Authority**: [Country] DPA (GDPR breach notifications)
- **CERT/CSIRT**: National cybersecurity center (threat intelligence sharing)
- **Regulatory bodies**: Financial regulators (if handling payment data)

**Contact list**: Maintained in [Incident Response Procedure](../procedures/incident-response.md)

**Evidence**:
- Contact list (updated quarterly)
- Communication records (past incident notifications)

---

### A.5.6: Contact with Special Interest Groups

**Control Objective**: Appropriate contacts with special interest groups or security forums are maintained.

**Implementation**:
- AI security community: OWASP LLM Top 10, AI security mailing lists
- Cloud security: AWS/Azure/GCP security bulletins
- Open source security: GitHub Security Lab, OSS security working groups
- Industry forums: [Industry] ISAC (Information Sharing and Analysis Center)

**Evidence**:
- Forum membership records
- Threat intelligence reports (derived from community sources)

---

### A.5.7: Threat Intelligence

**Control Objective**: Information relating to information security threats is collected and analyzed to produce threat intelligence.

**Implementation**:
- Threat feeds: NIST NVD, GitHub Security Advisories, vendor bulletins
- AI-specific threats: Prompt injection disclosures, AI security research
- Weekly threat intelligence report (distributed to security and engineering teams)
- Threat modeling: STRIDE-based (see [Threat Model](../architecture/threat-model.md))

**Evidence**:
- Threat intelligence reports (weekly)
- Threat model document (version controlled)
- Remediation actions (vulnerabilities addressed based on threat intel)

---

### A.5.8: Information Security in Project Management

**Control Objective**: Information security is integrated into project management.

**Implementation**:
- Security requirements in project charter
- [Security Review Checklist](../checklists/security-review.md) mandatory before production
- Security Team involved in architecture reviews
- Security testing in project timeline (pentest, vuln scan)

**Evidence**:
- Project charters (security requirements section)
- Security review approvals (checklists signed)
- Architecture review meeting minutes

---

### A.5.9: Inventory of Information and Other Associated Assets

**Control Objective**: An inventory of information and other associated assets is developed and maintained.

**Implementation**:
- Asset inventory: Automated discovery (AWS Config, Azure Resource Graph)
- **Assets tracked**:
  - Servers/VMs (EC2 instances, K8s nodes)
  - Containers (Docker images, running containers)
  - Databases (credentials store, conversation history)
  - API keys (credential management system)
  - Skills/MCP servers (skill manifest)
- Asset classification: Based on data classification (see [Data Classification Policy](../policies/data-classification.md))

**Tool**: Asset inventory in CMDB (Configuration Management Database)

**Evidence**:
- Asset inventory reports (automated, daily)
- Asset ownership assignments
- Asset classification tags (cloud resources)

---

### A.5.10: Acceptable Use of Information and Other Associated Assets

**Control Objective**: Rules for acceptable use and procedures for handling information are identified, documented.

**Implementation**:
- [Acceptable Use Policy](../policies/acceptable-use-policy.md) (SEC-005) defines acceptable/prohibited activities
- Technical enforcement: openclaw-shield blocks prohibited prompts
- Monitoring: openclaw-telemetry detects policy violations
- Consequences: Progressive discipline (verbal warning → written warning → termination)

**Evidence**:
- Acceptable use policy acknowledgments (100% signed)
- Policy violation records (incidents documented)
- Disciplinary action records

---

### A.5.11: Return of Assets

**Control Objective**: Personnel and other interested parties as appropriate return all organization assets in their possession upon termination or change of employment.

**Implementation**:
- Off-boarding checklist (see [Onboarding Checklist - Off-boarding](../checklists/onboarding-checklist.md#off-boarding))
- **Assets to return**:
  - Laptop, mobile phone, security tokens
  - Access badges
  - API keys (revoked), VPN certificates (revoked)
  - Company data (deleted from personal devices)
- Access revocation within 1 hour of termination

**Evidence**:
- Off-boarding checklists (completed)
- Asset return records (signed receipts)
- Access revocation logs (timestamp within 1h of termination)

---

### A.5.12: Classification of Information

**Control Objective**: Information is classified in accordance with legal, regulatory, contractual, and business requirements.

**Implementation**:
- [Data Classification Policy](../policies/data-classification.md) (SEC-003) defines 4 levels:
  - **Public**: Product documentation, marketing materials
  - **Internal**: Internal wikis, non-sensitive business data
  - **Confidential**: Customer conversation history, business strategies
  - **Restricted**: API keys, cryptographic keys, personal data (PII)
- Classification labels: Applied to files (metadata), cloud resources (tags), documents (headers/footers)

**Evidence**:
- Classification policy (approved)
- Classification labels (applied to assets)
- Handling procedures (per classification level)

---

### A.5.13: Labelling of Information

**Control Objective**: An appropriate set of procedures for information labelling is developed and implemented.

**Implementation**:
- **File metadata**: Extended attributes (xattr) for classification level
- **Cloud resources**: AWS/Azure tags (e.g., `Classification=Restricted`)
- **Documents**: Header/footer labels (e.g., "CONFIDENTIAL - Internal Use Only")
- **Email**: Subject line prefix for classified emails

**Automated labeling**: DLP tools auto-classify based on content (e.g., detect PII → label Restricted)

**Evidence**:
- Labeling standards document
- Sample labeled assets (screenshots)
- DLP classification reports

---

### A.5.14: Information Transfer

**Control Objective**: Information transfer rules, procedures, or agreements are in place for all types of transfer facilities.

**Implementation**:
- **Network transfer**: TLS 1.2+ encryption (see [Network Segmentation](../guides/03-network-segmentation.md))
- **Backup transfer**: Encrypted backups to S3 (AES-256 + GPG)
- **Email**: Encrypted email for Restricted data (PGP or S/MIME)
- **Third-party transfer**: Data Processing Agreements (DPA) required, secure file transfer (SFTP, S3 pre-signed URLs)

**DLP**: openclaw-shield blocks transfer of Restricted data without approval

**Evidence**:
- TLS configuration audits
- Backup encryption verification
- DPA agreements (signed)
- DLP block logs (unauthorized transfer attempts)

---

### A.5.15: Access Control

**Control Objective**: Rules to control physical and logical access to information and other associated assets are established and implemented.

**Implementation**:
- [Access Control Policy](../policies/access-control-policy.md) (SEC-002) defines access rules
- **Logical access**: RBAC (Admin, Developer, Operator), MFA, JIT privileged access
- **Physical access**: Badge access to offices, data centers managed by cloud provider
- **Enforcement**: Technical (IAM policies, K8s RBAC) + Administrative (quarterly access reviews)

**Evidence**:
- Access control policy (approved)
- RBAC configuration (K8s, AWS IAM)
- Access review reports (quarterly)

---

### A.5.16: Identity Management

**Control Objective**: The full life cycle of identities is managed.

**Implementation**:
- **Identity creation**: Automated via onboarding (see [Onboarding Checklist](../checklists/onboarding-checklist.md))
- **Identity modification**: Role change requests (manager approval)
- **Identity deletion**: Off-boarding (access revoked within 1 hour)
- **Identity lifecycle**: User account → Enable MFA → Assign roles → Quarterly review → Termination → Revoke access

**Identity Provider**: Azure AD / Okta (centralized identity management)

**Evidence**:
- User account provisioning logs
- Role change approvals
- Account deactivation logs (1-hour SLA compliance)

---

### A.5.17: Authentication Information

**Control Objective**: Allocation and management of authentication information is controlled by a management process.

**Implementation**:
- **Passwords**: 12+ characters, complexity, 90-day rotation
- **MFA**: Mandatory, hardware tokens preferred (YubiKey)
- **API keys**: Generated by system (32-byte random), stored in OS keychain, rotated every 90 days
- **Certificates**: Issued by internal CA, 1-year validity, auto-renewal 30 days before expiry

**Evidence**:
- Password policy configuration
- MFA enrollment records (100% compliance)
- API key rotation logs
- Certificate inventory (expiry tracking)

---

### A.5.18: Access Rights

**Control Objective**: Access rights to information and other associated assets are provisioned, reviewed, modified, and removed.

**Implementation**:
- **Provisioning**: Manager approval + Security approval (dual control)
- **Review**: Quarterly access reviews (see [Access Review Procedure](../procedures/access-review.md))
- **Modification**: Role change process (re-approval required)
- **Removal**: Off-boarding (immediate revocation), quarterly review (identify stale accounts)

**Least privilege**: Users granted minimum necessary access

**Evidence**:
- Provisioning approvals (JIRA tickets)
- Quarterly access review reports (manager certifications)
- Access revocation logs

---

### A.5.19: Information Security in Supplier Relationships

**Control Objective**: Processes and procedures are defined and implemented to manage information security risks associated with supplier products and services.

**Implementation**:
- Vendor risk assessment (see [Supply Chain Security](../guides/05-supply-chain-security.md))
- **Critical suppliers**: Anthropic (Claude API), cloud providers (AWS/Azure/GCP)
- Security requirements in contracts: SOC 2 compliance, encryption, breach notification
- Annual supplier reviews (re-assessment)

**Evidence**:
- Vendor risk assessments (annual)
- Supplier contracts (security clauses)
- Supplier SOC 2 reports (on file)

---

### A.5.20: Addressing Information Security Within Supplier Agreements

**Control Objective**: Relevant information security requirements are established and agreed with each supplier.

**Implementation**:
- Data Processing Agreements (DPA) for suppliers processing personal data
- Security requirements:
  - Encryption (data at rest and in transit)
  - Access controls (least privilege)
  - Breach notification (72 hours)
  - Audit rights (annual SOC 2 or equivalent)
  - Data deletion (upon contract termination)

**Evidence**:
- Signed DPAs
- Supplier security questionnaires (completed)
- Audit rights clauses (in contracts)

---

### A.5.21: Managing Information Security in the ICT Supply Chain

**Control Objective**: Processes and procedures are defined and implemented to manage information security risks associated with the supply chain.

**Implementation**:
- Skill supply chain: Only approved skills installable (allowlist in [skill-policies/allowlist.json](../../configs/skill-policies/allowlist.json))
- Signature verification: Skills must be GPG-signed by trusted publishers
- SBOM (Software Bill of Materials): Generated for all containers (see [Supply Chain Security](../guides/05-supply-chain-security.md))
- Vulnerability scanning: Daily scans of container images (Trivy)

**Tool**: [skill_manifest.py](../../scripts/supply-chain/skill_manifest.py) validates skill integrity

**Evidence**:
- Skill allowlist (version controlled)
- Signature verification logs (GPG verification results)
- SBOM files (JSON format)
- Vulnerability scan reports (daily)

---

### A.5.22: Monitoring, Review, and Change Management of Supplier Services

**Control Objective**: Organization regularly monitors, reviews, evaluates, and manages changes in supplier information security practices.

**Implementation**:
- Quarterly supplier reviews (security posture)
- Annual re-assessment (risk score may change)
- Change management: Supplier must notify of significant changes (architecture, data location, subprocessors)
- Audit reports: Request annual SOC 2 / ISO 27001 reports

**Evidence**:
- Supplier review meeting minutes (quarterly)
- Re-assessment reports (annual)
- Change notifications (from suppliers)
- Audit reports (collected annually)

---

### A.5.23: Information Security for Use of Cloud Services

**Control Objective**: Processes for acquisition, use, management, and exit from cloud services are established.

**Implementation**:
- Cloud provider selection: SOC 2 Type II, ISO 27001, data residency requirements
- Shared responsibility model: Documented (provider secures infrastructure, we secure workloads)
- Data residency: Specified in contracts (e.g., EU data in eu-west-1)
- Exit strategy: Backup data in portable format (no vendor lock-in)

**Cloud providers**: AWS (primary), Azure (DR site)

**Evidence**:
- Cloud provider contracts (data residency clauses)
- Shared responsibility matrix
- Data portability tested (backup restore to different cloud)

---

### A.5.24: Information Security Incident Management Planning and Preparation

**Control Objective**: Organization plans and prepares for managing information security incidents.

**Implementation**:
- [Incident Response Policy](../policies/incident-response-policy.md) (SEC-004) defines process
- [Incident Response Procedure](../procedures/incident-response.md) provides runbooks
- Incident playbooks: 7 playbooks for common attacks (see [examples/incident-response/](../../examples/incident-response/))
- Incident response team: On-call rotation (24/7 coverage)
- Testing: Quarterly tabletop exercises, annual full DR drill

**Evidence**:
- Incident response policy (approved)
- Incident playbooks (version controlled)
- On-call schedule (PagerDuty)
- Tabletop exercise reports (quarterly)

---

### A.5.25: Assessment and Decision on Information Security Events

**Control Objective**: Organization assesses information security events and decides if they are to be categorized as security incidents.

**Implementation**:
- Event classification criteria:
  - **Event**: Any observable occurrence (e.g., authentication failure)
  - **Incident**: Event with actual or potential security impact (e.g., successful phishing)
- Severity levels: P0 (critical), P1 (high), P2 (medium), P3 (low)
- Triage process: Security analyst reviews alerts → Classify as event or incident → Escalate if incident

**Evidence**:
- Event logs (SIEM)
- Incident tickets (JIRA, classified by severity)
- Triage notes (incident vs non-incident determination)

---

### A.5.26: Response to Information Security Incidents

**Control Objective**: Information security incidents are responded to in accordance with documented procedures.

**Implementation**:
- 6-phase incident response lifecycle (see [Incident Response Policy](../policies/incident-response-policy.md)):
  1. **Detection**: Automated alerts (SIEM, openclaw-telemetry)
  2. **Analysis**: Triage, classification, impact assessment
  3. **Containment**: Isolate affected systems (network, credentials)
  4. **Eradication**: Remove malware, patch vulnerabilities, rotate credentials
  5. **Recovery**: Restore services, verify security
  6. **Post-Incident Review**: Root cause analysis, lessons learned

**Response SLA**: P0 (15 minutes), P1 (1 hour), P2 (4 hours), P3 (1 business day)

**Evidence**:
- Incident tickets (timeline documented)
- Response actions (logs of containment, eradication)
- SLA compliance metrics

---

### A.5.27: Learning from Information Security Incidents

**Control Objective**: Knowledge gained from information security incidents is used to strengthen and improve information security controls.

**Implementation**:
- Post-Incident Review (PIR) mandatory within 5 business days
- Root cause analysis (5 Whys)
- Action items: Assigned to owners, tracked to completion
- Knowledge sharing: PIR summaries shared in monthly security newsletter
- Runbook updates: Playbooks updated with learnings

**Evidence**:
- PIR reports (see [reporting-template.md](../../examples/incident-response/reporting-template.md))
- Action item completion records
- Updated runbooks (version control shows changes)

---

### A.5.28: Collection of Evidence

**Control Objective**: Organization establishes and implements procedures for identification, collection, acquisition, and preservation of evidence.

**Implementation**:
- Forensics procedures: Chain of custody maintained
- Evidence sources: Audit logs (immutable), system snapshots (read-only), network captures
- Forensic tools: [forensics-collector.py](../../scripts/incident-response/forensics-collector.py) automates evidence collection
- Evidence preservation: Encrypted storage, 7-year retention

**Evidence types**:
- Log files (SIEM exports)
- Memory dumps (VM snapshots)
- Disk images (EBS snapshots with "evidence" tag)
- Network captures (pcap files)

**Evidence**:
- Chain of custody forms
- Encrypted evidence archives
- Forensics tool logs (what was collected, when, by whom)

---

### A.5.29: Information Security During Disruption

**Control Objective**: Organization plans how to maintain information security at an appropriate level during disruption.

**Implementation**:
- Business Continuity Plan (BCP): Defines critical business functions
- Disaster Recovery (DR): See [Backup and Recovery Procedure](../procedures/backup-recovery.md)
- 4 disaster levels: L1 (file-level), L2 (service-level), L3 (regional failover), L4 (catastrophic)
- DR site: Secondary AWS region (eu-west-1), kept in sync (hourly replication)
- DR testing: Monthly backup restore, annual full DR drill

**RPO/RTO targets**:
- Agent configuration: RPO 1h, RTO 4h
- Credentials: RPO 0, RTO 1h (replicated real-time)
- Audit logs: RPO 0, RTO 8h (immutable append-only)

**Evidence**:
- BCP document (approved by executive team)
- DR test results (monthly, annual)
- RPO/RTO actuals (tracked in incidents)

---

### A.5.30: ICT Readiness for Business Continuity

**Control Objective**: ICT readiness is planned, implemented, maintained, and tested to ensure business objectives are met during disruptions.

**Implementation**:
- High availability: Multi-AZ deployment (AWS availability zones)
- Auto-scaling: Handles load spikes (CPU > 70% triggers scale-up)
- Health checks: Kubernetes liveness/readiness probes
- Graceful degradation: Rate limiting prevents overload
- Testing: Load testing (monthly), chaos engineering (quarterly)

**Evidence**:
- HA architecture diagrams (multi-AZ)
- Auto-scaling configurations
- Load test results (monthly)
- Chaos engineering reports (quarterly)

---

### A.5.31: Legal, Statutory, Regulatory, and Contractual Requirements

**Control Objective**: Legal, statutory, regulatory, and contractual requirements relevant to information security are identified, documented, and kept up to date.

**Implementation**:
- Compliance register: Tracks applicable regulations (GDPR, SOC 2, ISO 27001, PCI DSS where applicable)
- Legal review: General Counsel reviews security policies annually
- Contractual obligations: Customer contracts may impose additional security requirements
- Updates: Compliance team monitors regulatory changes (e.g., GDPR amendments)

**Evidence**:
- Compliance register (updated quarterly)
- Legal review sign-offs (annual)
- Customer contract reviews (security requirements identified)

---

### A.5.32: Intellectual Property Rights

**Control Objective**: Organization implements appropriate procedures to protect intellectual property rights.

**Implementation**:
- Software licensing: All software properly licensed (license manifest maintained)
- Open source compliance: SBOM tracks open source components, licenses reviewed
- AI model usage: Anthropic Claude API terms of service compliance
- Skill licensing: Skills must specify license in manifest (GPL, MIT, proprietary, etc.)

**Evidence**:
- Software license inventory
- SBOM with license information
- API usage within terms of service limits
- Skill licenses (validated by skill_manifest.py)

---

### A.5.33: Protection of Records

**Control Objective**: Records are protected from loss, destruction, falsification, unauthorized access, and unauthorized release.

**Implementation**:
- Audit log protection: Immutable logs (cannot be modified or deleted by users)
- Encryption: Logs encrypted at rest (AES-256)
- Access control: Audit log access restricted to security team and auditors
- Retention: 7 years (compliance requirement)
- Backup: Logs backed up to S3 (3-2-1 backup strategy)

**Evidence**:
- Immutable log configuration (WORM - Write Once Read Many)
- Encryption verification
- Access logs (who accessed audit logs)
- Backup test results (log restore tested monthly)

---

### A.5.34: Privacy and Protection of Personal Identifiable Information (PII)

**Control Objective**: Organization identifies and meets requirements regarding preservation of privacy and protection of PII.

**Implementation**:
- [Data Classification Policy](../policies/data-classification.md) classifies PII as Restricted
- PII handling: Minimize collection, encrypt in transit/rest, delete when no longer needed
- AI-specific: PII redaction in prompts (openclaw-shield detects and redacts), conversation history classified
- GDPR compliance: See [GDPR Compliance](./gdpr-compliance.md)
- Data subject rights: Access, rectification, erasure, portability (procedures documented)

**Evidence**:
- PII inventory (data mapping)
- PII redaction logs (openclaw-shield)
- Data subject rights requests (handled within 30 days)
- GDPR compliance attestation

---

### A.5.35: Independent Review of Information Security

**Control Objective**: Organization's approach to managing information security is reviewed independently at planned intervals.

**Implementation**:
- **External audits**: Annual ISO 27001 surveillance audit, SOC 2 Type II audit
- **Internal audits**: Quarterly internal security audits (different auditor each quarter)
- **Penetration testing**: Annual external pentest by third-party firm
- **Vulnerability assessments**: Monthly automated scans (Trivy, Nessus)

**Independence**: Internal auditors not responsible for audited areas, external auditors independent firm

**Evidence**:
- ISO 27001 audit reports (annual)
- SOC 2 reports (annual)
- Penetration test reports (annual)
- Internal audit reports (quarterly)

---

### A.5.36: Compliance with Policies, Rules, and Standards for Information Security

**Control Objective**: Compliance with organization's information security policies, topic-specific policies, rules, and standards is regularly reviewed.

**Implementation**:
- Policy compliance testing: Automated (scripts/verification/verify_openclaw_security.sh)
- Configuration audits: Quarterly (checks actual vs documented configs)
- Compliance dashboard: Real-time (shows policy adherence metrics)
- Accountability: Non-compliance results in corrective action plans (CAP)

**Evidence**:
- Compliance test results (automated daily)
- Configuration audit reports (quarterly)
- Corrective action plans (CAP) for non-compliance

---

### A.5.37: Documented Operating Procedures

**Control Objective**: Operating procedures for information processing facilities are documented and made available to personnel.

**Implementation**:
- Documented procedures:
  - [Incident Response](../procedures/incident-response.md)
  - [Vulnerability Management](../procedures/vulnerability-management.md)
  - [Access Review](../procedures/access-review.md)
  - [Backup and Recovery](../procedures/backup-recovery.md)
- Accessibility: Internal wiki (all employees)
- Version control: Git (changes tracked)
- Review: Procedures reviewed annually or after significant incidents

**Evidence**:
- Procedure documents (version controlled)
- Procedure review meeting minutes (annual)
- Procedure usage logs (when followed during incidents)

---

## People Controls (A.6)

### A.6.1: Screening

**Control Objective**: Background verification checks on all candidates for employment are carried out.

**Implementation**:
- **Pre-employment screening**:
  - Criminal background check
  - Employment verification (previous 2 employers)
  - Education verification (degree for technical roles)
  - Credit check (for roles with financial access)
- **Level of screening**: Based on role sensitivity (Admin roles: extensive screening)

**Evidence**:
- Screening records (HR database)
- Consent forms (candidates authorize checks)

---

### A.6.2: Terms and Conditions of Employment

**Control Objective**: Employment agreements state personnel and organization's responsibilities for information security.

**Implementation**:
- Employment contract includes:
  - Confidentiality obligations (NDA)
  - Acceptable use of information systems
  - Reporting security incidents
  - Return of assets upon termination
  - Post-employment restrictions (non-compete, non-solicitation where legally enforceable)

**Evidence**:
- Employment contracts (signed by employee)
- NDA agreements (separate or incorporated)

---

### A.6.3: Information Security Awareness, Education, and Training

**Control Objective**: Personnel and relevant interested parties receive appropriate information security awareness, education, and training.

**Implementation**:
- **Mandatory training** (see [Onboarding Checklist](../checklists/onboarding-checklist.md)):
  - All employees: Security awareness (1 hour annually)
  - Developers: AI security training (2 hours)
  - Operators: Incident response training (2 hours)
  - Admins: Advanced security training (4 hours)
- **Phishing simulations**: Quarterly (identify at-risk users)
- **Specialized training**: Certifications encouraged (CISSP, CEH)

**Evidence**:
- Training completion records (LMS - 100% completion)
- Phishing simulation results (click rates tracked)
- Certification records (security team)

---

### A.6.4: Disciplinary Process

**Control Objective**: Formal disciplinary process is established for personnel who have committed an information security breach.

**Implementation**:
- Progressive discipline (see [Acceptable Use Policy](../policies/acceptable-use-policy.md)):
  - **Minor violations**: Verbal warning (e.g., one-time policy lapse)
  - **Moderate violations**: Written warning (e.g., multiple failed phishing tests)
  - **Severe violations**: Suspension or termination (e.g., intentional credential exfiltration)
- Investigation process: HR + Security + Legal review
- Appeal process: Employee can appeal to executive team

**Evidence**:
- Disciplinary action records (HR database)
- Investigation reports
- Appeal decisions

---

### A.6.5: Responsibilities After Termination or Change of Employment

**Control Objective**: Information security responsibilities remain valid after termination or change of employment.

**Implementation**:
- Post-termination obligations:
  - Confidentiality remains binding (perpetual NDA)
  - Non-compete (if applicable, typically 6-12 months)
  - Return of assets (immediate)
  - No retention of company data (delete from personal devices)
- Exit interview: Reminds of ongoing obligations

**Evidence**:
- Exit interview records (confidentiality reminder)
- Asset return receipts (signed)
- NDA references post-termination obligations

---

### A.6.6: Confidentiality or Non-Disclosure Agreements

**Control Objective**: Confidentiality or non-disclosure agreements reflecting organization's needs for protection of information are identified, documented, regularly reviewed, and signed.

**Implementation**:
- **Employees**: Sign NDA in employment contract
- **Contractors**: Separate NDA before engagement
- **Customers**: Mutual NDA before sharing security documentation (SOC 2 reports)
- **Partners**: NDA for integrations, skill development
- Review: NDAs reviewed by Legal annually

**Evidence**:
- Signed NDAs (on file)
- NDA register (tracks who signed, when, expiry)

---

### A.6.7: Remote Working

**Control Objective**: Security measures are implemented when personnel are working remotely.

**Implementation**:
- VPN required for remote access (see [Network Segmentation](../guides/03-network-segmentation.md))
- Multi-factor authentication mandatory
- Laptop security:
  - Full disk encryption (BitLocker, FileVault)
  - Screen lock (5 minutes idle)
  - Anti-malware (CrowdStrike, Microsoft Defender)
- Secure home network: Employees advised to use WPA3 WiFi

**Evidence**:
- VPN connection logs (remote workers)
- Laptop encryption verification (MDM reports 100% compliance)
- MFA logs (all remote authentications)

---

### A.6.8: Information Security Event Reporting

**Control Objective**: Organization provides mechanism for personnel to report observed or suspected information security events.

**Implementation**:
- Reporting channels:
  - Email: security@company.com (monitored 24/7)
  - Slack: #security-incidents
  - Hotline: +1-XXX-XXX-XXXX (PagerDuty)
  - Anonymous reporting: Web form (for whistleblowing)
- Encouragement: No retaliation policy, rewards for high-quality reports
- Response SLA: Acknowledgment within 1 hour

**Evidence**:
- Reported events (ticket system)
- Response times (SLA compliance)
- Rewards issued (for exceptional reports)

---

## Physical Controls (A.7)

### A.7.1: Physical Security Perimeters

**Control Objective**: Security perimeters are defined and used to protect areas that contain information and other associated assets.

**Implementation**:
- **Cloud data centers**: Managed by AWS/Azure/GCP (physical security is their responsibility)
- **Office spaces**: Badge-controlled entry, visitor sign-in
- **Secure zones**: Server room (if applicable) with additional badge restrictions

**Evidence**:
- Cloud provider SOC 2 reports (physical security controls documented)
- Badge access logs (office entry)
- Visitor logs (name, date, host, purpose)

---

### A.7.2: Physical Entry

**Control Objective**: Secure areas are protected by appropriate entry controls.

**Implementation**:
- **Office**: Badge access (RFID), failed attempts logged
- **Data center**: Cloud provider controls (biometric, mantrap, security guards)
- **Tailgating prevention**: Security training, cameras monitor entry points

**Evidence**:
- Badge access logs (successful and failed attempts)
- Cloud provider audit reports (data center physical security)

---

### A.7.3: Securing Offices, Rooms, and Facilities

**Control Objective**: Physical security for offices, rooms, and facilities is designed and implemented.

**Implementation**:
- Office security: Locked doors after hours, alarm system
- Equipment placement: Servers (if on-prem) in locked server room
- Clean desk policy: Lock sensitive documents when unattended
- Visitor escorts: Visitors must be accompanied by employee

**Evidence**:
- Alarm system logs
- Clean desk audit results (quarterly spot checks)
- Visitor escort records

---

### A.7.4: Physical Security Monitoring

**Control Objective**: Premises are continuously monitored for unauthorized physical access.

**Implementation**:
- **Office**: Security cameras (24/7 recording, 90-day retention)
- **Data center**: Cloud provider monitoring (AWS/Azure/GCP)
- **Intrusion detection**: Alarm system for after-hours access

**Evidence**:
- Camera footage (available for 90 days)
- Alarm system logs
- Cloud provider monitoring (in SOC 2 reports)

---

### A.7.5: Protecting Against Physical and Environmental Threats

**Control Objective**: Physical protection against natural disasters, malicious attack, or accidents is designed and applied.

**Implementation**:
- **Fire protection**: Smoke detectors, fire extinguishers, sprinkler system
- **Flood protection**: Data center in non-flood zone (elevation >50m above sea level)
- **Power**: UPS (uninterruptible power supply) for 30 minutes, generator for extended outages
- **Climate control**: HVAC maintains optimal temperature for equipment

**Evidence**:
- Fire safety inspections (annual)
- Flood risk assessment (data center location)
- UPS test results (monthly)
- HVAC maintenance logs

---

### A.7.6: Working in Secure Areas

**Control Objective**: Security measures for working in secure areas are designed and applied.

**Implementation**:
- Access to server room: Authorized personnel only, log entry/exit
- Security briefing: Visitors briefed on security requirements
- Unattended work: Lock screens, secure documents in drawers

**Evidence**:
- Secure area access logs
- Visitor briefing records
- Clean desk audits

---

### A.7.7: Clear Desk and Clear Screen

**Control Objective**: Clear desk policy and clear screen policy are adopted.

**Implementation**:
- Clear desk: Lock sensitive documents when leaving desk
- Clear screen: Screen lock after 5 minutes idle (enforced by Group Policy / MDM)
- Enforcement: Quarterly audits (unannounced), non-compliance results in re-training

**Evidence**:
- Screen lock policy (GPO configuration)
- Clear desk audit results (quarterly)

---

### A.7.8: Equipment Siting and Protection

**Control Objective**: Equipment is sited securely and protected.

**Implementation**:
- Laptop protection: Cable locks available for use in public spaces
- Server placement: Locked server room (if on-prem), racks secured
- Environmental protection: HVAC, fire suppression (server room)

**Evidence**:
- Server room access logs
- Environmental monitoring (temperature, humidity)

---

### A.7.9: Security of Assets Off-Premises

**Control Objective**: Off-site assets are protected.

**Implementation**:
- Laptops: Full disk encryption, screen lock, anti-theft tracking (Find My Device)
- Physical security: Employees advised to keep laptops secure (not left in cars)
- Remote wipe capability: MDM can remotely wipe lost/stolen devices

**Evidence**:
- Laptop encryption reports (MDM - 100% compliance)
- Lost device incidents (remote wipe executed)

---

### A.7.10: Storage Media

**Control Objective**: Storage media are managed through their life cycle in accordance with classification.

**Implementation**:
- Media classification: Labeled based on highest data classification stored
- Handling: Restricted media stored in locked cabinets
- Transport: Encrypted USB drives (if used), courier with tracking
- Backup tapes: Stored off-site in secure facility (if using tape backups)

**Evidence**:
- Media inventory (classification labels)
- Transport logs (courier tracking)
- Off-site storage access logs

---

### A.7.11: Supporting Utilities

**Control Objective**: Information processing facilities are protected from power failures and other disruptions.

**Implementation**:
- **Power**: UPS (30 minutes), generator (extended outages)
- **Network**: Redundant internet connections (primary + backup ISP)
- **HVAC**: Redundant AC units (server room)
- **Testing**: UPS tested monthly, generator tested quarterly

**Evidence**:
- UPS test logs (monthly)
- Generator test logs (quarterly)
- Failover test results (network redundancy)

---

### A.7.12: Cabling Security

**Control Objective**: Cables carrying power, data, or supporting information services are protected from damage.

**Implementation**:
- Cable routing: Conduits protect cables from physical damage
- Labeling: Network cables labeled for identification
- Access: Cable rooms locked, access restricted
- Inspection: Annual inspection for damage

**Evidence**:
- Cable routing diagrams
- Cable room access logs
- Inspection reports (annual)

---

### A.7.13: Equipment Maintenance

**Control Objective**: Equipment is maintained correctly to ensure availability, integrity, and confidentiality.

**Implementation**:
- Maintenance schedule: Annual hardware maintenance (cloud provider responsibility for IaaS)
- Firmware updates: Patched within 30 days of release (critical patches within 7 days)
- Maintenance logs: Documented (who, what, when)

**Evidence**:
- Maintenance schedules
- Firmware patch logs
- Cloud provider maintenance notifications (coordination)

---

### A.7.14: Secure Disposal or Re-Use of Equipment

**Control Objective**: Items of equipment containing storage media are verified to ensure sensitive data and licensed software is removed or securely overwritten before disposal or re-use.

**Implementation**:
- **Laptops**: NIST 800-88 media sanitization (3-pass overwrite) before re-use
- **Hard drives**: Physical destruction (shredding) for Restricted data devices
- **Cloud**: Cryptographic erasure (delete encryption keys) when decommissioning volumes
- **Certificates of destruction**: Obtained from destruction vendor

**Evidence**:
- Data sanitization logs (NIST 800-88 procedures)
- Destruction certificates (shredded drives)
- Cryptographic key deletion logs

---

## Technological Controls (A.8)

### A.8.1: User Endpoint Devices

**Control Objective**: Information stored on, processed by, or accessible via user endpoint devices is protected.

**Implementation**:
- Endpoint security: Anti-malware (CrowdStrike), firewall (enabled), auto-updates
- Full disk encryption: Mandatory (BitLocker, FileVault)
- Device management: MDM (Intune, Jamf) enforces compliance
- Lost device: Remote wipe capability

**Evidence**:
- MDM compliance reports (100% encrypted, 100% anti-malware)
- Remote wipe logs (lost devices)

---

### A.8.2: Privileged Access Rights

**Control Objective**: Allocation and use of privileged access rights is restricted and managed.

**Implementation**:
- JIT (Just-In-Time) access: Admin privileges granted for 4 hours only
- Approval workflow: Manager + Security approval required
- Logging: All privileged actions logged (immutable audit trail)
- Separate accounts: Admins have separate accounts for privileged work (no daily use of admin accounts)

**Evidence**:
- JIT access logs (granted, used, auto-revoked after 4 hours)
- Approval records (JIRA tickets)
- Privileged action audit logs

---

### A.8.3: Information Access Restriction

**Control Objective**: Access to information and other associated assets is restricted in accordance with established topic-specific policies.

**Implementation**:
- [Access Control Policy](../policies/access-control-policy.md) defines access rules
- Enforcement: RBAC (AWS IAM, K8s RBAC, Azure AD)
- Need-to-know: Access granted only for job responsibilities
- Access reviews: Quarterly (revoke unnecessary access)

**Evidence**:
- RBAC policies (IAM, K8s RoleBindings)
- Access review reports (quarterly)
- Access denial logs (unauthorized attempts blocked)

---

### A.8.4: Access to Source Code

**Control Objective**: Read and write access to source code, development tools, and software libraries is appropriately managed.

**Implementation**:
- Source code: GitHub with branch protection (require pull request, review, status checks)
- Access control: Developers have read/write to feature branches, protected main branch
- Audit: All Git operations logged (commits, merges, force pushes)

**Evidence**:
- GitHub branch protection rules
- Git audit logs (GitHub API)
- Pull request reviews (required approvals)

---

### A.8.5: Secure Authentication

**Control Objective**: Secure authentication technologies and procedures are implemented based on information access restrictions.

**Implementation**:
- MFA: Mandatory for all users (hardware tokens preferred)
- Strong passwords: 12+ characters, complexity, 90-day rotation
- Passwordless: FIDO2 keys (YubiKey) for high-security accounts
- Session management: Timeout after 30 minutes idle

**Evidence**:
- MFA enrollment (100% compliance)
- Password policy enforcement (Active Directory / Azure AD)
- Session timeout logs (idle sessions terminated)

---

### A.8.6: Capacity Management

**Control Objective**: Use of resources is monitored and adjusted to ensure required system performance.

**Implementation**:
- Monitoring: CPU, memory, disk, network (Grafana/Prometheus)
- Capacity planning: Quarterly review, forecast 6 months ahead
- Auto-scaling: Triggered at 70% CPU utilization
- Alerting: Capacity warnings at 80%, critical at 90%

**Evidence**:
- Capacity dashboards (Grafana)
- Capacity planning reports (quarterly)
- Auto-scaling logs (scale-up/scale-down events)

---

### A.8.7: Protection Against Malware

**Control Objective**: Protection against malware is implemented and supported by user awareness.

**Implementation**:
- Anti-malware: CrowdStrike Falcon (endpoints), AWS GuardDuty (cloud)
- Definitions: Updated automatically (daily)
- Scanning: Real-time on-access scanning, weekly full scans
- User awareness: Annual security training includes malware recognition

**Evidence**:
- Anti-malware deployment (100% endpoints)
- Definition update logs (daily)
- Malware detection logs (incidents blocked)

---

### A.8.8: Management of Technical Vulnerabilities

**Control Objective**: Information about technical vulnerabilities is obtained, exposure to such vulnerabilities is evaluated, and appropriate measures are taken.

**Implementation**:
- [Vulnerability Management Procedure](../procedures/vulnerability-management.md) defines process
- Scanning: Daily (containers), weekly (dependencies), monthly (infrastructure)
- Risk assessment: Severity × Exploitability × Exposure
- Remediation SLA: P0 (24h), P1 (7d), P2 (30d), P3 (90d)

**Evidence**:
- Vulnerability scan reports (daily/weekly/monthly)
- Risk scores (CVSS + context)
- Remediation tickets (JIRA with SLA tracking)

---

### A.8.9: Configuration Management

**Control Objective**: Configurations, including security configurations, of hardware, software, services, and networks are established, documented, implemented, monitored, and reviewed.

**Implementation**:
- Infrastructure as Code: Terraform (cloud resources), Ansible (configuration management)
- Configuration baselines: Hardened images (see [docker-compose-full-stack.yml](../../configs/examples/docker-compose-full-stack.yml))
- Configuration audits: Quarterly (detect drift)
- Change management: All config changes via Git pull requests

**Evidence**:
- IaC Git repository (version controlled)
- Configuration baselines (documented)
- Configuration audit reports (quarterly drift detection)

---

### A.8.10: Information Deletion

**Control Objective**: Information stored in information systems, devices, or other storage media is deleted when no longer required.

**Implementation**:
- Data retention policy: 7 years for compliance data, then delete
- Automated deletion: Scripts delete old logs, backups per retention schedule
- Secure deletion: NIST 800-88 media sanitization, cryptographic erasure (cloud)
- Verification: Deletion logs audited quarterly

**Evidence**:
- Data retention policy (approved)
- Automated deletion logs (cron jobs)
- Deletion verification audits (quarterly)

---

### A.8.11: Data Masking

**Control Objective**: Data masking is used in accordance with organization's topic-specific policy.

**Implementation**:
- PII masking: Logs mask email addresses (u***@example.com), credit cards (****1234)
- Test data: Production data masked when copied to staging (fake-generator)
- AI data: openclaw-shield redacts PII from prompts

**Evidence**:
- Log masking configuration
- Test data masking scripts
- PII redaction logs (openclaw-shield)

---

### A.8.12: Data Leakage Prevention

**Control Objective**: Data leakage prevention measures are applied to systems, networks, and other devices that process, store, or transmit sensitive information.

**Implementation**:
- DLP tool: openclaw-shield blocks credential exfiltration in prompts
- Network DLP: Firewall blocks unauthorized data transfer (outbound rules)
- Email DLP: Encrypted email required for Restricted data
- Monitoring: Alerts on suspected data exfiltration attempts

**Evidence**:
- DLP block logs (openclaw-shield)
- Firewall rules (outbound restrictions)
- DLP alerts (investigated)

---

### A.8.13: Information Backup

**Control Objective**: Backup copies of information, software, and systems are maintained and regularly tested.

**Implementation**:
- [Backup and Recovery Procedure](../procedures/backup-recovery.md) documents process
- 3-2-1 backup strategy: 3 copies, 2 media, 1 off-site
- Backup testing: Monthly restore test (verify data integrity)
- Retention: 90 days daily backups, 7 years compliance data

**Evidence**:
- Backup logs (automated daily)
- Restore test results (monthly - 100% success rate)
- Backup inventory (what's backed up)

---

### A.8.14: Redundancy of Information Processing Facilities

**Control Objective**: Information processing facilities are implemented with redundancy sufficient to meet availability requirements.

**Implementation**:
- High availability: Multi-AZ deployment (AWS availability zones)
- Load balancing: Application Load Balancer distributes traffic
- Database: Multi-AZ RDS with automatic failover
- Network: Redundant internet connections (primary + backup ISP)

**Evidence**:
- HA architecture diagrams (multi-AZ)
- Failover test results (annual)
- Uptime metrics (99.9% availability target)

---

### A.8.15: Logging

**Control Objective**: Logs that record activities, exceptions, faults, and other relevant events are produced, stored, protected, and analyzed.

**Implementation**:
- **What to log** (see [Audit Configuration](./audit-configuration.md)):
  - Authentication (login, logout, MFA)
  - Authorization (access grants, denials)
  - Data access (read Restricted data)
  - Configuration changes (who changed what)
  - Privileged actions (admin commands)
- **Log protection**: Immutable (append-only), encrypted at rest
- **Retention**: 7 years (compliance requirement)

**Evidence**:
- Log configuration (what's logged)
- Immutability verification (WORM storage)
- Log retention verification (7-year backups exist)

---

### A.8.16: Monitoring Activities

**Control Objective**: Networks, systems, and applications are monitored for anomalous behavior and appropriate actions taken.

**Implementation**:
- Real-time monitoring: openclaw-telemetry, SIEM (see [monitoring-stack.yml](../../configs/examples/monitoring-stack.yml))
- Anomaly detection: Behavioral analytics (unusual API usage, abnormal prompt patterns)
- Alerting: PagerDuty for critical alerts, email for warnings
- Response: Security analyst reviews alerts (daily), automated containment for critical threats

**Evidence**:
- Monitoring dashboards (Grafana)
- Anomaly detection alerts (investigated)
- Incident tickets (triggered by monitoring)

---

### A.8.17: Clock Synchronization

**Control Objective**: Clocks of information processing systems are synchronized to approved time sources.

**Implementation**:
- Time source: NTP servers (pool.ntp.org for public internet, AWS Time Sync Service for AWS)
- Synchronization: All servers sync time every hour
- Timezone: UTC for all logs (consistency across regions)
- Verification: NTP sync status monitored (alerts if drift >1 second)

**Evidence**:
- NTP configuration (chrony.conf)
- Time sync logs (successful syncs)
- Time drift alerts (if any)

---

### A.8.18: Use of Privileged Utility Programs

**Control Objective**: Use of utility programs that can override system and application controls is restricted and tightly controlled.

**Implementation**:
- Privileged utilities: sudo, root access, database admin tools
- Access control: JIT access only (4-hour grants)
- Logging: All privileged utility usage logged (command, user, timestamp)
- Approval: Required for installing new privileged utilities

**Evidence**:
- Privileged utility inventory
- sudo logs (all commands logged)
- JIT access logs (when privileged access granted)

---

### A.8.19: Installation of Software on Operational Systems

**Control Objective**: Procedures and measures are implemented to securely manage software installation on operational systems.

**Implementation**:
- Approved software: Only approved software installable (allowlist)
- Change management: Software installation via CAB-approved change
- Skills: Only approved skills installable (see [Supply Chain Security](../guides/05-supply-chain-security.md))
- Verification: Software signatures verified (GPG, Authenticode)

**Evidence**:
- Approved software list (maintained)
- CAB approvals (change tickets)
- Skill allowlist (configs/skill-policies/allowlist.json)
- Signature verification logs

---

### A.8.20: Network Security

**Control Objective**: Networks and network devices are secured, managed, and controlled.

**Implementation**:
- Network segmentation: Firewall rules separate zones (see [Network Segmentation](../guides/03-network-segmentation.md))
- Network binding: Services bind to localhost (127.0.0.1:18789) unless VPN
- Firewall: Deny all inbound by default, explicit allow rules
- IDS/IPS: AWS GuardDuty, VPC Flow Logs analyzed

**Evidence**:
- Network diagrams (segmentation)
- Firewall rules (least privilege)
- IDS/IPS alerts (investigated)

---

### A.8.21: Security of Network Services

**Control Objective**: Security mechanisms, service levels, and service requirements of network services are identified, implemented, and monitored.

**Implementation**:
- Secure protocols: TLS 1.2+ (no SSLv3, TLS 1.0/1.1)
- Service SLA: 99.9% uptime, response time <500ms
- Monitoring: Health checks every 30 seconds (Kubernetes probes)
- Third-party services: Anthropic Claude API (SLA in contract)

**Evidence**:
- TLS configuration (tested with sslyze)
- Uptime metrics (Grafana - 99.9%+ actual)
- Service contract SLAs (Anthropic)

---

### A.8.22: Segregation of Networks

**Control Objective**: Groups of information services, users, and information systems are segregated on networks.

**Implementation**:
- Network zones: Production, staging, development (separate VPCs/VNets)
- VPN-only: Production not directly accessible from internet
- Micro-segmentation: Kubernetes NetworkPolicies restrict pod-to-pod traffic
- Firewall: Between zones (production ↔ staging traffic blocked)

**Evidence**:
- Network architecture diagrams (segregated zones)
- NetworkPolicies (K8s)
- Firewall rules (inter-zone restrictions)

---

### A.8.23: Web Filtering

**Control Objective**: Access to external websites is managed to reduce exposure to malicious content.

**Implementation**:
- Web filtering: Firewall blocks known malicious domains (threat intelligence feeds)
- Category blocking: Block gambling, adult content (corporate policy)
- HTTPS inspection: Enabled for malware detection
- Bypass requests: Approved by Security Team

**Evidence**:
- Web filter configuration (blocked categories)
- Blocked access logs (malicious domains blocked)
- Bypass approvals (legitimate sites unblocked)

---

### A.8.24: Use of Cryptography

**Control Objective**: Rules for effective use of cryptography are defined and implemented.

**Implementation**:
- Encryption standards: AES-256 (data at rest), TLS 1.2+ (data in transit)
- Key management: AWS KMS, Azure Key Vault (cloud providers)
- Credential encryption: GPG for backup encryption
- Cryptographic policy: Approved algorithms (AES, RSA 2048+, ECDSA P-256+)

**Evidence**:
- Cryptographic standards document (approved algorithms)
- Encryption verification (backups encrypted, TLS enabled)
- Key management logs (KMS operations)

---

### A.8.25: Secure Development Life Cycle

**Control Objective**: Rules for secure development of software and systems are established and applied.

**Implementation**:
- Security requirements: Defined in project charter
- Threat modeling: STRIDE methodology (see [Threat Model](../architecture/threat-model.md))
- Secure coding: OWASP Top 10 training for developers
- Code review: Peer review required, security review for sensitive changes
- Security testing: Static analysis (SonarQube), dependency scanning (Dependabot), DAST (OWASP ZAP)

**Evidence**:
- Security requirements (in project docs)
- Threat models (version controlled)
- Code review approvals (GitHub pull requests)
- Security testing reports (SonarQube, OWASP ZAP)

---

### A.8.26: Application Security Requirements

**Control Objective**: Information security requirements are identified, specified, and approved when developing or acquiring applications.

**Implementation**:
- Security requirements checklist: Authentication, authorization, input validation, output encoding, logging
- [Security Review Checklist](../checklists/security-review.md) mandatory before production
- Acceptance criteria: Security tests must pass
- Third-party apps: Security assessment required (see [Supply Chain Security](../guides/05-supply-chain-security.md))

**Evidence**:
- Security requirements (documented in tickets)
- Security review approvals (checklists signed)
- Third-party assessments (vendor security questionnaires)

---

### A.8.27: Secure System Architecture and Engineering Principles

**Control Objective**: Principles for engineering secure systems are established, documented, maintained, and applied.

**Implementation**:
- Defense-in-depth: 7 layers (see [Security Layers](../architecture/security-layers.md))
- Least privilege: Minimum necessary access
- Secure by default: Hardened configurations (see [docker-compose-full-stack.yml](../../configs/examples/docker-compose-full-stack.yml))
- Fail secure: Errors deny access (don't fail open)
- Separation of concerns: Authentication, authorization, business logic separated

**Evidence**:
- Security architecture diagrams (defense-in-depth)
- Hardened configurations (baseline configs)
- Architecture review meeting minutes

---

### A.8.28: Secure Coding

**Control Objective**: Secure coding principles are applied to software development.

**Implementation**:
- Secure coding standards: OWASP Secure Coding Practices
- Input validation: All user input validated, sanitized
- Output encoding: Prevent injection attacks (XSS, SQL injection)
- Error handling: Don't expose sensitive information in errors
- Code review: Security-focused review for all code

**Evidence**:
- Secure coding standards document (distributed to developers)
- Code review checklists (security items)
- Static analysis reports (SonarQube detects insecure patterns)

---

### A.8.29: Security Testing in Development and Acceptance

**Control Objective**: Security testing processes are defined and implemented in development life cycle.

**Implementation**:
- **Testing types**:
  - Static analysis (SAST): SonarQube
  - Dependency scanning: Dependabot, Trivy
  - Dynamic analysis (DAST): OWASP ZAP
  - Penetration testing: Annual (third-party)
- **Acceptance criteria**: All P0/P1 vulnerabilities fixed before production
- **Regression testing**: Security tests in CI/CD pipeline

**Evidence**:
- Security test reports (SonarQube, ZAP)
- Vulnerability remediation records (tickets)
- CI/CD logs (security tests executed)

---

### A.8.30: Outsourced Development

**Control Objective**: Organization directs, monitors, and reviews activities related to outsourced system development.

**Implementation**:
- Contractor agreements: Include security requirements, IP ownership, confidentiality
- Code review: All outsourced code reviewed by internal team
- Access control: Contractors have limited access (no production)
- Escrow: Source code escrowed for critical systems

**Evidence**:
- Contractor agreements (security clauses)
- Code review records (outsourced code reviewed)
- Escrow agreements (if applicable)

---

### A.8.31: Separation of Development, Test, and Production Environments

**Control Objective**: Development, testing, and production environments are separated and secured.

**Implementation**:
- Separate environments: Development, staging, production (separate AWS accounts/Azure subscriptions)
- Data separation: Production data not copied to dev/staging (or masked if copied)
- Access control: Developers have write access to dev, read-only to production
- Network segmentation: Firewall between environments

**Evidence**:
- Environment architecture (separate cloud accounts)
- Access control matrix (per environment)
- Network segmentation (firewall rules between environments)

---

### A.8.32: Change Management

**Control Objective**: Changes to information processing facilities and systems are subject to change management procedures.

**Implementation**:
- [Production Deployment Checklist](../checklists/production-deployment.md) mandatory
- Change Advisory Board (CAB): Reviews all production changes
- Rollback plan: Required and tested in staging
- Post-change validation: Smoke tests after deployment

**Evidence**:
- CAB meeting minutes (change approvals)
- Deployment checklists (signed)
- Rollback test results (staging)

---

### A.8.33: Test Information

**Control Objective**: Test information is appropriately selected, protected, and managed.

**Implementation**:
- Test data: Synthetic data preferred, production data masked if used
- Data protection: Test data deleted after testing
- Access control: Test data access restricted to QA team
- Compliance: No PII in test data (GDPR compliance)

**Evidence**:
- Test data generation scripts (synthetic data)
- Data masking logs (if production data used)
- Test data deletion logs (after testing)

---

### A.8.34: Protection of Information Systems During Audit Testing

**Control Objective**: Audit tests and other assurance activities involving assessment of operational systems are planned and agreed between tester and management.

**Implementation**:
- Audit planning: Scope, timing, access requirements agreed in advance
- Read-only access: Auditors have read-only access (no write/delete)
- Audit window: Non-peak hours for performance-intensive tests
- Backup before audit: Snapshot taken before intrusive testing

**Evidence**:
- Audit plans (scope, schedule agreed)
- Auditor access logs (read-only verified)
- Pre-audit backups (snapshots taken)

---

## Audit Evidence

### Evidence Repository

**Location**: `/compliance/iso27001-audit-evidence/2026/`

**Structure**:
```
2026/
├── organizational-controls/
│   ├── policies/ (SEC-001 through SEC-005, version controlled)
│   ├── procedures/ (signed checklists, execution records)
│   ├── risk-assessment/ (annual risk register, threat model)
│   └── vendor-management/ (DPAs, SOC 2 reports, assessments)
├── people-controls/
│   ├── screening/ (background check records, consents)
│   ├── training/ (LMS reports, phishing simulations)
│   └── off-boarding/ (checklists, access revocation logs)
├── physical-controls/
│   ├── access-logs/ (badge entries, visitor logs)
│   ├── environmental/ (UPS tests, HVAC maintenance)
│   └── cloud-provider/ (SOC 2 reports, audit attestations)
└── technological-controls/
    ├── access-control/ (RBAC configs, MFA logs, JIT logs)
    ├── vulnerability-management/ (scan reports, remediation tickets)
    ├── monitoring/ (SIEM logs, anomaly alerts, incident tickets)
    └── backup-recovery/ (backup logs, restore tests, DR drills)
```

**Retention**: 7 years (ISO 27001 requirement, aligned with SOC 2)

---

### Certification Audit Schedule

**Certification Audit**: January 2026 (completed)  
**Surveillance Audit 1**: January 2027 (scheduled)  
**Surveillance Audit 2**: January 2028 (scheduled)  
**Re-Certification Audit**: January 2029 (3-year cycle)

**Audit Preparation**:
- Internal audit (Q4 2026): Identify gaps before surveillance audit
- Evidence collection: Ongoing throughout year
- Management review: Quarterly (ISMS performance reviewed)

---

### Auditor Information

**Certification Body**: [Certification Body Name]  
**Lead Auditor**: [Name], [Email]  
**Certificate Number**: ISO27K-2026-001234  
**Scope**: AI agent operations, credential management, runtime sandboxing, supply chain security, monitoring

**Contact Points**:
- **CISO**: ciso@company.com (primary contact)
- **Compliance Officer**: compliance@company.com (evidence coordination)
- **DPO**: dpo@company.com (privacy matters)

---

**Document Owner**: Compliance Team + Security Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-08-14 (semi-annual)  
**Certificate Requests**: compliance@company.com  
**Questions**: security@company.com

**Related Documentation**:
- [ISO 27001 Compliance Mapping JSON](../../configs/organization-policies/iso27001-compliance-mapping.json) - Machine-readable mapping
- [SOC 2 Controls Mapping](./soc2-controls.md) - SOC 2 crosswalk
- [GDPR Compliance](./gdpr-compliance.md) - Privacy compliance
- [Audit Configuration](./audit-configuration.md) - Technical audit logging
