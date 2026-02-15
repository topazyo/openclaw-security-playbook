# GDPR Compliance Guide

**Document Type**: Compliance Guide  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Data Protection Officer (DPO) + Legal + Security Team  
**Regulation**: EU General Data Protection Regulation (GDPR) 2016/679

This document details ClawdBot/OpenClaw compliance with the EU General Data Protection Regulation (GDPR).

---

## Table of Contents

1. [Overview](#overview)
2. [Lawfulness of Processing (Article 5, 6)](#lawfulness-of-processing-article-5-6)
3. [Data Subject Rights (Articles 12-23)](#data-subject-rights-articles-12-23)
4. [Security of Processing (Article 32)](#security-of-processing-article-32)
5. [Data Protection by Design and by Default (Article 25)](#data-protection-by-design-and-by-default-article-25)
6. [Data Breach Notification (Article 33, 34)](#data-breach-notification-article-33-34)
7. [Data Protection Impact Assessment (Article 35)](#data-protection-impact-assessment-article-35)
8. [International Data Transfers (Articles 44-50)](#international-data-transfers-articles-44-50)
9. [DPO and Governance](#dpo-and-governance)
10. [Evidence and Accountability](#evidence-and-accountability)

---

## Overview

### GDPR Scope

**Controller**: [Company Name]  
**Data Protection Officer (DPO)**: [Name], dpo@company.com, [Phone]  
**EU Representative** (if non-EU company): [Name], [Address], eu-rep@company.com

**Processing Activities**:
- AI agent conversation history (user interactions with ClawdBot/OpenClaw)
- User authentication data (email, MFA tokens)
- Audit logs (access logs, security events)
- Employee data (HR records, access credentials)

**Territorial Scope**:
- Applies to processing of personal data of EU data subjects
- Applies regardless of company location (extra-territorial effect)

---

### Personal Data We Process

| Data Category | Source | Purpose | Legal Basis | Retention |
|---------------|--------|---------|-------------|-----------|
| **User Identity** | User registration | Authentication, access control | Legitimate interest (security) | Duration of account + 90 days |
| **Conversation History** | ClawdBot interactions | Service provision, improve AI | Consent or legitimate interest | User-configurable (default: 90 days) |
| **Access Credentials** | User setup | Authentication | Contractual necessity | Duration of account |
| **Audit Logs** | System-generated | Security, compliance, fraud detection | Legitimate interest + legal obligation | 7 years (compliance requirement) |
| **Employee Data** | HR onboarding | Employment, access control | Contractual necessity | Employment + 7 years (legal requirement) |
| **PII in Prompts** | User input | [REDACTED by openclaw-shield] | N/A - not stored | Immediately redacted |

---

### GDPR Principles (Article 5)

1. **Lawfulness, Fairness, Transparency**: Processing lawful, transparent privacy notices
2. **Purpose Limitation**: Data collected for specific purposes only
3. **Data Minimization**: Only collect necessary data (PII redaction in prompts)
4. **Accuracy**: Data subjects can correct inaccurate data
5. **Storage Limitation**: Retention limits (conversation history: 90 days default)
6. **Integrity and Confidentiality**: Security measures (encryption, access controls)
7. **Accountability**: DPO, DPIA, compliance documentation

---

## Lawfulness of Processing (Article 5, 6)

### Legal Bases for Processing

**Article 6(1) Legal Bases**:

1. **Consent** (Article 6(1)(a)):
   - **When used**: Conversation history storage (user can opt-in for longer retention)
   - **How obtained**: Explicit consent during onboarding, can be withdrawn anytime
   - **Records**: Consent logs (timestamp, user ID, what consented to)

2. **Contractual Necessity** (Article 6(1)(b)):
   - **When used**: Provide AI agent services, user authentication, credential management
   - **Necessity**: Cannot provide service without processing this data

3. **Legal Obligation** (Article 6(1)(c)):
   - **When used**: Audit logs (security regulations, SOC 2, ISO 27001 require 7-year retention)
   - **Applicable laws**: SOC 2, ISO 27001, NIST Cybersecurity Framework, financial regulations

4. **Legitimate Interest** (Article 6(1)(f)):
   - **When used**: Fraud detection, security monitoring, incident response
   - **Balancing test**: Our interest in security outweighs data subject's rights (security is paramount for AI agents)
   - **Right to object**: Data subjects can object, reviewed case-by-case (may result in service termination if security cannot be maintained)

**Evidence**:
- Legal basis documented per processing activity (in Records of Processing Activities - ROPA)
- Consent records (if consent is legal basis)
- Balancing test documentation (for legitimate interest)

---

### Transparency (Articles 12-14)

**Privacy Notice**: Published at [URL] and provided during onboarding

**Privacy Notice Contents** (Article 13 requirements):
- Identity and contact details of controller and DPO
- Purposes of processing and legal basis
- Recipients of personal data (Anthropic, cloud providers)
- Data retention periods (90 days conversation history, 7 years audit logs)
- Data subject rights (access, rectification, erasure, portability, object, complain to DPA)
- Right to withdraw consent (if applicable)
- Automated decision-making (none - AI agent is assistive, not autonomous decision-maker)
- International transfers (US data protection frameworks, SCCs)

**Language**: Plain language, not legalese (GDPR requires clear, transparent communication)

**Evidence**:
- Privacy notice (version controlled, dated)
- Privacy notice acknowledgment (users confirm reading during onboarding)

---

## Data Subject Rights (Articles 12-23)

### Right of Access (Article 15)

**What**: Data subjects can request copy of their personal data

**Implementation**:
- Request form: [URL] or email dpo@company.com
- Response SLA: 30 days (can extend by 2 months if complex, must notify)
- Provided data: Conversation history (JSON export), account details, audit logs where user is subject

**Procedure**:
1. Verify identity (to prevent unauthorized disclosure)
2. Collect data (scripts query databases, logs)
3. Redact third-party data (if logs mention other users)
4. Deliver via secure channel (encrypted email or secure download link)

**Evidence**:
- Access request records (who requested, when, what provided, delivery confirmation)
- Identity verification logs

---

### Right to Rectification (Article 16)

**What**: Data subjects can correct inaccurate personal data

**Implementation**:
- Self-service: Users can update profile (email, preferences) in UI
- Assisted: Email dpo@company.com for data user cannot modify
- Response SLA: 30 days

**Procedure**:
1. Verify identity
2. Update data in systems
3. Notify user of completion
4. If data was shared with third parties (e.g., cloud logs), notify them of correction

**Evidence**:
- Rectification logs (what changed, when, by whom)
- Third-party notifications (if applicable)

---

### Right to Erasure ("Right to be Forgotten") (Article 17)

**What**: Data subjects can request deletion of their personal data

**Grounds for Erasure** (Article 17(1)):
- Data no longer necessary for original purpose
- User withdraws consent (if consent was legal basis)
- User objects to legitimate interest processing (and no overriding legitimate grounds)
- Data processed unlawfully
- Legal obligation to delete

**Exceptions** (Article 17(3)):
- Legal obligation to retain (audit logs retained 7 years for compliance)
- Public interest (archiving, scientific research)
- Legal claims (data needed for litigation)

**Implementation**:
- Request form: [URL] or email dpo@company.com
- Response SLA: 30 days
- **What we delete**: Conversation history, user profile, authentication credentials
- **What we retain**: Audit logs (7 years legal requirement), anonymized analytics

**Procedure**:
1. Verify identity and grounds for erasure
2. Assess exceptions (legal retention requirements)
3. Delete data from production databases
4. Pseudonymize audit logs (user ID → anonymous UUID, no re-identification possible)
5. Delete backups (or ensure purge from backups within 90 days)
6. Notify user of completion

**Evidence**:
- Erasure request records (grounds, assessment, actions taken)
- Deletion logs (what deleted, timestamp)
- Legal retention justifications (audit logs retained)

---

### Right to Restriction of Processing (Article 18)

**What**: Data subjects can request temporary halt to processing

**Grounds for Restriction**:
- User contests accuracy (restrict while verifying)
- Processing unlawful but user doesn't want erasure
- Data no longer needed but user needs it for legal claims
- User objects to legitimate interest (restrict while assessing objection)

**Implementation**:
- Request: Email dpo@company.com
- Response SLA: 30 days
- **Effect**: Data marked as "restricted" in database, not processed except for storage and legal claims

**Procedure**:
1. Verify grounds for restriction
2. Mark data as restricted (database flag)
3. Notify user before lifting restriction

**Evidence**:
- Restriction records (grounds, start date, end date)
- Database flags (restricted status)

---

### Right to Data Portability (Article 20)

**What**: Data subjects can receive their data in structured, machine-readable format and transmit to another controller

**Scope**: Only applies to data processed by automated means based on consent or contract (not audit logs under legal obligation)

**Implementation**:
- Request form: [URL] or email dpo@company.com
- Response SLA: 30 days
- **Format**: JSON (structured, machine-readable)
- **Data included**: Conversation history, user profile, preferences

**Procedure**:
1. Verify identity
2. Export data to JSON
3. Provide via secure download link (expires after 7 days)

**Sample JSON Export**:
```json
{
  "user_id": "user-12345",
  "email": "user@example.com",
  "conversation_history": [
    {
      "timestamp": "2026-02-01T10:30:00Z",
      "message": "User prompt...",
      "response": "AI response...",
      "model": "claude-opus-4"
    }
  ],
  "preferences": {
    "retention_days": 90,
    "analytics_opt_in": false
  }
}
```

**Evidence**:
- Portability request records
- Data export logs (what exported, format, delivery method)

---

### Right to Object (Article 21)

**What**: Data subjects can object to processing based on legitimate interest or direct marketing

**Implementation**:
- Objection: Email dpo@company.com, explain grounds for objection
- Response SLA: 30 days
- **Assessment**: Balancing test (our legitimate interests vs data subject's rights)
- **Outcome**: Stop processing unless compelling legitimate grounds override (e.g., security monitoring essential for service)

**Consequence of Objection**:
- If security monitoring objected to and no overriding grounds: Service termination (cannot safely operate without monitoring)
- If direct marketing objected to: Immediately stop (no balancing test required)

**Evidence**:
- Objection records (grounds, balancing test, decision)
- Service termination records (if applicable)

---

### Rights Related to Automated Decision-Making (Article 22)

**What**: Data subjects have right not to be subject to solely automated decisions with legal/significant effects

**OpenClaw/ClawdBot Context**:
- **No automated decisions**: AI agent is assistive tool, not autonomous decision-maker
- **Human oversight**: Users review AI suggestions before acting
- **No profiling**: We don't profile users for automated decisions

**Notice**: Privacy notice clarifies no automated decision-making

**Evidence**:
- System design documentation (human-in-the-loop)
- Privacy notice (states no automated decisions)

---

### Procedure for Exercising Rights

**How to Submit Request**:
1. **Online form**: [URL] (preferred, faster processing)
2. **Email**: dpo@company.com (PGP key available for encrypted requests)
3. **Postal mail**: [Company Address], Attn: Data Protection Officer

**Identity Verification**:
- Online: Login to account (authentication proves identity)
- Email/Postal: Request copy of government-issued ID (to prevent unauthorized disclosure)

**Response Timeline**:
- **Standard**: 30 days from receipt of request
- **Extension**: Up to 90 days total if complex (notify within 30 days)
- **Refusal**: If request manifestly unfounded or excessive (notify within 30 days, explain why, inform of complaint right)

**Free of Charge**: First request free, subsequent repetitive requests may incur reasonable fee

**Evidence**:
- Request tracking system (JIRA tickets for DSR - Data Subject Requests)
- Identity verification records
- Response delivery confirmations
- Extension/refusal notifications

---

## Security of Processing (Article 32)

**Article 32 Requirement**: Implement appropriate technical and organizational measures to ensure security appropriate to risk

### Technical Measures

**Encryption** (Article 32(1)(a)):
- **Data at rest**: AES-256 encryption (credentials, backups, conversation history)
- **Data in transit**: TLS 1.2+ (all network communication)
- **Key management**: AWS KMS, Azure Key Vault (cryptographic key protection)

**Pseudonymization** (Article 32(1)(a)):
- **Audit logs**: User IDs pseudonymized after erasure requests (UUID replaces user ID)
- **Analytics**: Aggregated data only, no individual identifiers

**Access Controls** (Article 32(1)(b)):
- **Authentication**: MFA mandatory (see [Access Control Policy](../policies/access-control-policy.md))
- **Authorization**: RBAC (least privilege), JIT for privileged access
- **Access reviews**: Quarterly (revoke unnecessary access)

**Monitoring** (Article 32(1)(d)):
- **Continuous monitoring**: openclaw-telemetry, SIEM (see [monitoring-stack.yml](../../configs/examples/monitoring-stack.yml))
- **Anomaly detection**: Behavioral analytics (unusual data access patterns trigger alerts)
- **Audit logging**: Immutable logs (who accessed what personal data, when)

**Backup and Recovery** (Article 32(1)(c)):
- **3-2-1 backup strategy**: 3 copies, 2 media, 1 off-site (see [Backup and Recovery Procedure](../procedures/backup-recovery.md))
- **Encrypted backups**: AES-256 + GPG
- **Tested recovery**: Monthly restore tests

**PII Redaction**:
- **AI prompts**: openclaw-shield detects PII (email, SSN, credit card) and redacts before processing
- **Logs**: Email addresses masked (u***@example.com)

---

### Organizational Measures

**Policies and Procedures**:
- [Security Policy](../policies/security-policy.md) (SEC-001)
- [Data Classification Policy](../policies/data-classification.md) (SEC-003) - PII classified as Restricted
- [Incident Response Policy](../policies/incident-response-policy.md) (SEC-004) - Breach notification procedures

**Training**:
- **Annual security awareness training**: GDPR module (data protection principles, data subject rights)
- **Role-specific training**: DPO, Security Team (advanced GDPR training)

**Vendor Management**:
- **Data Processing Agreements (DPA)**: All processors sign DPA (see [Supply Chain Security](../guides/05-supply-chain-security.md))
- **Processor security**: Anthropic (SOC 2 compliant), AWS/Azure/GCP (ISO 27001 certified)

**Testing**:
- **Penetration testing**: Annual (includes data protection controls)
- **Vulnerability scanning**: Daily (containers), weekly (dependencies), monthly (infrastructure)

**Evidence**:
- Encryption configuration audits
- Access control verification ([verify_openclaw_security.sh](../../scripts/verification/verify_openclaw_security.sh))
- Monitoring dashboards (data access logs)
- Backup test results (monthly)
- DPA signed agreements (on file)
- Penetration test reports (annual)

**Reference**: [Security of Processing](../policies/data-classification.md#security-requirements)

---

## Data Protection by Design and by Default (Article 25)

**Article 25 Requirement**: Implement data protection principles at design stage and by default

### Data Protection by Design

**Privacy-Enhancing Technologies (PETs)**:
- **PII redaction**: openclaw-shield automatically redacts PII in prompts (default enabled)
- **Pseudonymization**: User IDs can be pseudonymized on request
- **Encryption by default**: All credentials encrypted (OS keychain), backups encrypted

**Minimize Data Collection**:
- **No unnecessary data**: Don't collect name, address, phone unless service requires
- **Conversation history**: User-configurable retention (default 90 days, not indefinite)
- **Analytics**: Aggregated only (no individual tracking)

**Access Controls**:
- **Least privilege**: Users access only their own data (no cross-user data access)
- **RBAC**: Admins can't access user conversation history without explicit justification + approval

**Transparency**:
- **Privacy notice**: Clear language (no legalese), what data collected, why, how long
- **Data export**: Users can export their data (JSON format)

---

### Data Protection by Default

**Default Settings Maximize Privacy**:
- **Conversation retention**: 90 days (not indefinite)
- **Analytics**: Opt-in (not opt-out)
- **PII redaction**: Enabled (cannot be disabled for user safety)
- **MFA**: Enabled by default for all accounts (security + privacy)

**User Consent**:
- **Explicit consent**: For longer retention (>90 days), analytics opt-in
- **Granular consent**: Separate consent for different purposes (not bundled)
- **Easy withdrawal**: One-click consent withdrawal in user settings

**Evidence**:
- Default configuration documentation (privacy-maximizing)
- Architecture diagrams (PII redaction, encryption, access controls)
- User consent management logs (opt-ins, opt-outs)

---

## Data Breach Notification (Article 33, 34)

### Internal Breach Detection

**Detection Methods**:
- **Automated alerts**: SIEM detects anomalies (unusual data access, bulk exports)
- **openclaw-telemetry**: Behavioral monitoring (credential exfiltration attempts)
- **User reports**: Users can report suspected breaches (security@company.com)

**Incident Classification** (see [Incident Response Policy](../policies/incident-response-policy.md)):
- **P0 (Critical)**: Active exfiltration of personal data, confirmed breach
- **P1 (High)**: Suspected breach, potential PII exposure
- **P2 (Medium)**: Security incident, no confirmed PII exposure
- **P3 (Low)**: Minor security event, no PII impact

---

### Notification to Supervisory Authority (Article 33)

**Timeline**: 72 hours from awareness of breach (Article 33(1))

**When to Notify**:
- **Must notify**: Breach likely to result in risk to data subject rights (loss, unauthorized disclosure, alteration)
- **Exceptions**: Breach unlikely to result in risk (e.g., encrypted data breached, keys not compromised)

**How to Notify**:
- **Authority**: [Country] Data Protection Authority (DPA)
- **Method**: Online portal (if available) or email
- **Template**: [reporting-template.md](../../examples/incident-response/reporting-template.md) adapted for DPA

**Notification Contents** (Article 33(3)):
1. **Nature of breach**: What data, how many data subjects, categories of data
2. **DPO contact**: Name, email, phone
3. **Likely consequences**: Risk to data subjects (identity theft, financial loss, etc.)
4. **Measures taken/proposed**: Containment, mitigation, remediation

**Phased Notification**: If full information unavailable within 72 hours, initial notification with available info, supplementary information later

**Evidence**:
- Breach notification records (timestamp, what reported, to whom)
- DPA acknowledgments (confirmation of receipt)

---

### Notification to Data Subjects (Article 34)

**Timeline**: Without undue delay

**When to Notify**:
- **Must notify**: Breach likely to result in high risk to data subject rights (Article 34(1))
- **Exceptions** (Article 34(3)):
  - Encrypted data (keys not compromised)
  - Mitigation measures taken (risk no longer high)
  - Disproportionate effort (contact info unavailable) → public communication instead

**How to Notify**:
- **Method**: Email to affected users (or postal mail if no email)
- **Language**: Plain language (not technical jargon)
- **Template**: [reporting-template.md](../../examples/incident-response/reporting-template.md) user notification section

**Notification Contents** (Article 34(2)):
1. **What happened**: Nature of breach (plain language)
2. **DPO contact**: How to contact for more information
3. **Likely consequences**: What risks to data subject (concrete examples)
4. **Measures taken**: What we did to contain breach
5. **Recommended actions**: Steps data subjects should take (e.g., change passwords, monitor accounts)

**Evidence**:
- User notification records (who notified, when, delivery confirmation)
- Email logs (sent notifications)

---

### Breach Response Procedure

**6-Phase Response** (see [Incident Response Procedure](../procedures/incident-response.md)):

1. **Detection** (0-15 minutes for P0):
   - SIEM alert or user report
   - Security team notified (PagerDuty)

2. **Analysis** (15 minutes - 1 hour for P0):
   - Classify severity (P0-P3)
   - Determine if personal data involved (→ potential GDPR breach)
   - Assess data subjects affected, data categories, risk level

3. **Containment** (1-4 hours for P0):
   - Isolate affected systems (network segmentation, revoke credentials)
   - Prevent further data loss
   - Preserve evidence (forensic snapshots)

4. **Eradication** (4 hours - ongoing):
   - Remove malware, patch vulnerabilities
   - Rotate compromised credentials

5. **Recovery** (24 hours - ongoing):
   - Restore services
   - Verify security (re-scan for vulnerabilities)

6. **Post-Incident Review** (within 5 business days):
   - Root cause analysis
   - Update [Breach Register](#breach-register)
   - Lessons learned, action items

**72-Hour Countdown**:
- **Hour 0**: Breach awareness (when we have reasonable certainty personal data breached)
- **Hour 72**: DPA notification deadline (Article 33)
- **Ongoing**: Data subject notification (without undue delay if high risk)

**Evidence**:
- Incident timeline (when detected, contained, eradicated)
- Breach assessment (risk determination, data subjects affected)
- Notification records (DPA, data subjects)
- Post-incident review report

---

### Breach Register

**Requirement**: Article 33(5) requires documented record of all breaches (even if not notified to DPA)

**Breach Register Contents**:
- **Date/time of breach**: When occurred, when detected
- **Nature of breach**: What data, how many data subjects, categories
- **Consequences**: Actual or potential harm
- **Remedial actions**: What we did to mitigate
- **DPA notification**: Whether notified (yes/no), when, reference number
- **Data subject notification**: Whether notified (yes/no), when, how

**Location**: Secure internal system (compliance database), accessible to DPO and auditors

**Sample Entry**:
| Breach ID | Date Detected | Data Affected | Data Subjects | Risk Level | DPA Notified | Data Subjects Notified | Status |
|-----------|---------------|---------------|---------------|------------|--------------|------------------------|--------|
| BR-2026-001 | 2026-01-15 | Conversation history (50 users) | 50 | Medium | No (encrypted) | No (low risk) | Closed |
| BR-2026-002 | 2026-03-10 | Email addresses (1,000 users) | 1,000 | High | Yes (2026-03-12) | Yes (2026-03-13) | Closed |

**Evidence**:
- Breach register (updated for all incidents involving personal data)

---

## Data Protection Impact Assessment (Article 35)

**Requirement**: DPIA required when processing likely to result in high risk (Article 35(1))

**When DPIA Required** (Article 35(3)):
- Systematic and extensive automated processing (not applicable to OpenClaw - human oversight)
- Large-scale processing of sensitive data (health, biometric, etc.)
- Systematic monitoring of public areas (not applicable)

**OpenClaw/ClawdBot Assessment**:
- **Conversation history**: AI agent interactions, may contain PII if users include it
- **High risk?**: Potentially, if users discuss sensitive topics (health, finances)
- **DPIA performed**: Yes (see below)

---

### DPIA for OpenClaw Conversation History Processing

**DPIA Date**: January 2026  
**DPO**: [Name], dpo@company.com  
**Reviewed by**: Security Team, Legal, Executive Team

#### 1. Description of Processing

**What**: Store user conversation history with ClawdBot AI agent  
**Purpose**: Provide multi-turn conversation context, improve AI responses  
**Legal basis**: Consent (user opts in for retention >1 session) or Legitimate Interest (session-only storage for service provision)  
**Data subjects**: OpenClaw users (employees, contractors using AI agent)  
**Data categories**: Conversation prompts (may include PII if user provides it), AI responses, timestamps, user ID  
**Recipients**: Anthropic (Claude API processes prompts, see DPA), cloud providers (AWS/Azure for storage)  
**Retention**: User-configurable (default 90 days, max 1 year with consent)  
**Transfers**: US (Anthropic HQ), EU (if using AWS eu-west-1)

#### 2. Necessity and Proportionality

**Necessity**: Conversation history necessary for multi-turn context (AI needs prior conversation to provide relevant responses)  
**Alternatives considered**:
- **Stateless (no history)**: Poor user experience (AI forgets previous conversation)
- **Client-side only**: Not feasible (AI API requires server-side access)
- **Shorter retention**: 90 days default balances utility and privacy

**Proportionality**: Data minimization (don't collect unless user consents for longer retention), PII redaction (openclaw-shield), encryption

#### 3. Risk Assessment

| Risk | Likelihood | Severity | Impact | Mitigation |
|------|------------|----------|--------|------------|
| **Unauthorized access** (credential theft) | Medium | High | Identity theft, confidential info disclosure | MFA, VPN, access controls (see [Access Control Policy](../policies/access-control-policy.md)) |
| **PII leakage** (user includes PII in prompt) | High | Medium | Privacy violation, GDPR breach | PII redaction (openclaw-shield), user training (don't share PII) |
| **Data breach** (cloud storage compromised) | Low | High | Mass disclosure of conversations | Encryption (AES-256), access logging, monitoring |
| **Insider threat** (employee exfiltration) | Low | High | Confidential info disclosure | Least privilege, behavioral monitoring (openclaw-telemetry), audit logs |
| **Third-party risk** (Anthropic breach) | Low | High | Mass disclosure | DPA with Anthropic, SOC 2 compliance, contractual liability |

**Overall Risk**: Medium (after mitigations)

#### 4. Measures to Address Risks

**Technical**:
- **PII redaction**: openclaw-shield (default enabled)
- **Encryption**: AES-256 (at rest), TLS 1.2+ (in transit)
- **Access controls**: RBAC, JIT, MFA
- **Monitoring**: openclaw-telemetry, SIEM alerts

**Organizational**:
- **Data classification**: Conversation history classified as Confidential (see [Data Classification Policy](../policies/data-classification.md))
- **User training**: Don't include PII in prompts
- **DPA with Anthropic**: Processor obligations, liability clauses
- **Incident response**: Breach notification procedures (72-hour SLA)

**User Rights**:
- **Transparency**: Privacy notice explains conversation history storage
- **Consent**: Explicit opt-in for retention >90 days
- **Access**: Users can export conversation history (JSON)
- **Erasure**: Users can delete conversation history (immediate deletion)

#### 5. DPO Opinion

**DPO Recommendation**: Processing acceptable with implemented mitigations (PII redaction, encryption, access controls, user rights mechanisms)

**Conditions**:
- PII redaction must remain enabled (cannot be disabled)
- Annual DPIA review (reassess risk profile)
- User training on not sharing PII in prompts

**Approval**: Executive Team approved DPIA (2026-01-15)

**Evidence**:
- DPIA document (signed by DPO, Security Team, Legal, Executive)
- Annual review schedule (next review: January 2027)

---

## International Data Transfers (Articles 44-50)

### Adequacy Decisions (Article 45)

**Countries with Adequacy Decision** (EU Commission recognizes equivalent data protection):
- Andorra, Argentina, Canada (commercial orgs), Faroe Islands, Guernsey, Israel, Isle of Man, Japan, Jersey, New Zealand, South Korea, Switzerland, UK, Uruguay

**If transferring to adequate country**: No additional safeguards required (adequacy decision is sufficient)

**OpenClaw transfers**: US (Anthropic) - **no adequacy decision** → need safeguards

---

### Standard Contractual Clauses (SCCs) (Article 46)

**What**: EU Commission-approved contract templates for international transfers

**OpenClaw Implementation**:
- **Anthropic (US)**: Data Processing Agreement (DPA) incorporates SCCs (Controller-to-Processor clauses)
- **Cloud providers**: AWS/Azure/GCP standard DPAs include SCCs
- **Module**: Module 2 (Controller to Processor) typically used

**SCC Obligations**:
- Processor implements technical and organizational measures (Article 32)
- Processor cooperates with supervisory authorities
- Data subject rights: Processor assists controller
- Sub-processors: Processor notifies controller of changes

**Evidence**:
- Signed DPAs with SCCs (Anthropic, cloud providers)
- SCC module 2 (Controller to Processor)

**Reference**: [Vendor Management](../policies/access-control-policy.md#vendor-access)

---

### Supplementary Measures (Schrems II)

**Schrems II Decision** (CJEU Case C-311/18, July 2020): SCCs alone may be insufficient if recipient country has intrusive surveillance laws (e.g., US FISA 702)

**Supplementary Measures Required**:
- **Transfer Impact Assessment (TIA)**: Assess if recipient country laws undermine SCCs
- **Additional safeguards**: If laws undermine, implement supplementary measures

**OpenClaw TIA (US Transfers)**:

**Recipient Country Laws** (US):
- **FISA Section 702**: Permits NSA surveillance of non-US persons
- **CLOUD Act**: Permits US law enforcement to access data stored by US companies

**Risk Assessment**:
- **Anthropic (US company)**: Subject to FISA 702, CLOUD Act
- **Data type**: Conversation history (may include sensitive info)
- **Likelihood**: Low (no indication OpenClaw is surveillance target)
- **Impact**: High (if surveillance occurs)

**Supplementary Measures**:
1. **Encryption**: End-to-end encryption considered (not feasible - AI needs plaintext to process)
2. **Pseudonymization**: User IDs pseudonymized (but prompt content still personal data)
3. **Contractual**: Anthropic contractually obligated to challenge overbroad government requests
4. **Transparency**: Anthropic publishes transparency report (government data requests)
5. **Data minimization**: PII redaction (openclaw-shield) reduces sensitive data transferred
6. **Retention minimization**: 90-day default retention (less data stored = less data subject to surveillance)

**Conclusion**: Supplementary measures reduce (but don't eliminate) risk. Users informed of residual risk in privacy notice.

**Evidence**:
- TIA document (assessment of US laws, supplementary measures)
- Privacy notice (discloses US transfers, risks, safeguards)

---

### User Consent for Transfers (Article 49)

**Derogation**: Article 49(1)(a) allows transfers based on explicit consent (if no adequacy, SCCs, or other safeguards)

**When used**: If user objects to US transfer and we cannot provide service without it

**Consent requirements**:
- **Explicit**: Clear affirmative action (not pre-ticked box)
- **Informed**: User understands country lacks adequacy, possible risks, available safeguards
- **Specific**: For specific transfer(s), not blanket consent
- **Freely given**: User can refuse and choose different service

**OpenClaw**: Rely on SCCs + supplementary measures (not consent, as consent derogation should be exceptional)

**Evidence**:
- Privacy notice (explains transfers, safeguards)
- SCCs (primary legal basis for transfers)

---

## DPO and Governance

### Data Protection Officer (DPO) (Article 37)

**Requirement**: Appoint DPO if:
- Public authority (not applicable to OpenClaw)
- Core activities involve large-scale systematic monitoring (AI telemetry may qualify)
- Core activities involve large-scale processing of sensitive data (depends on use case)

**OpenClaw Decision**: DPO appointed (proactive, even if not strictly mandatory)

**DPO Details**:
- **Name**: [Name]
- **Contact**: dpo@company.com, [Phone]
- **Position**: Reports to CISO and Executive Team
- **Independence**: No conflict of interest (does not determine processing purposes)

**DPO Duties** (Article 39):
1. **Inform and advise**: Educate organization on GDPR obligations
2. **Monitor compliance**: Audit GDPR compliance, policies, training
3. **Cooperate with DPA**: Liaise with supervisory authority
4. **Act as contact point**: For data subjects (DSR) and DPA (investigations)

**DPO Resources**:
- Adequate time and resources for DPO duties
- Training budget (GDPR courses, CIPP/E certification)
- Access to all processing records, systems (for monitoring)

**Evidence**:
- DPO appointment letter (name, contact, effective date)
- DPO published on website and privacy notice
- DPO training records (CIPP/E certification)

---

### Records of Processing Activities (ROPA) (Article 30)

**Requirement**: Document all processing activities (controller and processor obligations)

**OpenClaw ROPA Entries**:

| Processing Activity | Purpose | Legal Basis | Categories of Data | Data Subjects | Recipients | Retention | Transfers |
|---------------------|---------|-------------|-------------------|---------------|-----------|-----------|-----------|
| User Authentication | Secure access | Contractual necessity | Email, password hash, MFA token | OpenClaw users | None (internal) | Duration of account + 90 days | None |
| Conversation History | AI service provision | Consent (>90d) or Legitimate interest (session) | Prompts, responses, user ID, timestamp | OpenClaw users | Anthropic (DPA) | 90 days default (user-configurable up to 1 year) | US (Anthropic) |
| Audit Logs | Security, compliance | Legal obligation (SOC 2, ISO 27001) | User ID, actions, timestamps, IP addresses | OpenClaw users | None (internal) | 7 years | None |
| Employee HR Data | Employment | Contractual necessity, legal obligation | Name, email, SSN, address, salary | Employees | Payroll processor (DPA) | Employment + 7 years | US (payroll SaaS) |

**ROPA Format**: Spreadsheet or database, updated quarterly

**Evidence**:
- ROPA document (version controlled, dated)
- Quarterly review records (DPO reviews, approves)

---

### Compliance Monitoring

**Quarterly DPO Review**:
- ROPA updates (new processing activities?)
- Policy compliance (any violations?)
- DSR metrics (requests received, response times)
- Breach register (any new breaches?)
- Training completion (100% employees trained?)

**Annual Activities**:
- **DPIA review**: Reassess risks (processing changed? new risks?)
- **Vendor audits**: Review DPAs, request SOC 2 reports
- **Privacy notice review**: Update for changes (new processing, new recipients)
- **GDPR training**: Refresher for all employees

**Metrics Dashboard** (DPO reporting to Executive Team):
- **DSR metrics**: Access (X requests, Y% within 30 days), Erasure (X requests, Y% within 30 days), Objection (X requests, Y% upheld)
- **Breach metrics**: Incidents (X), Breaches requiring DPA notification (X), Data subject notifications (X)
- **Training**: % employees completed GDPR training
- **Compliance**: Open audit findings (GDPR-related)

**Evidence**:
- Quarterly DPO reports (to Executive Team)
- Metrics dashboards
- Annual DPIA reviews

---

## Evidence and Accountability

### Principle of Accountability (Article 5(2))

**Requirement**: Demonstrate compliance (not just achieve it)

**OpenClaw Accountability Evidence**:

1. **Policies and Procedures**:
   - [Data Classification Policy](../policies/data-classification.md) (PII handling)
   - [Incident Response Policy](../policies/incident-response-policy.md) (breach notification)
   - [Access Control Policy](../policies/access-control-policy.md) (access to personal data)

2. **Technical Measures**:
   - Encryption (configurations audited)
   - PII redaction (openclaw-shield logs)
   - Access controls (RBAC configurations, access logs)

3. **Organizational Measures**:
   - DPO appointed (published on website)
   - ROPA (documented processing activities)
   - DPIA (conversation history processing)
   - Training (LMS records - 100% completion)

4. **Data Subject Rights**:
   - DSR request tracking (JIRA tickets with SLA compliance)
   - Data export capability (JSON format)
   - Erasure procedure (documented, tested)

5. **Vendor Management**:
   - DPAs signed (Anthropic, cloud providers)
   - SCCs for international transfers
   - TIA for US transfers (supplementary measures)

6. **Breach Preparedness**:
   - Breach register (all incidents documented)
   - Incident response procedures (tested quarterly - tabletop exercises)
   - DPA notification template (ready for 72-hour deadline)

7. **Audits**:
   - Annual GDPR compliance audit (internal)
   - External audits (SOC 2, ISO 27001 include GDPR controls)

**Evidence Archive**: `/compliance/gdpr-evidence/`

---

### Supervisory Authority Cooperation

**Competent Supervisory Authority**: [Country] Data Protection Authority (DPA)

**Contact**:
- **DPA**: [Name of DPA]
- **Address**: [Address]
- **Website**: [URL]
- **Helpline**: [Phone/Email]

**When to Contact DPA**:
- Breach notification (Article 33 - within 72 hours)
- Prior consultation (Article 36 - if DPIA shows high risk and no mitigation)
- Regulatory questions (interpretation of GDPR)

**Cooperation Obligations**:
- Respond to DPA inquiries (reasonable timeframe)
- Provide evidence (processing records, policies, audit results)
- Cooperate with investigations (grant DPA access to systems if requested)

**Evidence**:
- DPA contact info (documented)
- Past communications (breach notifications, inquiries)

---

### Data Subject Complaints

**Right to Complain** (Article 77): Data subjects can lodge complaint with DPA if they believe processing violates GDPR

**If Data Subject Files Complaint**:
1. **DPA notification**: DPA will contact us for information
2. **Cooperation**: Respond to DPA inquiries, provide evidence
3. **Investigation**: DPA investigates complaint, may inspect our systems
4. **Outcome**: DPA issues decision (compliant, corrective action required, fine)

**Internal Complaint Handling**:
- Encourage data subjects to contact us first (dpo@company.com) before DPA
- Attempt to resolve amicably (address concern, explain processing)
- If unresolved, data subject has right to DPA complaint (we inform them of this right)

**Evidence**:
- Complaint records (what complaint, how resolved)
- DPA correspondence (if complaint escalated)

---

### GDPR Fines and Penalties

**Article 83 Fines**:
- **Administrative fines**: Up to €20 million or 4% of global annual turnover (whichever higher)
- **Factors**: Severity, negligence vs intentional, cooperation with DPA, mitigation efforts

**Avoiding Fines**:
- **Proactive compliance**: DPO, DPIA, policies, training
- **Cooperation**: Respond to DPA inquiries promptly, transparently
- **Quick remediation**: If violation found, fix immediately, document corrective actions
- **Demonstrated accountability**: Show we take compliance seriously (evidence archive)

**Insurance**: Cybersecurity insurance may cover GDPR fines (check policy - some exclude regulatory fines)

**Evidence**:
- Proactive compliance measures (documented)
- Incident response (if breach, show swift action)

---

**Document Owner**: Data Protection Officer (DPO) + Legal + Security Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2027-02-14 (annual)  
**DPO Contact**: dpo@company.com  
**Data Subject Requests**: dpo@company.com or [URL]  
**Privacy Notice**: [URL]

**Related Documentation**:
- [Data Classification Policy](../policies/data-classification.md) - PII handling requirements
- [Incident Response Policy](../policies/incident-response-policy.md) - Breach notification procedures
- [Access Control Policy](../policies/access-control-policy.md) - Access to personal data
- [Breach Notification Template](../../examples/incident-response/reporting-template.md) - DPA and data subject notifications
- [SOC 2 Controls](./soc2-controls.md) - Overlapping security controls
- [ISO 27001 Controls](./iso27001-controls.md) - Information security management
