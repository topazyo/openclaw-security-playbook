# Data Classification Policy

**Policy ID**: SEC-003  
**Version**: 1.0.0  
**Effective Date**: 2026-01-15  
**Last Updated**: 2026-02-14  
**Owner**: Security Team (security@company.com)  
**Approval**: CISO, Legal, Privacy Officer  
**Review Frequency**: Annually

This policy defines data classification levels, handling requirements, and protection controls for data processed by AI agent systems (ClawdBot/OpenClaw).

---

## Table of Contents

1. [Purpose](#purpose)
2. [Scope](#scope)
3. [Classification Levels](#classification-levels)
4. [Handling Requirements](#handling-requirements)
5. [AI Agent Specific Considerations](#ai-agent-specific-considerations)
6. [Compliance](#compliance)
7. [References](#references)

---

## Purpose

This policy ensures:
- Consistent classification of data across the organization
- Appropriate security controls based on data sensitivity
- Compliance with regulatory requirements (GDPR, CCPA, HIPAA where applicable)
- Protection of intellectual property and competitive advantage
- Clear handling requirements for AI agent interactions

---

## Scope

**In Scope:**
- All data processed, stored, or transmitted by ClawdBot/OpenClaw agents
- Conversation histories and interaction logs
- Credentials and API keys
- Skill data and configurations
- Agent outputs and generated content
- Training data (if applicable)

**Out of Scope:**
- Public datasets and open-source code (unless containing sensitive company information)
- Data processed by external LLM providers (covered by vendor agreements)

---

## Classification Levels

### Level 1: Public

**Definition**: Information that can be freely shared with the general public.

**Examples**:
- Published marketing materials
- Public blog posts and documentation
- Open-source code repositories
- Public API documentation

**Handling Requirements**:
- No special controls required
- May be shared externally without restriction
- Should still maintain accuracy and quality

**AI Agent Usage**: ✅ Allowed in prompts and outputs

---

### Level 2: Internal

**Definition**: Information intended for internal use only; not harmful if disclosed but should not be publicly shared.

**Examples**:
- Internal documentation and wikis
- Employee directories
- Non-sensitive project plans
- General company announcements

**Handling Requirements**:
- Accessible to all employees
- Should not be shared with external parties without approval
- No special encryption required for storage
- Standard access controls (authentication required)

**AI Agent Usage**: ✅ Allowed with authentication

---

### Level 3: Confidential

**Definition**: Sensitive business information that could cause moderate harm if disclosed.

**Examples**:
- Unpublished product roadmaps
- Internal financial reports (non-regulated)
- Customer lists and contact information
- Proprietary algorithms and business logic
- Non-production credentials
- Agent configurations and system prompts

**Handling Requirements**:
- Access restricted to users with business need-to-know
- Encryption required for storage and transmission
- Must be marked as "Confidential" in documents
- Requires approval for external sharing
- PII redaction required in logs and outputs

**AI Agent Usage**: ⚠️ Allowed with restrictions
- Output redaction required (openclaw-shield)
- Access logged and monitored
- Conversation history encrypted
- No storage in unapproved third-party systems

**See**: [Layer 4 (Runtime Enforcement)](../guides/07-community-tools-integration.md#openclaw-shield)

---

### Level 4: Restricted

**Definition**: Highly sensitive information that could cause severe harm if disclosed; includes regulated data.

**Examples**:
- Production API keys and credentials
- Customer personally identifiable information (PII)
- Payment card information (PCI data)
- Protected health information (PHI under HIPAA)
- Social Security Numbers, national ID numbers
- Encryption keys and certificates
- Security vulnerability details
- Legal documents under attorney-client privilege
- M&A information

**Handling Requirements**:
- Access strictly limited to authorized personnel only
- Must be stored in OS keychain or HSM (never plaintext)
- Encryption required (AES-256 or equivalent)
- Multi-factor authentication required for access
- Data Loss Prevention (DLP) monitoring
- Audit trail required for all access
- Disposal requires secure deletion/shredding
- External sharing prohibited without legal/compliance approval

**AI Agent Usage**: ❌ Prohibited in prompts (input filtering)
- Credentials: OS keychain only (Layer 1)
- PII: Automatic redaction in outputs
- Agent must never log or persist restricted data
- Conversations containing restricted data purged immediately

**See**:
- [Layer 1 (Credential Isolation)](../guides/02-credential-isolation.md)
- [Layer 4 (Output Redaction)](../guides/07-community-tools-integration.md#openclaw-shield)

---

## Handling Requirements

### Data at Rest

| Classification | Encryption | Access Control | Backup | Retention |
|----------------|------------|----------------|--------|-----------|
| **Public** | Optional | None | Optional | Indefinite |
| **Internal** | Recommended | Authentication | Standard | Per business need |
| **Confidential** | Required (AES-256) | Role-based | Encrypted | 7 years max |
| **Restricted** | Required (AES-256) + Key mgmt | Need-to-know + MFA | Encrypted + Access logged | Minimal (purge ASAP) |

**Implementation**:
```yaml
# configs/agent-config/data-classification.yaml
storage_policies:
  public:
    encryption: false
    access: "authenticated"
    
  internal:
    encryption: false
    access: "role:viewer"
    
  confidential:
    encryption: true
    encryption_algorithm: "AES-256-GCM"
    access: "role:operator"
    audit_access: true
    
  restricted:
    encryption: true
    encryption_algorithm: "AES-256-GCM"
    key_management: "hsm"
    access: "role:administrator + mfa"
    audit_access: true
    dlp_scan: true
    purge_after_days: 30
```

### Data in Transit

| Classification | Transport Encryption | Additional Controls |
|----------------|----------------------|---------------------|
| **Public** | Recommended (TLS 1.2+) | None |
| **Internal** | Required (TLS 1.2+) | None |
| **Confidential** | Required (TLS 1.3) | Certificate pinning recommended |
| **Restricted** | Required (TLS 1.3 + mTLS) | Certificate pinning, VPN required |

**Implementation**: See [configs/templates/gateway.hardened.yml](../../configs/templates/gateway.hardened.yml)

### Data in Use

| Classification | Memory Protection | Process Isolation |
|----------------|-------------------|-------------------|
| **Public** | None | Standard |
| **Internal** | None | Standard |
| **Confidential** | Memory locking (mlock) | Container isolation |
| **Restricted** | Memory locking + No swap | Dedicated container, read-only FS |

**Implementation**: See [Layer 3 (Runtime Sandboxing)](../guides/04-runtime-sandboxing.md)

---

## AI Agent Specific Considerations

### Conversation History

**Classification**: Inherits highest classification level of any message in the conversation.

**Example**:
```
User: "What's the weather?"          [Public]
Agent: "Sunny, 72°F"                 [Public]
→ Conversation: Public

User: "What's the weather?"          [Public]
Agent: "Sunny. By the way, your API key is sk-ant-123..."  [RESTRICTED!]
→ Conversation: Restricted (VIOLATION - must be purged)
```

**Handling**:
- Conversations scanned for data classification markers
- PII/credentials automatically redacted from outputs (openclaw-shield)
- Restricted data triggers immediate purge + incident report
- Encrypted storage required for Confidential+ conversations

### System Prompts

**Classification**: Typically Confidential (proprietary business logic)

**Handling**:
- Stored encrypted in config files
- Access restricted to administrators
- Version controlled in private repositories
- Not included in logs or error messages

### Agent Outputs

**Classification**: Varies; default to same as input unless downgraded

**Examples**:
- Summarization: Input = Confidential → Output = Confidential
- Public data query: Input = Public → Output = Public
- Credential exposure: ❌ OUTPUT BLOCKED (see [scenario-006](../../examples/scenarios/scenario-006-credential-theft-conversation-history.md))

**Handling**:
- Output classification labels added to responses
- Automated DLP scanning forCredentials/PII (openclaw-shield)
- Misclassified outputs trigger security alerts

### Training Data (If Applicable)

**Classification**: Minimum Confidential (contains business logic)

**Handling**:
- Stored in encrypted, access-controlled repositories
- PII/regulated data scrubbed before training
- Data lineage documented
- Regular audits for data leakage

---

## Compliance

### GDPR (General Data Protection Regulation)

**Applies to**: Personal data of EU residents

| GDPR Principle | Implementation | Data Class |
|----------------|----------------|-----------|
| **Lawfulness, fairness, transparency** | User consent, privacy notice | All PII (Restricted) |
| **Purpose limitation** | Data used only for stated purpose | All PII |
| **Data minimization** | Collect only necessary data | All |
| **Accuracy** | Processes to correct inaccurate data | All PII |
| **Storage limitation** | Retention periods enforced | All |
| **Integrity and confidentiality** | Encryption, access controls | All |
| **Accountability** | Audit trails, DPIAs | All |

**AI Agent Requirements**:
- PII redaction in outputs (Article 5: data minimization)
- Automated purging (Article 17: right to erasure)
- Audit trails (Article 5: accountability)
- Breach notification within 72 hours (Article 33)

**See**: [docs/compliance/gdpr-compliance.md](../compliance/gdpr-compliance.md)

### SOC 2 Type II

**Control**: CC6.8 - Information is processed, stored, and disposed of in accordance with policies.

**Evidence**:
- Data classification policy (this document)
- Classification labels in systems
- Encryption verification reports
- Access logs showing role-based restrictions

### ISO 27001

**Standards**:
- A.8.2.1: Classification of information
- A.8.2.2: Labeling of information
- A.8.2.3: Handling of assets

**Evidence**:
- Classification scheme documented
- Labeling applied to data
- Handling procedures followed

### HIPAA (If Applicable)

**Applies to**: Protected Health Information (PHI)

**Requirements**:
- PHI classified as Restricted
- Encryption required (45 CFR § 164.312(a)(2)(iv))
- Access controls (45 CFR § 164.312(a)(1))
- Audit trails (45 CFR § 164.312(b))
- Business Associate Agreements (BAAs) for AI providers

**AI Agent Usage**: ❌ PHI prohibited without BAA and technical safeguards

---

## References

### Internal Documentation
- [Access Control Policy](./access-control-policy.md)
- [Incident Response Policy](./incident-response-policy.md)
- [Credential Isolation Guide](../guides/02-credential-isolation.md)
- [Runtime Enforcement (PII Redaction)](../guides/07-community-tools-integration.md#openclaw-shield)

### Configuration Examples
- [Agent Security Config](../../configs/agent-config/openclaw-agent.yml)
- [Gateway Encryption Settings](../../configs/templates/gateway.hardened.yml)
- [Output Redaction (openclaw-shield)](../../configs/examples/with-community-tools.yml)

### Compliance Frameworks
- [GDPR Compliance](../compliance/gdpr-compliance.md)
- [SOC 2 Controls](../compliance/soc2-controls.md)
- [ISO 27001 Controls](../compliance/iso27001-controls.md)

### External Resources
- [NIST SP 800-60: Guide for Mapping Types of Information and Information Systems to Security Categories](https://csrc.nist.gov/publications/detail/sp/800-60/vol-1-rev-1/final)
- [GDPR Official Text](https://gdpr-info.eu/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)

---

**Policy Owner**: Security Team + Privacy Officer  
**Approved By**: CISO, Legal, Privacy Officer  
**Next Review Date**: January 15, 2027 (annual)  
**Questions**: security@company.com, privacy@company.com
