# Security Incident Report

**Report ID**: INC-YYYY-NNNN  
**Report Date**: YYYY-MM-DD  
**Report Author**: [Your Name]  
**Classification**: [Public / Internal / Confidential / Restricted]  
**Status**: [Draft / Under Review / Final]

---

## Executive Summary

*Provide a 2-3 paragraph high-level overview suitable for executives and non-technical stakeholders.*

**Incident Type**: [Data Breach / Prompt Injection / Unauthorized Access / Malicious Skill / Service Outage / Other]  
**Severity**: [P0 Critical / P1 High / P2 Medium / P3 Low]  
**Detection Date**: YYYY-MM-DD HH:MM UTC  
**Resolution Date**: YYYY-MM-DD HH:MM UTC  
**Total Duration**: X hours Y minutes  

**Impact Summary**:
- **Users Affected**: [Number or percentage]
- **Data Exposure**: [Yes/No - describe if yes]
- **Service Availability**: [% uptime during incident]
- **Financial Impact**: [Estimated cost]

**Key Findings**:
- Finding 1
- Finding 2
- Finding 3

---

## 1. Incident Overview

### 1.1 Incident Classification

| Attribute | Value |
|-----------|-------|
| **Incident ID** | INC-YYYY-NNNN |
| **Incident Type** | [Select: Prompt Injection / Data Leakage / Unauthorized Access / Malicious Skill / Service Outage / Supply Chain Attack / Compliance Violation] |
| **Severity Level** | P0 / P1 / P2 / P3 |
| **Affected System** | ClawdBot Gateway / Agent / Skill / API / Infrastructure |
| **MITRE ATT&CK Tactics** | [If applicable: Initial Access, Execution, Persistence, etc.] |
| **CVE Reference** | [If applicable: CVE-YYYY-NNNNN] |

### 1.2 Incident Timeline

| Date/Time (UTC) | Event | Source | Action Taken |
|-----------------|-------|--------|--------------|
| YYYY-MM-DD HH:MM | Initial detection | SIEM Alert | Security team notified |
| YYYY-MM-DD HH:MM | Investigation started | SOC Analyst | Log review initiated |
| YYYY-MM-DD HH:MM | Incident confirmed | Security Engineer | Incident response activated |
| YYYY-MM-DD HH:MM | Containment implemented | IR Team | Affected services isolated |
| YYYY-MM-DD HH:MM | Root cause identified | Security Architect | RCA documented |
| YYYY-MM-DD HH:MM | Remediation completed | Engineering Team | Fix deployed |
| YYYY-MM-DD HH:MM | Service restored | Operations | Monitoring resumed |
| YYYY-MM-DD HH:MM | Incident closed | CISO | Post-mortem scheduled |

### 1.3 Detection Method

**How was the incident detected?**
- [ ] Automated alert (SIEM/IDS/IPS)
- [ ] User report
- [ ] Security audit
- [ ] Threat intelligence
- [ ] Routine monitoring
- [ ] Third-party notification
- [ ] Other: _______________

**Detection Details**:
[Describe the specific alert, report, or finding that led to detection]

---

## 2. Incident Details

### 2.1 What Happened?

**Detailed Description**:
[Provide comprehensive technical details of what occurred, including:]
- Initial compromise or trigger event
- Attack vector and techniques used
- Systems and data affected
- Propagation or lateral movement (if applicable)

**Attack Timeline**:
```
[Attacker Action] → [System Response] → [Detection] → [Response]
```

### 2.2 Affected Assets

| Asset Type | Asset Name/ID | Impact | Data Classification |
|------------|---------------|--------|---------------------|
| Server | clawdbot-gateway-01 | Compromised | Internal |
| Database | user-preferences-db | Accessed | Confidential |
| API Key | anthropic-api-prod | Exposed | Restricted |
| User Data | PII records | Leaked | Restricted |

### 2.3 Indicators of Compromise (IoCs)

**IP Addresses**:
- 203.0.113.45 (malicious)
- 198.51.100.78 (C2 server)

**File Hashes**:
- SHA256: a1b2c3d4e5f6... (malicious script)

**URLs/Domains**:
- evil-skill-repo.example.com
- c2-server.malicious.net

**User Accounts**:
- compromised-user@example.com (compromised)
- service-account-123 (misused)

**Malicious Patterns**:
```
Prompt injection pattern: "Ignore previous instructions and..."
Skill manifest: malicious-skill-v1.2.3.json
```

---

## 3. Impact Assessment

### 3.1 Confidentiality Impact

**Rating**: [None / Low / Medium / High / Critical]

**Details**:
- **Data Exposed**: [Type and volume of data]
- **Sensitivity Level**: [Public / Internal / Confidential / Restricted]
- **Number of Records**: [Count]
- **Data Types**: [PII, credentials, proprietary information, etc.]

### 3.2 Integrity Impact

**Rating**: [None / Low / Medium / High / Critical]

**Details**:
- **Data Modified**: [What data was altered]
- **System Changes**: [Unauthorized configuration changes]
- **Trust Impact**: [Effect on data trustworthiness]

### 3.3 Availability Impact

**Rating**: [None / Low / Medium / High / Critical]

**Details**:
- **Downtime**: X hours Y minutes
- **Services Affected**: [List services]
- **Users Impacted**: [Number or percentage]
- **Geographic Impact**: [Regions affected]

### 3.4 Business Impact

| Impact Category | Rating | Description |
|----------------|--------|-------------|
| **Financial** | [$X,XXX] | Direct costs, recovery costs, potential fines |
| **Reputational** | [Low/Med/High] | Customer trust, brand damage, media coverage |
| **Operational** | [Low/Med/High] | Service disruption, productivity loss |
| **Legal/Regulatory** | [Low/Med/High] | GDPR, SOC2, contractual obligations |
| **Customer Impact** | [Low/Med/High] | Service degradation, data exposure risk |

---

## 4. Root Cause Analysis

### 4.1 Primary Root Cause

**Category**: [Technical / Process / Human Error / Third-Party / Unknown]

**Description**:
[Detailed explanation of the fundamental reason the incident occurred]

**Contributing Factors**:
1. Factor 1: [Description]
2. Factor 2: [Description]
3. Factor 3: [Description]

### 4.2 Technical Root Cause

**Vulnerability Exploited**: [CVE or internal ID]  
**Affected Component**: [Software/hardware/configuration]  
**Attack Vector**: [How the attacker gained access]  

**Technical Details**:
```
[Code snippets, configuration examples, or technical evidence]
```

### 4.3 Why It Happened (5 Whys Analysis)

1. **Why did the incident occur?**  
   Answer: [First level cause]

2. **Why did that happen?**  
   Answer: [Second level cause]

3. **Why did that happen?**  
   Answer: [Third level cause]

4. **Why did that happen?**  
   Answer: [Fourth level cause]

5. **Why did that happen?**  
   Answer: [Root cause]

---

## 5. Response Actions

### 5.1 Immediate Response (Containment)

**Actions Taken**:
- [ ] Isolated affected systems
- [ ] Blocked malicious IP addresses
- [ ] Revoked compromised credentials
- [ ] Disabled malicious skills
- [ ] Enabled additional monitoring
- [ ] Notified stakeholders

**Timeline**:
- Detection to containment: X minutes
- Containment to isolation: Y minutes

### 5.2 Investigation Actions

**Evidence Collected**:
- System logs (X GB from Y systems)
- Network traffic captures
- Memory dumps
- Disk images
- User activity logs

**Analysis Performed**:
- Log correlation and analysis
- Forensic examination
- Malware analysis (if applicable)
- User behavior analysis

### 5.3 Eradication Actions

**Remediation Steps**:
1. Patched vulnerable software (version X.Y.Z → A.B.C)
2. Removed malicious files/configurations
3. Closed unauthorized access points
4. Updated security rules
5. Strengthened authentication

### 5.4 Recovery Actions

**System Restoration**:
- Rebuilt compromised systems from clean backups
- Verified integrity of restored data
- Re-deployed security controls
- Conducted security validation testing
- Resumed normal operations

**Validation Tests**:
- [ ] Vulnerability scan passed
- [ ] Penetration test passed
- [ ] Security configuration verified
- [ ] Monitoring confirmed operational

---

## 6. Communication

### 6.1 Internal Communication

| Stakeholder | Notification Time | Method | Summary Provided |
|-------------|-------------------|--------|------------------|
| CISO | YYYY-MM-DD HH:MM | Phone | Initial alert |
| Engineering VP | YYYY-MM-DD HH:MM | Email | Technical details |
| Legal | YYYY-MM-DD HH:MM | Meeting | Regulatory implications |
| Executive Team | YYYY-MM-DD HH:MM | Briefing | Business impact |

### 6.2 External Communication

**Customer Notification**:
- **Required**: [Yes / No]
- **Notification Date**: YYYY-MM-DD
- **Method**: [Email / Portal / Press Release]
- **Recipients**: [All customers / Affected customers only]

**Regulatory Notification**:
- **GDPR (72-hour requirement)**: [Yes / No / N/A]
- **Notification Date**: YYYY-MM-DD HH:MM
- **Regulator**: [DPA / ICO / Other]
- **Reference Number**: [REG-YYYY-NNNN]

**Media/PR**:
- **Public Statement**: [Yes / No]
- **Press Release**: [Attached / N/A]
- **Media Inquiries**: [Number received]

---

## 7. Lessons Learned

### 7.1 What Went Well

1. **Detection**: [What worked in detecting the incident]
2. **Response**: [Effective response actions]
3. **Communication**: [Successful communication practices]
4. **Tools/Processes**: [Useful tools or processes]

### 7.2 What Could Be Improved

1. **Area 1**: [Specific improvement needed]
   - Current state: [Description]
   - Desired state: [Description]
   
2. **Area 2**: [Specific improvement needed]
   - Current state: [Description]
   - Desired state: [Description]

### 7.3 Knowledge Gained

**New Threats Identified**:
- Threat pattern 1
- Threat pattern 2

**Security Gaps Discovered**:
- Gap 1: [Description and impact]
- Gap 2: [Description and impact]

---

## 8. Recommendations

### 8.1 Immediate Actions (0-30 days)

| Priority | Action | Owner | Due Date | Status |
|----------|--------|-------|----------|--------|
| P0 | Deploy security patch X.Y.Z | Engineering | YYYY-MM-DD | In Progress |
| P0 | Implement MFA for all admin accounts | IT Security | YYYY-MM-DD | Not Started |
| P1 | Update incident response playbook | Security | YYYY-MM-DD | Not Started |

### 8.2 Short-term Actions (1-3 months)

| Priority | Action | Owner | Due Date | Estimated Cost |
|----------|--------|-------|----------|----------------|
| P1 | Deploy enhanced monitoring | SecOps | YYYY-MM-DD | $X,XXX |
| P2 | Conduct security training | HR/Security | YYYY-MM-DD | $X,XXX |

### 8.3 Long-term Actions (3-12 months)

| Priority | Action | Owner | Target Quarter | Budget Required |
|----------|--------|-------|----------------|-----------------|
| P2 | Implement zero-trust architecture | Infrastructure | Q3 2026 | $XX,XXX |
| P3 | Achieve ISO 27001 certification | Compliance | Q4 2026 | $XX,XXX |

---

## 9. Compliance and Regulatory

### 9.1 Regulatory Requirements Met

- [ ] GDPR Article 33 (72-hour notification) - Completed YYYY-MM-DD
- [ ] SOC 2 incident reporting - Documented in compliance system
- [ ] PCI DSS incident response - Notified acquiring bank
- [ ] HIPAA breach notification - [N/A / Completed]
- [ ] Contractual SLA reporting - Customers notified

### 9.2 Evidence Retention

**Retention Period**: [X years per policy/regulation]  
**Storage Location**: [Secure evidence repository]  
**Access Controls**: [Restricted to IR team and auditors]  
**Chain of Custody**: [Maintained and documented]

---

## 10. Metrics

### 10.1 Response Metrics

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| Time to Detect | <1 hour | X minutes | ✓ Met / ✗ Missed |
| Time to Respond | <15 min | Y minutes | ✓ Met / ✗ Missed |
| Time to Contain | <1 hour | Z minutes | ✓ Met / ✗ Missed |
| Time to Resolve | <24 hours | W hours | ✓ Met / ✗ Missed |

### 10.2 Cost Analysis

| Cost Category | Amount |
|--------------|---------|
| Direct Response Costs | $X,XXX |
| System Recovery | $X,XXX |
| Forensic Analysis | $X,XXX |
| Customer Notification | $X,XXX |
| Legal/Compliance | $X,XXX |
| Lost Revenue | $X,XXX |
| **Total Cost** | **$XX,XXX** |

---

## 11. Appendices

### Appendix A: Technical Details
[Detailed technical logs, configurations, or evidence]

### Appendix B: Communication Templates
[Copies of customer notifications, press releases, etc.]

### Appendix C: Evidence Inventory
[List of all preserved evidence with hashes and locations]

### Appendix D: External Reports
[Third-party assessment reports, forensic findings]

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | YYYY-MM-DD | [Name] | Initial draft |
| 1.1 | YYYY-MM-DD | [Name] | Added RCA section |
| 2.0 | YYYY-MM-DD | [Name] | Final version |

**Review and Approval**:

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Incident Commander | [Name] | _________ | YYYY-MM-DD |
| CISO | [Name] | _________ | YYYY-MM-DD |
| Legal Counsel | [Name] | _________ | YYYY-MM-DD |
| VP Engineering | [Name] | _________ | YYYY-MM-DD |

---

**Classification**: [Public / Internal / Confidential / Restricted]  
**Distribution**: [List authorized recipients]  
**Document ID**: INC-YYYY-NNNN-REPORT  
**Last Updated**: YYYY-MM-DD
