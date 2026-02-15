# Incident Response Policy

**Policy ID**: SEC-004  
**Version**: 1.0.0  
**Effective Date**: 2026-01-15  
**Last Updated**: 2026-02-14  
**Owner**: Security Team (security@company.com)  
**Approval**: CISO, CTO, Legal  
**Review Frequency**: Semi-annually

This policy defines the procedures and responsibilities for detecting, responding to, and recovering from security incidents affecting AI agent systems (ClawdBot/OpenClaw).

---

## Table of Contents

1. [Purpose](#purpose)
2. [Scope](#scope)
3. [Incident Categories](#incident-categories)
4. [Roles and Responsibilities](#roles-and-responsibilities)
5. [Incident Response Lifecycle](#incident-response-lifecycle)
6. [Communication Procedures](#communication-procedures)
7. [Compliance](#compliance)
8. [References](#references)

---

## Purpose

This policy ensures:
- Rapid detection and response to security incidents
- Minimized impact and recovery time
- Preservation of evidence for forensic analysis
- Clear communication to stakeholders
- Continuous improvement through post-incident reviews
- Compliance with regulatory notification requirements (GDPR, SOC 2, state breach laws)

---

## Scope

**In Scope:**
- Security incidents affecting ClawdBot/OpenClaw deployments
- Data breaches involving AI agent systems
- Compromise of credentials or API keys
- Unauthorized access or malicious use
- Prompt injection attacks
- Supply chain compromises (malicious skills)
- Denial of service attacks
- Infrastructure compromises (MCP servers, gateways)

**Out of Scope:**
- General IT incidents (handled by IT Operations)
- Anthropic Claude API outages (vendor responsibility)
- User error without security impact (handled by Support)

---

## Incident Categories

### P0 - Critical (Response Time: 15 minutes)

**Definition**: Immediate threat to production systems or data; active exploitation.

**Examples**:
- Active data exfiltration in progress
- Production credentials compromised
- Ransomware/destructive attack
- PII/PHI disclosure to unauthorized parties
- Critical infrastructure compromise (gateway, agent runtime)

**Response Team**: Full incident response team activated
**Communication**: CISO, CTO, Legal notified immediately
**SLA**: Containment within 1 hour, resolution plan within 4 hours

**See**: [Incident Response Playbooks](../../examples/incident-response/)

---

### P1 - High (Response Time: 1 hour)

**Definition**: Significant security concern; potential for escalation to P0.

**Examples**:
- Successful prompt injection attack ([scenario-001](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md))
- Malicious skill installation ([scenario-002](../../examples/scenarios/scenario-002-malicious-skill-deployment.md))
- MCP server compromise ([scenario-003](../../examples/scenarios/scenario-003-mcp-server-compromise.md))
- Unauthorized access to confidential data
- Failed container escape attempt (detected)
- Suspicious behavioral anomalies (openclaw-telemetry alerts)

**Response Team**: Core security team + on-call engineer
**Communication**: Security team + engineering lead
**SLA**: Containment within 4 hours, resolution within 24 hours

---

### P2 - Medium (Response Time: 4 hours)

**Definition**: Security vulnerability or policy violation requiring attention.

**Examples**:
- Plaintext credentials found in config files
- Failed authentication attempts (below lockout threshold)
- Non-production data exposure
- Policy violations (skill not in allowlist)
- Denied prompt injection attempts (blocked by openclaw-shield)
- Configuration drift from security baseline

**Response Team**: Security team + system owner
**Communication**: Security team
**SLA**: Fix plan within 1 business day, resolution within 1 week

---

### P3 - Low (Response Time: 1 business day)

**Definition**: Minor security concern; informational only.

**Examples**:
- Security scan findings (informational)
- Expired certificates (non-production)
- Outdated dependencies (no known exploits)
- User education opportunities

**Response Team**: System owner
**Communication**: Email notification
**SLA**: Fix plan within 1 week, resolution at convenience

---

## Roles and Responsibilities

### Incident Commander (IC)

**Responsibilities**:
- Own the incident response from detection to resolution
- Decide on containment, eradication, and recovery actions
- Coordinate response team activities
- Authorize communications to stakeholders
- Call post-incident review

**Who**: Security team lead (P0/P1), on-call engineer (P2), system owner (P3)

### Security Analyst

**Responsibilities**:
- Monitor security alerts and logs
- Triage and categorize incidents
- Perform initial investigation
- Collect and preserve evidence
- Coordinate with SOC/SIEM team

### Engineering Team

**Responsibilities**:
- Implement containment measures (firewall blocks, container kills)
- Perform forensic analysis
- Deploy fixes and patches
- Restore from backups if needed
- Validate security posture post-incident

### Legal / Privacy Officer

**Responsibilities**:
- Advise on regulatory notification requirements
- Review external communications
- Coordinate with law enforcement if criminal activity
- Manage breach notification process (GDPR Article 33, state laws)

### CISO / CTO

**Responsibilities**:
- Executive oversight for P0/P1 incidents
- Approve major response decisions (shutdowns, notifications)
- Communicate with board and executives
- Allocate resources for response and remediation

### Communications / PR

**Responsibilities**:
- Draft customer communications
- Coordinate public disclosure (if required)
- Manage media inquiries
- Update status page

---

## Incident Response Lifecycle

### 1. Detection

**Goal**: Identify security incidents as quickly as possible.

**Detection Sources**:
- **Automated Monitoring**: openclaw-telemetry, SIEM alerts, IDS/IPS
- **User Reports**: Security@ email, Slack #security channel
- **Security Scans**: [verify_openclaw_security.sh](../../scripts/verification/verify_openclaw_security.sh)
- **Third-Party Notifications**: Vulnerability disclosures, threat intelligence
- **Audit Log Review**: Quarterly access reviews

**Actions**:
1. Security analyst receives alert or report
2. Initial triage: Is this a security incident? (Yes → proceed, No → close)
3. Categorize severity (P0/P1/P2/P3)
4. Create incident ticket (JIRA, ServiceNow, GitHub issue)
5. Page incident commander if P0/P1

**SLA**: P0 paged within 5 minutes, P1 within 30 minutes

---

### 2. Analysis

**Goal**: Understand the scope, impact, and root cause.

**Questions to Answer**:
- What happened? (attack vector, timeline)
- What was affected? (systems, data, users)
- How did it happen? (vulnerability exploited, misconfiguration)
- Is it still happening? (ongoing vs contained)
- What data was accessed/exfiltrated?

**Actions**:
1. **Collect Evidence**:
   ```bash
   # Forensic data collection
   ./scripts/incident-response/forensics-collector.py --incident-id INC-2026-001
   ```
   
2. **Review Logs**:
   - Authentication logs (failed logins, MFA bypasses)
   - Authorization logs (privilege escalation attempts)
   - Agent execution logs (tool invocations, skill executions)
   - Network logs (unusual connections, data exfiltration)
   - Telemetry data (anomalies, behavioral changes)

3. **Document Timeline** (see [reporting-template.md](../../examples/incident-response/reporting-template.md)):
   ```
   T-0: Initial compromise (attacker gains access)
   T+2h: Persistence established (malicious skill installed)
   T+24h: Detection (anomaly alert triggered)
   T+24h+15min: Containment (skill removed, IP blocked)
   ```

4. **Assess Impact**:
   - Data breach? (PII, credentials, regulated data)
   - Service disruption? (downtime, degraded performance)
   - Reputational damage?
   - Regulatory notification required?

**Output**: Incident analysis report with scope, impact, and root cause

---

### 3. Containment

**Goal**: Stop the bleeding; prevent further damage.

**Short-Term Containment** (immediate, may be non-ideal):
- Block attacker IP addresses at firewall
- Kill compromised containers
- Revoke compromised API keys
- Disconnect affected systems from network
- Enable additional logging/monitoring

**Long-Term Containment** (more permanent):
- Deploy fixes for exploited vulnerabilities
- Rotate all potentially compromised credentials
- Rebuild compromised systems from clean images
- Update firewall rules and policies

**Containment Actions by Incident Type**:

| Incident Type | Containment Actions |
|---------------|---------------------|
| **Credential Theft** | 1. Rotate API keys immediately<br>2. Check for unauthorized usage (audit logs)<br>3. Block attacker IPs<br>4. See [Playbook 1](../../examples/incident-response/playbook-credential-theft.md) |
| **Prompt Injection** | 1. Enable stricter input validation<br>2. Block specific patterns<br>3. Roll back to safe conversation state<br>4. See [Playbook 2](../../examples/incident-response/playbook-prompt-injection.md) |
| **Malicious Skill** | 1. Quarantine skill (move to `/quarantine`)<br>2. Kill skill processes<br>3. Check for persistence (cron, startup scripts)<br>4. See [Playbook 3](../../examples/incident-response/playbook-skill-compromise.md) |
| **Container Escape** | 1. Kill container immediately<br>2. Isolate host from network<br>3. Image forensics<br>4. Review seccomp/AppArmor logs |

**Automated Containment**:
```python
# scripts/incident-response/auto-containment.py
./scripts/incident-response/auto-containment.py \
  --incident-type credential-theft \
  --affected-resources "api-key-abc123" \
  --action rotate+block
```

**SLA**: P0 contained within 1 hour, P1 within 4 hours

---

### 4. Eradication

**Goal**: Remove the threat completely.

**Actions**:
1. **Remove Malicious Components**:
   - Uninstall malicious skills
   - Delete backdoors and persistence mechanisms
   - Remove compromised accounts

2. **Patch Vulnerabilities**:
   - Apply security updates
   - Fix misconfigurations
   - Update security policies

3. **Rebuild Compromised Systems**:
   - Wipe and reinstall from clean images
   - Verify integrity checksums
   - Apply security hardening

4. **Validate Eradication**:
   ```bash
   # Re-run security verification
   ./scripts/verification/verify_openclaw_security.sh
   # Should show: 0 critical findings
   ```

**Output**: Clean, hardened environment with no traces of attacker

---

### 5. Recovery

**Goal**: Restore normal operations safely.

**Actions**:
1. **Restore from Backups** (if needed):
   ```bash
   ./configs/examples/backup-restore.sh restore \
     --backup-id backup-2026-02-13 \
     --verify-integrity
   ```

2. **Gradual Restoration**:
   - Start with non-production environments
   - Canary deployment (10% traffic → 50% → 100%)
   - Monitor closely for 24-48 hours

3. **Enhanced Monitoring**:
   - Increase log verbosity temporarily
   - Lower anomaly detection thresholds
   - Add specific alerts for this attack vector

4. **Communicate Recovery**:
   - Internal: "Systems restored, monitoring ongoing"
   - Customers (if affected): Status page update, direct notification

**Validation**:
- All systems operational
- No anomalies detected for 24 hours
- Security baseline restored

---

### 6. Post-Incident Activity

**Goal**: Learn from the incident; prevent recurrence.

**Post-Incident Review (PIR) Meeting** (within 5 business days):
- Attendees: Incident commander, response team, engineering, management
- Duration: 60-90 minutes
- Agenda:
  1. Timeline review (what happened when)
  2. What went well?
  3. What went poorly?
  4. Root cause analysis (5 Whys)
  5. Action items with owners and deadlines

**PIR Output**: 
- Incident report (see [reporting-template.md](../../examples/incident-response/reporting-template.md))
- Action items tracked in JIRA/GitHub
- Runbook updates
- Policy/procedure changes
- Security control improvements

**Example Action Items (from [scenario-001](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md)):
- [ ] Deploy openclaw-shield (Layer 4) - Owner: DevSecOps, Due: 2 weeks
- [ ] Add email parsing to prompt injection rules - Owner: Security Analyst, Due: 1 week
- [ ] Conduct prompt injection training for engineers - Owner: Security Team, Due: 1 month
- [ ] Update incident playbook with learnings - Owner: IC, Due: 1 week

**Metrics**:
- Time to detect (TTD)
- Time to contain (TTC)
- Time to recover (TTR)
- Number of affected users/systems
- Data exposed (if applicable)
- Cost of incident (labor, downtime, fines)

---

## Communication Procedures

### Internal Communication

**Security Team**:
- Slack: #security-incidents (real-time coordination)
- Email: security@company.com (formal notifications)
- PagerDuty: On-call rotation for P0/P1

**Engineering / Operations**:
- Incident updates every 2 hours (P0), every 4 hours (P1)
- Status: "Investigating", "Contained", "Eradicating", "Recovered"

**Executive Team**:
- P0: Immediate notification (phone call within 15 minutes)
- P1: Email within 1 hour, daily updates
- P2/P3: Weekly summary email

### External Communication

**Customers**:
- **Data Breach**: Notification required if PII/regulated data exposed
  - Timeline: GDPR = 72 hours, CCPA/state laws vary
  - Channel: Email, in-app notification, status page
  - Content: Reviewed by Legal before sending
- **Service Disruption**: Status page update (no sensitive details)

**Regulatory Authorities**:
- **GDPR**: Data Protection Authority (DPA) notification within 72 hours (Article 33)
- **State Breach Laws**: Varies by state (e.g., California = "without unreasonable delay")
- Coordinated by Legal/Privacy Officer

**Media / Public**:
- All media inquiries routed to Communications/PR
- No public statement without CISO + CEO approval
- Focus: What happened (high-level), what we're doing, how we're protecting customers

**Template Communication**:
```
Subject: Security Incident Notification - [Incident ID]

Dear Customer,

We are writing to inform you of a security incident that may have affected your data.

What Happened:
[Brief description of the incident]

What Information Was Affected:
[Types of data potentially accessed]

What We're Doing:
[Containment and remediation actions]

What You Should Do:
[Recommended user actions, if any]

Contact:
For questions, contact security@company.com or call [phone number].

We take security seriously and apologize for any inconvenience.

Sincerely,
[Name], CISO
```

---

## Compliance

### GDPR Article 33: Notification of Data Breach

**Requirements**:
- Notify supervisory authority (DPA) within 72 hours
- Include: Nature of breach, categories/number of affected individuals, consequences, measures taken
- If >72 hours, provide reason for delay

**OpenClaw Implementation**:
- Automated detection via openclaw-telemetry (real-time alerts)
- Evidence collection preserved (see [forensics-collector.py](../../scripts/incident-response/forensics-collector.py))
- Notification draft generated from [reporting-template.md](../../examples/incident-response/reporting-template.md)
- Legal reviews before submission

### SOC 2 Type II

**Controls**:
- CC7.3: Incidents are detected and communicated to appropriate personnel
- CC7.4: System incidents are analyzed to identify root cause
- CC7.5: Corrective actions are taken to remediate incidents

**Evidence**:
- Incident tickets (JIRA with full timeline)
- Post-incident review reports
- Action item tracking (completion verified)
- Incident metrics (TTD, TTC, TTR)

### ISO 27001

**Standards**:
- A.16.1.1: Responsibilities and procedures for incident management
- A.16.1.4: Assessment of and decision on information security events
- A.16.1.5: Response to information security incidents
- A.16.1.6: Learning from information security incidents

**Evidence**:
- This policy (defined procedures)
- Incident response playbooks
- PIR reports with lessons learned
- Updated runbooks/controls

---

## References

### Internal Documentation
- [Incident Response Guide](../guides/06-incident-response.md) - Detailed procedures
- [Incident Report Template](../../examples/incident-response/reporting-template.md)
- [Access Control Policy](./access-control-policy.md)
- [Data Classification Policy](./data-classification.md)

### Response Playbooks
- [Playbook: Credential Exfiltration](../../examples/incident-response/playbook-credential-theft.md)
- [Playbook: Prompt Injection](../../examples/incident-response/playbook-prompt-injection.md)
- [Playbook: Malicious Skill](../../examples/incident-response/playbook-skill-compromise.md)
- [Playbook: Data Breach](../../examples/incident-response/playbook-data-breach.md)

### Real-World Scenarios
- [Scenario 001: Indirect Prompt Injection](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md)
- [Scenario 002: Malicious Skill Deployment](../../examples/scenarios/scenario-002-malicious-skill-deployment.md)
- [Scenario 003: MCP Server Compromise](../../examples/scenarios/scenario-003-mcp-server-compromise.md)
- [Scenarios 004-007](../../examples/scenarios/)

### Automation Scripts
- [Auto-Containment](../../scripts/incident-response/auto-containment.py)
- [Forensics Collector](../../scripts/incident-response/forensics-collector.py)
- [Notification Manager](../../scripts/incident-response/notification-manager.py)

### External Resources
- [NIST SP 800-61r2: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [SANS Incident Response Process](https://www.sans.org/security-resources/posters/incident-response-process-step-by-step/170/download)
- [GDPR Article 33: Breach Notification](https://gdpr-info.eu/art-33-gdpr/)

---

**Policy Owner**: Security Team  
**24/7 Security Hotline**: security-oncall@company.com (PagerDuty)  
**Approved By**: CISO, CTO, Legal  
**Next Review Date**: August 14, 2026 (semi-annual)  
**Questions**: security@company.com
