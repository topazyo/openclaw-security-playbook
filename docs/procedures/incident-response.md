# Incident Response Procedure

**Document Type**: Operational Runbook  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Security Team  
**Related Policy**: [Incident Response Policy](../policies/incident-response-policy.md)

This runbook provides step-by-step procedures for responding to security incidents affecting ClawdBot/OpenClaw deployments.

---

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [Incident Classification](#incident-classification)
3. [Response Procedures](#response-procedures)
4. [Playbook Index](#playbook-index)
5. [Tools and Scripts](#tools-and-scripts)
6. [Escalation Matrix](#escalation-matrix)

---

## Quick Reference

> **⚠️ FILL IN BEFORE OPERATIONAL USE** — the contact details below are placeholder examples.
> Replace every `@company.com` address and phone number with your organisation's real contacts
> before distributing this runbook to your incident response team.

### Emergency Contacts

| Role | Contact | Availability |
|------|---------|--------------|
| **Security On-Call** | security-oncall@company.com (PagerDuty) | 24/7 |
| **CISO** | ciso@company.com, +1-555-0100 | Business hours |
| **CTO** | cto@company.com, +1-555-0101 | Business hours |
| **Legal** | legal@company.com, +1-555-0102 | Business hours |
| **Security Team** | security@company.com | Business hours |

### Response SLA

| Priority | Response Time | Containment SLA | Resolution SLA |
|----------|---------------|-----------------|----------------|
| **P0** | 15 minutes | 1 hour | 4 hours (plan) |
| **P1** | 1 hour | 4 hours | 24 hours |
| **P2** | 4 hours | 1 business day | 1 week |
| **P3** | 1 business day | 1 week | At convenience |

### First Steps (Any Incident)

1. **Create Incident Ticket**: JIRA (SEC-INC-YYYY-NNN) or GitHub Issue
2. **Notify Security On-Call**: PagerDuty (P0/P1) or Slack #security-incidents (P2/P3)
3. **Gather Initial Evidence**: Timestamps, affected systems, observed behavior
4. **Reference Playbook**: See [Playbook Index](#playbook-index) for specific attack types
5. **Execute OODA Loop**: Observe → Orient → Decide → Act (repeat until contained)

---

## Incident Classification

Use this decision tree to classify incidents:

```
Is data being actively exfiltrated OR
   credentials actively compromised OR
   production systems destroyed?
   ├─ YES → P0 (Critical)
   └─ NO ↓

Is there successful unauthorized access OR
   high-value data exposed OR
   attack in progress (but contained)?
   ├─ YES → P1 (High)
   └─ NO ↓

Is there a security vulnerability OR
   policy violation OR
   failed attack attempt (detected)?
   ├─ YES → P2 (Medium)
   └─ NO ↓

Is this informational OR
   low-risk finding?
   └─ YES → P3 (Low)
```

### Real-World Examples

| Scenario | Priority | Playbook |
|----------|----------|----------|
| Production API key found on GitHub | P0 | [Playbook 1: Credential Exfiltration](../../examples/incident-response/playbook-credential-theft.md) |
| Malicious skill installed, exfiltrating data | P0 | [Playbook 3: Malicious Skill](../../examples/incident-response/playbook-skill-compromise.md) |
| Successful prompt injection attack | P1 | [Playbook 2: Prompt Injection](../../examples/incident-response/playbook-prompt-injection.md) |
| MCP server compromised (contained) | P1 | [Scenario 003: MCP Server Compromise](../../examples/scenarios/scenario-003-mcp-server-compromise.md) |
| Plaintext credentials in config file | P2 | Fix: Rotate + migrate to keychain |
| Outdated Docker image (no known exploits) | P3 | Recommendation: Update during next maintenance |

---

## Response Procedures

### Phase 1: Detection and Analysis

**Objective**: Identify and understand the incident.

#### Step 1.1: Receive Alert or Report

**Automated Detection**:
```bash
# Review recent anomalies from openclaw-telemetry logs
python scripts/monitoring/anomaly_detector.py \
  --logfile ~/.openclaw/logs/telemetry.jsonl \
  --output-json

# Review SIEM for security events
# (Integration: see configs/examples/monitoring-stack.yml)
```

**Manual Report** (user calls security hotline):
- Who: Name and role of reporter
- What: What did you observe?
- When: When did this happen? (exact timestamp preferred)
- Where: Which system? (hostname, IP, URL)
- Evidence: Screenshots, log excerpts, error messages

#### Step 1.2: Create Incident Ticket

```bash
# Option 1: JIRA (preferred for compliance audit trail)
jira create \
  --project SEC \
  --type Incident \
  --summary "Suspected credential compromise - API key" \
  --priority P0 \
  --assignee security-oncall

# Option 2: GitHub Issue (for open-source deployments)
gh issue create \
  --repo company/openclaw-security \
  --title "[INCIDENT] Suspected credential compromise" \
  --label incident,p0 \
  --assignee @security-oncall
```

**Ticket Template**: See [reporting-template.md](../../examples/incident-response/reporting-template.md)

#### Step 1.3: Initial Triage

**Questions to Answer**:
1. Is this a true security incident? (Yes → proceed; No → reassign to IT/Support)
2. What is the severity? (P0/P1/P2/P3 - see classification above)
3. Is it still ongoing? (Active attack vs historical compromise)
4. What systems are affected? (production, staging, dev)

**Triage Script**:
```bash
# Quick security check
./scripts/verification/verify_openclaw_security.sh --quick

# Check for indicators of compromise
./scripts/incident-response/ioc-scanner.py \
  --indicators malicious-ips.txt \
  --logs /var/log/openclaw/
```

**Output**: Incident ticket updated with severity, affected systems, initial assessment

#### Step 1.4: Notify Incident Commander

**P0/P1**: Page immediately via PagerDuty
```bash
# Automated paging
curl -X POST https://api.pagerduty.com/incidents \
  -H "Authorization: Token token={PD_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "incident": {
      "type": "incident",
      "title": "P0: Active credential exfiltration",
      "service": {"id": "OPENCLAW_SERVICE_ID", "type": "service_reference"},
      "urgency": "high"
    }
  }'
```

**P2/P3**: Slack notification + email
```bash
# Slack notification
python scripts/incident-response/notification-manager.py \
  --incident SEC-INC-2026-042 \
  --severity MEDIUM \
  --channel slack \
  --message "New P2 incident: Plaintext creds in config (SEC-INC-2026-042)"
```

#### Step 1.5: Collect Evidence

**Preserve Evidence BEFORE any containment actions** (containment may destroy evidence):

```bash
# Full forensic collection (use for P0/P1)
./scripts/incident-response/forensics-collector.py \
  --incident-id SEC-INC-2026-042 \
  --output /evidence/SEC-INC-2026-042/ \
  --collect all

# Artifacts collected:
# - Running processes (ps aux snapshot)
# - Network connections (netstat, ss)
# - Docker container state (docker inspect)
# - Log files (last 7 days)
# - Configuration files (with secrets redacted)
# - Memory dump (optional, for P0 only)
```

**Evidence Chain of Custody**:
- All evidence stored in tamper-evident location (`/evidence/` with immutable flag)
- SHA-256 checksums computed immediately
- Access logged (who, when, why)
- Required for legal proceedings

---

### Phase 2: Containment

**Objective**: Stop the attack; prevent further damage.

#### Step 2.1: Short-Term Containment

**Goal**: Immediate action to stop the bleeding (may be crude).

**Containment Actions by Incident Type**:

| Incident Type | Containment Command |
|---------------|---------------------|
| **Credential Exfiltration** | `python scripts/incident-response/notification-manager.py --incident SEC-INC-2026-042 --severity CRITICAL --channel all --message "Rotate compromised provider keys immediately"` |
| **Malicious Skill** | `docker stop clawdbot-production && mv ~/.openclaw/skills/evil-tool ~/.openclaw/quarantine/` |
| **Container Escape** | `docker kill <container-id>; docker network disconnect <network> <container>` |
| **DoS Attack** | `iptables -I INPUT -s 203.0.113.45 -j DROP` |
| **MCP Server Compromise** | `systemctl stop openclaw-mcp-server; iptables -I INPUT -p tcp --dport 3000 -j DROP` |

**Automated Containment** (if openclaw-shield is deployed):
```yaml
# Containment rules triggered automatically
# See: configs/examples/with-community-tools.yml
shield:
  autoContainment:
    enabled: true
    actions:
      - trigger: "PromptInjectionDetected"
        action: "BlockRequest"
      - trigger: "CredentialExfilAttempt"
        action: "KillContainer"
      - trigger: "UnauthorizedSkillInstall"
        action: "QuarantineSkill"
```

**Verification**:
```bash
# Confirm attack has stopped by checking fresh telemetry
python scripts/monitoring/anomaly_detector.py \
  --logfile ~/.openclaw/logs/telemetry.jsonl \
  --output-json
# Expected: No new anomalies tied to this incident after containment
```

#### Step 2.2: Damage Assessment

**Questions to Answer**:
1. What data was accessed or exfiltrated?
2. How many systems are compromised?
3. How long has the attack been ongoing? (dwell time)
4. Are there additional victims we haven't detected?

**Assessment Script**:
```bash
# Analyze audit logs for data access
./scripts/incident-response/impact-analyzer.py \
  --incident-id SEC-INC-2026-042 \
  --start-time "2026-02-14 08:00" \
  --end-time "2026-02-14 12:00"

# Output:
# - Timeline of attacker actions
# - Data files accessed (with classification levels)
# - Lateral movement attempts
# - Persistence mechanisms installed
```

**Regulatory Notification Decision**:
- **PII exposed?** → GDPR Article 33 (72 hours), state breach laws
- **PHI exposed?** → HIPAA (60 days)
- **Payment card data?** → PCI DSS (immediate notification to acquirer)

**Document in**: [reporting-template.md](../../examples/incident-response/reporting-template.md)

#### Step 2.3: Long-Term Containment

**Goal**: More permanent fix while preparing for eradication.

**Actions**:
1. **Rotate All Potentially Compromised Credentials**:
   ```bash
  # Re-store rotated provider keys in the supported OS keychain flows
  ./scripts/credential-migration/macos/migrate_credentials_macos.sh
  # Or on Linux:
  ./scripts/credential-migration/linux/migrate_credentials_linux.sh
   ```

2. **Patch Exploited Vulnerabilities**:
   ```bash
  # Apply the relevant host or container patch using your standard package process,
  # then rerun the security verifier before restoring service.
  ./scripts/verification/verify_openclaw_security.sh
   ```

3. **Update Firewall Rules**:
   ```bash
  # Block attacker infrastructure
  while read -r indicator; do iptables -I INPUT -s "$indicator" -j DROP; done < attacker-infrastructure.txt
   ```

4. **Isolate Compromised Systems**:
   ```bash
  # Isolate the affected runtime from external networks
  docker network disconnect bridge clawdbot-production
   ```

**Verification**:
```bash
# Full security scan
./scripts/verification/verify_openclaw_security.sh
# Expected: 0 critical findings
```

---

### Phase 3: Eradication

**Objective**: Remove the threat completely.

#### Step 3.1: Remove Malicious Components

```bash
# Automated eradication (P1/P2)
docker stop clawdbot-production
rm -rf /path/to/malicious-skill/
pkill -f evil-miner

# Manual eradication (P0) - use forensics data to identify all artifacts
```

#### Step 3.2: Rebuild Compromised Systems

**For severely compromised systems** (e.g., container escape, rootkit):
```bash
# Full rebuild from clean images
docker compose -f configs/examples/docker-compose-full-stack.yml down
docker system prune -a --volumes  # Remove all containers/images
docker compose -f configs/examples/docker-compose-full-stack.yml up -d

# Verify integrity of the deployed skill set
./scripts/supply-chain/skill_integrity_monitor.sh --skills-dir ~/.openclaw/skills
```

#### Step 3.3: Apply Hardening

**Prevent recurrence**:
```bash
# Reapply the documented runtime hardening baseline and verify it
./scripts/verification/verify_openclaw_security.sh

# If you use external runtime-enforcement tooling, re-enable it per
# docs/guides/08-community-tools-integration.md after validation succeeds.
```

**Reference**: [Security Hardening Guide](../guides/04-runtime-sandboxing.md)

---

### Phase 4: Recovery

**Objective**: Restore normal operations safely.

#### Step 4.1: Restore from Backups (if needed)

```bash
# Verify backup integrity BEFORE restoring
./configs/examples/backup-restore.sh verify \
  --backup-id backup-2026-02-13

# Restore to staging first (canary)
./configs/examples/backup-restore.sh restore \
  --backup-id backup-2026-02-13 \
  --target staging

# Test staging thoroughly, then restore production
./configs/examples/backup-restore.sh restore \
  --backup-id backup-2026-02-13 \
  --target production
```

**Reference**: [Backup and Recovery Procedure](./backup-recovery.md)

#### Step 4.2: Gradual Re-Enable

**Phased Rollout** (minimize risk):
1. Enable for 10% of traffic (canary)
2. Monitor for 2 hours (check alerts, logs, metrics)
3. If stable: 50% traffic
4. Monitor for 4 hours
5. If stable: 100% traffic

```bash
# Kubernetes canary deployment
kubectl set image deployment/clawdbot \
  clawdbot=openclaw/clawdbot:1.2.4-post-incident \
  --record

kubectl rollout status deployment/clawdbot
# Wait for: "deployment 'clawdbot' successfully rolled out"
```

#### Step 4.3: Enhanced Monitoring

**Temporary measures** (48 hours post-recovery):
```bash
# Increase log verbosity
sed -i 's/LOG_LEVEL=INFO/LOG_LEVEL=DEBUG/' .env
docker compose restart

# Run anomaly detection in follow mode during the recovery watch window
python scripts/monitoring/anomaly_detector.py \
  --logfile ~/.openclaw/logs/telemetry.jsonl \
  --follow
```

#### Step 4.4: Communicate Recovery

**Internal**:
```
Slack #engineering: "Incident SEC-INC-2026-042 resolved. All systems operational."
```

**External** (if customer-impacting):
```
Email: "Service restoration complete. Thank you for your patience."
Status Page: Update to "All Systems Operational"
```

---

### Phase 5: Post-Incident Activity

**Objective**: Learn and improve.

#### Step 5.1: Schedule Post-Incident Review (PIR)

**Timeline**: Within 5 business days of resolution

**Attendees**:
- Incident Commander (facilitator)
- Security team
- Engineering team
- Affected system owners
- Management (for P0/P1)

**Agenda**: See [Incident Response Policy](../policies/incident-response-policy.md) Section 6

#### Step 5.2: Document Lessons Learned

**PIR Template**:
```markdown
# Post-Incident Review: SEC-INC-2026-042

## Incident Summary
- Date: 2026-02-14
- Severity: P0
- Root Cause: Plaintext API key in config file leaked to GitHub

## Timeline
- T-0: API key committed to public GitHub repo
- T+2h: Attacker discovers key via automated scanning
- T+24h: Anomaly detected (unusual API usage spike)
- T+24h+15m: Key rotated, attacker IP blocked

## What Went Well
- Detection: Anomaly alert triggered within 24 hours (good)
- Containment: Key rotated within 15 minutes of detection (excellent)
- Communication: CISO notified immediately (as required)

## What Went Poorly
- Prevention: Developer bypassed pre-commit hook for secret detection
- Dwell Time: 24 hours before detection (attacker exfiltrated 5GB data)
- Documentation: Incident runbook missing specific commands (caused delay)

## Action Items
- [ ] Enforce pre-commit hooks (mandatory, no bypass) - Owner: DevOps, Due: 2 weeks
- [ ] Deploy GitHub secret scanning (GitHub Advanced Security) - Owner: Security, Due: 1 week
- [ ] Add git-secrets to developer onboarding - Owner: HR, Due: 1 month
- [ ] Update runbook with tested commands - Owner: IC, Due: 1 week
- [ ] Conduct security training on credential management - Owner: Security, Due: 1 month

## Metrics
- Time to Detect: 24 hours (target: <1 hour) ❌
- Time to Contain: 15 minutes (target: <1 hour) ✅
- Time to Recover: 4 hours (target: <4 hours) ✅
- Data Exposed: 5GB confidential data (requires GDPR notification) ⚠️
```

#### Step 5.3: Update Documentation

**Runbooks**:
```bash
# Copy the closest existing playbook and adapt it for the new pattern
cp examples/incident-response/playbook-credential-theft.md \
  examples/incident-response/playbook-github-secret-leak.md

# Update the copied playbook with tested commands and the final incident timeline
```

**Controls**:
```bash
# Re-run the baseline verifier after applying the remediation controls
./scripts/verification/verify_openclaw_security.sh
```

**Policies**:
- Update [Acceptable Use Policy](../policies/acceptable-use-policy.md) if needed
- Update [Incident Response Policy](../policies/incident-response-policy.md) with new procedures

---

## Playbook Index

Incident-specific response procedures:

| Playbook | Attack Type | Severity | Link |
|----------|-------------|----------|------|
| **Playbook 1** | Credential Exfiltration | P0/P1 | [playbook-credential-theft.md](../../examples/incident-response/playbook-credential-theft.md) |
| **Playbook 2** | Prompt Injection | P1 | [playbook-prompt-injection.md](../../examples/incident-response/playbook-prompt-injection.md) |
| **Playbook 3** | Malicious Skill | P0/P1 | [playbook-skill-compromise.md](../../examples/incident-response/playbook-skill-compromise.md) |
| **Playbook 4** | Data Breach | P0 | [playbook-data-breach.md](../../examples/incident-response/playbook-data-breach.md) |
| **Reference Scenario** | MCP Server Compromise | P1 | [scenario-003-mcp-server-compromise.md](../../examples/scenarios/scenario-003-mcp-server-compromise.md) |
| **Reference Guide** | Container Escape Recovery Inputs | P0 | [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md) |
| **Playbook 7** | DoS Attack | P1/P2 | [playbook-denial-of-service.md](../../examples/incident-response/playbook-denial-of-service.md) |

**See also**: [Real-World Scenarios](../../examples/scenarios/) for detailed attack demonstrations

---

## Tools and Scripts

### Detection

```bash
# Review recent anomalies
python scripts/monitoring/anomaly_detector.py --logfile ~/.openclaw/logs/telemetry.jsonl --output-json

# Scan for indicators of compromise
python scripts/incident-response/ioc-scanner.py --file iocs.txt
```

### Analysis

```bash
# Collect forensic evidence
python scripts/incident-response/forensics-collector.py --incident SEC-INC-XXX

# Timeline generation
./scripts/forensics/build_timeline.sh --incident-dir ~/openclaw-incident-TIMESTAMP

# Impact assessment
python scripts/incident-response/impact-analyzer.py --incident SEC-INC-XXX
```

### Containment

```bash
# Trigger emergency communications for credential rotation
python scripts/incident-response/notification-manager.py --incident SEC-INC-XXX --severity CRITICAL --channel all

# Block IP addresses
iptables -I INPUT -s 203.0.113.45 -j DROP

# Quarantine skill
mv ~/.openclaw/skills/evil-tool ~/.openclaw/quarantine/

# Kill container
docker kill <container-id>
```

### Eradication

```bash
# Remove malicious components manually using the forensics output
rm -rf /path/to/malicious-components

# Rebuild from clean images
docker compose down && docker system prune -a && docker compose up -d

# Verify integrity
./scripts/verification/verify_openclaw_security.sh
```

### Communication

```bash
# Send notifications
python scripts/incident-response/notification-manager.py --incident SEC-INC-XXX --message "..." --channel slack
```

---

## Escalation Matrix

> **⚠️ FILL IN BEFORE OPERATIONAL USE** — names, emails, and phone numbers below are placeholder examples.

### Security Team

| Role | Name | Email | Phone | PagerDuty |
|------|------|-------|-------|-----------|
| Security Analyst | On-Call Rotation | security-oncall@company.com | +1-555-0200 | ✅ |
| Security Engineer | Alice Johnson | alice@company.com | +1-555-0201 | ✅ |
| Security Lead | Bob Smith | bob@company.com | +1-555-0202 | ✅ |
| CISO | Carol Chen | carol@company.com | +1-555-0100 | ✅ (P0 only) |

### Engineering

| Role | Email | Phone | Escalation |
|------|-------|-------|------------|
| Engineer On-Call | engineering-oncall@company.com | +1-555-0300 | PagerDuty |
| DevOps Lead | devops-lead@company.com | +1-555-0301 | P0/P1 |
| CTO | cto@company.com | +1-555-0101 | P0 only |

### Legal / Compliance

| Role | Email | Phone | When to Engage |
|------|-------|-------|----------------|
| Privacy Officer | privacy@company.com | +1-555-0400 | Data breach (PII/PHI) |
| General Counsel | legal@company.com | +1-555-0102 | Criminal activity, legal hold |
| Compliance Officer | compliance@company.com | +1-555-0401 | Regulatory notification |

### External

| Entity | Contact | When to Engage |
|--------|---------|----------------|
| **Anthropic Support** | support@anthropic.com | API issues, suspected API-side compromise |
| **Law Enforcement** | FBI Cyber (1-800-CALL-FBI) | Criminal activity, nation-state attacks |
| **Regulatory Authorities** | (Per jurisdiction) | Data breach notification (GDPR, state laws) |

---

**Document Owner**: Security Team  
**Last Drill**: 2026-01-15 (Tabletop Exercise: Scenario 001)  
**Next Review**: 2026-05-14 (quarterly)  
**Questions**: security@company.com  
**Emergency**: security-oncall@company.com (PagerDuty, 24/7)
