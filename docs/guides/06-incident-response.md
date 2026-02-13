# Incident Response Guide

**Layer 6-7 Integration: Response Procedures Across All Layers**

**Estimated Time:** 60 minutes to read, ongoing for implementation  
**Difficulty:** Advanced  
**Prerequisites:** Understanding of all previous security layers, incident response basics

This guide provides actionable incident response playbooks for AI agent security incidents, from detection through recovery.

## Table of Contents

1. [Incident Classification](#incident-classification)
2. [Detection and Triage](#detection-and-triage)
3. [Playbook 1: Credential Exfiltration](#playbook-1-credential-exfiltration)
4. [Playbook 2: Prompt Injection Attack](#playbook-2-prompt-injection-attack)
5. [Playbook 3: Unauthorized Network Access](#playbook-3-unauthorized-network-access)
6. [Playbook 4: Malicious Skill Installation](#playbook-4-malicious-skill-installation)
7. [Evidence Collection](#evidence-collection)
8. [Communication Templates](#communication-templates)
9. [Post-Incident Review](#post-incident-review)

---

## Incident Classification

### Severity Levels

| Level | Description | Response Time | Examples |
|-------|-------------|---------------|----------|
| **P0 - Critical** | Active exploitation, data exfiltration | Immediate (5 min) | Credentials being exfiltrated, ongoing breach |
| **P1 - High** | High risk of exploitation, system compromise | 15 minutes | Malicious skill detected, unauthorized access attempts |
| **P2 - Medium** | Potential security weakness, no active exploit | 1 hour | Configuration drift, missing security controls |
| **P3 - Low** | Security hygiene, best practice violations | 1 business day | Outdated dependencies, log gaps |

### Incident Types

1. **Credential Compromise**
2. **Unauthorized Access**
3. **Malicious Code Execution**
4. **Data Exfiltration**
5. **Supply Chain Compromise**

---

## Playbook 1: Credential Exfiltration

### Symptoms
- Alert: "Skill sent data to non-whitelisted endpoint"
- Unusual API usage patterns
- Network traffic to unknown IPs

### Phase 1: Containment (5-10 minutes)

#### Step 1.1: Isolate the Agent
```bash
# Stop ClawdBot immediately
docker stop clawdbot-production

# Verify stopped
ps aux | grep -i claw
```

#### Step 1.2: Block Network Access
```bash
# Block all traffic
sudo iptables -I INPUT -s <AGENT_IP> -j DROP
sudo iptables -I OUTPUT -d <AGENT_IP> -j DROP
```

#### Step 1.3: Revoke Credentials
- Anthropic: https://console.anthropic.com/settings/keys
- OpenAI: https://platform.openai.com/api-keys
- AWS: IAM Console

### Phase 2: Evidence Collection (10-15 minutes)

```bash
# Preserve logs
mkdir -p ~/incident-$(date +%Y%m%d-%H%M%S)
cp -r ~/.openclaw/logs ~/incident-$(date +%Y%m%d-%H%M%S)/

# Create archive
tar -czf incident-logs.tar.gz ~/.openclaw/logs
sha256sum incident-logs.tar.gz > evidence-hash.txt
```

### Phase 3: Investigation (20-30 minutes)

```bash
# Identify exfiltration endpoint
grep -r "http" ~/.openclaw/logs/ | grep -v "api.anthropic.com"

# Timeline reconstruction
jq -r '.timestamp + " " + .event' ~/.openclaw/logs/audit.jsonl
```

### Phase 4: Recovery (30-60 minutes)

```bash
# Rotate credentials
security add-generic-password \
  -s "ai.openclaw.anthropic" \
  -a "$USER" \
  -w "NEW-API-KEY" \
  -U

# Restart with enhanced monitoring
docker start clawdbot-production
```

---

## Playbook 2: Prompt Injection Attack

### Symptoms
- Agent performs unexpected actions
- Tool execution logs show suspicious commands
- Alert: "Potential prompt injection detected"

### Phase 1: Immediate Actions (2-5 minutes)

```bash
# Pause agent operations
docker exec clawdbot-production touch /app/maintenance.lock

# Capture active session
curl http://127.0.0.1:18789/admin/debug/session > session.json
```

### Phase 2: Analysis (10-20 minutes)

```bash
# Identify injection patterns
grep -E "ignore previous|disregard|execute" ~/.openclaw/logs/prompts.jsonl

# Assess damage
jq -r 'select(.event=="tool_execution") | .tool_name' ~/.openclaw/logs/audit.jsonl
```

### Phase 3: Containment (10-15 minutes)

Deploy openclaw-shield:

```yaml
# ~/.openclaw/config/shield.yml
shield:
  prompt_guard:
    enabled: true
    detection:
      - type: "instruction_override"
        patterns:
          - "ignore previous"
          - "new instructions"
        action: "block"
```

---

## Playbook 3: Unauthorized Network Access

### Symptoms
- Alert: "Gateway accessed from non-VPN IP"
- Failed authentication from unexpected source

### Phase 1: Immediate Block (1-2 minutes)

```bash
# Block attacker IP
sudo ufw deny from <ATTACKER_IP>

# Reset gateway token
NEW_TOKEN=$(openssl rand -base64 32)
# Update configuration and restart
```

### Phase 2: Investigation (10-15 minutes)

```bash
# Review access logs
grep "<ATTACKER_IP>" ~/.openclaw/logs/network-access.jsonl

# Check for successful auth
jq 'select(.source_ip=="<ATTACKER_IP>" and .auth_status=="success")' \
  ~/.openclaw/logs/network-access.jsonl
```

---

## Playbook 4: Malicious Skill Installation

### Symptoms
- Alert: "Skill integrity check failed"
- New skill appears in directory

### Phase 1: Quarantine (2-5 minutes)

```bash
# Stop agent
docker stop clawdbot-production

# Identify malicious skill
./scripts/supply-chain/skill_manifest.py \
  --skills-dir ~/.openclaw/skills \
  --compare manifests/baseline.json

# Quarantine
mkdir -p ~/incident-quarantine
mv ~/.openclaw/skills/malicious-skill ~/incident-quarantine/
```

### Phase 2: Analysis (15-30 minutes)

```bash
# Reverse engineer
cat ~/incident-quarantine/malicious-skill.py | grep -E "http|requests|exec"

# Check if executed
grep "malicious-skill" ~/.openclaw/logs/tool-execution.jsonl
```

### Phase 3: Recovery (20-30 minutes)

```bash
# Restore clean skills
rm -rf ~/.openclaw/skills/*
git clone https://github.com/anthropic-ai/openclaw-skills ~/.openclaw/skills

# Verify integrity
./scripts/supply-chain/skill_manifest.py --compare manifests/baseline.json
```

---

## Evidence Collection

### Automated Evidence Collection Script

```bash
#!/bin/bash
# evidence_collection.sh

INCIDENT_ID="INC-$(date +%Y%m%d-%H%M%S)"
EVIDENCE_DIR=~/incidents/$INCIDENT_ID

mkdir -p $EVIDENCE_DIR/{logs,configs,network,forensics}

# Collect logs
cp -r ~/.openclaw/logs $EVIDENCE_DIR/logs/
docker logs clawdbot-production > $EVIDENCE_DIR/logs/docker.log 2>&1

# Collect configurations
cp -r ~/.openclaw/config $EVIDENCE_DIR/configs/

# Network state
ss -tuln > $EVIDENCE_DIR/network/listening-ports.txt
sudo iptables -L -n -v > $EVIDENCE_DIR/network/firewall-rules.txt

# Process list
ps auxf > $EVIDENCE_DIR/forensics/processes.txt

# Skill manifest
./scripts/supply-chain/skill_manifest.py \
  --skills-dir ~/.openclaw/skills \
  --output $EVIDENCE_DIR/forensics/skill-manifest.json

# Calculate hashes
cd $EVIDENCE_DIR
find . -type f -exec sha256sum {} \; > evidence-hashes.txt

# Create archive
tar -czf ../evidence-$INCIDENT_ID.tar.gz .
sha256sum ../evidence-$INCIDENT_ID.tar.gz > ../evidence-$INCIDENT_ID.tar.gz.sha256

echo "Evidence collected: evidence-$INCIDENT_ID.tar.gz"
```

---

## Communication Templates

### Internal Notification

```
Subject: [P0] Security Incident - Credential Exfiltration

Team,

We've detected credential exfiltration from ClawdBot.

STATUS: Contained - Agent isolated, credentials revoked
IMPACT: Anthropic API key exposed
ACTIONS: Agent stopped, credentials rotated
NEXT: Root cause analysis in progress

Incident Commander: [Name]
War Room: #incident-20260214
```

### Customer Notification

```
Subject: Security Incident Notification

Dear Customer,

On [date], we detected [incident]. We immediately [actions].

IMPACT: [Customer impact]
ACTIONS TAKEN: [List]
WHAT YOU SHOULD DO: [Guidance]

For questions: security@company.com
Incident ID: INC-[ID]
```

---

## Post-Incident Review

### PIR Template

```markdown
# Post-Incident Review: INC-YYYYMMDD-NNN

Date: [Date]
Attendees: [Names]

## Incident Summary
- Type: [Type]
- Severity: P[0-3]
- Duration: [Hours]
- Impact: [Description]

## Timeline

| Time | Event | Action | By Whom |
|------|-------|--------|---------|
| 01:30 | Alert | Acknowledged | John |
| 01:35 | Containment | Stopped agent | John |

## What Went Well
- Alert fired promptly
- Runbook was clear
- Fast containment

## What Went Wrong
- Root cause identification took too long
- No automated rollback
- Manual evidence collection

## Root Cause
[Detailed explanation]

## Action Items

| Action | Owner | Due Date | Priority |
|--------|-------|----------|----------|
| Deploy shield | DevOps | 2026-02-16 | P0 |
| Automated rollback | Eng | 2026-02-20 | P1 |

## Metrics
- Time to Detect: 2 min
- Time to Contain: 10 min
- Time to Resolve: 90 min
```

---

## Best Practices

1. **Prepare Before Incidents**
   - Maintain updated runbooks
   - Practice response drills
   - Have scripts ready

2. **Respond Systematically**
   - Follow playbooks
   - Document everything
   - Communicate frequently

3. **Learn and Improve**
   - Conduct PIRs
   - Track action items
   - Update runbooks

---

## Related Guides

- **Credential Isolation:** [02-credential-isolation.md](02-credential-isolation.md)
- **Network Segmentation:** [03-network-segmentation.md](03-network-segmentation.md)
- **Supply Chain Security:** [05-supply-chain-security.md](05-supply-chain-security.md)

---

**Last Updated:** February 14, 2026  
**Review Frequency:** Quarterly or after each P0/P1 incident
