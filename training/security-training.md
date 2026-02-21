# Security Team Training Guide

**OpenClaw Security Framework - Security Team Onboarding**

Version: 1.1  
Last Updated: 2026-02-21  
Duration: 4 hours  
Audience: Security engineers, SOC analysts, incident responders

---

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Daily Operations](#daily-operations)
4. [Incident Response](#incident-response)
5. [Monitoring & Alerting](#monitoring--alerting)
6. [Compliance & Audit](#compliance--audit)
7. [Tools & CLI](#tools--cli)
8. [Hands-On Labs](#hands-on-labs)

---

## Introduction

This guide provides comprehensive training for security team members responsible for operating and maintaining the OpenClaw AI agent security framework.

### Learning Objectives

By the end of this training, you will:
- Understand the 7-layer defense-in-depth architecture
- Execute incident response playbooks from `examples/incident-response/`
- Monitor security events using Grafana dashboards
- Generate compliance reports for SOC 2/ISO 27001/GDPR
- Use the `openclaw-cli` toolkit for daily operations

### Prerequisites

- Basic understanding of cloud security (AWS, containers)
- Familiarity with incident response procedures
- Experience with Linux command line
- Python 3.11+ installed

---

## Architecture Overview

### 7-Layer Defense Model

#### Layer 1: Credential Isolation
- **Purpose**: Prevent credential exfiltration from AI agents
- **Implementation**: OS keychains (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- **Attack Vectors**: Backup file persistence, conversation history leaks
- **Verification**: `scripts/verification/verify_openclaw_security.sh`

#### Layer 2: Network Segmentation
- **Purpose**: Isolate AI agents from untrusted networks
- **Implementation**: Tailscale/WireGuard VPNs, firewall rules
- **Configuration**: `configs/templates/gateway.hardened.yml`
- **Verification**: Check VPN connectivity, review firewall logs

#### Layer 3: Runtime Sandboxing
- **Purpose**: Contain AI agent processes
- **Implementation**: Docker with hardening (read-only, no-new-privileges, seccomp)
- **Configuration**: `configs/examples/production-k8s.yml`
- **Verification**: `docker inspect` for security settings

#### Layer 4: Runtime Enforcement
- **Purpose**: Block malicious AI agent actions in real-time
- **Implementation**: openclaw-shield (prompt injection guards, PII redaction, tool allowlisting)
- **Configuration**: `docs/guides/07-community-tools-integration.md`

#### Layer 5: Supply Chain Security
- **Purpose**: Prevent malicious skills
- **Implementation**: Skill manifest verification, integrity checking
- **Tools**: `scripts/supply-chain/skill_integrity_monitor.sh`

#### Layer 6: Monitoring & Detection
- **Purpose**: Detect anomalous AI agent behavior
- **Implementation**: openclaw-telemetry, Prometheus, Grafana, Elasticsearch
- **Dashboards**: `examples/monitoring/`

#### Layer 7: Governance & Compliance
- **Purpose**: Discover and manage shadow AI deployments
- **Implementation**: openclaw-detect, MDM integration, organization policies
- **Policies**: `configs/organization-policies/`

---

## Daily Operations

### Morning Routine

1. **Check Grafana Dashboards**
   - Open [dashboard-system-health.json](https://grafana.openclaw.ai/d/system-health)
   - Review Panel 10 (vulnerability metrics) for new CVEs
   - Check CPU/memory/disk usage trends

2. **Scan for New Vulnerabilities**
   ```bash
   python tools/openclaw-cli.py scan vulnerability --target production
   ```
   
3. **Review Compliance Status**
   ```bash
   python tools/openclaw-cli.py scan compliance --policy SEC-003
   ```

4. **Generate Daily Security Summary**
   ```bash
   python tools/openclaw-cli.py report weekly --start $(date -d '1 day ago' +%Y-%m-%d) --end $(date +%Y-%m-%d)
   ```

### Weekly Tasks

1. **Quarterly Access Review** (every 90 days)
   ```bash
   python tools/openclaw-cli.py scan access --days 90
   ```
   
2. **Certificate Expiry Check**
   ```bash
   python tools/certificate-manager.py
   ```
   
3. **Backup Verification**
   ```bash
   pytest tests/integration/test_backup_recovery.py
   ```

### Monthly Tasks

1. **SOC 2 Compliance Report**
   ```bash
   python tools/openclaw-cli.py report compliance --framework SOC2 --output reports/soc2-$(date +%Y-%m).json
   ```
   
2. **Skill Integrity Audit**
   ```bash
   ./scripts/supply-chain/skill_integrity_monitor.sh --skills-dir ~/.openclaw/skills
   ```

---

## Incident Response

### Playbook Execution

The framework includes 6 incident response playbooks:

1. **playbook-credential-theft.md**: Credential exfiltration scenario
2. **playbook-prompt-injection.md**: Prompt injection attack
3. **playbook-skill-compromise.md**: Malicious or compromised skill
4. **playbook-data-breach.md**: Sensitive data disclosure/breach
5. **playbook-denial-of-service.md**: Resource exhaustion attack
6. **docs/guides/06-incident-response.md**: Canonical triage and response procedure

### Example: Responding to Credential Exfiltration

**Detection Phase**
```bash
# Collect forensic evidence
python scripts/incident-response/forensics-collector.py --incident INC-2026-001 --level quick

# Scan for indicators of compromise
python scripts/incident-response/ioc-scanner.py --ip 198.51.100.10
```

**Containment Phase**
```bash
# Isolate compromised EC2 instance
python scripts/incident-response/auto-containment.py --incident INC-2026-001 --target i-0abc123 --action isolate-ec2 --dry-run

# Send PagerDuty alert
python scripts/incident-response/notification-manager.py --incident INC-2026-001 --severity CRITICAL --channel pagerduty
```

**Eradication Phase**
```bash
# Generate incident timeline
python scripts/incident-response/timeline-generator.py --incident INC-2026-001 --output timeline.md

# Calculate blast radius
python scripts/incident-response/impact-analyzer.py --incident INC-2026-001 --resource i-0abc123 --data-types PII,Credentials
```

**Recovery Phase**
```bash
# Restore services
bash configs/examples/backup-restore.sh list
```

**PIR Phase**
```bash
# Include in weekly report
python scripts/vulnerability-scanning/generate-weekly-report.py --output reports/weekly-vuln-report.pdf --weeks 12
```

### Using openclaw-cli for Incidents

```bash
# Execute playbook
python tools/openclaw-cli.py playbook execute playbook-credential-theft --severity P0 --dry-run

# Simulate incident for testing
python tools/openclaw-cli.py simulate incident --type credential-theft --severity P1
```

---

## Monitoring & Alerting

### Grafana Dashboards

Access dashboards at [https://grafana.openclaw.ai](https://grafana.openclaw.ai):

1. **System Health Dashboard**
   - Panel 1: CPU/Memory usage
   - Panel 10: Vulnerability metrics (CVSS histogram)
   - Panel 15: Network traffic analysis

2. **Incident Response Dashboard**
   - Real-time incident alerts
   - MTTR (Mean Time To Resolve) metrics
   - SLA compliance tracking

3. **API Security Dashboard**
   - Rate limiting violations
   - Authentication failures
   - SQL injection / XSS attempts

4. **MCP Security Dashboard**
   - MCP server health checks
   - TLS connection monitoring
   - Certificate expiry warnings

### Alert Response

**Prometheus Alerts** are routed via Alertmanager:

- **CRITICAL (P0)**: PagerDuty + Slack #security-incidents + CISO email
- **HIGH (P1)**: Slack #security-alerts + security team email
- **MEDIUM (P2)**: Security team email (batched every 15min)
- **LOW (P3)**: Ops team email (batched daily)

**Common Alerts**:

| Alert | Severity | Action |
|-------|----------|--------|
| CredentialExfiltrationDetected | CRITICAL | Execute `playbook-credential-theft.md` and follow `docs/guides/06-incident-response.md` |
| VulnerabilityCritical | HIGH | Apply patch within 7 days (SEC-003) |
| AuthFailureRateLimitExceeded | MEDIUM | Review access logs |
| CertificateExpiringSoon | LOW | Renew with certificate-manager.py |

---

## Compliance & Audit

### SOC 2 Type II

**Relevant Controls**:
- CC6.1: Logical and physical access controls (MFA required)
- CC7.1: Threat identification procedures (vulnerability scanning)
- CC7.2: Continuous monitoring (Prometheus/Grafana)
- CC7.3: Incident response (documented playbooks in `examples/incident-response/`)

**Evidence Collection**:
```bash
# Generate SOC 2 report
python tools/openclaw-cli.py report compliance --framework SOC2 --output audits/soc2-2026-Q1.json

# Export audit logs (7-year retention)
python scripts/monitoring/anomaly_detector.py --logfile ~/.openclaw/logs/telemetry.jsonl --output-json
```

### ISO 27001:2022

**Key Controls**:
- A.9.2.1: User registration and de-registration (access review)
- A.10.1.1: Cryptographic key management (90-day rotation)
- A.12.6.1: Technical vulnerability management (auto-remediate.sh)
- A.16.1.5: Response to information security incidents (playbooks)

**Compliance Check**:
```bash
python tools/openclaw-cli.py scan compliance --policy SEC-002  # Data classification
python tools/openclaw-cli.py scan compliance --policy SEC-003  # Vulnerability management
python tools/openclaw-cli.py scan compliance --policy SEC-004  # Access control
python tools/openclaw-cli.py scan compliance --policy SEC-005  # Incident response
```

### GDPR

**Article 32**: Security of processing (encryption, MFA, monitoring)

**Data Breach Notification**:
- Automated via `notification-manager.py` (72-hour notification requirement)
- Breach notification template: `examples/incident-response/reporting-template.md`

---

## Tools & CLI

### openclaw-cli Commands

```bash
# Scan operations
python tools/openclaw-cli.py scan vulnerability --target production
python tools/openclaw-cli.py scan compliance --policy SEC-003
python tools/openclaw-cli.py scan access --days 90

# Playbook execution
python tools/openclaw-cli.py playbook list
python tools/openclaw-cli.py playbook execute playbook-credential-theft --severity P0 --dry-run

# Report generation
python tools/openclaw-cli.py report weekly --start 2026-02-01 --end 2026-02-21
python tools/openclaw-cli.py report compliance --framework SOC2

# Configuration management
python tools/openclaw-cli.py config validate configs/agent-config/openclaw-agent.yml
python tools/openclaw-cli.py config migrate configs/agent-config/openclaw-agent.yml --from-version 1.0 --to-version 2.0

# Incident simulation
python tools/openclaw-cli.py simulate incident --type credential-theft --severity P1
```

### Python Tools

```bash
# Policy validation
python tools/policy-validator.py

# Incident simulation
python tools/incident-simulator.py

# Compliance reporting
python tools/compliance-reporter.py

# Certificate management
python tools/certificate-manager.py

# Configuration migration
python tools/config-migrator.py
```

---

## Hands-On Labs

### Lab 1: Execute Vulnerability Scan

1. Run OS package scan:
   ```bash
   ./scripts/vulnerability-scanning/os-scan.sh --image debian:12
   ```

2. Review results in Grafana dashboard-system-health.json Panel 10

3. Create Jira tickets for CRITICAL vulnerabilities:
   ```bash
   python scripts/vulnerability-scanning/create-tickets.py --input scan-results.json --severity CRITICAL
   ```

### Lab 2: Simulate Incident Response

1. Simulate credential exfiltration incident:
   ```bash
   python tools/openclaw-cli.py simulate incident --type credential-theft --severity P0
   ```

2. Execute credential exfiltration playbook:
   ```bash
   python tools/openclaw-cli.py playbook execute playbook-credential-theft --severity P0 --dry-run
   ```

3. Review incident timeline:
   ```bash
   python scripts/incident-response/timeline-generator.py --incident INC-2026-001 --output timeline.md
   ```

### Lab 3: Generate Compliance Report

1. Run SOC 2 compliance check:
   ```bash
python tools/openclaw-cli.py scan compliance --policy SEC-002
python tools/openclaw-cli.py scan compliance --policy SEC-003
python tools/openclaw-cli.py scan compliance --policy SEC-004
python tools/openclaw-cli.py scan compliance --policy SEC-005
   ```

2. Generate report:
   ```bash
   python tools/openclaw-cli.py report compliance --framework SOC2 --output soc2-report.json
   ```

3. Review control status (should be 100% compliant)

---

## Additional Resources

- **Documentation**: [docs/guides/](../docs/guides/)
- **Runbooks**: [examples/incident-response/](../examples/incident-response/)
- **Troubleshooting**: [docs/troubleshooting/](../docs/troubleshooting/)
- **Community Tools**: [docs/guides/07-community-tools-integration.md](../docs/guides/07-community-tools-integration.md)

---

## Assessment

After completing training, security team members should be able to:

1. ✅ Explain the 7-layer defense-in-depth architecture
2. ✅ Execute incident response playbooks using openclaw-cli
3. ✅ Monitor security events in Grafana dashboards
4. ✅ Generate SOC 2/ISO 27001/GDPR compliance reports
5. ✅ Validate configurations with policy-validator.py
6. ✅ Simulate and respond to security incidents

---

**Training completed? Contact security-team@openclaw.ai for assessment.**
