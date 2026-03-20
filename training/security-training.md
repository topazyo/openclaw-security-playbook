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

### Environment Setup

Install the package in a virtual environment before running the CLI examples in this guide:

```bash
python -m venv .venv
source .venv/bin/activate  # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -e .
```

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
- **Configuration**: `configs/examples/docker-compose-full-stack.yml`
- **Verification**: `docker inspect clawdbot-production` for security settings

#### Layer 4: Runtime Enforcement
- **Purpose**: Block malicious AI agent actions in real-time
- **Implementation**: openclaw-shield (prompt injection guards, PII redaction, tool allowlisting)
- **Configuration**: `docs/guides/08-community-tools-integration.md`

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
   - Import `examples/monitoring/dashboard-system-health.json` into your locally deployed Grafana instance
     (see `configs/monitoring-config/grafana-dashboards.yml` for provisioning config).
   - Open the **System Health** dashboard in your browser (typically http://localhost:3000).
   - Review Panel 10 (vulnerability metrics) for new CVEs
   - Check CPU/memory/disk usage trends

2. **Scan for New Vulnerabilities**
   ```bash
   # CLI wrapper — mirrors the CI pipeline (Trivy, pip-audit, Bandit, Gitleaks, syft)
   openclaw-cli scan vulnerability --target production

   # Or run individual tools directly:
   trivy fs .
   pip-audit --format json
   # For full CI-backed scanning see .github/workflows/security-scan.yml
   ```

3. **Review Compliance Status**
   ```bash
   openclaw-cli scan compliance --policy SEC-003
   ```

4. **Generate Weekly Security Report**
   ```bash
   # Full weekly report aggregating compliance, certs, and optional scan results
   openclaw-cli report weekly --start $(date -d 'last monday' +%Y-%m-%d) --end $(date +%Y-%m-%d) \
       --output reports/weekly-$(date +%Y-%m-%d).json

   # Framework-only compliance snapshot
   openclaw-cli report compliance --framework SOC2 --output reports/soc2-$(date +%Y-%m-%d).json
   ```

### Weekly Tasks

1. **Quarterly Access Review** (every 90 days)

   See [docs/procedures/access-review.md](../docs/procedures/access-review.md) for the full runbook.
   ```bash
   # CSV-based review using a runbook-format export
   openclaw-cli scan access --input-csv exports/access-$(date +%Y-%m-%d).csv --days 90

   # Live Azure AD review (requires AZURE_AD_* environment variables)
   openclaw-cli scan access --provider azure-ad --output reports/access-review.json
   ```

2. **Certificate Expiry Check**
   ```bash
   openclaw-cli scan certificates
   ```
   
3. **Backup Verification**
   ```bash
   pytest tests/integration/test_backup_recovery.py
   ```

### Monthly Tasks

1. **SOC 2 Compliance Report**
   ```bash
   openclaw-cli report compliance --framework SOC2 --output reports/soc2-$(date +%Y-%m).json
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
./scripts/forensics/build_timeline.sh --incident-dir ~/openclaw-incident-TIMESTAMP

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
openclaw-cli playbook execute playbook-credential-theft --severity P0 --dry-run

# Simulate incident for testing
openclaw-cli simulate incident --type credential-theft --severity P1
```

---

## Monitoring & Alerting

### Grafana Dashboards

Access dashboards in your locally deployed Grafana (typically http://localhost:3000).
Import dashboard JSON files from `examples/monitoring/` using Grafana → Dashboards → Import.
Provisioning can be automated via `configs/monitoring-config/grafana-dashboards.yml`.

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
openclaw-cli report compliance --framework SOC2 --output audits/soc2-2026-Q1.json

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
openclaw-cli scan compliance --policy SEC-002  # Data classification
openclaw-cli scan compliance --policy SEC-003  # Vulnerability management
openclaw-cli scan compliance --policy SEC-004  # Access control
openclaw-cli scan compliance --policy SEC-005  # Incident response
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
# ── Repo-backed (work from a clean checkout) ─────────────────────────────────

# Compliance and certificate scanning
openclaw-cli scan compliance --policy SEC-003
openclaw-cli scan certificates

# Playbook execution
openclaw-cli playbook list
openclaw-cli playbook execute playbook-credential-theft --severity P0 --dry-run

# Compliance reporting
openclaw-cli report compliance --framework SOC2

# Configuration management
openclaw-cli config validate configs/agent-config/openclaw-agent.yml
openclaw-cli config migrate configs/agent-config/openclaw-agent.yml --from-version 1.0 --to-version 2.0

# Incident simulation
openclaw-cli simulate incident --type credential-theft --severity P1

# ── Vulnerability, access, and weekly reporting ──────────────────────────────
openclaw-cli scan vulnerability --target production --output vuln.json
openclaw-cli scan access --input-csv access-export.csv --output access.json
openclaw-cli report weekly --start 2026-03-14 --end 2026-03-21 \
    --vulnerability-scan vuln.json --access-scan access.json \
    --output report.json

# Or run individual scanners directly:
trivy fs .
pip-audit --format json
```

### Python Tools

```bash
# Policy validation
openclaw-cli scan compliance --policy SEC-002

# Incident simulation
openclaw-cli simulate incident --type credential-theft --severity P1

# Compliance reporting
openclaw-cli report compliance --framework SOC2 --output reports/soc2-training.json

# Certificate management
openclaw-cli scan certificates --output reports/certificates-training.json

# Configuration migration
openclaw-cli config migrate configs/agent-config/openclaw-agent.yml --from-version 1.0 --to-version 2.0
```

Standalone tool scripts under `tools/` remain available for debugging, but operational workflows should use `openclaw-cli.py` for consistent policy checks and exit codes.

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
   openclaw-cli simulate incident --type credential-theft --severity P0
   ```

2. Execute credential exfiltration playbook:
   ```bash
   openclaw-cli playbook execute playbook-credential-theft --severity P0 --dry-run
   ```

3. Review incident timeline:
   ```bash
   ./scripts/forensics/build_timeline.sh --incident-dir ~/openclaw-incident-TIMESTAMP
   ```

### Lab 3: Generate Compliance Report

1. Run SOC 2 compliance check:
   ```bash
openclaw-cli scan compliance --policy SEC-002
openclaw-cli scan compliance --policy SEC-003
openclaw-cli scan compliance --policy SEC-004
openclaw-cli scan compliance --policy SEC-005
   ```

2. Generate report:
   ```bash
   openclaw-cli report compliance --framework SOC2 --output soc2-report.json
   ```

3. Review control status (should be 100% compliant)

---

## Additional Resources

- **Documentation**: [docs/guides/](../docs/guides/)
- **Runbooks**: [examples/incident-response/](../examples/incident-response/)
- **Troubleshooting**: [docs/troubleshooting/](../docs/troubleshooting/)
- **Community Tools**: [docs/guides/08-community-tools-integration.md](../docs/guides/08-community-tools-integration.md)

---

## Assessment

After completing training, security team members should be able to:

1. ✅ Explain the 7-layer defense-in-depth architecture
2. ✅ Execute incident response playbooks using openclaw-cli
3. ✅ Monitor security events in Grafana dashboards
4. ✅ Generate SOC 2/ISO 27001/GDPR compliance reports
5. ✅ Validate configurations with openclaw-cli
6. ✅ Simulate and respond to security incidents

---

**Training completed? Contact security-team@openclaw.ai for assessment.**
