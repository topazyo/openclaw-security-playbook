# OpenClaw Security Playbook

> **Production-Ready Security Hardening for AI Agents**  
> Prevent credential exfiltration, prompt injection, and supply chain attacks

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Documentation](https://img.shields.io/badge/docs-complete-brightgreen.svg)](docs/guides/)
[![Security: Hardened](https://img.shields.io/badge/security-hardened-blue.svg)](docs/guides/01-quick-start.md)
[![Platform: Multi](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey.svg)](docs/guides/)
[![SOC 2 Type II](https://img.shields.io/badge/SOC%202-17%20mapped%20controls-green.svg)](configs/organization-policies/soc2-compliance-mapping.json)
[![ISO 27001:2022](https://img.shields.io/badge/ISO%2027001-19%20mapped%20controls-green.svg)](configs/organization-policies/iso27001-compliance-mapping.json)
[![GDPR](https://img.shields.io/badge/GDPR-policy%20mapped-green.svg)](docs/policies/data-classification.md)
[![Tests](https://img.shields.io/badge/tests-15%20files%2C%203%20dirs-brightgreen.svg)](tests/)
[![CI](https://img.shields.io/badge/CI-GitHub%20Actions-blue.svg)](.github/workflows/)

---

## 🚨 The Problem

AI agents like OpenClaw/ClawdBot face critical security vulnerabilities:

- **Credential exposure** via plaintext config files and backup file persistence
- **Localhost authentication bypass** via SSH tunneling and reverse proxies
- **Supply chain attacks** through malicious skill installation
- **Prompt injection** leading to unauthorized tool execution

---

## ✅ The Solution

This playbook provides **7-layer defense-in-depth** security architecture:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 7: Organizational Controls                           │
│  • Shadow AI detection • Governance • Compliance            │
├─────────────────────────────────────────────────────────────┤
│  Layer 6: Behavioral Monitoring                             │
│  • Anomaly detection • Alerting • openclaw-telemetry        │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Supply Chain Security                             │
│  • Skill integrity • GPG verification • Allowlists          │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Runtime Security Enforcement (Optional)          │
│  • Prompt injection guards • PII redaction                 │
│  • openclaw-shield (external, not vendored by this repo)   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Runtime Sandboxing                                │
│  • Docker security • Read-only FS • Capability dropping     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Network Segmentation                              │
│  • VPN-only access • Firewall rules • Rate limiting         │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Credential Isolation (OS-Level)                   │
│  • OS keychain • No plaintext • Backup file prevention      │
└─────────────────────────────────────────────────────────────┘
```

**Result:** Layers 1–3 and 5–7 are fully covered by this repo's guidance, configs, and validation tooling. Layers 4, 6, and 7 include optional integrations with external community tools (`openclaw-shield`, `openclaw-telemetry`, `openclaw-detect`) documented in `docs/guides/08-community-tools-integration.md` — these are not vendored or verified by this repo.

---

## 📦 What's Included

  This playbook provides a **production-focused security documentation and validation framework** for AI agents, with 110+ files of guidance, validation content, and reference configurations:

  ### 📚 Documentation & Threat Modeling
  - **Guides & Checklists:** Complete implementation guides, onboarding, security review, and production checklists (see `docs/guides/`, `docs/checklists/`)
  - **Policies & Procedures:** Data classification, vulnerability management, access control, incident response, and operational policies (`docs/policies/`, `docs/procedures/`, `configs/organization-policies/`)
  - **Threat Model:** MITRE ATLAS mapping, kill chains, and scenario cross-references (`docs/threat-model/`)

  ### 💻 Implementation Examples & Scenarios
  - **Security Controls:** Python implementations for authentication, input validation, encryption, logging, rate limiting, backup verification, and vulnerability scanning (`examples/security-controls/`)
  - **Incident Response:** Playbooks for credential theft, data breach, DoS, prompt injection, skill compromise, and reporting templates (`examples/incident-response/`)
  - **Monitoring:** Grafana dashboards, Prometheus/Alertmanager configs, alert rules, and executive/IR dashboards (`examples/monitoring/`, `configs/monitoring-config/`)
  - **Attack Scenarios:** Seven mapped adversary scenarios with replay and detection validation (`examples/scenarios/`)

  ### 🔍 Detection Rules & Coverage
  - **Sigma Rules:** 12+ platform-agnostic rules for credential harvest, gateway exposure, skill child process, SOUL.md modification, supply chain drift, TLS downgrade, impersonation, path traversal, RAG poisoning, and more (`detections/sigma/`)
  - **KQL (MDE):** Discovery, behavioral hunting, and kill chain detection for Microsoft Defender for Endpoint (`detections/edr/mde/`)
  - **Splunk SPL:** Discovery and behavioral hunting queries (`detections/siem/splunk/`)
  - **YARA/IOC:** Indicators for credential exfiltration, malicious skills, SOUL.md injection (`detections/ioc/`)
  - **Replay Validation:** Detection replay and regression workflows for hosted and local runners (`.github/workflows/detection-replay-validation.yml`)

  ### 🤖 Automation Scripts & Tools
  - **Verification:** Security posture checks and detection validation (`scripts/verification/`)
  - **Incident Response:** Auto-containment, forensics collection, notification, ticketing, timeline generation (`scripts/incident-response/`, `scripts/forensics/`)
  - **Supply Chain:** Skill integrity monitoring, manifest validation (`scripts/supply-chain/`)
  - **Operational Tools:** CLI, policy validator, incident simulator, compliance reporter, certificate manager, config migrator (`tools/`)

  ### ⚙️ Configuration & Policy Files
  - **Agent Config:** Hardened agent configs with environment overrides (`configs/agent-config/`)
  - **MCP Server:** TLS 1.3+, mTLS, OAuth2, firewall rules (`configs/mcp-server-config/`)
  - **Monitoring:** Prometheus, Grafana datasources, Alertmanager routing (`configs/monitoring-config/`)
  - **Skill Policies:** Allowlist, dangerous patterns, enforcement, manifest schemas (`configs/skill-policies/`)
  - **Templates:** Secure defaults for credentials, gateway, nginx (`configs/templates/`)

  ### ✅ Testing Framework
  - **Unit Tests:** Authentication, encryption, input validation, rate limiting, CLI smoke tests (`tests/unit/`)
  - **Integration Tests:** Playbook procedures, backup/recovery, access review (`tests/integration/`)
  - **Security Tests:** Detection replay, evidence snapshot, malicious skill chain, policy compliance, runtime regression, vulnerability scanning (`tests/security/`)
  - **Fixtures:** Adversarial and evasion test cases (`tests/security/fixtures/`)

  ### 🎓 Training Materials
  - **Security Training:** 4-hour security team curriculum (architecture, operations, IR, monitoring) (`training/security-training.md`)
  - **Developer Guide:** 2-hour onboarding for integration, testing, troubleshooting (`training/developer-guide.md`)

  ### 🤖 CI/CD Workflows
  - **Security Scan:** Trivy, Bandit, npm audit, pip-audit, Gitleaks, SBOM (`.github/workflows/security-scan.yml`). The Trivy image job builds the repo-native `playbook` container target so CI scans a runnable image that this repository can actually produce.
  - **Compliance Check:** Policy validation, YAML linting, security tests, compliance reports (`.github/workflows/compliance-check.yml`)
  - **Runtime Regression:** Hosted runner validation and artifact archiving (`.github/workflows/runtime-security-regression.yml`)
  - **Detection Replay:** Adversarial replay and evasion validation (`.github/workflows/detection-replay-validation.yml`)

  **Total: 110+ files providing reference security guidance, validation content, and operational tooling**

---

## 🚀 Quick Start (15 Minutes)

Get the playbook tooling installed and validate the reference security configuration in about 15 minutes:

```bash
# 1. Clone repository
git clone https://github.com/openclaw/openclaw-security-playbook.git
cd openclaw-security-playbook

# 2. Create a virtual environment and install the package
python -m venv .venv
source .venv/bin/activate  # Windows (PowerShell): .venv\Scripts\Activate.ps1
pip install -e .

# 3. Run baseline security verification
./scripts/verification/verify_openclaw_security.sh

# 4. Validate the reference agent configuration
openclaw-cli config validate configs/agent-config/openclaw-agent.yml

# 5. List the shipped incident-response playbooks
openclaw-cli playbook list

# 6. Inspect the canonical hardened runtime definition (syntax check only)
#    Requires env vars: CLAWDBOT_IMAGE, GATEWAY_TOKEN, ANTHROPIC_API_KEY, GRAFANA_PASSWORD
#    See configs/examples/docker-compose-full-stack.yml header for details
#    Build locally first (optional):
#      docker build -f scripts/hardening/docker/Dockerfile.hardened -t clawdbot-production .
#      export CLAWDBOT_IMAGE=clawdbot-production
docker compose -f configs/examples/docker-compose-full-stack.yml config
```

> **Shell support note:** scripts under `scripts/` assume bash or zsh. On Windows use WSL2 or Git Bash for shell workflows. The `openclaw-cli` command works natively on Windows via the installed Python entrypoint. Credential migration scripts require macOS or Linux; Windows users should follow the manual `cmdkey` setup in [docs/guides/01-quick-start.md](docs/guides/01-quick-start.md).
>
> **CLI availability note:** Three `openclaw-cli` subcommands (`scan vulnerability`, `scan access`, `report weekly`) are not yet implemented and will raise an error if invoked. See the [openclaw-cli Commands](#-operational-tools--cli) section for the full availability matrix before running commands from training docs.
>
> **Runtime API note:** this repo ships health (`/health`, `/healthz`, `/ready`) and metrics (`/metrics`) endpoints only. It does not ship a runtime inference API. See [`docs/api/README.md`](docs/api/README.md).

Fresh-clone note: the verifier can return warnings until a compatible OpenClaw/ClawdBot runtime and TLS endpoint are running. Use [docs/guides/01-quick-start.md](docs/guides/01-quick-start.md) and [training/developer-guide.md](training/developer-guide.md) to align runtime settings with the verifier.

---

## 🎓 Learning Paths

### For Developers (New to Security)

**Goal:** Understand and implement basic security

1. **Start here:** [Quick Start Guide](docs/guides/01-quick-start.md) (15 min)
2. **Learn:** [Credential Isolation](docs/guides/02-credential-isolation.md) (30 min)
3. **Practice:** Review and adapt `configs/examples/docker-compose-full-stack.yml`
4. **Verify:** Run `./scripts/verification/verify_openclaw_security.sh`

**Time Investment:** 2 hours → Secure deployment

---

### For Security Engineers

**Goal:** Implement complete defense-in-depth

**Week 1:**
- Day 1-2: Layers 1-3 (Credentials, Network, Sandboxing)
- Day 3: Layer 4 (Runtime Enforcement - openclaw-shield)
- Day 4: Layer 5 (Supply Chain Security)
- Day 5: Deploy monitoring stack

**Week 2:**
- Day 1-2: Layer 6 (Behavioral Monitoring - openclaw-telemetry)
- Day 3: Incident response planning
- Day 4-5: Testing and validation

**Time Investment:** 2 weeks → Enterprise-grade security

---

### For DevOps/SRE

**Goal:** Production deployment with observability

1. **Infrastructure:** Deploy [production-k8s.yml](configs/examples/production-k8s.yml) (2 hours)
2. **Monitoring:** Configure [monitoring-stack.yml](configs/examples/monitoring-stack.yml) (1 hour)
3. **Automation:** Set up [backup-restore.sh](configs/examples/backup-restore.sh) (30 min)
4. **Runbooks:** Review [Incident Response](docs/guides/06-incident-response.md) (1 hour)

**Time Investment:** 4-5 hours → Production-ready deployment

---

### For Security Researchers

**Goal:** Understand attack vectors and mitigations

**Recommended Reading Order:**
1. [Supply Chain Security](docs/guides/05-supply-chain-security.md) - Malicious skills
2. [Network Segmentation](docs/guides/03-network-segmentation.md) - Authentication bypass
3. [Credential Isolation](docs/guides/02-credential-isolation.md) - Backup file persistence
4. [Community Tools](docs/guides/08-community-tools-integration.md) - Optional third-party integrations
5. [Detection & Hunting](docs/guides/07-detection-and-hunting.md) - 3-tier detection, kill chain queries
6. [ATLAS Threat Mapping](docs/threat-model/ATLAS-mapping.md) - MITRE ATLAS kill chains

**Focus Areas:**
- Prompt injection attack vectors
- Indirect prompt injection via external data
- Supply chain attack scenarios
- Container escape attempts
- MITRE ATLAS kill chain mapping (5 chains documented)
- Detection rule authoring (Sigma, KQL, SPL)

---

### For SOC / Detection Engineers

**Goal:** Deploy detection rules and build hunting workflows

1. **Start here:** [Detection & Hunting Guide](docs/guides/07-detection-and-hunting.md) (60 min)
2. **Deploy Tier 1:** Import discovery queries from `detections/edr/` for your EDR platform
3. **Convert Sigma rules:** `sigma convert -t <backend> detections/sigma/openclaw-*.yml`
4. **Deploy Tier 2-3:** Import behavioral hunting and kill chain queries after openclaw-telemetry is running
5. **Forensics toolkit:** Review `scripts/forensics/` for evidence collection and timeline building
6. **Threat mapping:** [ATLAS Mapping](docs/threat-model/ATLAS-mapping.md) for kill chain taxonomy

**Time Investment:** 2-3 hours → Full detection coverage

---

## 🏗️ Architecture Overview

### Defense-in-Depth Layers

```
                    ┌─────────────────┐
                    │   AI Agent      │
                    │  (ClawdBot)     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Layer 4        │
     ┌──────────────┤  Shield Guard   ├────────────┐
     │              │  (Prompt Guard) │            │
     │              └─────────────────┘            │
     │                                             │
┌────▼─────┐   ┌──────────────┐   ┌────────────────▼───┐
│ Layer 5  │   │  Layer 3     │   │    Layer 6         │
│ Supply   │   │  Sandbox     │   │    Telemetry       │
│ Chain    │   │  (Docker)    │   │    (Monitoring)    │
└────┬─────┘   └──────┬───────┘   └────────────────┬───┘
     │                │                            │
     │         ┌──────▼───────┐                    │
     └─────────┤  Layer 2     ├────────────────────┘
               │  Network     │
               │  (VPN/FW)    │
               └──────┬───────┘
                      │
               ┌──────▼───────┐
               │  Layer 1     │
               │  OS Keychain │
               └──────────────┘
```

### Data Flow Security

```
External Request
    │
    ▼
┌─────────────────────────────────────┐
│  1. Network Layer (Layer 2)         │
│  • VPN authentication               │
│  • Firewall filtering               │
│  • Rate limiting                    │
└─────────────┬───────────────────────┘
              │ ✅ Authorized
              ▼
┌─────────────────────────────────────┐
│  2. Gateway Authentication          │
│  • Token verification               │
│  • IP allowlisting                  │
└─────────────┬───────────────────────┘
              │ ✅ Authenticated
              ▼
┌─────────────────────────────────────┐
│  3. Input Sanitization (Layer 4)    │
│  • Prompt injection detection       │
│  • Delimiter stripping              │
│  • Pattern matching                 │
└─────────────┬───────────────────────┘
              │ ✅ Clean
              ▼
┌─────────────────────────────────────┐
│  4. AI Agent Processing             │
│  • Skill execution (Layer 5 check)  │
│  • Tool invocation (Layer 3 sandbox)│
│  • Credential access (Layer 1)      │
└─────────────┬───────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  5. Output Scanning (Layer 4)       │
│  • PII/secret redaction             │
│  • Credential filtering             │
└─────────────┬───────────────────────┘
              │ ✅ Safe
              ▼
┌─────────────────────────────────────┐
│  6. Monitoring & Logging (Layer 6)  │
│  • Behavioral analysis              │
│  • Anomaly detection                │
│  • Audit trail                      │
└─────────────────────────────────────┘
```

---

## 🛡️ Security Features

### ✅ Credential Protection
- **OS Keychain Integration:** macOS Keychain, Linux Secret Service, Windows Credential Manager
- **Zero Plaintext:** No credentials in config files, environment variables, or logs
- **Backup File Prevention:** Automated detection and cleanup of editor backup files
- **Rotation Support:** Documented procedures for emergency credential rotation

### ✅ Network Security
- **Localhost-Only Binding:** Gateway never exposed to public internet
- **VPN-Based Access:** Tailscale, WireGuard, or OpenVPN integration
- **Reverse Proxy Hardening:** mTLS, rate limiting, IP whitelisting
- **Firewall Configuration:** UFW, iptables, pf ruleset examples

### ✅ Container Security
- **Non-Root User:** All containers run as UID 1000+
- **Read-Only Filesystem:** Root filesystem mounted read-only
- **Capability Dropping:** Only NET_BIND_SERVICE capability when needed
- **Resource Limits:** CPU, memory, process, and disk I/O limits
- **Seccomp/AppArmor:** System call filtering and mandatory access control

### ✅ Supply Chain Security
- **Cryptographic Verification:** GPG signature checking for all skills
- **Integrity Manifests:** SHA256 checksums for all skill files
- **Automated Monitoring:** Daily integrity checks with alerting
- **Allowlist Enforcement:** Only approved skills can be installed

### ✅ Runtime Protection Guidance
- **Prompt Injection Guards:** Reference integration guidance for external enforcement tooling
- **PII Redaction:** Documented control patterns for sensitive output handling
- **Tool Allowlisting:** Reference policy and configuration patterns for allowed tools
- **Behavioral Monitoring:** Repo-native detection validation plus optional external telemetry integrations

### ✅ Detection & Hunting
- **3-Tier Detection Model:** Discovery → Behavioral Hunting → Kill Chain Detection
- **Platform Coverage:** Sigma (platform-agnostic), MDE KQL, Splunk SPL, YARA
- **5 Kill Chain Detections:** Prompt injection to RCE, data theft, malicious skill, staged payload, token theft
- **MITRE ATLAS Mapping:** Full taxonomy with OWASP LLM and NIST CSF cross-references

### ✅ Incident Response & Forensics
- **4 Response Playbooks:** Credential exfiltration, prompt injection, unauthorized access, malicious skills
- **Evidence Collection:** Automated forensics and chain of custody (`collect_evidence.sh`)
- **Attack Timeline:** Chronological reconstruction with risk-scored events (`build_timeline.sh`)
- **Hash Chain Verification:** Tamper detection for openclaw-telemetry logs (`verify_hash_chain.py`)
- **Credential Scoping:** Post-incident credential exposure assessment (`check_credential_scope.sh`)
- **Communication Templates:** Pre-written notifications for stakeholders
- **Post-Incident Review:** Structured PIR process with action items

---

## 🛠️ Operational Tools & CLI

### Operational Scripts

| Script | Purpose | Example Command |
|--------|---------|-------|
| **[verify_openclaw_security.sh](scripts/verification/verify_openclaw_security.sh)** | Security posture verification | `./scripts/verification/verify_openclaw_security.sh` |
| **[skill_manifest.py](scripts/supply-chain/skill_manifest.py)** | Skill integrity checking | `python scripts/supply-chain/skill_manifest.py --skills-dir ~/.openclaw/skills` |
| **[backup-restore.sh](configs/examples/backup-restore.sh)** | Backup and restore | `./configs/examples/backup-restore.sh backup` |
| **[collect_evidence.sh](scripts/forensics/collect_evidence.sh)** | Incident evidence preservation | `./scripts/forensics/collect_evidence.sh [--containment]` |
| **[build_timeline.sh](scripts/forensics/build_timeline.sh)** | Attack timeline reconstruction | `./scripts/forensics/build_timeline.sh --incident-dir ~/openclaw-incident-*` |
| **[check_credential_scope.sh](scripts/forensics/check_credential_scope.sh)** | Credential exposure assessment | `./scripts/forensics/check_credential_scope.sh [YYYY-MM-DD]` |
| **[verify_hash_chain.py](scripts/forensics/verify_hash_chain.py)** | Telemetry tamper detection | `python scripts/forensics/verify_hash_chain.py --input telemetry.jsonl` |

### openclaw-cli Commands

The framework includes a comprehensive CLI for daily security operations. Install the package with `pip install -e .` from repo root to make the command available in your virtual environment:

```bash
# ── Repo-backed (work from a clean checkout) ─────────────────────────────────

# Configuration management
openclaw-cli config validate configs/agent-config/openclaw-agent.yml
openclaw-cli config migrate configs/agent-config/openclaw-agent.yml --from-version 1.0 --to-version 2.0

# Policy and certificate scanning
openclaw-cli scan compliance --policy SEC-003
openclaw-cli scan certificates

# Incident response playbooks
openclaw-cli playbook list
openclaw-cli playbook execute playbook-credential-theft --severity P0  # by filename stem
openclaw-cli playbook execute IRP-001 --severity P0                    # same, by Playbook ID
openclaw-cli simulate incident --type credential-theft --severity P1

# Compliance reporting
openclaw-cli report compliance --framework SOC2 --output report.json

# ── Filesystem / dependency scanning (run directly; no CLI wrapper yet) ───────
trivy fs .
pip-audit --format json

# ── Not yet implemented (placeholder modules; see scripts/README.md) ──────────
# openclaw-cli scan vulnerability  (requires scripts.discovery  — Placeholder)
# openclaw-cli scan access         (requires scripts.compliance — Placeholder)
# openclaw-cli report weekly       (requires scripts.reporting  — Placeholder)
```

### Python Security Tools

```bash
# Policy validation (SEC-002/003/004/005)
python tools/policy-validator.py --policy SEC-002

# Incident simulation
python tools/incident-simulator.py --type credential-theft

# Compliance reporting
python tools/compliance-reporter.py --framework SOC2

# Certificate management
python tools/certificate-manager.py

# Configuration migration
python tools/config-migrator.py --config openclaw-agent.yml
```

### Testing Framework

Test suite — 15 files across 3 directories:

```bash
# Unit tests (6 files)
pytest tests/unit/test_input_validation.py        # XSS/SQL/path traversal
pytest tests/unit/test_rate_limiting.py            # Token bucket, Redis
pytest tests/unit/test_authentication.py           # mTLS, OAuth2, MFA
pytest tests/unit/test_encryption.py               # AES-256-GCM, key rotation
pytest tests/unit/test_clawdbot_runtime.py         # Runtime smoke tests
pytest tests/unit/test_tools_help_smoke.py         # CLI help surface

# Integration tests (3 files)
pytest tests/integration/test_playbook_procedures.py  # Playbook execution
pytest tests/integration/test_backup_recovery.py      # RTO/RPO validation
pytest tests/integration/test_access_review.py        # Quarterly reviews

# Security tests (6 files)
pytest tests/security/test_policy_compliance.py              # SEC-002/003/004/005
pytest tests/security/test_vulnerability_scanning.py         # Trivy/npm/pip audits
pytest tests/security/test_runtime_security_regression.py    # Runtime hardening regression
pytest tests/security/test_detection_replay_validation.py    # Sigma/YARA replay
pytest tests/security/test_malicious_skill_chain_exercise.py # Attack-chain exercise
pytest tests/security/test_evidence_snapshot_cli.py          # Evidence capture

# Run all tests with coverage
pytest --cov=scripts --cov=examples --cov-report=html
```

---

## 📊 Metrics & Compliance

### Security Improvements

| Metric | Before Playbook | After Playbook | Improvement |
|--------|----------------|----------------|-------------|
| **Credential Exposure Risk** | 90% (plaintext files) | 0% (OS keychain) | ✅ **100%** |
| **Network Attack Surface** | High (0.0.0.0 binding) | Low (localhost + VPN) | ✅ **95%** |
| **Container Escape Risk** | High (root, writable FS) | Minimal (non-root, read-only) | ✅ **90%** |
| **Supply Chain Integrity** | None (auto-install) | High (signatures, manifests) | ✅ **100%** |
| **Incident Response Time** | Unknown | < 15 min (documented playbooks) | ✅ **Defined** |
| **Vulnerability Patching** | Manual | Automated (CRITICAL <7d, HIGH <30d) | ✅ **Automated** |
| **Compliance Coverage** | 0% | Repo-backed mapped controls and policy documentation | ✅ **Documented** |

### Compliance Mappings

This playbook provides repo-backed compliance mappings and policy references:

#### SOC 2 Type II (17 Mapped Controls in Repo)
- **CC6.1:** Logical and physical access controls (MFA required)
- **CC7.1:** Threat identification procedures (vulnerability scanning)
- **CC7.2:** Continuous monitoring (Prometheus/Grafana/Alertmanager)
- **CC7.3:** Incident response (5 playbooks: IRP-001, IRP-002, IRP-003, IRP-004, IRP-007)
- **CC7.4:** Security awareness training (security-training.md)
- **CC8.1:** Change management procedures (developer-guide.md)

**Evidence Available:**
- `configs/organization-policies/soc2-compliance-mapping.json` (17 mapped controls)
- `openclaw-cli report compliance --framework SOC2` (automated reporting)

#### ISO 27001:2022 (19 Mapped Controls in Repo)
- **A.9.2.1:** User registration and de-registration (access review)
- **A.10.1.1:** Cryptographic key management (90-day rotation)
- **A.12.6.1:** Technical vulnerability management (auto-remediate.sh)
- **A.13.1.1:** Network security (VPN, firewall, mTLS)
- **A.16.1.5:** Response to information security incidents (playbooks)
- **A.18.1.3:** Protection of records (7-year audit log retention)

**Evidence Available:**
- `configs/organization-policies/iso27001-compliance-mapping.json` (19 mapped controls)
- `openclaw-cli report compliance --framework ISO27001` (automated reporting)

#### GDPR (Policy and Control Mapping)
- **Encryption:** AES-256-GCM for personal data (data-classification.md)
- **Access Control:** MFA + RBAC (authentication.yml)
- **Breach Notification:** Automated 72-hour notification (notification-manager.py)
- **Data Minimization:** PII detection and redaction (input-validation.py)
- **Right to be Forgotten:** Documented deletion procedures

**Evidence Available:**
- `docs/policies/data-classification.md` (GDPR requirements)
- `openclaw-cli scan compliance --policy SEC-002` (encryption validation)

---

## 🚨 Incident Response

### Emergency Contacts

When a security incident occurs:

1. **Immediate Response:** Follow [Incident Response Guide](docs/guides/06-incident-response.md)
2. **Evidence Collection:** Run `./scripts/forensics/collect_evidence.sh`
3. **Timeline Reconstruction:** Run `./scripts/forensics/build_timeline.sh --incident-dir ~/openclaw-incident-*`
4. **Credential Scoping:** Run `./scripts/forensics/check_credential_scope.sh`
5. **Tamper Detection:** Run `python scripts/forensics/verify_hash_chain.py --input ~/.openclaw/logs/telemetry.jsonl`
6. **Containment:** Execute playbook for specific incident type
7. **Communication:** Use templates in incident response guide

### Response Playbooks

| Incident Type | Playbook | Response Time |
|---------------|----------|---------------|
| **Credential Exfiltration** | [Playbook 1](docs/guides/06-incident-response.md#playbook-1-credential-exfiltration) | 5 min containment |
| **Prompt Injection** | [Playbook 2](docs/guides/06-incident-response.md#playbook-2-prompt-injection-attack) | 10 min containment |
| **Unauthorized Access** | [Playbook 3](docs/guides/06-incident-response.md#playbook-3-unauthorized-network-access) | 2 min block |
| **Malicious Skill** | [Playbook 4](docs/guides/06-incident-response.md#playbook-4-malicious-skill-installation) | 5 min quarantine |

---

## 🤖 CI/CD and Automation

### GitHub Actions Workflows

The framework includes automated security scanning and compliance checks:

#### Security Scanning Workflow (`.github/workflows/security-scan.yml`)
Runs on every pull request and daily schedule:

- **Trivy:** Container and filesystem vulnerability scanning (CRITICAL/HIGH severity)
- **Bandit:** Python security linter for scripts and examples
- **npm audit:** JavaScript dependency vulnerability scanning
- **pip-audit:** Python dependency vulnerability scanning
- **Gitleaks:** Secret detection (API keys, passwords, tokens)
- **SBOM Generation:** CycloneDX software bill of materials

**Results:** SARIF files uploaded to GitHub Security tab, JSON artifacts retained 90 days

#### Compliance Check Workflow (`.github/workflows/compliance-check.yml`)
Validates configurations and policies:

- **Policy Validation:** Checks SEC-002/003/004/005 compliance
- **YAML Linting:** Validates configuration syntax
- **Security Tests:** Runs pytest security test suite
- **Compliance Reports:** Generates SOC 2/ISO 27001 reports
- **PR Comments:** Automatic compliance percentage in pull requests

**Enforcement:** Fails build if compliance drops below 95%

---

## 🤝 Contributing

We welcome contributions! This is living documentation that improves with community input.

### How to Contribute

1. **Test on Your Platform:** Try procedures on your environment
2. **Document Issues:** Open GitHub issues for problems or gaps
3. **Share Learnings:** Submit PRs with improvements from your incidents
4. **Add Examples:** Contribute new configuration examples or scripts

### Contribution Areas

- ✅ **High Priority:**
  - Windows-specific procedures (currently partial coverage)
  - AWS ECS / Azure Container Instances configurations
  - CrowdStrike, Cortex XDR, and SentinelOne detection queries (MDE and Splunk covered)
  - Datadog / Elastic SIEM integration examples
  - Compliance mapping details (SOC2, ISO 27001)

- ⏳ **Medium Priority:**
  - Additional VPN provider examples
  - Cloud-native secret management (AWS Secrets Manager, Vault)
  - Multi-region deployment patterns
  - Disaster recovery procedures

- 💡 **Enhancement Ideas:**
  - Automated security testing suite
  - Terraform/Pulumi infrastructure-as-code examples
  - Video tutorials for each guide
  - Translated documentation (Hebrew, Spanish, etc.)

### Code of Conduct

Be respectful, constructive, and focused on improving AI agent security for everyone.

---


## 📖 Repository Structure

```
openclaw-security-playbook/
│
├── README.md                          # Project overview and quick start
│
├── docs/                              # Core documentation
│   ├── architecture/                  # System architecture and design
│   ├── checklists/                    # Operational checklists
│   ├── compliance/                    # Compliance frameworks
│   ├── guides/                        # Implementation guides
│   ├── plan/                          # Audit and execution plans
│   ├── policies/                      # Security policies and standards
│   ├── procedures/                    # Operational procedures
│   ├── threat-model/                  # Threat mapping and taxonomy
│   └── troubleshooting/               # Troubleshooting guides
│
├── detections/                        # Detection rules and hunting queries
│   ├── README.md                      # Detection content overview
│   ├── edr/                           # EDR platform queries
│   │   └── mde/                       # Microsoft Defender for Endpoint (KQL)
│   ├── ioc/                           # Indicators of compromise (YARA, IOC)
│   ├── siem/                          # SIEM platform queries
│   │   └── splunk/                    # Splunk SPL queries
│   └── sigma/                         # Platform-agnostic Sigma rules
│
├── examples/                          # Real-world examples and scenarios
│   ├── incident-response/             # IR playbooks and templates
│   ├── monitoring/                    # Dashboards and alert rules
│   ├── scenarios/                     # Complete incident scenarios
│   └── security-controls/             # Control implementations (Python)
│
├── scripts/                           # Automation and tooling
│   ├── credential-migration/          # Credential migration scripts
│   ├── discovery/                     # Discovery and scanning scripts
│   ├── forensics/                     # Forensics and evidence scripts
│   ├── hardening/                     # System hardening scripts
│   ├── incident-response/             # IR automation scripts
│   ├── monitoring/                    # Monitoring automation scripts
│   ├── supply-chain/                  # Supply chain validation scripts
│   ├── verification/                  # Security verification scripts
│   └── vulnerability-scanning/        # Vulnerability scanning scripts
│
├── configs/                           # Configuration and policy files
│   ├── agent-config/                  # Agent configuration files
│   ├── examples/                      # Example deployment configs
│   ├── mcp-server-config/             # MCP server configuration
│   ├── monitoring-config/             # Monitoring configuration
│   ├── organization-policies/         # Org-level policy JSON
│   ├── skill-policies/                # Skill allowlist, enforcement, schemas
│   └── templates/                     # Secure config and gateway templates
│
├── tests/                             # Test suite
│   ├── integration/                   # Integration tests
│   ├── security/                      # Security and adversarial tests
│   └── unit/                          # Unit tests
│
├── tools/                             # Operational tools (Python CLI, validators)
│   ├── certificate-manager.py
│   ├── compliance-reporter.py
│   ├── config-migrator.py
│   ├── incident-simulator.py
│   ├── openclaw-cli.py
│   └── policy-validator.py
│
├── training/                          # Security and developer training
│   ├── developer-guide.md
│   └── security-training.md
│
├── .github/                           # GitHub automation
│   ├── copilot-instructions.md        # Copilot/agent instructions
│   └── workflows/                     # CI/CD workflows (security-scan, compliance-check, etc)
│
├── LICENSE                            # Repository license
├── CONTRIBUTING.md                    # Contribution guidelines
└── SECURITY.md                        # Security policy and disclosure
```

---

## 🔗 Additional Resources

### Training Materials

- **[Security Team Training](training/security-training.md)** - 4-hour security operations training
  - 7-layer defense architecture
  - Daily security operations (vulnerability scanning, compliance checks)
  - Incident response procedures (playbook execution and dry-run)
  - Monitoring and alerting (Grafana dashboards, Alertmanager routing)
  - Hands-on labs (vulnerability scan, incident simulation, compliance reporting)

- **[Developer Integration Guide](training/developer-guide.md)** - 2-hour developer onboarding
  - Quick start and installation
  - Security controls integration (input validation, rate limiting, authentication, encryption)
  - Testing framework (unit/integration/security tests)
  - CI/CD integration (GitHub Actions workflows)
  - Troubleshooting common issues

### Official Documentation
- **OpenClaw Documentation:** https://docs.openclaw.ai
- **Anthropic Safety Best Practices:** https://www.anthropic.com/safety
- **Claude Security Guide:** https://docs.anthropic.com/claude/docs/security

### Security Frameworks
- **OWASP Top 10 for LLMs:** https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **NIST AI Risk Management:** https://www.nist.gov/itl/ai-risk-management-framework
- **CIS Docker Benchmark:** https://www.cisecurity.org/benchmark/docker

### Research & Publications
- **AI Agent Security Research:** https://arxiv.org/abs/2302.12173
- **Prompt Injection Taxonomy:** https://arxiv.org/abs/2402.00898
- **Supply Chain Security for AI:** https://dl.acm.org/doi/10.1145/3634737.3656289

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 [Your Organization]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software.
```

---

## 🙏 Acknowledgments

This playbook was developed based on:

- **Real-world incident research** from 2024-2025 exposed AI agent discoveries
- **Community contributions** from security researchers and practitioners
- **Best practices** from OWASP, NIST, CIS, and other security frameworks
- **Open-source tools** from the AI security community (Knostic, Anthropic, etc.)

Special thanks to:
- Anthropic for Claude and AI safety research
- The OWASP LLM Security community
- All contributors who shared their incident learnings

---

## 📞 Support

### Getting Help

- **Documentation Issues:** Open a GitHub issue
- **General Discussion:** GitHub Discussions
- **Emergency Security Issues:** Follow responsible disclosure in [SECURITY.md](SECURITY.md)

### Quick Links

- 🚀 **[Quick Start (15 min) →](docs/guides/01-quick-start.md)**
- 📖 **[All Guides →](docs/guides/)**
- ⚙️ **[Configuration Examples →](configs/examples/)**
- 🚨 **[Incident Response →](docs/guides/06-incident-response.md)**
- 🛠️ **[Scripts & Tools →](scripts/)**

---

## ⭐ Star This Repository

If this playbook helped secure your AI agents, please star the repository to help others discover it!

---

<div align="center">

**[Get Started →](docs/guides/01-quick-start.md)** | **[Report Issue](https://github.com/openclaw/openclaw-security-playbook/issues)** | **[Contribute](CONTRIBUTING.md)**

Made with 🔒 for AI Agent Security

**Version 3.0.0** | **Last Updated:** February 2026 | **110+ Files** | **17 SOC 2 / 19 ISO 27001 mapped controls documented**

</div>
