# ClawdBot Security Playbook

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security Audit](https://github.com/your-org/clawdbot-security-playbook/workflows/security-audit/badge.svg)](https://github.com/your-org/clawdbot-security-playbook/actions)
[![Tests](https://github.com/your-org/clawdbot-security-playbook/workflows/tests/badge.svg)](https://github.com/your-org/clawdbot-security-playbook/actions)

Production-ready security tools, configurations, and guides for hardening AI agent deployments. 
These resources address the attack vectors affecting 1,200+ exposed instances: backup file 
persistence, localhost authentication bypass, and 91.3% prompt injection success rates.

## 🎯 Quick Start (5 minutes)

**Stop active exploitation right now:**

```bash
# 1. Download and run security verification
curl -fsSL https://raw.githubusercontent.com/your-org/clawdbot-security-playbook/main/scripts/verification/verify_openclaw_security.sh | bash

# 2. If issues found, fix network binding immediately
# Edit ~/.moltbot/config.yml:
gateway:
  bind:
    address: "127.0.0.1"  # Change from 0.0.0.0

# 3. Restart Gateway
systemctl restart moltbot
```

**Expected safe results:**
- ✓ Gateway bound to 127.0.0.1:18789 (localhost only)
- ✓ No backup files found
- ✓ Tool execution logging enabled
- ✓ 0 critical issues, 0 warnings

If issues detected, see [Immediate Actions](#-immediate-actions-checklist) below.

---

## 📖 About This Repository

These tools accompany a two-part technical blog series on AI agent security:

- **[Part 1: Attack Vectors and Verification](https://your-blog.com/part1)** - Analysis of three critical vulnerabilities with immediate mitigations
- **[Part 2: Production Security Playbook](https://your-blog.com/part2)** - Defense-in-depth architecture with OS-level isolation and monitoring

**Target audience**: Security practitioners, DevOps engineers, AI developers deploying agentic AI systems

**Scope**: OpenClaw/Moltbot/ClawdBot deployments (applies to similar AI agent frameworks)

---

## 🤝 Complementary Community Tools

Production-ready security tools from the open-source community that address specific layers of the defense-in-depth model. **We recommend evaluating these before building custom solutions.**

### Shadow AI Discovery & MDM Deployment

**[openclaw-detect](https://github.com/knostic/openclaw-detect/)** (Knostic)
- Cross-platform detection scripts (macOS, Linux, Windows)
- Finds CLI binaries, app bundles, config files, Gateway services
- MDM deployment docs for Intune, Jamf, JumpCloud, Kandji, Workspace ONE
- **Use when**: You need to discover shadow AI deployments across enterprise endpoints

### Enterprise Telemetry & Behavioral Monitoring

**[openclaw-telemetry](https://github.com/knostic/openclaw-telemetry/)** (Knostic)
- Native OpenClaw plugin for comprehensive logging
- Tamper-proof hash chains ensure audit log integrity
- SIEM integration via CEF/syslog forwarding
- Automatic sensitive data redaction
- **Use when**: You need enterprise-grade behavioral monitoring with SIEM integration

### Runtime Security Enforcement

**[openclaw-shield](https://github.com/knostic/openclaw-shield)** (Knostic)
- 5-layer defense-in-depth security plugin for OpenClaw
- Prompt Guard: Injects security policy into agent context
- Output Scanner: Redacts secrets and PII from tool output
- Tool Blocker: Blocks dangerous tool calls before execution
- Input Audit: Logs inbound messages and flags secrets
- **Use when**: You need native OpenClaw runtime security enforcement

**[clawguard](https://github.com/capsulesecurity/clawguard)** (Capsule Security)
- NPM package for JavaScript/TypeScript agents
- 150+ heuristic patterns for prompt injection detection
- 35+ international language patterns (KO/JA/ZH/ES/DE/FR/RU)
- Encoding evasion detection (base64, unicode, homoglyphs)
- Pre-tool invocation hooks for runtime validation
- **Use when**: You're building agents with JavaScript/TypeScript

### Integration Guidance

Each tool focuses on specific security layers and can be used independently or combined:

| Tool | Defense Layer | Deployment Complexity | Best For |
|------|---------------|----------------------|----------|
| openclaw-detect | Organizational Controls | Low (MDM scripts) | Shadow AI discovery |
| openclaw-telemetry | Behavioral Monitoring | Medium (plugin install) | Enterprise logging |
| openclaw-shield | Runtime Enforcement | Medium (plugin install) | OpenClaw deployments |
| clawguard | Runtime Enforcement | Low (npm install) | JS/TS agents |

→ **[Complete integration guide](docs/guides/07-community-tools-integration.md)** with deployment recommendations, compatibility notes, and combined configurations.

→ **[Example configuration](configs/examples/with-community-tools.yml)** showing openclaw-shield + openclaw-telemetry deployment.

---

## 🗂️ Repository Structure

```
clawdbot-security-playbook/
├── scripts/              # Production-ready security automation
│   ├── verification/     # Security audit and checking tools
│   ├── credential-migration/  # OS keychain integration
│   ├── supply-chain/     # Skill integrity monitoring
│   ├── monitoring/       # Behavioral anomaly detection (custom)
│   └── hardening/        # Container and VPN setup
│
├── configs/              # Hardened configuration templates
│   ├── templates/        # Production-ready configs
│   ├── examples/         # Dev/prod/airgapped scenarios
│   └── skill-policies/   # Skill vetting and allowlists
│
├── docs/                 # Detailed implementation guides
│   ├── guides/           # Step-by-step walkthroughs
│   ├── architecture/     # Threat models and design docs
│   └── troubleshooting/  # Common issues and fixes
│
└── examples/             # Real-world deployment scenarios
```

---

## 🚨 Immediate Actions Checklist

If you're running Clawdbot/OpenClaw/Moltbot **right now**, take these actions:

### Priority 1: Stop Network Exposure (5 minutes)

- [ ] Run [verification script](scripts/verification/verify_openclaw_security.sh)
- [ ] If binding to `0.0.0.0`, stop Gateway: `systemctl stop moltbot`
- [ ] Edit config: Change bind address to `127.0.0.1`
- [ ] Restart: `systemctl start moltbot`
- [ ] Verify: `ss -lntp | grep 18789` should show `127.0.0.1` only

**Why**: Over 1,200 instances exposed on internet with no authentication

### Priority 2: Rotate Compromised Credentials (15 minutes)

If backup files found OR instance was exposed:

- [ ] Anthropic: Regenerate at https://console.anthropic.com/settings/keys
- [ ] OpenAI: Regenerate at https://platform.openai.com/api-keys
- [ ] AWS: Rotate at https://console.aws.amazon.com/iam/
- [ ] Slack: Regenerate OAuth tokens
- [ ] SSH: Generate new keypair, update authorized_keys

Then securely delete backups:
```bash
shred -vfz -n 3 ~/.clawdbot/*.bak* ~/.moltbot/*.bak*
```

**Why**: Deleted credentials persist in .bak files up to 35 days

### Priority 3: Enable Monitoring (10 minutes)

**Option A: Community Tool (Recommended)**
- [ ] Install [openclaw-telemetry](https://github.com/knostic/openclaw-telemetry) plugin
- [ ] Configure SIEM forwarding (optional)
- [ ] Enable tamper-proof hash chains

**Option B: Basic Logging**
- [ ] Add tool execution logging to config.yml ([template](configs/templates/gateway.hardened.yml))
- [ ] Configure high-risk tool confirmation
- [ ] Set up daily log review: `grep "tool_executed" ~/.moltbot/logs/*.log`

**Why**: 91.3% prompt injection success rate requires runtime monitoring

---

## 🛠️ Core Tools

### Security Verification

**[verify_openclaw_security.sh](scripts/verification/verify_openclaw_security.sh)**
- Checks all three attack vectors simultaneously
- Exits with status 1 on critical issues (CI/CD ready)
- Provides specific remediation commands

```bash
./scripts/verification/verify_openclaw_security.sh
# Exit codes: 0=pass, 1=critical, 2=warnings
```

### Credential Migration

**macOS**: [migrate_credentials_macos.sh](scripts/credential-migration/macos/migrate_credentials_macos.sh)
**Linux**: [migrate_credentials_linux.sh](scripts/credential-migration/linux/migrate_credentials_linux.sh)

Migrates plaintext JSON credentials to OS-encrypted storage:
- macOS Keychain with optional Touch ID requirement
- Linux Secret Service (GNOME Keyring/KWallet)
- Creates audit trail for all credential access
- Securely deletes backup files

```bash
# macOS
./scripts/credential-migration/macos/migrate_credentials_macos.sh

# Linux  
./scripts/credential-migration/linux/migrate_credentials_linux.sh
```

### Supply Chain Integrity

**[skill_manifest.py](scripts/supply-chain/skill_manifest.py)**

Generates cryptographic manifest of installed skills:
- SHA256 hashes detect tampering
- Scans for dangerous patterns (eval, exec, innerHTML)
- Daily comparison alerts on unauthorized changes
- Integrates with CI/CD pipelines

```bash
# Generate baseline
python3 skill_manifest.py --output manifest_baseline.json

# Daily comparison
python3 skill_manifest.py --compare manifest_baseline.json
```

### Behavioral Monitoring (Custom Implementation)

**[anomaly_detector.py](scripts/monitoring/anomaly_detector.py)**

Custom behavioral analysis for organizations with specific detection requirements:
- Off-hours tool execution detection
- Unusual command sequences (file_read → base64 → http_post)
- Burst activity patterns
- Suspicious recipients in messaging tools

**Note**: For production deployments, consider [openclaw-telemetry](https://github.com/knostic/openclaw-telemetry) which provides enterprise features including SIEM integration and tamper-proof logging.

```bash
# Continuous monitoring
python3 anomaly_detector.py --logdir ~/.moltbot/logs --follow
```

---

## 📋 Configuration Templates

### Production Gateway Config

[gateway.hardened.yml](configs/templates/gateway.hardened.yml) - Maximum security

Key settings:
- Localhost-only binding
- Authentication required (even for loopback)
- Rate limiting and IP whitelisting
- VPN-only access (no reverse proxy)

```yaml
gateway:
  bind:
    address: "127.0.0.1"
  auth:
    mode: "required"
    loopback:
      autoApprove: false
```

### Alternative Configs

- **[development.yml](configs/examples/development.yml)** - Less restrictive for dev work
- **[production.yml](configs/examples/production.yml)** - Enterprise production settings
- **[airgapped.yml](configs/examples/airgapped.yml)** - Isolated environment deployment
- **[with-community-tools.yml](configs/examples/with-community-tools.yml)** - openclaw-shield + openclaw-telemetry integration

### Nginx Hardening (If Required)

[nginx.secure.conf](configs/templates/nginx.secure.conf) - Reverse proxy last resort

**Recommendation**: Use VPN (Tailscale/WireGuard) instead. See [VPN setup guide](docs/guides/03-network-segmentation.md).

---

## 📚 Documentation Guides

### Step-by-Step Walkthroughs

1. **[Quick Start](docs/guides/01-quick-start.md)** - 5-minute security wins
2. **[Credential Isolation](docs/guides/02-credential-isolation.md)** - OS keychain migration
3. **[Network Segmentation](docs/guides/03-network-segmentation.md)** - VPN setup (Tailscale/WireGuard)
4. **[Runtime Sandboxing](docs/guides/04-runtime-sandboxing.md)** - Container isolation
5. **[Supply Chain Security](docs/guides/05-supply-chain-security.md)** - Skill vetting and monitoring
6. **[Incident Response](docs/guides/06-incident-response.md)** - What to do when compromised
7. **[Community Tools Integration](docs/guides/07-community-tools-integration.md)** - Deploying openclaw-detect, openclaw-telemetry, openclaw-shield

### Architecture References

- **[Threat Model](docs/architecture/threat-model.md)** - Detailed attack analysis
- **[Defense-in-Depth](docs/architecture/defense-in-depth.md)** - Layered security strategy
- **[Attack Vectors](docs/architecture/attack-vectors.md)** - Known vulnerabilities reference

### Troubleshooting

- **[Common Issues](docs/troubleshooting/common-issues.md)** - FAQ and error resolution
- **[Migration Failures](docs/troubleshooting/migration-failures.md)** - Rollback procedures
- **[Verification Failures](docs/troubleshooting/verification-failures.md)** - Audit script errors

---

## 🧪 Testing

All scripts include tests for verification:

```bash
# Run integration tests
./tests/integration/test_credential_migration.sh
./tests/integration/test_network_isolation.sh
./tests/integration/test_skill_integrity.sh

# Run unit tests
python3 -m pytest tests/unit/
```

---

## 🔄 Versioning Strategy

This repository uses semantic versioning:

- **v1.x**: Current stable release (tested in production)
- **main**: Latest stable code
- Feature branches: Development work

**Blog posts link to**: `main` branch for always-current code

**Production deployments should**: Pin to tagged releases (e.g., `v1.2.0`)

---

## 🤝 Contributing

Contributions welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Code style guidelines
- Testing requirements
- Pull request process
- Security vulnerability disclosure

### Security Issues

**Do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) 
for responsible disclosure process.

---

## 📜 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file.

---

## 🔗 Related Resources

### Community Security Tools

- **[openclaw-detect](https://github.com/knostic/openclaw-detect/)** - Shadow AI discovery (Knostic)
- **[openclaw-telemetry](https://github.com/knostic/openclaw-telemetry/)** - Enterprise telemetry (Knostic)
- **[openclaw-shield](https://github.com/knostic/openclaw-shield)** - Runtime security plugin (Knostic)
- **[clawguard](https://github.com/capsulesecurity/clawguard)** - JS/TS security guards (Capsule Security)

### Official Documentation

- [Anthropic Claude Docs](https://docs.anthropic.com/)
- [OpenAI Platform Docs](https://platform.openai.com/docs)

### Security Research

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Anthropic AI Safety Research](https://www.anthropic.com/safety)

### Community

- [AI Security Community Discord](https://discord.gg/example)
- [Reddit r/openclaw](https://reddit.com/r/openclaw)

---

## ⚠️ Disclaimer

These tools are provided "as-is" for educational and hardening purposes. While tested 
in production environments, you should review and test all scripts before deploying 
to your infrastructure. The authors are not responsible for misconfigurations or data loss.

**Recommendation**: Test in non-production environment first, maintain backups, 
and have rollback procedures ready.

---

**Blog Series**:
- [Part 1: Attack Vectors and Verification](https://your-blog.com/part1)
- [Part 2: Production Security Playbook](https://your-blog.com/part2)

---

<div align="center">

**⭐ Star this repository** if you find it helpful!

**🛡️ Share with your security team** to improve AI agent security across your organization.

**🤝 Acknowledge community tools** - Consider starring openclaw-detect, openclaw-telemetry, openclaw-shield, and clawguard.

</div>
