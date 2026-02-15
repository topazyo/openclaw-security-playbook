# Defense-in-Depth Security Architecture

**Estimated Time:** 45 minutes  
**Difficulty:** Intermediate  
**Prerequisites:** Basic understanding of security concepts and Docker

This document details the **7-layer defense-in-depth security architecture** for AI agent deployments. Each layer provides independent security controls that work together to prevent, detect, and respond to threats.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture Principles](#architecture-principles)
3. [Layer Descriptions](#layer-descriptions)
4. [Cross-Layer Integration](#cross-layer-integration)
5. [Implementation Roadmap](#implementation-roadmap)
6. [Verification](#verification)
7. [References](#references)

---

## Overview

### Defense-in-Depth Model

No single security control is perfect. Defense-in-depth provides multiple independent layers so that if one fails, others still protect the system.

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 7: Organizational Controls & Shadow AI Detection     │
│  Purpose: Enterprise-wide governance, MDM deployment        │
│  Tools: openclaw-detect, group policies                     │
├─────────────────────────────────────────────────────────────┤
│  Layer 6: Behavioral Monitoring & Anomaly Detection         │
│  Purpose: Detect unusual behavior, unauthorized actions     │
│  Tools: openclaw-telemetry, SIEM integration                │
├─────────────────────────────────────────────────────────────┤
│  Layer 5: Supply Chain Security & Integrity Checking        │
│  Purpose: Prevent malicious skill installation              │
│  Controls: GPG signatures, manifests, allowlists            │
├─────────────────────────────────────────────────────────────┤
│  Layer 4: Runtime Security Enforcement                      │
│  Purpose: Guard against prompt injection, PII leakage       │
│  Tools: openclaw-shield, input validation                   │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Runtime Sandboxing & Isolation                    │
│  Purpose: Contain compromised skills, prevent escapes       │
│  Controls: Docker, seccomp, read-only FS, capabilities      │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Network Segmentation & Access Control             │
│  Purpose: Limit who can access the agent                    │
│  Controls: VPN, firewall, rate limiting, mTLS               │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Credential Isolation (OS-Level)                   │
│  Purpose: Protect API keys from exfiltration                │
│  Controls: OS keychain, zero plaintext, backup cleanup      │
└─────────────────────────────────────────────────────────────┘
```

### Layer Independence

Each layer must:
- **Function independently**: Failure in one layer doesn't cascade
- **Provide value alone**: Partial deployment still improves security
- **Be verifiable**: Security posture can be measured per layer
- **Have clear ownership**: One team/person responsible

---

## Architecture Principles

### 1. Least Privilege

Every component runs with the minimum permissions needed.

**Examples:**
- Docker containers run as non-root user (UID 1000)
- Skills only get explicitly granted permissions
- Network access restricted to required endpoints
- Filesystem access limited to specific directories

### 2. Fail Secure

When something goes wrong, the system defaults to the safe state.

**Examples:**
- Missing GPG signature → skill installation blocked
- Invalid prompt detected → request rejected
- Keychain unavailable → agent refuses to start
- Rate limit exceeded → connection dropped

### 3. Zero Trust

Never trust, always verify. No implicit trust based on network location.

**Examples:**
- VPN access doesn't skip authentication
- Agent-to-MCP communication requires mTLS
- Every skill execution checked against allowlist
- All credential access logged

### 4. Defense-in-Depth

Multiple independent layers protect against the same threat.

**Example - Credential Theft Protection:**
- Layer 1: OS keychain (prevents reading plaintext)
- Layer 2: VPN (prevents remote access to gateway)
- Layer 3: Sandbox (skill can't access keychain)
- Layer 4: Output redaction (credentials filtered from responses)
- Layer 5: Skill integrity (malicious skills blocked)
- Layer 6: Anomaly detection (credential exfiltration detected)

---

## Layer Descriptions

### Layer 1: Credential Isolation

**Threat Mitigated**: Credential exfiltration (STRIDE: Information Disclosure)

**Problem**: API keys stored in plaintext config files are easily stolen:
- Direct file access by malicious skills
- Backup files (.yml~, .bak) persist in version control
- Environment variables leak via process listings
- Memory dumps expose credentials

**Solution**: Operating system keychain storage with zero plaintext.

**Controls:**
- **Primary**: macOS Keychain, Linux Secret Service, Windows Credential Manager
- **Backup Prevention**: Automated detection and cleanup of .bak/.swp/.tmp files
- **Access Logging**: OS-level audit trail for credential reads
- **Rotation Support**: Emergency credential rotation procedures

**Implementation**:
```yaml
# configs/templates/credentials.yml
api_keys:
  anthropic:
    keychain_service: "ai.openclaw.anthropic"
    keychain_account: "claude-api"
    storage: "keychain"  # NEVER "plaintext"
```

**Verification**:
```bash
# No plaintext credentials anywhere
find ~/.openclaw -type f -exec grep -l "sk-ant-" {} \; | wc -l  # Should be 0
```

**Guide**: [02-credential-isolation.md](../guides/02-credential-isolation.md)

---

### Layer 2: Network Segmentation

**Threat Mitigated**: Authentication bypass, unauthorized access (STRIDE: Spoofing, Elevation of Privilege)

**Problem**: Binding to 0.0.0.0 or using "localhost authentication" allows bypass:
- SSH tunneling: `ssh -L 8080:localhost:18789 user@host`
- Reverse proxies: ngrok, CloudFlare Tunnel, serveo.net
- Multi-user systems: any local user can access
- NAT reflection: router forwards localhost ports

**Solution**: VPN-only access with strict firewall rules.

**Controls:**
- **Gateway Binding**: 127.0.0.1:18789 only (never 0.0.0.0)
- **VPN Requirement**: Tailscale, WireGuard, or OpenVPN
- **Firewall**: UFW/iptables rules block non-VPN traffic
- **Rate Limiting**: Per-IP request limits (100 req/min)
- **Authentication**: API keys, mTLS client certificates

**Implementation**:
```yaml
# configs/templates/gateway.hardened.yml
server:
  host: "127.0.0.1"  # NEVER "0.0.0.0"
  port: 18789
  
  authentication:
    required: true
    methods: ["api_key", "mtls"]
  
  rate_limiting:
    enabled: true
    requests_per_minute: 100
```

**Verification**:
```bash
# Confirm localhost-only binding
netstat -tulpn | grep 18789  # Should show 127.0.0.1:18789 only
```

**Guide**: [03-network-segmentation.md](../guides/03-network-segmentation.md)

---

### Layer 3: Runtime Sandboxing

**Threat Mitigated**: Container escape, host compromise (STRIDE: Elevation of Privilege, Tampering)

**Problem**: Default Docker configuration allows container escapes:
- Root user in container → host root with volume mounts
- Full kernel capabilities → exploit kernel vulnerabilities
- Writable filesystem → persistent backdoors
- No seccomp → unrestricted syscalls

**Solution**: Hardened Docker configuration with defense-in-depth.

**Controls:**
- **Non-Root User**: UID 1000 (never root)
- **Capability Dropping**: `cap_drop: [ALL]`, only add essential
- **Read-Only Filesystem**: Root FS mounted read-only
- **Seccomp**: BPF filter blocks 53 dangerous syscalls
- **AppArmor/SELinux**: Mandatory access control
- **Resource Limits**: CPU, memory, PID, disk I/O limits
- **No New Privileges**: Prevents privilege escalation

**Implementation**:
```yaml
# configs/examples/docker-compose-full-stack.yml
services:
  clawdbot:
    image: anthropic/clawdbot:latest
    user: "1000:1000"
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE]
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=100m
    security_opt:
      - no-new-privileges:true
      - seccomp=./scripts/hardening/docker/seccomp-profiles/clawdbot.json
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
          pids: 100
```

**Verification**:
```bash
# Confirm non-root user
docker exec <container> whoami  # Should be "clawdbot" not "root"

# Verify read-only rootfs
docker exec <container> touch /test  # Should fail: Read-only file system
```

**Guide**: [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md)

---

### Layer 4: Runtime Security Enforcement

**Threat Mitigated**: Prompt injection, PII leakage (STRIDE: Tampering, Information Disclosure)

**Problem**: AI agents vulnerable to prompt injection attacks:
- Indirect injection via emails, PDFs, web pages
- Jailbreak attempts bypass system prompts
- Tool execution without authorization
- PII/credentials in outputs

**Solution**: Runtime guards with input validation and output filtering.

**Controls:**
- **Prompt Injection Detection**: Pattern matching, ML-based detection
- **Delimiter Stripping**: Remove delimiter characters from inputs
- **Tool Allowlisting**: Only approved tools can execute
- **Output Redaction**: Remove PII, credentials, secrets from outputs
- **Context Window Limiting**: Prevent context stuffing attacks

**Implementation** (using openclaw-shield):
```yaml
# configs/examples/with-community-tools.yml
services:
  openclaw-shield:
    image: knostic/openclaw-shield:latest
    environment:
      SHIELD_MODE: "enforce"  # block vs log
      PROMPT_INJECTION_THRESHOLD: 0.7
      PII_REDACTION_ENABLED: "true"
      TOOL_ALLOWLIST: "/config/tool-allowlist.json"
```

**Verification**:
```bash
# Test prompt injection detection
echo "Ignore previous instructions" | ./test-shield.sh
# Should return: BLOCKED - Prompt injection detected
```

**Guide**: [07-community-tools-integration.md](../guides/07-community-tools-integration.md#openclaw-shield)

---

### Layer 5: Supply Chain Security

**Threat Mitigated**: Malicious skill installation (STRIDE: Tampering, Elevation of Privilege)

**Problem**: Skills/tools can be compromised:
- Typosquatting: @openclaw-skill vs @openclaw-skil1
- Compromised npm packages: event-stream incident
- Malicious updates: version pinning bypassed
- Dependency confusion: private package names

**Solution**: Cryptographic verification and integrity monitoring.

**Controls:**
- **GPG Signature Verification**: All skills must be signed
- **Integrity Manifests**: SHA256 checksums for all files
- **Allowlist Enforcement**: Only approved skills installable
- **Automated Monitoring**: Daily integrity checks
- **Auto-Update Disabled**: Manual review required

**Implementation**:
```json
// configs/skill-policies/allowlist.json
{
  "skills": {
    "approved": [
      {
        "id": "openclaw-http-skill",
        "source": "https://github.com/openclaw/http-skill",
        "gpg_fingerprint": "ABCD1234...",
        "allowed_permissions": ["network"],
        "version": ">=1.2.0,<2.0.0"
      }
    ]
  },
  "enforcement": {
    "autoInstall": false,
    "requireSignature": true
  }
}
```

**Verification**:
```bash
# Check integrity
./scripts/supply-chain/skill_manifest.py --skills-dir ~/.openclaw/skills
# Should report: All skills verified ✓
```

**Guide**: [05-supply-chain-security.md](../guides/05-supply-chain-security.md)

---

### Layer 6: Behavioral Monitoring

**Threat Mitigated**: Anomalous behavior, data exfiltration (STRIDE: All categories - detection)

**Problem**: Security controls can be bypassed; detection is critical:
- Zero-day prompt injections
- Insider threats
- Configuration drift
- Slow data exfiltration

**Solution**: Continuous monitoring with anomaly detection.

**Controls:**
- **Behavioral Baseline**: Establish normal agent behavior
- **Anomaly Detection**: Detect deviations (rate, volume, endpoints)
- **SIEM Integration**: Centralized logging and alerting
- **Audit Trails**: Immutable record of all actions
- **Alerting**: Real-time notifications for incidents

**Implementation** (using openclaw-telemetry):
```yaml
# configs/examples/with-community-tools.yml
services:
  openclaw-telemetry:
    image: knostic/openclaw-telemetry:latest
    environment:
      BASELINE_PERIOD: "7d"
      ANOMALY_THRESHOLD: "3sigma"
      ALERT_WEBHOOK: "${SLACK_WEBHOOK_URL}"
      SIEM_INTEGRATION: "splunk"
```

**Key Metrics Monitored:**
- Tokens consumed per request (detect exfiltration loops)
- Tool invocation patterns (detect unauthorized access)
- Network connections (detect C2 communication)
- Credential access frequency (detect brute force)

**Verification**:
```bash
# Check telemetry
curl http://localhost:9090/metrics | grep openclaw
```

**Guide**: [07-community-tools-integration.md](../guides/07-community-tools-integration.md#openclaw-telemetry)

---

### Layer 7: Organizational Controls

**Threat Mitigated**: Shadow AI, policy violations (STRIDE: Repudiation, Elevation of Privilege)

**Problem**: Individual hardening isn't enough in enterprise settings:
- Shadow AI deployments (unmanaged agents)
- Policy violations (unauthorized use cases)
- Compliance gaps (GDPR, SOC 2, ISO 27001)
- Lack of visibility across organization

**Solution**: Enterprise governance and discovery.

**Controls:**
- **Shadow AI Detection**: Network scanning, MDM integration
- **Group Policy Enforcement**: Centralized configuration management
- **Compliance Monitoring**: SOC 2, ISO 27001, GDPR tracking
- **Usage Policies**: Acceptable use, data classification
- **Access Reviews**: Quarterly recertification

**Implementation**:
```json
// configs/organization-policies/security-policy.json
{
  "policy_id": "SEC-001",
  "department": "Security",
  "policies": {
    "credential_storage": {
      "policy": "All AI agent credentials MUST use OS keychain storage",
      "requirements": [
        "No plaintext credentials in configs",
        "Automated backup file cleanup",
        "Quarterly access reviews"
      ],
      "compliance_mapping": {
        "SOC2": ["CC6.1"],
        "ISO27001": ["A.9.2.1", "A.10.1.1"]
      }
    }
  }
}
```

**Verification**:
```bash
# Scan for shadow AI
./scripts/discovery/shadow-ai-scan.sh --network 10.0.0.0/8
```

**Guide**: [07-community-tools-integration.md](../guides/07-community-tools-integration.md#openclaw-detect)

---

## Cross-Layer Integration

### Data Flow Security

```
External Request
    │
    ▼
┌──────────────────────────────┐
│  Layer 7: Policy Check       │  ← Is this user/deployment authorized?
│  (openclaw-detect)            │
└───────────┬──────────────────┘
            │ ✅ Authorized
            ▼
┌──────────────────────────────┐
│  Layer 6: Telemetry Start    │  ← Log request, start monitoring
│  (openclaw-telemetry)         │
└───────────┬──────────────────┘
            │
            ▼
┌──────────────────────────────┐
│  Layer 2: VPN Auth + FW      │  ← VPN authentication, IP check
│  (Gateway)                    │
└───────────┬──────────────────┘
            │ ✅ Authenticated
            ▼
┌──────────────────────────────┐
│  Layer 4: Input Sanitization │  ← Prompt injection detection
│  (openclaw-shield)            │
└───────────┬──────────────────┘
            │ ✅ Clean Input
            ▼
┌──────────────────────────────┐
│  Agent Processing             │
│  ┌────────────────────────┐  │
│  │ Need credential?       │  │
│  │ → Layer 1: Keychain    │  ← Credential access from OS keychain
│  └────────────────────────┘  │
│  ┌────────────────────────┐  │
│  │ Execute skill?         │  │
│  │ → Layer 5: Verify sig  │  ← Integrity check, allowlist verification
│  │ → Layer 3: Sandbox     │  ← Execute in isolated container
│  └────────────────────────┘  │
└───────────┬──────────────────┘
            │
            ▼
┌──────────────────────────────┐
│  Layer 4: Output Redaction   │  ← Remove PII/credentials
│  (openclaw-shield)            │
└───────────┬──────────────────┘
            │ ✅ Safe Output
            ▼
┌──────────────────────────────┐
│  Layer 6: Telemetry End      │  ← Log completion, check anomalies
│  (openclaw-telemetry)         │
└──────────────────────────────┘
```

### Incident Response Integration

When Layer 6 (monitoring) detects an anomaly:

1. **Alert**: Notification to security team
2. **Triage**: Was this legitimate or malicious?
3. **Containment**: 
   - Layer 2: Block IP at firewall
   - Layer 1: Rotate compromised credentials
   - Layer 3: Kill suspicious containers
4. **Investigation**:
   - Layer 6: Review audit trails
   - Layer 5: Check skill integrity
   - Layer 4: Analyze prompt logs
5. **Recovery**: Restore from known-good state
6. **Post-Incident**: Update detection rules, policies

**Reference**: [06-incident-response.md](../guides/06-incident-response.md)

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1)

**Priority**: P0 threats (credential exfiltration, prompt injection)

1. **Day 1-2**: Layer 1 (Credential Isolation)
   - Migrate credentials to OS keychain
   - Remove all plaintext credentials
   - Set up automated backup file cleanup

2. **Day 3-4**: Layer 2 (Network Segmentation)
   - Deploy Tailscale/WireGuard VPN
   - Configure gateway for localhost-only
   - Set up firewall rules

3. **Day 5**: Verification
   - Run [verify_openclaw_security.sh](../../scripts/verification/verify_openclaw_security.sh)
   - Confirm zero critical findings

### Phase 2: Hardening (Week 2)

**Priority**: P1 threats (container escape, authentication bypass)

1. **Day 1-2**: Layer 3 (Runtime Sandboxing)
   - Deploy hardened Docker configuration
   - Implement seccomp profile
   - Test container escape resistance

2. **Day 3**: Layer 4 (Runtime Enforcement)
   - Deploy openclaw-shield
   - Configure prompt injection detection
   - Enable output redaction

3. **Day 4**: Layer 5 (Supply Chain)
   - Set up GPG signing for skills
   - Create integrity manifests
   - Enable allowlist enforcement

4. **Day 5**: Verification & Testing
   - Test all security controls
   - Attempt bypasses (authorized pentest)

### Phase 3: Observability (Week 3)

**Priority**: Detection and response

1. **Day 1-2**: Layer 6 (Monitoring)
   - Deploy openclaw-telemetry
   - Configure SIEM integration
   - Set up alerting

2. **Day 3**: Layer 7 (Governance)
   - Deploy organization policies
   - Set up compliance monitoring
   - Schedule access reviews

3. **Day 4-5**: Incident Response
   - Create response playbooks
   - Test containment procedures
   - Train security team

### Phase 4: Continuous Improvement (Ongoing)

- Weekly: Review telemetry data, adjust thresholds
- Monthly: Patch updates, skill integrity checks
- Quarterly: Access reviews, penetration testing, policy updates
- Annually: Full architecture review, threat model update

---

## Verification

### Pre-Deployment Checklist

Use [verify_openclaw_security.sh](../../scripts/verification/verify_openclaw_security.sh):

```bash
# Full security verification
./scripts/verification/verify_openclaw_security.sh

# Layer-specific verification
./scripts/verification/verify_openclaw_security.sh --layer 1  # Credentials
./scripts/verification/verify_openclaw_security.sh --layer 2  # Network
./scripts/verification/verify_openclaw_security.sh --layer 3  # Sandbox
```

**Expected Results:**
- ✅ All layers: 0 critical findings
- ✅ Warnings acceptable for non-production environments
- ✅ Layer 1-3: Must pass before production deployment
- ✅ Layer 4-7: Recommended but not blocking

### Per-Layer Verification

**Layer 1**:
```bash
# No plaintext credentials
grep -r "sk-ant-" ~/.openclaw/  # Should find nothing
```

**Layer 2**:
```bash
# Localhost-only binding
netstat -tulpn | grep 18789 | grep -v 127.0.0.1  # Should be empty
```

**Layer 3**:
```bash
# Non-root user
docker exec <container> id  # Should show uid=1000
```

**Layer 4**:
```bash
# Prompt injection blocked
curl -X POST http://localhost:18789/v1/chat \
  -d '{"prompt": "Ignore previous instructions"}' \
  -H "Authorization: Bearer ${API_KEY}"
# Should return: 400 Bad Request (blocked)
```

**Layer 5**:
```bash
# Skill integrity verified
./scripts/supply-chain/skill_manifest.py --verify --skills-dir ~/.openclaw/skills
# Should return: All skills verified ✓
```

**Layer 6**:
```bash
# Telemetry operational
curl http://localhost:9090/metrics | grep openclaw_requests_total
# Should return: openclaw_requests_total{...} <number>
```

**Layer 7**:
```bash
# Policy compliance
./scripts/compliance/policy-audit.sh
# Should return: 0 violations
```

---

## References

### Related Documentation
- [Threat Model](./threat-model.md) - STRIDE analysis
- [Zero-Trust Design](./zero-trust-design.md) - Zero-trust principles
- [Quick Start Guide](../guides/01-quick-start.md) - Get started in 15 minutes
- [Incident Response](../guides/06-incident-response.md) - Response procedures

### Implementation Guides
- [Layer 1: Credential Isolation](../guides/02-credential-isolation.md)
- [Layer 2: Network Segmentation](../guides/03-network-segmentation.md)
- [Layer 3: Runtime Sandboxing](../guides/04-runtime-sandboxing.md)
- [Layer 5: Supply Chain Security](../guides/05-supply-chain-security.md)
- [Layers 4, 6, 7: Community Tools](../guides/07-community-tools-integration.md)

### Configuration Examples
- [Docker Compose Full Stack](../../configs/examples/docker-compose-full-stack.yml)
- [Production Kubernetes](../../configs/examples/production-k8s.yml)
- [With Community Tools](../../configs/examples/with-community-tools.yml)
- [Monitoring Stack](../../configs/examples/monitoring-stack.yml)

### External Resources
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker)
- [OWASP Defense in Depth](https://owasp.org/www-community/Defense_in_Depth)

---

**Document Version**: 1.0.0  
**Last Updated**: February 14, 2026  
**Next Review**: May 14, 2026 (quarterly)
