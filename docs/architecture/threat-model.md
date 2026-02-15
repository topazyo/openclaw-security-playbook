# Threat Model for AI Agent Security (ClawdBot/OpenClaw)

**Estimated Time:** 60 minutes  
**Difficulty:** Advanced  
**Prerequisites:** Understanding of STRIDE methodology, AI agent architecture, and attack vectors

This document provides a comprehensive threat model for AI agent systems, specifically focusing on ClawdBot/OpenClaw deployments. Built using STRIDE methodology and informed by real-world incidents documented in [examples/scenarios/](../../examples/scenarios/).

---

## Table of Contents

1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [STRIDE Analysis](#stride-analysis)
4. [Threat Catalog](#threat-catalog)
5. [Attack Surface Analysis](#attack-surface-analysis)
6. [Threat Scenarios](#threat-scenarios)
7. [Mitigation Strategies](#mitigation-strategies)
8. [References](#references)

---

## Overview

### Purpose

This threat model identifies security threats to AI agent systems and provides prioritized mitigation strategies. It covers the complete attack surface from credential storage through runtime execution and supply chain integrity.

### Scope

**In Scope:**
- ClawdBot/OpenClaw agent runtime
- MCP (Model Context Protocol) server infrastructure
- Skill/tool installation and execution
- Network gateway and API endpoints
- Credential storage and secrets management
- Conversation history and persistent data

**Out of Scope:**
- Anthropic Claude API infrastructure (external)
- Third-party SaaS integrations (covered separately)
- End-user device security (client-side)

### Methodology

This threat model uses the **STRIDE** framework:
- **S**poofing of identity
- **T**ampering with data
- **R**epudiation
- **I**nformation disclosure
- **D**enial of service
- **E**levation of privilege

---

## System Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        External User/Client                      │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Network Layer (Layer 2)                     │
│  • VPN Gateway (Tailscale/WireGuard)                            │
│  • Firewall (UFW/iptables)                                      │
│  • Rate Limiter                                                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │ localhost:18789
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    HTTP Gateway (Layer 3 Boundary)               │
│  • Authentication (API keys, mTLS)                              │
│  • Input validation                                             │
│  • Request logging                                              │
└───────────────────────────┬─────────────────────────────────────┘
                            │ IPC/Unix socket
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    ClawdBot Agent (Core)                         │
│  ┌─────────────────────────────────────────────────────┐        │
│  │  Runtime Enforcement (Layer 4 - openclaw-shield)    │        │
│  │  • Prompt injection detection                       │        │
│  │  • PII/credential redaction                         │        │
│  │  • Tool execution allowlisting                      │        │
│  └─────────────────────────────────────────────────────┘        │
│                            │                                     │
│  ┌─────────────────────────▼─────────────────────────┐          │
│  │         Skill Execution Engine                     │          │
│  │  • Sandboxed runtime (Docker/gVisor)              │          │
│  │  • Resource limits (CPU/memory/PIDs)              │          │
│  │  • Filesystem isolation (read-only rootfs)        │          │
│  └────────────────────────────────────────────────────┘          │
│                            │                                     │
│  ┌─────────────────────────▼─────────────────────────┐          │
│  │      Credential Access (Layer 1)                   │          │
│  │  • OS Keychain (macOS/Linux/Windows)              │          │
│  │  • Zero plaintext storage                         │          │
│  └────────────────────────────────────────────────────┘          │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                ▼                       ▼
    ┌──────────────────────┐  ┌──────────────────────┐
    │  Anthropic Claude    │  │  External Services   │
    │  API (LLM Backend)   │  │  (Skills/MCP)        │
    └──────────────────────┘  └──────────────────────┘
```

### Trust Boundaries

1. **Public Internet → VPN**: User authentication, device posture check
2. **VPN → Gateway**: Network-level authorization, IP allowlisting
3. **Gateway → Agent**: API authentication, input sanitization
4. **Agent → Skills**: Permission boundaries, resource limits
5. **Skills → External**: Network policies, credential vetting

---

## STRIDE Analysis

### S - Spoofing of Identity

| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|------------|
| **Agent Impersonation** | Attacker spoofs agent identity in multi-agent coordination | High | Cryptographic signing of agent messages (see [scenario-004](../../examples/scenarios/scenario-004-multi-agent-coordination-attack.md)) |
| **API Key Theft** | Stolen Claude API keys allow unauthorized agent access | Critical | OS keychain storage (Layer 1), credential rotation (see [02-credential-isolation.md](../guides/02-credential-isolation.md)) |
| **User Identity Spoofing** | Attacker bypasses authentication to gateway | High | mTLS client certificates, API key validation (see [gateway.hardened.yml](../../configs/templates/gateway.hardened.yml)) |
| **MCP Server Impersonation** | Malicious server impersonates legitimate MCP endpoint | Medium | TLS certificate pinning, server allowlisting |

### T - Tampering with Data

| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|------------|
| **Prompt Injection** | Malicious prompts alter agent behavior | High | Input sanitization, delimiter stripping, openclaw-shield (see [scenario-001](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md)) |
| **Conversation History Poisoning** | Attacker modifies stored conversation data | Medium | Encrypted storage, integrity checksums, access controls |
| **RAG Database Poisoning** | Malicious documents injected into vector DB | High | Document validation, provenance tracking (see [examples/attack-scenarios/data-exfiltration/rag-poisoning.md](../../examples/attack-scenarios/data-exfiltration/rag-poisoning.md)) |
| **Skill Code Tampering** | Installed skills modified post-installation | Medium | Integrity monitoring, GPG signatures (Layer 5, see [05-supply-chain-security.md](../guides/05-supply-chain-security.md)) |
| **Config File Tampering** | Attacker modifies config to disable security | High | Read-only filesystem, config validation on load |

### R - Repudiation

| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|----------|
| **Unlogged Actions** | Attacker actions not captured in audit trail | Medium | Comprehensive logging to immutable destination (see [monitoring-stack.yml](../../configs/examples/monitoring-stack.yml)) |
| **Log Tampering** | Attacker deletes/modifies logs | Medium | Remote syslog, SIEM integration, log signing |
| **Credential Usage Tracking** | No audit trail for credential access | Low | OS keychain access logging, openclaw-telemetry |

### I - Information Disclosure

| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|------------|
| **Credential Exfiltration (Plaintext)** | API keys in config files | Critical | OS keychain (Layer 1), zero plaintext (see [02-credential-isolation.md](../guides/02-credential-isolation.md)) |
| **Backup File Persistence** | Editor backup files contain credentials | Critical | Automated cleanup (see [02-credential-isolation.md](../guides/02-credential-isolation.md#backup-file-management)) |
| **Conversation Leakage** | Stored conversations expose sensitive data | High | PII redaction, encryption at rest (see [scenario-006](../../examples/scenarios/scenario-006-credential-theft-conversation-history.md)) |
| **Skill Data Exfiltration** | Malicious skill exfiltrates data | High | Network policies, output filtering (see [scenario-005](../../examples/scenarios/scenario-005-credential-theft-via-skill.md)) |
| **Log Data Exposure** | Logs contain PII/credentials | Medium | Output redaction (openclaw-shield), log sanitization |
| **Error Message Leakage** | Stack traces expose system details | Low | Generic error messages, secure error handling |

### D - Denial of Service

| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|------------|
| **Resource Exhaustion** | Attacker drains compute/token budget | High | Rate limiting, resource quotas (see [scenario-007](../../examples/scenarios/scenario-007-denial-of-service-resource-exhaustion.md)) |
| **Recursive Skill Invocation** | Infinite loop exhausts resources | Medium | Call depth limits, timeout enforcement |
| **Network Flooding** | Gateway overwhelmed with requests | Medium | Rate limiting (see [gateway.hardened.yml](../../configs/templates/gateway.hardened.yml)), DDoS protection |
| **Disk Space Exhaustion** | Logs/conversations fill disk | Low | Log rotation, disk quotas, monitoring |
| **Container Escape Exploit** | DoS via container breakout | Low | Seccomp, AppArmor, read-only rootfs (see [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md)) |

### E - Elevation of Privilege

| Threat | Description | Impact | Mitigation |
|--------|-------------|--------|------------|
| **Skill Permission Escalation** | Skill gains unauthorized permissions | High | Allowlist enforcement, permission validation (see [allowlist.json](../../configs/skill-policies/allowlist.json)) |
| **Container Escape** | Attacker breaks out of Docker sandbox | High | Non-root user, capability dropping, seccomp (see [Dockerfile.hardened](../../scripts/hardening/docker/Dockerfile.hardened)) |
| **Prompt Injection → Code Execution** | Prompt bypasses tool restrictions | Critical | Tool allowlisting, input validation (openclaw-shield) |
| **Lateral Movement** | Compromised agent accesses other systems | Medium | Network segmentation, principle of least privilege |
| **Credential Access via Skill** | Skill reads credentials from agent memory | Critical | Credential isolation, skill sandboxing (see [scenario-005](../../examples/scenarios/scenario-005-credential-theft-via-skill.md)) |

---

## Threat Catalog

### Critical Threats (P0)

**1. Credential Exfiltration via Plaintext Storage**
- **Attack Vector**: Config files, environment variables, backups
- **Likelihood**: High (90% exposure rate in research)
- **Impact**: Complete API key compromise
- **Mitigation**: Layer 1 (OS Keychain), see [02-credential-isolation.md](../guides/02-credential-isolation.md)

**2. Prompt Injection → Unauthorized Tool Execution**
- **Attack Vector**: Indirect prompt injection via emails, documents
- **Likelihood**: Medium
- **Impact**: Data exfiltration, privilege escalation
- **Mitigation**: Layer 4 (openclaw-shield), see [scenario-001](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md)

**3. Supply Chain Compromise via Malicious Skills**
- **Attack Vector**: Typosquatted npm packages, compromised repositories
- **Likelihood**: Medium
- **Impact**: Code execution, data theft
- **Mitigation**: Layer 5, see [scenario-002](../../examples/scenarios/scenario-002-malicious-skill-deployment.md) and [05-supply-chain-security.md](../guides/05-supply-chain-security.md)

### High Threats (P1)

**4. Authentication Bypass via Localhost Tunneling**
- **Attack Vector**: SSH tunneling, ngrok, CloudFlare Tunnel
- **Likelihood**: High (public tutorials available)
- **Impact**: Unauthorized agent access
- **Mitigation**: Layer 2 (VPN-only), see [03-network-segmentation.md](../guides/03-network-segmentation.md)

**5. Container Escape to Host**
- **Attack Vector**: Kernel vulnerabilities, misconfigurations
- **Likelihood**: Low
- **Impact**: Host compromise
- **Mitigation**: Layer 3 (sandboxing), see [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md)

**6. RAG Poisoning → Credential Theft**
- **Attack Vector**: Malicious documents in vector DB
- **Likelihood**: Medium
- **Impact**: Information disclosure
- **Mitigation**: Document validation, provenance tracking

### Medium Threats (P2)

**7. Log/Conversation Data Exposure**
- **Attack Vector**: Misconfigured S3, log aggregation systems
- **Likelihood**: Medium
- **Impact**: PII/credential leakage
- **Mitigation**: Encryption, PII redaction (see [scenario-006](../../examples/scenarios/scenario-006-credential-theft-conversation-history.md))

**8. Economic DoS via Token Exhaustion**
- **Attack Vector**: Repeated expensive operations
- **Likelihood**: Medium
- **Impact**: Financial loss, service disruption
- **Mitigation**: Rate limiting, cost controls (see [scenario-007](../../examples/scenarios/scenario-007-denial-of-service-resource-exhaustion.md))

---

## Attack Surface Analysis

### External Attack Surface

1. **HTTP Gateway** (localhost:18789)
   - **Exposure**: Localhost-only by default
   - **Risk**: High if exposed (tunneling, misconfiguration)
   - **Controls**: VPN requirement, authentication, rate limiting

2. **VPN/Tailscale Interface**
   - **Exposure**: Internet-facing with device authentication
   - **Risk**: Medium (device compromise)
   - **Controls**: Device posture checks, IP allowlisting

3. **MCP Server Endpoints**
   - **Exposure**: Varies per deployment
   - **Risk**: Medium (third-party code)
   - **Controls**: TLS, allowlisting, network policies

### Internal Attack Surface

4. **Skill Execution Environment**
   - **Exposure**: Accessible to agent runtime
   - **Risk**: High (untrusted code)
   - **Controls**: Sandboxing, permission boundaries, integrity checking

5. **Credential Storage**
   - **Exposure**: OS keychain (user-scoped)
   - **Risk**: Medium (requires host access)
   - **Controls**: OS-level encryption, access logging

6. **Conversation History Database**
   - **Exposure**: Filesystem or remote storage
   - **Risk**: Medium (persistent sensitive data)
   - **Controls**: Encryption, PII redaction, access controls

---

## Threat Scenarios

### Scenario 1: Multi-Stage Credential Theft

**Attacker Goal**: Exfiltrate Claude API keys

**Attack Chain**:
1. **Reconnaissance**: Discover exposed gateway via Shodan/GitHub search
2. **Initial Access**: Exploit authentication bypass (SSH tunnel)
3. **Persistence**: Install malicious skill via typosquatted package
4. **Credential Access**: Skill reads from config file or environment
5. **Exfiltration**: Skill sends credentials to attacker-controlled server
6. **Impact**: Unauthorized API usage, data access

**Mitigations**:
- ✅ Layer 1: OS keychain (blocks step 4)
- ✅ Layer 2: VPN-only access (blocks step 2)
- ✅ Layer 5: Skill integrity checking (blocks step 3)

**Reference**: [scenario-005](../../examples/scenarios/scenario-005-credential-theft-via-skill.md)

### Scenario 2: Indirect Prompt Injection

**Attacker Goal**: Execute unauthorized commands

**Attack Chain**:
1. **Preparation**: Craft malicious email with embedded prompts
2. **Delivery**: Send email to target organization
3. **Trigger**: Agent processes email as part of workflow
4. **Execution**: Injected prompt causes tool invocation
5. **Exfiltration**: Data sent to attacker endpoint
6. **Impact**: Data breach, unauthorized actions

**Mitigations**:
- ✅ Layer 4: Prompt injection detection (blocks step 4)
- ✅ Layer 4: Tool allowlisting (limits step 4)
- ✅ Layer 6: Anomaly detection (detects step 5)

**Reference**: [scenario-001](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md)

### Scenario 3: Supply Chain Compromise

**Attacker Goal**: Distribute malicious skill

**Attack Chain**:
1. **Preparation**: Create typosquatted npm package
2. **Distribution**: Publish to npm registry
3. **Installation**: Target installs malicious skill
4. **Execution**: Skill runs in agent context
5. **Persistence**: Skill modifies agent config
6. **Impact**: Backdoor, credential theft

**Mitigations**:
- ✅ Layer 5: GPG signature verification (blocks step 3)
- ✅ Layer 5: Allowlist enforcement (blocks step 3)
- ✅ Layer 5: Integrity monitoring (detects step 5)

**Reference**: [scenario-002](../../examples/scenarios/scenario-002-malicious-skill-deployment.md)

---

## Mitigation Strategies

### Defense-in-Depth Layers

This threat model maps to the [7-layer security architecture](./security-layers.md):

| Layer | Primary Threats Mitigated | Implementation Guide |
|-------|---------------------------|----------------------|
| **Layer 1: Credential Isolation** | Credential exfiltration (P0), backup persistence | [02-credential-isolation.md](../guides/02-credential-isolation.md) |
| **Layer 2: Network Segmentation** | Authentication bypass (P1), unauthorized access | [03-network-segmentation.md](../guides/03-network-segmentation.md) |
| **Layer 3: Runtime Sandboxing** | Container escape (P1), host compromise | [04-runtime-sandboxing.md](../guides/04-runtime-sandboxing.md) |
| **Layer 4: Runtime Enforcement** | Prompt injection (P0), PII leakage | [07-community-tools-integration.md](../guides/07-community-tools-integration.md) |
| **Layer 5: Supply Chain Security** | Malicious skills (P0), tampering | [05-supply-chain-security.md](../guides/05-supply-chain-security.md) |
| **Layer 6: Behavioral Monitoring** | Anomalous behavior, data exfiltration | [07-community-tools-integration.md](../guides/07-community-tools-integration.md) |
| **Layer 7: Organizational Controls** | Shadow AI, policy violations | [07-community-tools-integration.md](../guides/07-community-tools-integration.md) |

### Prioritization Matrix

```
Impact →     Low      Medium     High      Critical
           ┌────────┬──────────┬─────────┬──────────┐
High       │   P2   │    P1    │   P0    │    P0    │
           ├────────┼──────────┼─────────┼──────────┤
Medium     │   P3   │    P2    │   P1    │    P0    │
           ├────────┼──────────┼─────────┼──────────┤
Low        │   P4   │    P3    │   P2    │    P1    │
           └────────┴──────────┴─────────┴──────────┘
           Likelihood
```

**Implementation Priority**:
1. **P0 (Critical)**: Implement immediately — credential isolation, prompt guards, supply chain controls
2. **P1 (High)**: Implement within 1 week — network segmentation, sandboxing
3. **P2 (Medium)**: Implement within 1 month — monitoring, log protection
4. **P3-P4 (Low)**: Implement as resources allow

---

## References

### Internal Documentation
- [Security Layers Architecture](./security-layers.md)
- [Zero-Trust Design](./zero-trust-design.md)
- [Quick Start Guide](../guides/01-quick-start.md)
- [Incident Response Guide](../guides/06-incident-response.md)

### Real-World Scenarios
- [Scenario 001: Indirect Prompt Injection](../../examples/scenarios/scenario-001-indirect-prompt-injection-attack.md)
- [Scenario 002: Malicious Skill Deployment](../../examples/scenarios/scenario-002-malicious-skill-deployment.md)
- [Scenario 003: MCP Server Compromise](../../examples/scenarios/scenario-003-mcp-server-compromise.md)
- [Scenario 004: Multi-Agent Coordination Attack](../../examples/scenarios/scenario-004-multi-agent-coordination-attack.md)
- [Scenario 005: Credential Theft via Skill](../../examples/scenarios/scenario-005-credential-theft-via-skill.md)
- [Scenario 006: Credential Theft (Conversation History)](../../examples/scenarios/scenario-006-credential-theft-conversation-history.md)
- [Scenario 007: Denial of Service](../../examples/scenarios/scenario-007-denial-of-service-resource-exhaustion.md)

### External Resources
- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework)
- [Microsoft STRIDE Threat Modeling](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Anthropic Claude Security](https://docs.anthropic.com/claude/docs/security)

---

**Document Version**: 1.0.0  
**Last Updated**: February 14, 2026  
**Next Review**: May 14, 2026 (quarterly)
