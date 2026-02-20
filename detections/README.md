# Detection Rules and Hunting Queries

This directory contains all detection content for OpenClaw, Moltbot, and Clawdbot deployments.
Coverage maps to the three-tier detection model in
[Part 3: Detecting OpenClaw Compromise](https://cloudsecops.hashnode.dev/openclaw-detecting-compromise).

## Directory Structure

| Path | Contents |
|------|----------|
| `ioc/` | Indicators of compromise: domains, ports, file paths, process names, YARA rules |
| `edr/crowdstrike/` | CrowdStrike Falcon queries (Falcon LogScale / Humio SPL) |
| `edr/mde/` | Microsoft Defender for Endpoint KQL queries |
| `edr/cortex/` | Palo Alto Cortex XDR XQL queries |
| `edr/sentinelone/` | SentinelOne Deep Visibility queries |
| `siem/sentinel/` | Microsoft Sentinel KQL queries (requires openclaw-telemetry CEF forwarding) |
| `siem/splunk/` | Splunk SPL queries |
| `sigma/` | Platform-agnostic Sigma rules (convert to your platform with sigmac or pySigma) |

## Detection Tiers

**Tier 1 — Discovery:** Find all OpenClaw installations and running instances on your fleet.
Deploy these as scheduled rules regardless of whether you suspect compromise.

**Tier 2 — Behavioral Hunting:** Detect anomalous agent behavior indicating compromise in progress.
Requires openclaw-telemetry (Part 2, Layer 6) to be deployed and forwarding to SIEM.

**Tier 3 — Kill Chain Detection:** Map observed activity to specific MITRE ATLAS attack chains.
See `docs/threat-model/ATLAS-mapping.md` for the full kill chain taxonomy.

## Prerequisites

- Tier 1 queries: EDR agent deployed on target endpoints, no additional tooling required
- Tier 2/3 queries: openclaw-telemetry installed and configured with SIEM CEF/syslog forwarding
- Sigma rules: sigmac or pySigma installed for conversion to your target platform

## Telemetry Schema

Tier 2 and 3 queries assume the openclaw-telemetry JSONL schema:

```json
{
  "timestamp": "2026-02-18T06:34:12.441Z",
  "event_type": "tool_executed",
  "session_id": "sess_abc123",
  "tool_name": "file_read",
  "tool_args": {"path": "/home/user/.ssh/id_ed25519"},
  "tool_result_summary": "success",
  "chain_hash": "sha256:a1b2c3..."
}
```

Event types: `tool_executed`, `message_received`, `session_start`, `session_end`,
`config_changed`, `skill_loaded`, `error`

## Contributing

If you write a detection rule that catches something not covered here, please open a PR.
Include: platform, query, tested telemetry version, and a brief description of what it catches.
