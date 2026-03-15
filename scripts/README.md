# Security Scripts

This directory contains automation scripts for various security tasks.

## Directories

| Directory | Status | Contents |
|-----------|--------|----------|
| `incident-response/` | Active | Incident containment, notification, forensics collection, and impact analysis automation |
| `forensics/` | Active | Evidence collection, credential scoping, timeline building, and hash-chain verification |
| `monitoring/` | Active | Behavioral monitoring and anomaly detection |
| `supply-chain/` | Active | Skill integrity monitoring and manifest validation |
| `verification/` | Active | Security posture checks and detection-replay validation |
| `hardening/` | Active | Docker seccomp profiles, VPN setup, and runtime hardening scripts |
| `credential-migration/` | Active | macOS and Linux keychain migration helpers |
| `vulnerability-scanning/` | Active | OS-level and dependency vulnerability scan helpers |
| `compliance/` | Placeholder | Access review and compliance helpers (see `tools/compliance-reporter.py`) |
| `discovery/` | Placeholder | Asset and dependency discovery helpers |
| `remediation/` | Placeholder | Remediation workflow scripts |
| `reporting/` | Placeholder | Reporting and metric-generation scripts |
| `incident_response/` | Placeholder | Legacy alias directory; use `incident-response/` instead |

## Related Tools

High-level CLI wrappers and management tools live in [`tools/`](../tools/):

| Tool | Purpose |
|------|---------|
| `openclaw-cli.py` | Main CLI entry point — scan, report, playbook, config, simulate subcommands |
| `certificate-manager.py` | TLS certificate expiry check and renewal via certbot / Let's Encrypt |
| `compliance-reporter.py` | SOC 2 / ISO 27001 compliance report generation |
| `config-migrator.py` | Configuration migration between schema versions |
| `incident-simulator.py` | Incident simulation for training and playbook testing |
| `policy-validator.py` | Security policy compliance validation |

## Usage

All scripts include built-in help:

```bash
./scripts/monitoring/anomaly_detector.py --help
```

Install the package first to get the `openclaw-cli` entry point:

```bash
pip install -e .
openclaw-cli --help
```