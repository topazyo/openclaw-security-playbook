---
title: Community Tools Integration Guide
layer: 4-6-7
estimated_time: 30 minutes
difficulty: Intermediate
---

# Community Tools Integration Guide

This guide documents optional third-party integrations that may complement this repository.

This repository does not vendor, pin, or verify releases for `openclaw-detect`, `openclaw-telemetry`, `openclaw-shield`, or `clawguard`. Treat them as external dependencies with their own trust, review, and approval requirements.

## Platform Notes

### Linux
Use this guide as a decision aid before introducing any external tool into production.

### macOS
Apply the same verification and approval requirements before adopting any external tool.

### Windows
Use PowerShell or WSL2 equivalents only after the external tool has been approved for use.

## Overview

Use this playbook alone when you need repo-native guidance, validation scripts, reference configurations, detection content, and incident-response procedures.

Use an external community tool only after you have independently verified its source, version, integrity, and operational fit for your environment.

## Integration Boundary

What this repository provides directly:

- Detection content under `detections/`
- Verification scripts under `scripts/verification/`
- Monitoring baseline logic in `scripts/monitoring/anomaly_detector.py`
- Incident-response and forensics tooling under `scripts/incident-response/` and `scripts/forensics/`
- Reference configuration patterns under `configs/`

What this repository does not provide directly:

- Vendored copies of `openclaw-detect`
- Vendored copies of `openclaw-telemetry`
- Vendored copies of `openclaw-shield`
- Vendored copies of `clawguard`
- Version-pinned installers or integrity hashes for those projects

## Tool Roles

### openclaw-detect

Potential role: endpoint discovery and shadow AI inventory.

Repo-native fallback:

- Organization policies in `configs/organization-policies/`
- Detection content in `detections/`
- Verification workflows in `.github/workflows/`

### openclaw-telemetry

Potential role: structured behavioral telemetry forwarding and tamper-evident logging.

Repo-native fallback:

- `scripts/monitoring/anomaly_detector.py`
- `scripts/forensics/verify_hash_chain.py`
- `docs/guides/07-detection-and-hunting.md`

### openclaw-shield

Potential role: runtime prompt-injection blocking, output filtering, and tool enforcement.

Repo-native fallback:

- `configs/skill-policies/`
- `configs/templates/`
- `docs/guides/04-runtime-sandboxing.md`
- `docs/guides/05-supply-chain-security.md`

### clawguard

Potential role: JavaScript or TypeScript guardrails outside the Python/OpenClaw-focused tooling in this repository.

Repo-native fallback:

- This repository does not ship a JS/TS guard library; use the repo for policy, hardening, and detection guidance only.

## Adoption Checklist

Before adopting any external community tool:

1. Confirm the upstream repository, package, or image still exists and is actively maintained.
2. Record the exact version or commit you intend to approve.
3. Review source, release notes, and license terms.
4. Verify integrity through your normal supply-chain controls before installation.
5. Test the tool in a non-production environment with the reference configs in `configs/examples/with-community-tools.yml`.
6. Re-run `./scripts/verification/verify_openclaw_security.sh` after integration.
7. Update your incident-response and rollback procedures to include the external dependency.

## How to Use This Repository Alongside External Tools

Use the repo-native materials to validate outcomes instead of trusting external-tool marketing claims:

- Use `docs/guides/07-detection-and-hunting.md` to validate detection coverage.
- Use `scripts/verification/validate_detection_rules.py` to validate local detection content.
- Use `scripts/forensics/collect_evidence.sh` and `scripts/forensics/build_timeline.sh` for incident evidence handling.
- Use `configs/examples/with-community-tools.yml` only as a reference integration shape, not as proof that an upstream tool release is verified by this repository.

## Troubleshooting Boundary

If an issue is inside an external tool itself, use that project's support channels and your internal software-approval process.

If the issue is with this repository's configs, detections, or validation scripts, use the repo documentation and scripts here first.

## Related Documentation

- [Detection and Hunting Guide](../guides/07-detection-and-hunting.md)
- [Runtime Sandboxing Guide](../guides/04-runtime-sandboxing.md)
- [Supply Chain Security Guide](../guides/05-supply-chain-security.md)
- [Incident Response Guide](../guides/06-incident-response.md)
- [with-community-tools.yml](../../configs/examples/with-community-tools.yml)
