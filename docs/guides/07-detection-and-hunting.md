---
title: Detection and Hunting Guide
layer: 6-7
estimated_time: 30 minutes
difficulty: Intermediate
---

# Detection and Hunting Guide

This guide covers deploying and operating the detection content in `detections/` for
OpenClaw, Moltbot, and Clawdbot deployments.

Cross-reference material:
- Platform-agnostic rule inventory: [`detections/README.md`](../../detections/README.md)
- Threat scenario coverage: [`docs/threat-model/ATLAS-mapping.md`](../threat-model/ATLAS-mapping.md)
- Detection-to-scenario replay matrix: [`docs/threat-model/detection-replay-matrix.md`](../threat-model/detection-replay-matrix.md)
- Monitoring stack configuration: [`configs/monitoring-config/`](../../configs/monitoring-config/)

## Platform Notes

### Linux
Use commands as written for telemetry validation and forensic scripts.

### macOS
Use equivalent CLI tooling where GNU/Linux command behavior differs.

### Windows
Run shell-centric commands through WSL2 or PowerShell equivalents.

## Prerequisites

**For Tier 1 (Discovery):** EDR agent deployed on target endpoints. No additional tooling required.

**For Tier 2/3 (Behavioral Hunting and Kill Chain Detection):**
- `openclaw-telemetry` installed and running on agent hosts, forwarding JSONL events to your SIEM.
  See [`docs/guides/08-community-tools-integration.md`](08-community-tools-integration.md) for
  setup guidance. The telemetry schema is documented in [`detections/README.md`](../../detections/README.md).
- SIEM receiving CEF/syslog events from openclaw-telemetry
- For KQL queries: Microsoft Sentinel with CommonSecurityLog table populated

## Deployment Sequence

### Step 1: Deploy Discovery Rules

Start with Tier 1. These find every OpenClaw installation on your fleet before you worry
about behavioral detection.

```bash
# MDE: Create Custom Detection Rule from detections/edr/mde/openclaw-discovery.kql
# Splunk: Import detections/siem/splunk/openclaw-discovery.spl if your telemetry is already landing in Splunk
```

For other platforms, convert the shipped Sigma rules or add platform-specific content under `detections/`.

Set the schedule to run hourly. Alert on any new result — every OpenClaw process or domain
contact should be documented in your asset inventory.

### Step 2: Import Sigma Rules

Sigma rules in `detections/sigma/` are platform-agnostic and can be converted to your
target SIEM using [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
# Install sigma-cli with your backend
pip install sigma-cli pysigma pysigma-backend-splunk

# Convert all OpenClaw rules to Splunk
sigma convert -t splunk detections/sigma/openclaw-*.yml \
    -o detections/siem/splunk/openclaw-from-sigma.spl

# Convert to Microsoft 365 Defender / MDE KQL
pip install pysigma-backend-microsoft365defender
sigma convert -t microsoft365defender detections/sigma/openclaw-*.yml
```

**Verify:** Expected output:
```text
Sigma conversion completes without parser errors.
Generated output includes openclaw rule names for the selected backend.
```

### Step 3: Deploy Behavioral Hunting

Once openclaw-telemetry is running and forwarding to your SIEM:

1. Establish a 7-day baseline of normal tool execution patterns before enabling alerts
2. Tune the off-hours window in Hunt 3 to match actual working hours for your org
3. Adjust the burst threshold in Hunt 4 based on typical automation workloads
4. Enable Hunt 5 (SOUL.md writes) immediately — it has no meaningful false positive rate

### Step 4: Validate Detection Coverage

Run this validation checklist weekly:

```bash
# Verify telemetry is flowing (should see recent events)
tail -5 ~/.openclaw/logs/telemetry.jsonl | jq '.timestamp'

# Validate shipped detection content
python scripts/verification/validate_detection_rules.py
```

**Verify:** Expected output:
```text
Recent telemetry timestamps are returned for the latest events.
Detection rule validation completes without Sigma or YARA errors.
```

## Tuning Notes

**Hunt 3 (Off-Hours Execution)** will produce false positives for:
- Scheduled tasks the agent legitimately runs overnight
- Users in different time zones
- Maintenance automation that uses the agent

**Hunt 4 (Burst Execution)** threshold of 10 calls/minute may be too low for:
- Agents processing large email queues
- Bulk document processing workflows

Raise the threshold to 25 or 50 for high-volume deployments.

**Kill Chain 1 (Prompt Injection to RCE)** will produce false positives if:
- Your agent legitimately executes commands immediately after reading external messages
- You have automation that sends messages and expects the agent to run scripts

## Forensics Quick Reference

When an alert fires and you need to investigate:

```bash
# Step 1: Preserve evidence (run BEFORE stopping agent)
./scripts/forensics/collect_evidence.sh

# Step 2: Build attack timeline
./scripts/forensics/build_timeline.sh \
    --incident-dir ~/openclaw-incident-TIMESTAMP

# Step 3: Assess credential exposure scope
./scripts/forensics/check_credential_scope.sh

# Step 4: Verify log integrity
python3 scripts/forensics/verify_hash_chain.py \
    --input ~/openclaw-incident-TIMESTAMP/logs/openclaw/telemetry.jsonl \
    --output ~/openclaw-incident-TIMESTAMP/hashes/chain-report.json
```

See `docs/guides/06-incident-response.md` for the complete IR playbook.

---

## Rolling Back Detection Rules

When a rule produces an unacceptable false-positive rate in production:

### Disable a Sigma-Converted Rule

```bash
# In Splunk: disable the saved search
curl -k -u admin:$SPLUNK_PASSWORD \
  -X POST https://localhost:8089/servicesNS/admin/search/saved/searches/<rule-name>/disable

# In Sentinel: disable the scheduled query rule via the Azure portal or CLI
az sentinel alert-rule update \
  --resource-group <rg> --workspace-name <ws> \
  --rule-id <id> --enabled false
```

### Modify a Sigma Rule and Re-Deploy

```bash
# Edit the relevant rule in detections/sigma/
# Then re-convert and re-deploy:
sigma convert -t splunk detections/sigma/openclaw-<rule>.yml \
    -o detections/siem/splunk/openclaw-<rule>.spl
# Re-import the generated SPL in your SIEM
```

### Validate After Rollback

```bash
# Confirm the replay test still detects the true-positive fixture
python scripts/verification/validate_detection_replay.py --skip-yara
# Expected: positive fixtures match, negative fixtures do not
```

For guidance on tuning thresholds before disabling a rule entirely, see the
[Tuning Notes](#tuning-notes) section above.
