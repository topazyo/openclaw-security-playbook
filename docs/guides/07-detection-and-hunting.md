# Detection and Hunting Guide

This guide covers deploying and operating the detection content in `detections/` for
OpenClaw, Moltbot, and Clawdbot deployments.

It is the companion reference to
[Part 3: Detecting OpenClaw Compromise](https://cloudsecops.hashnode.dev/openclaw-detecting-compromise).

## Prerequisites

**For Tier 1 (Discovery):** EDR agent deployed on target endpoints. No additional tooling required.

**For Tier 2/3 (Behavioral Hunting and Kill Chain Detection):**
- openclaw-telemetry installed and running (see Part 2, Layer 6)
- SIEM receiving CEF/syslog events from openclaw-telemetry
- For KQL queries: Microsoft Sentinel with CommonSecurityLog table populated

## Deployment Sequence

### Step 1: Deploy Discovery Rules

Start with Tier 1. These find every OpenClaw installation on your fleet before you worry
about behavioral detection.

```bash
# CrowdStrike: Import detections/edr/crowdstrike/openclaw-discovery-and-behavioral.spl
# MDE: Create Custom Detection Rule from detections/edr/mde/openclaw-discovery.kql
# Cortex: Import detections/edr/cortex/openclaw-discovery-and-behavioral.xql
# SentinelOne: Create Storyline from detections/edr/sentinelone/openclaw-discovery.s1ql
```

Set the schedule to run hourly. Alert on any new result — every OpenClaw process or domain
contact should be documented in your asset inventory.

### Step 2: Import Sigma Rules

Sigma rules in `detections/sigma/` are platform-agnostic and can be converted to your
target SIEM using [pySigma](https://github.com/SigmaHQ/pySigma):

```bash
# Install pySigma with your backend
pip install pysigma pysigma-backend-splunk

# Convert all OpenClaw rules to Splunk
sigma convert -t splunk detections/sigma/openclaw-*.yml \
    -o detections/siem/splunk/openclaw-from-sigma.spl

# Convert to Microsoft Sentinel KQL
pip install pysigma-backend-microsoft365defender
sigma convert -t microsoft365defender detections/sigma/openclaw-*.yml
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

# Verify hash chain is intact
python3 scripts/forensics/verify_hash_chain.py \
    --input ~/.openclaw/logs/telemetry.jsonl
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
