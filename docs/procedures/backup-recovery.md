# Backup and Recovery Procedure

**Document Type**: Operational Runbook  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Operations Team + Security Team  
**Related Policy**: [Operations Policy](../../configs/organization-policies/operations-policy.json)

This runbook defines backup and disaster recovery procedures for ClawdBot/OpenClaw deployments to ensure business continuity.

---

## Table of Contents

1. [Overview](#overview)
2. [Backup Strategy](#backup-strategy)
3. [Backup Procedures](#backup-procedures)
4. [Recovery Procedures](#recovery-procedures)
5. [Disaster Recovery](#disaster-recovery)
6. [Testing](#testing)
7. [Tools and Scripts](#tools-and-scripts)

---

## Overview

### Objectives

- **Protect** critical data from loss (hardware failure, ransomware, accidental deletion)
- **Recover** quickly from incidents (RTO: 4 hours, RPO: 1 hour)
- **Ensure** zero data loss for critical systems (transaction logs, audit trails)
- **Comply** with regulations (SOC 2, ISO 27001, GDPR data protection requirements)

### Recovery Targets

| System | RPO (Recovery Point Objective) | RTO (Recovery Time Objective) | Priority |
|--------|-------------------------------|-------------------------------|----------|
| **AI Agent (ClawdBot)** | 1 hour | 4 hours | P0 |
| **Credential Store** | 0 (synchronous replication) | 1 hour | P0 |
| **Conversation History** | 15 minutes | 2 hours | P1 |
| **Audit Logs** | 0 (write-ahead logging) | 8 hours | P1 |
| **Configuration Files** | 1 day | 1 hour | P2 |
| **Monitoring Data** | 1 hour | 24 hours | P3 |

**RPO**: Maximum acceptable data loss (how old is the backup?)  
**RTO**: Maximum acceptable downtime (how fast can we restore?)

---

## Backup Strategy

### 3-2-1 Backup Rule

- **3 Copies**: Production + 2 backups
- **2 Media Types**: Local disk + cloud storage
- **1 Off-Site**: Cloud backup in different region

```
Production Data
    ├─ Backup 1: Local NAS (hourly snapshots)
    ├─ Backup 2: Cloud Storage - Region 1 (hourly sync)
    └─ Backup 3: Cloud Storage - Region 2 (daily sync, off-site)
```

---

### What to Back Up

**Critical Data** (P0 - Must back up):
- **Credentials**: API keys, certificates, secrets (encrypted)
- **Audit Logs**: Immutable logs for compliance
- **Configuration**: Docker Compose, Kubernetes manifests, security policies
- **Skill Manifests**: Integrity hashes, signatures

**Important Data** (P1 - Should back up):
- **Conversation History**: User interactions (PII redacted per [Data Classification Policy](../policies/data-classification.md))
- **Agent State**: Running jobs, queued tasks
- **Monitoring Data**: Metrics, dashboards, alerts (for trend analysis)

**Nice to Have** (P2 - Can back up):
- **Logs**: Application logs (not required for compliance)
- **Temporary Files**: Caches, intermediate outputs

**Do NOT Back Up**:
- **Container Images**: Rebuilding from Dockerfile is preferred (supply chain integrity)
- **Dependencies**: Reinstall from package managers (with integrity checks)
- **Secrets in Plaintext**: Always encrypt before backing up

---

### Encryption

**All backups MUST be encrypted at rest** (see [Data Classification Policy](../policies/data-classification.md)):

```bash
# Encrypt backup with GPG
tar -czf - /data/openclaw | gpg --encrypt --recipient backup@company.com > backup.tar.gz.gpg

# Upload to cloud storage
aws s3 cp backup.tar.gz.gpg s3://company-backups/openclaw/$(date +%Y%m%d-%H%M%S).tar.gz.gpg \
  --sse AES256  # Server-side encryption
```

**Key Management**:
- Backup encryption keys stored in HSM or cloud KMS
- Key rotation: Annually
- Key escrow: Recovery keys held by CISO + CTO (split knowledge)

---

## Backup Procedures

### Automated Backups

#### Hourly: Incremental Backup

```bash
# Cron job: /etc/cron.d/openclaw-backup
0 * * * * /opt/openclaw/backup/hourly-backup.sh

# Script: hourly-backup.sh
#!/bin/bash
set -euo pipefail

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DIR="/backups/hourly"
DATA_DIR="/data/openclaw"

# Create incremental backup (rsync)
rsync -av --delete \
  --backup --backup-dir="$BACKUP_DIR/$TIMESTAMP" \
  "$DATA_DIR/" "$BACKUP_DIR/latest/"

# Rotate old backups (keep last 24 hours)
find "$BACKUP_DIR" -type d -mtime +1 -exec rm -rf {} \;

# Verify backup integrity
"$BACKUP_DIR/$TIMESTAMP/verify-integrity.sh"

echo "Hourly backup completed: $TIMESTAMP"
```

---

#### Daily: Full Backup to Cloud

```bash
# Cron job: /etc/cron.d/openclaw-backup-daily
0 2 * * * /opt/openclaw/backup/daily-backup.sh

# Script: daily-backup.sh
#!/bin/bash
set -euo pipefail

TIMESTAMP=$(date +%Y%m%d)
DATA_DIR="/data/openclaw"
BACKUP_FILE="openclaw-backup-$TIMESTAMP.tar.gz.gpg"

# Create encrypted tarball
tar -czf - "$DATA_DIR" | \
  gpg --encrypt --recipient backup@company.com > "/tmp/$BACKUP_FILE"

# Upload to S3 (primary region)
aws s3 cp "/tmp/$BACKUP_FILE" \
  "s3://company-backups-us-east-1/openclaw/$BACKUP_FILE" \
  --storage-class STANDARD_IA

# Upload to S3 (secondary region)
aws s3 cp "/tmp/$BACKUP_FILE" \
  "s3://company-backups-eu-west-1/openclaw/$BACKUP_FILE" \
  --storage-class GLACIER

# Cleanup
rm "/tmp/$BACKUP_FILE"

# Notify monitoring
curl -X POST https://healthcheck.io/openclaw-backup-daily
```

**Retention Policy**:
- Hourly backups: 24 hours (rolling window)
- Daily backups: 30 days
- Weekly backups (Sunday): 52 weeks
- Monthly backups (1st of month): 7 years (compliance requirement)

---

### Manual Backups

**Before risky operations** (major updates, migrations):

```bash
# On-demand backup
./configs/examples/backup-restore.sh backup \
  --tag pre-upgrade-v1.3.0 \
  --description "Backup before upgrading to v1.3.0" \
  --priority critical

# Stored at: /backups/manual/pre-upgrade-v1.3.0/
```

---

### Credential Backup

**Special handling for sensitive data**:

```bash
# Backup OS keychain (macOS)
security export-identities -k /Users/alice/Library/Keychains/login.keychain-db \
  -o keychain-backup.p12 -P "strong-passphrase"

# Encrypt with GPG (recipient: Security team)
gpg --encrypt --recipient security@company.com keychain-backup.p12

# Store in secure vault (not in regular backups)
aws s3 cp keychain-backup.p12.gpg \
  s3://company-secrets-vault/keychain-backups/alice-$(date +%Y%m%d).p12.gpg

# IMMEDIATELY delete plaintext file
shred -u keychain-backup.p12
```

**Credential Backup is NOT automated** (security risk). Manual export required quarterly.

---

## Recovery Procedures

### Disaster Levels

| Level | Definition | Response | Example |
|-------|------------|----------|---------|
| **L1 - Minor** | Single file loss | Restore from hourly backup | Accidentally deleted config file |
| **L2 - Major** | Service outage | Restore from daily backup | Database corruption |
| **L3 - Critical** | Data center failure | Failover to secondary region | AWS region outage |
| **L4 - Catastrophic** | Multi-region failure | Restore from offline backups | Ransomware attack |

---

### L1: File-Level Recovery

**Scenario**: Accidentally deleted a config file.

```bash
# List available backups
./configs/examples/backup-restore.sh list

# Output:
# 2026-02-14-14:00:00 (hourly)
# 2026-02-14-02:00:00 (daily)
# 2026-02-13-02:00:00 (daily)

# Restore single file
./configs/examples/backup-restore.sh restore-file \
  --backup-id 2026-02-14-14:00:00 \
  --file configs/templates/clawdbot.secure.yml \
  --destination /opt/openclaw/configs/

# Verify
diff /opt/openclaw/configs/clawdbot.secure.yml \
     configs/templates/clawdbot.secure.yml
```

**RTO**: 15 minutes  
**RPO**: 1 hour (last hourly backup)

---

### L2: Service-Level Recovery

**Scenario**: Agent service corrupted, needs full restore.

#### Step 1: Stop Service

```bash
# Stop ClawdBot service
docker-compose -f configs/examples/docker-compose-full-stack.yml down

# Or Kubernetes
kubectl delete deployment clawdbot -n openclaw
```

#### Step 2: Restore Data

```bash
# List available backups
./configs/examples/backup-restore.sh list --type daily

# Restore from last night's backup
./configs/examples/backup-restore.sh restore \
  --backup-id backup-2026-02-14 \
  --verify-integrity

# Restoration steps:
# 1. Download from S3
# 2. Decrypt with GPG
# 3. Extract tarball
# 4. Verify checksums
# 5. Copy to data directory
```

#### Step 3: Verify Data Integrity

```bash
# Check file integrity
./scripts/supply-chain/verify-checksums.sh \
  --directory /data/openclaw

# Verify conversation history (no corruption)
./scripts/verification/verify-conversation-history.sh

# Verify credentials (still accessible)
./scripts/verification/verify-credentials.sh
```

#### Step 4: Restart Service

```bash
# Restart ClawdBot
docker-compose -f configs/examples/docker-compose-full-stack.yml up -d

# Wait for health check
./scripts/verification/wait-for-healthy.sh --timeout 300

# Run smoke tests
./scripts/testing/smoke-tests.sh
```

**RTO**: 2-4 hours  
**RPO**: 1 hour (last hourly backup with sync)

---

### L3: Regional Failover

**Scenario**: AWS us-east-1 region outage.

#### Step 1: Declare Disaster

```bash
# Activate disaster recovery plan
./scripts/disaster-recovery/declare-disaster.sh \
  --level L3 \
  --reason "AWS us-east-1 outage" \
  --notify CISO,CTO,Operations

# Notifications sent via PagerDuty
```

#### Step 2: Failover to Secondary Region

```bash
# Switch DNS to secondary region (eu-west-1)
./scripts/disaster-recovery/failover-dns.sh \
  --from us-east-1 \
  --to eu-west-1

# DNS propagation: 5-15 minutes (TTL=300)
```

#### Step 3: Restore from Secondary Backups

```bash
# Download latest backup from eu-west-1
aws s3 cp \
  s3://company-backups-eu-west-1/openclaw/latest.tar.gz.gpg \
  /tmp/ \
  --region eu-west-1

# Restore data
./configs/examples/backup-restore.sh restore \
  --backup-file /tmp/latest.tar.gz.gpg \
  --target-region eu-west-1
```

#### Step 4: Deploy to Secondary Region

```bash
# Deploy infrastructure (Terraform)
cd infrastructure/terraform/
terraform workspace select eu-west-1
terraform apply -auto-approve

# Deploy ClawdBot
./scripts/deployment/deploy.sh \
  --env production \
  --region eu-west-1 \
  --skip-canary  # Emergency deployment
```

**RTO**: 4-8 hours  
**RPO**: 1 hour (last sync to secondary region)

---

### L4: Catastrophic Recovery

**Scenario**: Ransomware attack encrypted all data; restore from offline backups.

#### Step 1: Incident Response

**See**: [Incident Response Procedure](./incident-response.md)

```bash
# Isolate compromised systems
./scripts/incident-response/isolate-network.sh --all

# Kill all containers (prevent ransomware spread)
docker ps -q | xargs docker kill

# Collect forensics
./scripts/incident-response/forensics-collector.py \
  --incident-id RANSOMWARE-2026-001
```

#### Step 2: Wipe and Rebuild

```bash
# Full infrastructure rebuild
./scripts/disaster-recovery/rebuild-infrastructure.sh \
  --confirm "I understand this will destroy everything"

# Steps:
# 1. Delete all cloud resources (VMs, storage, databases)
# 2. Recreate from Terraform (infrastructure as code)
# 3. Deploy hardened base images
# 4. Apply security patches
```

#### Step 3: Restore from Offline Backup

```bash
# Retrieve offline backup (stored in Glacier)
aws s3api restore-object \
  --bucket company-backups-offline \
  --key openclaw/monthly-backup-2026-01-01.tar.gz.gpg \
  --restore-request Days=1  # Expedited retrieval: 1-5 minutes

# Wait for restore completion (email notification)

# Download and decrypt
aws s3 cp s3://company-backups-offline/openclaw/monthly-backup-2026-01-01.tar.gz.gpg /tmp/
gpg --decrypt /tmp/monthly-backup-2026-01-01.tar.gz.gpg | tar -xzf - -C /data/
```

#### Step 4: Rotate All Credentials

```bash
# Rotate all API keys (assume all compromised)
./scripts/credential-migration/rotate-all-keys.sh \
  --reason "RANSOMWARE-2026-001" \
  --scope all

# Regenerate certificates
./scripts/hardening/regenerate-certificates.sh --force
```

#### Step 5: Verify Security Posture

```bash
# Full security verification
./scripts/verification/verify_openclaw_security.sh

# Expected: 0 critical findings
```

**RTO**: 24-48 hours  
**RPO**: 1 month (last monthly backup; accept data loss for recent 30 days)

---

## Disaster Recovery

### DR Site Configuration

**Primary Site**: AWS us-east-1  
**DR Site**: AWS eu-west-1

**Synchronization**:
- Real-time: Audit logs (Kinesis streams)
- Hourly: Conversation history, agent state
- Daily: Full backup (encrypted)

**Failover Trigger**:
- Primary site unreachable for >15 minutes
- Data center disaster (fire, flood, power outage)
- Ransomware attack
- Manual trigger by CISO/CTO

---

### DR Runbook

**See**: [Disaster Recovery Section](./backup-recovery.md#disaster-recovery) (detailed procedures)

**Quick Reference**:
```bash
# Check DR readiness
./scripts/disaster-recovery/dr-readiness-check.sh

# Execute failover
./scripts/disaster-recovery/failover.sh --to eu-west-1

# Execute failback (restore to primary site)
./scripts/disaster-recovery/failback.sh --to us-east-1
```

---

## Testing

### Backup Testing Schedule

| Test Type | Frequency | Scope | Pass Criteria |
|-----------|-----------|-------|---------------|
| **File Restore** | Weekly | Single file recovery | RTO <15 min, data intact |
| **Service Restore** | Monthly | Full service recovery | RTO <4 hours, all tests pass |
| **Failover Test** | Quarterly | Regional failover | RTO <8 hours, zero data loss |
| **Full DR Drill** | Annually | Catastrophic recovery | RTO <48 hours, documented lessons learned |

---

### Monthly Backup Test

**Procedure**:
```bash
# Restore last night's backup to staging
./configs/examples/backup-restore.sh restore \
  --backup-id backup-2026-02-14 \
  --target staging \
  --verify-integrity

# Run integration tests
./scripts/testing/run-integration-tests.sh --env staging

# Verify data completeness
./scripts/verification/verify-backup-completeness.sh \
  --backup-id backup-2026-02-14

# Document results
./scripts/disaster-recovery/document-test.py \
  --test-id BACKUP-TEST-2026-02 \
  --result PASS \
  --rto-actual 2.5h \
  --notes "All 247 integration tests passed"
```

**Pass Criteria**:
- RTO: <4 hours actual
- RPO: <1 hour (no data loss beyond last backup)
- Data integrity: 100% checksums match
- Functionality: All integration tests pass

---

### Annual DR Drill

**Scenario**: Simulate complete data center failure.

**Participants**: Security, Operations, Engineering, Management

**Duration**: 8 hours (with 4-hour RTO target)

**Steps**:
1. **T-0**: Declare disaster (simulated)
2. **T+15min**: Activate DR plan, notify stakeholders
3. **T+1h**: Failover to secondary region
4. **T+4h**: Service restored in DR site
5. **T+6h**: Smoke tests complete, declare recovery success
6. **T+8h**: Post-drill review (lessons learned)

**Post-Drill Report**:
```markdown
# DR Drill Report: 2026 Annual Test

**Date**: January 15, 2026  
**Scenario**: Data center fire (simulated)  
**Outcomes**: SUCCESS (all objectives met)

**Metrics**:
- RTO Target: 8 hours | Actual: 5.5 hours ✅
- RPO Target: 1 hour | Actual: 45 minutes ✅
- Data Loss: 0 records ✅

**What Went Well**:
- Failover automation worked flawlessly
- Team coordination excellent
- Backup restoration faster than expected

**What Went Poorly**:
- DNS propagation slower than planned (15 min vs 5 min target)
- Initial confusion about credential rotation procedures
- Monitoring dashboard unavailable during first 30 minutes

**Action Items**:
- [ ] Lower DNS TTL to 60 seconds (Owner: DevOps, Due: Feb 1)
- [ ] Update credential rotation runbook (Owner: Security, Due: Feb 15)
- [ ] Deploy monitoring in multi-region (Owner: Operations, Due: Mar 1)
```

---

## Tools and Scripts

### Backup

```bash
# Automated backup
/opt/openclaw/backup/hourly-backup.sh  # Cron: hourly
/opt/openclaw/backup/daily-backup.sh   # Cron: daily 2 AM

# Manual backup
./configs/examples/backup-restore.sh backup --tag <name>

# Verify backup
./scripts/verification/verify-backup-integrity.sh --backup-id <id>
```

### Recovery

```bash
# List backups
./configs/examples/backup-restore.sh list

# Restore file
./configs/examples/backup-restore.sh restore-file \
  --backup-id <id> --file <path>

# Restore service
./configs/examples/backup-restore.sh restore \
  --backup-id <id> --verify-integrity
```

### Disaster Recovery

```bash
# DR readiness check
./scripts/disaster-recovery/dr-readiness-check.sh

# Failover to DR site
./scripts/disaster-recovery/failover.sh --to eu-west-1

# Failback to primary site
./scripts/disaster-recovery/failback.sh --to us-east-1
```

### Testing

```bash
# Backup restore test (monthly)
./scripts/disaster-recovery/test-backup-restore.sh --env staging

# Full DR drill (annually)
./scripts/disaster-recovery/execute-dr-drill.sh --scenario datacenter-failure
```

---

**Document Owner**: Operations Team + Security Team  
**Last DR Drill**: 2026-01-15 (Annual Test - PASS)  
**Next DR Drill**: 2027-01-15  
**Questions**: operations@company.com, security@company.com  
**Emergency**: ops-oncall@company.com (PagerDuty, 24/7)

**Related Documentation**:
- [Disaster Recovery Section](./backup-recovery.md#disaster-recovery)
- [Incident Response Procedure](./incident-response.md)
- [Operations Policy](../../configs/organization-policies/operations-policy.json)
