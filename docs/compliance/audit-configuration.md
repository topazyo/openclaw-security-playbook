# Audit Configuration and Logging

**Document Type**: Technical Configuration Guide  
**Version**: 1.0.0  
**Last Updated**: 2026-02-14  
**Owner**: Security Team + Compliance Team  
**Purpose**: Define audit logging requirements for compliance and security monitoring

This document specifies what events to log, where to store logs, retention requirements, and log review procedures.

---

## Table of Contents

1. [Overview](#overview)
2. [Logging Requirements](#logging-requirements)
3. [Log Storage and Protection](#log-storage-and-protection)
4. [Log Aggregation and SIEM](#log-aggregation-and-siem)
5. [Log Review Procedures](#log-review-procedures)
6. [Compliance Mappings](#compliance-mappings)
7. [Implementation Examples](#implementation-examples)

---

## Overview

### Purpose of Audit Logging

**Security**:
- Detect unauthorized access attempts
- Identify compromised credentials
- Trace attacker actions during incidents
- Support forensic investigations

**Compliance**:
- SOC 2: CC4.1 (monitoring activities), CC7.5 (incident remediation)
- ISO 27001: A.8.15 (logging), A.8.16 (monitoring activities)
- GDPR: Article 32 (security of processing), Article 33 (breach notification requires timeline of events)
- PCI DSS: Requirement 10 (track and monitor all access to network resources and cardholder data)

**Operations**:
- Troubleshoot application errors
- Capacity planning (resource usage trends)
- Performance optimization (identify bottlenecks)

---

### Audit Logging Principles

1. **Comprehensive**: Log all security-relevant events (authentication, authorization, data access, configuration changes, privileged actions)
2. **Immutable**: Logs cannot be modified or deleted by users (append-only, WORM storage)
3. **Tamper-evident**: Detect if logs have been tampered with (cryptographic hashing, log forwarding)
4. **Accessible**: Security team and auditors can access logs (RBAC, least privilege)
5. **Retained**: Logs retained per compliance requirements (7 years for SOC 2, ISO 27001)
6. **Monitored**: Automated alerts for critical events (failed authentication, privilege escalation)

---

## Logging Requirements

### What to Log

#### 1. Authentication Events

**Events to Log**:
- User login (successful and failed)
- User logout
- MFA enrollment, verification (success/failure)
- Password changes, resets
- Account lockouts (failed login threshold)
- Session creation, expiration

**Required Fields**:
- Timestamp (UTC, ISO 8601 format: `2026-02-14T10:30:00Z`)
- User ID (username or email)
- Source IP address
- User agent (browser/client)
- Authentication method (password+MFA, API key, certificate)
- Result (success/failure)
- Failure reason (if applicable: incorrect password, MFA failed, account locked)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T10:30:00Z",
  "event_type": "authentication",
  "action": "login",
  "user_id": "user@example.com",
  "source_ip": "203.0.113.42",
  "user_agent": "Mozilla/5.0 ...",
  "auth_method": "password_mfa",
  "result": "success",
  "session_id": "sess-abc123"
}
```

**Compliance References**:
- SOC 2: CC6.1 (logical access)
- ISO 27001: A.8.3 (information access restriction)
- GDPR: Article 32 (security of processing - detect unauthorized access)

---

#### 2. Authorization Events

**Events to Log**:
- Permission grants (role assignments, group memberships)
- Permission revocations (role removals, access reviews)
- Access denials (unauthorized access attempts)
- Privileged access grants (JIT access, temporary admin privileges)
- Privileged access usage (what admin did with elevated privileges)

**Required Fields**:
- Timestamp
- User ID (who was granted/denied access)
- Grantor ID (who granted access, or "system" if automatic)
- Resource (what access was granted to: production environment, API key, data)
- Permission level (read, write, admin)
- Result (granted, denied)
- Justification (for privileged access: ticket number, business reason)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T11:00:00Z",
  "event_type": "authorization",
  "action": "grant_role",
  "user_id": "new_developer@example.com",
  "grantor_id": "manager@example.com",
  "resource": "staging_environment",
  "role": "developer",
  "result": "granted",
  "approval_ticket": "JIRA-1234"
}
```

**Compliance References**:
- SOC 2: CC6.1 (logical access), CC6.3 (authorization)
- ISO 27001: A.8.2 (privileged access rights), A.8.3 (information access restriction)

---

#### 3. Data Access Events

**Events to Log** (for Confidential and Restricted data per [Data Classification Policy](../policies/data-classification.md)):
- Read access (view conversation history, API keys, configuration)
- Write access (modify data)
- Delete access (delete conversation history, revoke API keys)
- Export access (download data, API queries returning data)
- Bulk operations (export all data, mass updates)

**Required Fields**:
- Timestamp
- User ID (who accessed data)
- Resource (what data: `conversation_history`, `api_keys`, `user_pii`)
- Data classification level (Internal, Confidential, Restricted)
- Action (read, write, delete, export)
- Record count (for bulk operations: number of records accessed)
- Source IP
- Client (web UI, API, CLI)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T12:00:00Z",
  "event_type": "data_access",
  "action": "read",
  "user_id": "operator@example.com",
  "resource": "conversation_history",
  "resource_owner": "user123",
  "classification": "confidential",
  "source_ip": "10.0.1.50",
  "client": "web_ui"
}
```

**Compliance References**:
- GDPR: Article 32 (log access to personal data for accountability)
- PCI DSS: Requirement 10.2.2 (log all actions by privileged users)
- SOC 2: CC6.1 (logical access)

---

#### 4. Configuration Changes

**Events to Log**:
- System configuration changes (network settings, security settings)
- Application configuration changes (feature flags, settings)
- Infrastructure changes (Terraform/Ansible deployments)
- Policy changes (update security policies, access control rules)
- Firewall rule changes (add/remove rules)
- Encryption key rotation

**Required Fields**:
- Timestamp
- User ID (who made change, or "system" if automatic)
- Resource (what was changed: `firewall_rules`, `rbac_policy`, `encryption_key`)
- Change type (create, update, delete)
- Old value (before change, if applicable)
- New value (after change, if applicable)
- Approval reference (CAB ticket, change request number)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T13:00:00Z",
  "event_type": "configuration_change",
  "action": "update",
  "user_id": "admin@example.com",
  "resource": "firewall_rules",
  "resource_id": "rule-123",
  "old_value": {"port": "8080", "source": "0.0.0.0/0"},
  "new_value": {"port": "8080", "source": "10.0.0.0/8"},
  "approval_ticket": "CAB-5678",
  "change_description": "Restrict access to internal network only"
}
```

**Compliance References**:
- SOC 2: CC8.1 (change management)
- ISO 27001: A.8.9 (configuration management), A.8.32 (change management)

---

#### 5. Privileged Actions

**Events to Log** (for users with Admin or Root privileges):
- Sudo commands (Linux/macOS)
- PowerShell commands (Windows, if running as Administrator)
- Database admin actions (schema changes, user grants)
- Cloud console actions (AWS/Azure/GCP admin operations)
- Container exec (kubectl exec, docker exec into containers)
- Secret access (read API keys, credentials from vault)

**Required Fields**:
- Timestamp
- User ID (who executed command)
- Privileged user (root, Administrator, service account)
- Command (full command line)
- Working directory
- Exit code (success/failure)
- Duration (how long command took)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T14:00:00Z",
  "event_type": "privileged_action",
  "action": "sudo_command",
  "user_id": "sysadmin@example.com",
  "privileged_user": "root",
  "command": "systemctl restart clawdbot.service",
  "working_directory": "/home/sysadmin",
  "exit_code": 0,
  "duration_ms": 1234
}
```

**Compliance References**:
- SOC 2: CC6.4 (privileged access)
- ISO 27001: A.8.2 (privileged access rights), A.8.18 (use of privileged utility programs)
- PCI DSS: Requirement 10.2.2 (all actions by privileged users)

---

#### 6. Security Events

**Events to Log**:
- Firewall blocks (inbound/outbound connections denied)
- IDS/IPS alerts (intrusion detection, malware, anomalies)
- Anti-malware detections (malware found, quarantined)
- DLP blocks (openclaw-shield blocks credential exfiltration, PII leakage)
- Vulnerability scan results (findings, risk scores)
- Security policy violations (failed compliance checks)

**Required Fields**:
- Timestamp
- Event source (firewall, IDS, anti-malware, DLP)
- Severity (critical, high, medium, low, informational)
- Description (what was detected/blocked)
- Source IP (for network events)
- Destination IP/port (for network events)
- User ID (if applicable)
- Action taken (blocked, quarantined, alerted)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T15:00:00Z",
  "event_type": "security_event",
  "source": "openclaw_shield",
  "severity": "high",
  "description": "PII detected in prompt and redacted",
  "user_id": "user@example.com",
  "pii_type": "email_address",
  "action": "redacted",
  "original_prompt_hash": "sha256:abc123..."
}
```

**Compliance References**:
- SOC 2: CC7.2 (monitoring of system operations), CC7.3 (incident detection)
- ISO 27001: A.8.16 (monitoring activities), A.8.7 (protection against malware)

---

#### 7. Application Events

**Events to Log** (ClawdBot/OpenClaw specific):
- AI agent invocations (user sends prompt to ClawdBot)
- Skill installations (user adds new skill)
- Skill executions (skill called during agent workflow)
- MCP server connections (agent connects to MCP server)
- API calls to Anthropic (Claude API requests)
- Conversation history access (user views/exports past conversations)
- Backup operations (manual or scheduled backups)

**Required Fields**:
- Timestamp
- User ID
- Action (agent_invoke, skill_install, skill_execute, etc.)
- Resource (skill name, MCP server, conversation ID)
- Result (success, failure, partial)
- Duration (response time)
- Token count (for AI API calls: prompt tokens, completion tokens)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T16:00:00Z",
  "event_type": "application",
  "action": "agent_invoke",
  "user_id": "user@example.com",
  "conversation_id": "conv-789",
  "model": "claude-opus-4",
  "prompt_tokens": 150,
  "completion_tokens": 300,
  "duration_ms": 2500,
  "result": "success"
}
```

---

#### 8. System Events

**Events to Log**:
- System starts/stops (server boot, container start/stop)
- Service starts/stops (clawdbot.service, gateway.service)
- Resource alerts (high CPU, low disk space, OOM killer)
- Backup success/failure
- Health check failures
- Certificate expiry warnings (30 days, 7 days before expiry)

**Required Fields**:
- Timestamp
- Host (server/container hostname)
- Event (service_start, backup_complete, certificate_expiring)
- Severity (info, warning, error, critical)
- Details (error message, resource usage, etc.)

**Example Log Entry** (JSON):
```json
{
  "timestamp": "2026-02-14T17:00:00Z",
  "event_type": "system",
  "host": "clawdbot-prod-01",
  "service": "clawdbot.service",
  "action": "service_start",
  "severity": "info",
  "details": "Service started successfully after configuration reload"
}
```

---

### What NOT to Log

**Sensitive Data** (NEVER log plaintext):
- Passwords, password hashes (log authentication success/failure, not password itself)
- API keys, access tokens (log key ID/prefix, not full key: `key_abc***`)
- Credit card numbers, SSNs (log masked: `****1234`)
- Full conversation content (log conversation ID, token count, not actual prompts/responses unless required for debugging - then classify as Restricted)

**Rationale**: Logs themselves become high-value targets if they contain credentials/PII

**Masking Examples**:
```json
// WRONG (logs plaintext credential)
{"user": "user@example.com", "api_key": "sk_live_abc123def456"}

// RIGHT (logs key prefix only)
{"user": "user@example.com", "api_key_prefix": "sk_live_abc***"}
```

---

## Log Storage and Protection

### Log Destinations

**Local Logs** (per server/container):
- **Path**: `/var/log/clawdbot/` (Linux), `C:\ProgramData\ClawdBot\logs\` (Windows)
- **Retention**: 30 days local (then deleted to save disk space)
- **Rotation**: Daily log rotation, gzip compression
- **Protection**: Read-only to application (app writes via append-only logging library), read-only to admins (no modification)

**Centralized Logs** (aggregated):
- **Destination**: SIEM or log aggregator (see [monitoring-stack.yml](../../configs/examples/monitoring-stack.yml))
- **Options**: ELK Stack (Elasticsearch, Logstash, Kibana), Splunk, AWS CloudWatch Logs, Azure Log Analytics, Grafana Loki
- **Retention**: 7 years (compliance requirement)
- **Protection**: Immutable storage (WORM - Write Once Read Many), encrypted at rest (AES-256)

**Backup Logs**:
- **Destination**: S3 (AWS), Azure Blob Storage, GCS (Google Cloud Storage)
- **Format**: Compressed JSON (gzip)
- **Encryption**: AES-256 (server-side encryption) + GPG (client-side for extra protection)
- **Access control**: Restricted to Security Team and DPO only
- **Retention**: 7 years (then deleted per retention policy)

---

### Log Immutability

**Why**: Prevent attackers from covering tracks by deleting/modifying logs

**Implementation Options**:

1. **WORM Storage** (Write Once Read Many):
   - S3 Object Lock (AWS) with Compliance mode (cannot be deleted, even by root)
   - Azure Immutable Blob Storage (Legal Hold or Time-based retention)
   - Glacier Vault Lock (AWS, for long-term archival)

2. **Append-Only Logging**:
   - Application logs via append-only file descriptor (cannot seek backward to modify)
   - Syslog protocol (UDP forwarding, original logs intact even if server compromised)

3. **Log Forwarding** (real-time):
   - Forward logs to SIEM immediately (attacker cannot delete logs already forwarded)
   - Use TLS (encrypted channel, prevent tampering in transit)
   - Mutual TLS (MTLS) for log forwarder authentication

4. **Cryptographic Hashing**:
   - Hash each log entry (SHA-256)
   - Store hashes in blockchain or separate immutable store
   - Tamper detection: Rehash logs, compare to stored hashes (if mismatch, logs were modified)

**Recommended**: Combination of log forwarding (immediate SIEM ingestion) + WORM storage (S3 Object Lock)

**Configuration Example** (filebeat shipping logs to Elasticsearch):
```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    paths:
      - /var/log/clawdbot/*.log
    json.keys_under_root: true
    json.add_error_key: true

output.elasticsearch:
  hosts: ["https://elasticsearch.internal:9200"]
  protocol: "https"
  ssl.certificate_authorities: ["/etc/pki/ca.crt"]
  ssl.certificate: "/etc/pki/client.crt"
  ssl.key: "/etc/pki/client.key"
  index: "clawdbot-logs-%{+yyyy.MM.dd}"

# Elasticsearch ILM (Index Lifecycle Management) policy
# Logs transition to frozen tier after 90 days (readonly, cheap storage)
# Delete after 7 years (2555 days)
```

**Evidence**:
- WORM configuration (S3 Object Lock policies)
- Log forwarding configuration (filebeat.yml, monitored by Ansible)
- Immutability verification (quarterly audit - attempt to modify logs, verify failure)

**Reference**: [Audit Configuration JSON](../../configs/organization-policies/audit-configuration.json)

---

### Log Encryption

**Encryption at Rest**:
- **SIEM/Log aggregator**: Elasticsearch encryption at rest (encryption module or encrypted EBS/Azure Disk)
- **Backup logs**: S3 server-side encryption (SSE-S3 or SSE-KMS) + GPG encryption before upload

**Encryption in Transit**:
- **Log forwarding**: TLS 1.2+ (filebeat → Elasticsearch, syslog → SIEM)
- **Log access**: HTTPS (Kibana, Grafana, SIEM web UI)

**Key Management**:
- Encryption keys: AWS KMS, Azure Key Vault (automatic key rotation)
- GPG keys: Stored in secrets manager, access restricted to backup/restore scripts

**Evidence**:
- Encryption configuration (filebeat TLS, S3 encryption policies)
- Key rotation logs (KMS, GPG key expiry tracking)

---

### Access Control

**Who Can Access Logs**:
- **Security Team**: Full access (read all logs, search, export)
- **DPO**: Read access (for GDPR compliance, data subject rights)
- **Auditors**: Read access (time-limited, during audit period)
- **Developers**: No access to production logs (only staging/dev logs)
- **Operators**: Read access to application logs (for troubleshooting), no access to audit logs

**RBAC Enforcement**:
- Elasticsearch: Security module (role-based access to indices)
- Kibana: Spaces and roles (different teams see different dashboards)
- S3: IAM policies (least privilege)

**Privileged Access**:
- Access to backup logs (S3): JIT access only (4-hour grant)
- Access to SIEM admin: Dual approval (Security Manager + CISO)

**Audit Log of Log Access**:
- Meta-logging: Log who accessed logs (SIEM access logs, S3 access logs)
- Review: Quarterly review of log access (detect unauthorized access to logs)

**Evidence**:
- RBAC configuration (Elasticsearch roles, IAM policies)
- Log access logs (who accessed logs, when)
- Quarterly access reviews (log access audited)

---

## Log Aggregation and SIEM

### Architecture

**Log Sources** → **Log Shippers** → **SIEM** → **Alerting/Dashboards**

**Log Sources**:
- Application logs (ClawdBot, Gateway)
- System logs (syslog, Windows Event Log)
- Container logs (Docker, Kubernetes)
- Cloud provider logs (AWS CloudTrail, Azure Activity Log)
- Security tools (openclaw-shield, openclaw-telemetry, openclaw-detect)
- Network devices (firewall, VPN)

**Log Shippers**:
- Filebeat (ships files to Elasticsearch)
- Fluentd (collects, transforms, forwards logs)
- AWS CloudWatch Logs (AWS native)
- Azure Monitor (Azure native)

**SIEM**:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- AWS Security Lake
- Microsoft Sentinel (Azure)

**Alerting**:
- Elastic Alerts (Elasticsearch alerting)
- PagerDuty (for critical alerts)
- Email/Slack (for warnings)

**Reference**: [Monitoring Stack Configuration](../../configs/examples/monitoring-stack.yml)

---

### Log Parsing and Normalization

**Challenge**: Logs come in different formats (syslog, JSON, plain text, Windows Event XML)

**Solution**: Parse and normalize to common schema (Elastic Common Schema - ECS recommended)

**ECS Fields**:
- `@timestamp`: ISO 8601 timestamp (UTC)
- `event.action`: What happened (login, file_access, sudo_command)
- `event.outcome`: Result (success, failure)
- `user.name`: Who did it (user ID, username)
- `source.ip`: Where from (IP address)
- `destination.ip`: Where to (for network events)
- `file.path`: File accessed (for data access events)

**Logstash Pipeline Example** (parse application JSON logs):
```ruby
# logstash.conf
input {
  beats {
    port => 5044
    ssl => true
    ssl_certificate => "/etc/pki/server.crt"
    ssl_key => "/etc/pki/server.key"
  }
}

filter {
  json {
    source => "message"
  }
  
  # Normalize to ECS
  mutate {
    rename => {
      "user_id" => "[user][name]"
      "source_ip" => "[source][ip]"
      "event_type" => "[event][category]"
      "action" => "[event][action]"
      "result" => "[event][outcome]"
    }
  }
  
  # Enrich with GeoIP (for source IP)
  geoip {
    source => "[source][ip]"
    target => "[source][geo]"
  }
  
  # Add severity score (for alerting)
  if [event][category] == "authentication" and [event][outcome] == "failure" {
    mutate { add_field => { "event.severity" => 6 } }
  }
}

output {
  elasticsearch {
    hosts => ["https://elasticsearch.internal:9200"]
    index => "clawdbot-logs-%{+yyyy.MM.dd}"
    ssl => true
    cacert => "/etc/pki/ca.crt"
  }
}
```

**Evidence**:
- Logstash configuration (version controlled)
- Sample normalized logs (verify ECS compliance)

---

### Log Retention Tiers

**Hot Tier** (0-30 days):
- **Storage**: SSD (fast queries)
- **Access**: Frequent (real-time dashboards, alerting)
- **Cost**: High (expensive storage)

**Warm Tier** (31-90 days):
- **Storage**: HDD (slower queries acceptable)
- **Access**: Occasional (historical analysis, investigations)
- **Cost**: Medium

**Cold Tier** (91 days - 7 years):
- **Storage**: Object storage (S3, Azure Blob)
- **Access**: Rare (compliance, audits, legal holds)
- **Cost**: Low (cheap long-term storage)
- **Format**: Compressed JSON (gzip), WORM storage

**Frozen Tier** (7 years+):
- **Action**: Delete (per retention policy)
- **Exception**: Legal hold (if litigation pending, retain indefinitely until hold lifted)

**ILM Policy** (Elasticsearch Index Lifecycle Management):
```json
{
  "policy": "clawdbot-logs-policy",
  "phases": {
    "hot": {
      "min_age": "0ms",
      "actions": {
        "rollover": {
          "max_age": "1d",
          "max_size": "50gb"
        }
      }
    },
    "warm": {
      "min_age": "30d",
      "actions": {
        "shrink": { "number_of_shards": 1 },
        "forcemerge": { "max_num_segments": 1 }
      }
    },
    "cold": {
      "min_age": "90d",
      "actions": {
        "freeze": {},
        "searchable_snapshot": {
          "snapshot_repository": "s3_backup"
        }
      }
    },
    "delete": {
      "min_age": "2555d",
      "actions": {
        "delete": {}
      }
    }
  }
}
```

**Evidence**:
- ILM policy configuration (Elasticsearch)
- Storage tier metrics (cost per tier, data volume)
- Retention compliance verification (logs >7 years deleted)

---

## Log Review Procedures

### Daily Review (Security Analyst)

**Who**: Security Analyst (on-call rotation)  
**When**: Every business day (Monday-Friday), 9:00 AM local time  
**Duration**: 30 minutes

**Review Checklist**:
1. **Authentication anomalies**:
   - Failed login spikes (>10 failures for single user → alerting rule)
   - Logins from unusual locations (GeoIP: new country)
   - Logins at unusual times (3 AM on Sunday)
   
2. **Authorization anomalies**:
   - Privilege escalation (user suddenly has admin role)
   - Access denials (spikes in 403 Forbidden errors)
   
3. **Security alerts**:
   - DLP blocks (openclaw-shield)
   - IDS/IPS alerts (AWS GuardDuty)
   - Anti-malware detections
   
4. **System health**:
   - Service failures (restarts, crashes)
   - Disk space warnings
   - Certificate expiry warnings

**Dashboards**: Kibana dashboard "Daily Security Review" (pre-configured queries)

**Actions**:
- False positive: Document why (e.g., "CEO traveling to Japan, login from Tokyo expected")
- Investigate: Create incident ticket (JIRA), escalate if needed
- Tune alerting: Adjust thresholds to reduce false positives

**Evidence**:
- Daily review sign-off (checkbox in JIRA, "Daily Review 2026-02-14 - No issues")
- Investigation tickets (for anomalies detected)

---

### Weekly Review (Security Team Lead)

**Who**: Security Team Lead  
**When**: Every Monday, 10:00 AM  
**Duration**: 1 hour

**Review Checklist**:
1. **Trend analysis**:
   - Authentication failures (trending up? Brute force attack?)
   - API usage (capacity planning)
   - Security events (more IDS alerts this week?)
   
2. **Access reviews**:
   - New accounts created (expected?)
   - Privileged access grants (JIT access - all approved?)
   - Access revocations (terminated users - all access revoked?)
   
3. **Vulnerability management**:
   - New vulnerabilities discovered (scan results)
   - Remediation SLA compliance (P0 fixed within 24h?)
   
4. **Incident follow-up**:
   - Open incidents (status update)
   - Action items from PIR (completed?)

**Reports**: Automated weekly report (email from SIEM)

**Actions**:
- Report to CISO (summary email)
- Escalate risks (if trends concerning)
- Update runbooks (lessons learned)

**Evidence**:
- Weekly report (archived)
- CISO email summary (sent)

---

### Quarterly Review (CISO + Compliance)

**Who**: CISO, DPO, Compliance Officer  
**When**: Last week of quarter (March, June, September, December)  
**Duration**: 3 hours

**Review Checklist**:
1. **Compliance audit**:
   - Log retention compliance (7 years retained?)
   - Log immutability (WORM configured?)
   - Access control (only authorized users access logs?)
   
2. **Access reviews** (see [Access Review Procedure](../procedures/access-review.md)):
   - Review all user accounts (still need access?)
   - Review log access (who accessed logs? Authorized?)
   
3. **Metrics**:
   - Mean Time to Detect (MTTD) incidents
   - Mean Time to Respond (MTTR) incidents
   - False positive rate (alerting)
   - Log volume (capacity planning)
   
4. **Policy review**:
   - Audit configuration (this document) up to date?
   - Logging requirements still sufficient?

**Evidence**:
- Quarterly review report (presented to Board Audit Committee)
- Access review certifications (managers sign off)
- Policy review sign-offs (if policies updated)

---

### Annual Review (External Auditor)

**Who**: External auditor (SOC 2, ISO 27001)  
**When**: Q1 (January audit fieldwork)  
**Duration**: 1 week (auditor on-site/remote)

**Auditor Requests**:
- Provide log samples (authentication, authorization, data access, configuration changes)
- Demonstrate log immutability (attempt to modify log, verify failure)
- Demonstrate access controls (show RBAC, test unauthorized access)
- Demonstrate retention (show logs from 7 years ago still exist)
- Demonstrate log review (show daily/weekly/quarterly review records)

**Evidence Archive**: `/compliance/audit-evidence/logs/`

**Auditor Findings**:
- Non-conformities: Corrective action plans (CAP) created, tracked to completion
- Observations: Best practice recommendations, consider for next year

**Evidence**:
- Audit report (SOC 2, ISO 27001)
- CAP tracker (non-conformities, completion dates)

---

## Compliance Mappings

### SOC 2 Controls

| SOC 2 Control | Audit Requirement | Implementation |
|---------------|-------------------|----------------|
| **CC4.1** (Monitoring) | Organization obtains information to support operation of controls | SIEM aggregates logs from all sources, daily review by Security Analyst |
| **CC6.1** (Logical Access) | Authentication/authorization logged | Authentication events (login/logout/MFA), authorization events (role grants/denials) |
| **CC6.4** (Privileged Access) | Privileged access logged | Sudo commands, admin console actions, secret access logged |
| **CC7.2** (System Operations) | System operations monitored | Application events, system events (service starts/stops, health checks) |
| **CC7.3** (Incident Detection) | Security events detected | IDS/IPS alerts, DLP blocks, vulnerability scans, behavioral anomalies |
| **CC7.5** (Incident Remediation) | Incidents responded to | Incident response logs (containment, eradication, recovery actions) |
| **CC8.1** (Change Management) | Changes logged | Configuration changes, deployments, CAB approvals |

**Evidence**: [SOC 2 Controls Mapping](./soc2-controls.md)

---

### ISO 27001 Controls

| ISO 27001 Control | Audit Requirement | Implementation |
|-------------------|-------------------|----------------|
| **A.8.15** (Logging) | Logs record activities, exceptions, faults | All event types logged (authentication, authorization, data access, config changes, privileged actions, security events, application events, system events) |
| **A.8.16** (Monitoring Activities) | Networks, systems, applications monitored for anomalous behavior | SIEM with behavioral analytics, openclaw-telemetry anomaly detection |
| **A.5.28** (Collection of Evidence) | Evidence identified, collected, preserved | Audit logs immutable (WORM), retained 7 years, chain of custody maintained |
| **A.5.33** (Protection of Records) | Records protected from loss, destruction, falsification, unauthorized access | Immutable storage (S3 Object Lock), encrypted (AES-256), access restricted (RBAC), backed up (3-2-1 strategy) |
| **A.8.2** (Privileged Access Rights) | Privileged access logged | Sudo commands, admin actions, secret access logged with full command line |
| **A.8.3** (Information Access Restriction) | Access to information logged | Data access events (read/write/delete of Confidential/Restricted data) |

**Evidence**: [ISO 27001 Controls Mapping](./iso27001-controls.md)

---

### GDPR Requirements

| GDPR Article | Requirement | Implementation |
|--------------|-------------|----------------|
| **Article 32** (Security of Processing) | Implement measures to ensure security, including ability to restore availability | Logs support incident detection, backup/recovery procedures (see [Backup and Recovery](../procedures/backup-recovery.md)) |
| **Article 33** (Breach Notification to DPA) | Document facts of breach, effects, remedial action | Audit logs provide breach timeline (when detected, what data, containment actions) |
| **Article 30** (Records of Processing) | Maintain records of processing activities | Logs document data access (who accessed what personal data, when) for accountability |
| **Article 5(2)** (Accountability) | Demonstrate compliance | Logs provide evidence of security controls (MFA usage, access controls, PII redaction by openclaw-shield) |

**Evidence**: [GDPR Compliance Guide](./gdpr-compliance.md)

---

### PCI DSS Requirements (if applicable)

**Requirement 10**: Track and monitor all access to network resources and cardholder data

**Applicable if**: ClawdBot processes payment card data (unlikely for AI agent, but document if applicable)

| PCI DSS Requirement | Implementation |
|---------------------|----------------|
| **10.1** (Audit Trails) | Link all access to individual users | user_id field in all log entries |
| **10.2.1** (Logged Events) | All individual user accesses to cardholder data | Data access events (if cardholder data classified as Restricted) |
| **10.2.2** (Privileged Actions) | All actions by privileged users | Privileged action logging (sudo, admin console) |
| **10.2.3** (Audit Trail Access) | All access to audit trails | Log access logs (meta-logging), quarterly access reviews |
| **10.2.7** (Security Mechanism Events) | Initialization, stopping, pausing of audit logs | System events (service starts/stops, including log shippers) |
| **10.3** (Log Entry Elements) | User ID, event type, date/time, success/failure, origination, identity of affected data | All required fields present in log entries |
| **10.5** (Protect Audit Trails) | Cannot be altered | WORM storage, log forwarding, immutable Elasticsearch indices |
| **10.6** (Review Logs) | Daily review by security personnel | Daily review checklist (Security Analyst) |
| **10.7** (Retain Audit Trail History) | Retain at least one year, 3 months readily available | 7 years total retention (exceeds PCI DSS requirement), 90 days in hot/warm tiers (readily available) |

**Evidence**: PCI DSS compliance (if applicable, engagement letter with QSA, ROC report)

---

## Implementation Examples

### Example 1: Logging Authentication (Python)

**Application Code** (Flask web app):
```python
import logging
import logging.handlers
import json
from datetime import datetime

# Configure JSON logging
logger = logging.getLogger('clawdbot.auth')
logger.setLevel(logging.INFO)

# File handler (local logs)
file_handler = logging.handlers.RotatingFileHandler(
    '/var/log/clawdbot/auth.log',
    maxBytes=100*1024*1024,  # 100 MB
    backupCount=30  # Keep 30 days
)
file_handler.setFormatter(logging.Formatter('%(message)s'))  # JSON only, no extra formatting
logger.addHandler(file_handler)

# Syslog handler (forward to SIEM)
syslog_handler = logging.handlers.SysLogHandler(address=('siem.internal', 514))
syslog_handler.setFormatter(logging.Formatter('%(message)s'))
logger.addHandler(syslog_handler)


def log_authentication(user_id, source_ip, user_agent, auth_method, result, failure_reason=None):
    """Log authentication event in JSON format"""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + 'Z',
        "event_type": "authentication",
        "action": "login",
        "user_id": user_id,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "auth_method": auth_method,
        "result": result,  # "success" or "failure"
    }
    
    if failure_reason:
        log_entry["failure_reason"] = failure_reason
    
    # Log as JSON (one line, parseable)
    logger.info(json.dumps(log_entry))


# Usage in login endpoint
@app.route('/login', methods=['POST'])
def login():
    user_id = request.form['email']
    password = request.form['password']
    source_ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    # Authenticate user
    user = authenticate(user_id, password)
    
    if user:
        log_authentication(
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            auth_method="password_mfa",
            result="success"
        )
        return redirect('/dashboard')
    else:
        log_authentication(
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent,
            auth_method="password",
            result="failure",
            failure_reason="incorrect_password"
        )
        return render_template('login.html', error='Invalid credentials')
```

**Log Output** (JSON, one per line):
```json
{"timestamp": "2026-02-14T10:30:00Z", "event_type": "authentication", "action": "login", "user_id": "user@example.com", "source_ip": "203.0.113.42", "user_agent": "Mozilla/5.0 ...", "auth_method": "password_mfa", "result": "success"}
{"timestamp": "2026-02-14T10:31:00Z", "event_type": "authentication", "action": "login", "user_id": "attacker@evil.com", "source_ip": "198.51.100.10", "user_agent": "curl/7.64.1", "auth_method": "password", "result": "failure", "failure_reason": "incorrect_password"}
```

---

### Example 2: Logging Data Access (Express.js API)

**API Endpoint** (conversation history export):
```javascript
const winston = require('winston');

// Configure Winston logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  defaultMeta: { service: 'clawdbot-api' },
  transports: [
    new winston.transports.File({ filename: '/var/log/clawdbot/api.log' }),
    new winston.transports.Syslog({ host: 'siem.internal', port: 514 })
  ]
});

// Middleware: Log data access
function logDataAccess(req, res, next) {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Log after response is sent (so we know if successful)
    logger.info({
      timestamp: new Date().toISOString(),
      event_type: 'data_access',
      action: req.method === 'GET' ? 'read' : (req.method === 'DELETE' ? 'delete' : 'write'),
      user_id: req.user.email,  // From authentication middleware
      resource: req.path,
      classification: 'confidential',  // Conversation history is Confidential
      source_ip: req.ip,
      client: 'api',
      result: res.statusCode < 400 ? 'success' : 'failure',
      http_status: res.statusCode
    });
    
    originalSend.call(this, data);
  };
  
  next();
}

// API endpoint: Export conversation history
app.get('/api/conversations/export', authenticate, authorize('user'), logDataAccess, async (req, res) => {
  try {
    const conversations = await getConversationHistory(req.user.id);
    
    res.json({
      user_id: req.user.id,
      conversation_history: conversations,
      exported_at: new Date().toISOString()
    });
  } catch (error) {
    res.status(500).json({ error: 'Export failed' });
  }
});
```

---

### Example 3: Logging Privileged Actions (Bash script with sudo)

**Script** (rotate API keys):
```bash
#!/bin/bash
# rotate_api_keys.sh - Rotate API keys for all users

set -euo pipefail

# Log privileged action
log_privileged_action() {
    local action="$1"
    local details="$2"
    local exit_code="$3"
    
    logger -t clawdbot-admin -p auth.info --id=$$ \
        "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"event_type\":\"privileged_action\",\"action\":\"$action\",\"user_id\":\"$USER\",\"privileged_user\":\"$(whoami)\",\"command\":\"$0 $*\",\"working_directory\":\"$(pwd)\",\"exit_code\":$exit_code,\"details\":\"$details\"}"
}

# Trap exit to log completion
trap 'log_privileged_action "rotate_api_keys" "Script completed" $?' EXIT

echo "Rotating API keys for all users..."

# Require sudo
if [ "$EUID" -ne 0 ]; then
    echo "Error: Must run as root (sudo)"
    exit 1
fi

# Rotate keys (implementation...)
# ...

log_privileged_action "rotate_api_keys" "Keys rotated successfully" 0
echo "API keys rotated successfully"
```

**Run with sudo**:
```bash
sudo ./rotate_api_keys.sh
```

**Log Output** (syslog):
```
Feb 14 10:30:00 clawdbot-prod-01 clawdbot-admin[12345]: {"timestamp":"2026-02-14T10:30:00Z","event_type":"privileged_action","action":"rotate_api_keys","user_id":"sysadmin","privileged_user":"root","command":"./rotate_api_keys.sh","working_directory":"/opt/clawdbot","exit_code":0,"details":"Keys rotated successfully"}
```

---

### Example 4: Kibana Dashboard for Daily Review

**Dashboard**: "Daily Security Review"

**Visualizations**:

1. **Failed Logins (Last 24h)** (bar chart):
   - X-axis: Time (hourly buckets)
   - Y-axis: Count of failed logins
   - Filter: `event.action: "login" AND event.outcome: "failure"`
   - Alert: Spike >50 failures per hour

2. **Logins by Country (Last 24h)** (map):
   - GeoIP visualization (source.geo.country_name)
   - Filter: `event.action: "login" AND event.outcome: "success"`
   - Alert: Login from new country (not seen in last 90 days)

3. **Privileged Actions (Last 24h)** (table):
   - Columns: timestamp, user.name, privileged_user, command
   - Filter: `event.type: "privileged_action"`
   - Review: Ensure all sudo commands are expected

4. **DLP Blocks (Last 24h)** (count):
   - Metric: Count of `source: "openclaw_shield" AND action: "blocked"`
   - Alert: Any DLP block (investigate immediately)

5. **Security Alerts (Last 24h)** (table):
   - Columns: timestamp, source (IDS/IPS/anti-malware), severity, description
   - Filter: `event.type: "security_event" AND severity: ["critical", "high"]`
   - Alert: Any critical/high severity event

**Daily Workflow**:
1. Security Analyst opens Kibana dashboard (9:00 AM)
2. Reviews each visualization (5 minutes)
3. Investigates anomalies (if any, create JIRA ticket)
4. Signs off in JIRA ("Daily Review 2026-02-14 - No issues" or "2 anomalies investigated, see JIRA-1234, JIRA-1235")

---

## Summary

**Comprehensive Logging**: Authentication, authorization, data access, configuration changes, privileged actions, security events, application events, system events

**Immutable Storage**: WORM (S3 Object Lock), log forwarding (real-time SIEM ingestion), append-only logging

**7-Year Retention**: Compliance requirement (SOC 2, ISO 27001, GDPR accountability)

**Daily Review**: Security Analyst reviews dashboards, investigates anomalies, signs off

**Quarterly Review**: CISO, DPO, Compliance Officer review compliance, access, metrics

**Annual Audit**: External auditor verifies log retention, immutability, access controls, review procedures

**Evidence**: `/compliance/audit-evidence/logs/` (log samples, configuration, review sign-offs)

---

**Document Owner**: Security Team + Compliance Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-08-14 (semi-annual)  
**Questions**: security@company.com  
**SIEM Access Requests**: security@company.com (requires CISO approval)

**Related Documentation**:
- [Audit Configuration JSON](../../configs/organization-policies/audit-configuration.json) - Machine-readable log config
- [Monitoring Stack](../../configs/examples/monitoring-stack.yml) - SIEM deployment (ELK, Grafana, Prometheus)
- [Incident Response Procedure](../procedures/incident-response.md) - Using logs for incident investigation
- [SOC 2 Controls](./soc2-controls.md) - SOC 2 logging requirements
- [ISO 27001 Controls](./iso27001-controls.md) - ISO 27001 logging requirements
- [GDPR Compliance](./gdpr-compliance.md) - GDPR accountability through logging
