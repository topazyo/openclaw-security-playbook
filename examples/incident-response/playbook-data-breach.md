# Incident Response Playbook: Data Breach / Exfiltration

**Playbook ID**: IRP-004  
**Severity**: P0 - Critical  
**Estimated Response Time**: 15 minutes (initial containment) + 12 hours (full response + notification)  
**Last Updated**: 2026-02-14  
**Owner**: Security Operations Team

---

## Table of Contents

1. [Overview](#overview)
2. [Related Documents](#related-documents)
3. [Detection Indicators](#detection-indicators)
4. [Triage & Assessment](#triage--assessment)
5. [Containment](#containment)
6. [Eradication](#eradication)
7. [Recovery](#recovery)
8. [Notification & Reporting](#notification--reporting)
9. [Post-Incident Review](#post-incident-review)
10. [Appendix](#appendix)

---

## Overview

### Purpose
This playbook provides step-by-step procedures for responding to data breach incidents involving unauthorized access, theft, or exfiltration of OpenClaw/ClawdBot data, including conversation history, credentials, PII, and proprietary information.

### Scope
- **Data types**: Personal data (PII), credentials (API keys), conversation history, configuration data, proprietary algorithms, customer data
- **Attack vectors**: Prompt injection, malicious skills, S3 bucket misconfiguration, database compromise, insider threats, supply chain attacks
- **Systems covered**: Conversation databases, S3 buckets, agent memory, credential vaults, backup systems

### Success Criteria
- ✅ Data exfiltration stopped within 15 minutes
- ✅ Affected data classified and breach scope determined within 2 hours
- ✅ GDPR notification assessment completed within 24 hours (72-hour notification deadline)
- ✅ Affected parties notified per regulatory requirements
- ✅ Root cause patched to prevent recurrence

---

## Related Documents

### Policies & Procedures
- **[SEC-004 Incident Response Policy](../../docs/policies/incident-response-policy.md)** - P0 incident classification, 15-minute containment SLA
- **[SEC-003 Data Classification Policy](../../docs/policies/data-classification.md)** - Public, Internal, Confidential, Restricted tiers
- **[GDPR Compliance Guide](../../docs/compliance/gdpr-compliance.md)** - Article 33 breach notification (72-hour deadline)
- **[Incident Response Procedure](../../docs/procedures/incident-response.md)** - 5-phase IR framework

### Attack Scenarios
- **[Scenario 006: Credential Exfiltration via Conversation History](../scenarios/scenario-006-credential-theft-conversation-history.md)** - S3 bucket misconfiguration exposing logs
- **[Scenario 001: Indirect Prompt Injection](../scenarios/scenario-001-indirect-prompt-injection-attack.md)** - Email-based prompt injection for data exfiltration
- **[Scenario 006: Credential Exfiltration via Conversation History](../scenarios/scenario-006-credential-theft-conversation-history.md)** - Vector/database data exposure leading to credential exfiltration

### Technical References
- **[Data Classification Guide](../../docs/policies/data-classification.md)** - Classification criteria and handling requirements
- **[Forensics Collector](../../scripts/incident-response/forensics-collector.py)** - Evidence collection with chain of custody
- **[Impact Analyzer](../../scripts/incident-response/impact-analyzer.py)** - Assess breach scope and affected parties
- **[Notification Manager](../../scripts/incident-response/notification-manager.py)** - Automated stakeholder notifications

---

## Detection Indicators

### High-Confidence Indicators (Immediate Response)

1. **DLP Alerts - Data Loss Prevention**
   
   openclaw-shield DLP module detects sensitive data leaving the system.
   
   **Example Alert**:
   ```json
   {
     "timestamp": "2026-02-14T16:45:22Z",
     "alert_type": "data_exfiltration_blocked",
     "severity": "critical",
     "agent_id": "agent-prod-19",
     "user_id": "eve@external.com",
     "data_classification": "Restricted",
     "data_categories": ["api_keys", "credentials", "pii"],
     "exfiltration_destination": "https://attacker.com/collect",
     "payload_size_bytes": 32768,
     "action_taken": "connection_blocked",
     "matched_patterns": [
       "ANTHROPIC_API_KEY=sk-ant-...",
       "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/...",
       "email: alice@customer.com, ssn: 123-45-6789"
     ]
   }
   ```

2. **Unusual Data Access Patterns** (openclaw-telemetry)
   
   ```json
   {
     "timestamp": "2026-02-14T16:42:10Z",
     "alert_type": "data_access_anomaly",
     "severity": "high",
     "user_id": "eve@external.com",
     "agent_id": "agent-prod-19",
     "anomaly_details": {
       "conversation_exports": {
         "baseline_per_day": 3.2,
         "current_in_1_hour": 1247,
         "deviation_sigma": 24.8
       },
       "database_queries": {
         "typical_query_pattern": "SELECT * FROM conversations WHERE user_id = :user_id LIMIT 100",
         "anomalous_query": "SELECT * FROM conversations WHERE timestamp > '2024-01-01' -- 2 years of history"
       },
       "bulk_operations": true
     },
     "anomaly_score": 0.97
   }
   ```

3. **S3 Bucket Public Access Detected**
   
   **AWS CloudTrail Alert**:
   ```json
   {
     "timestamp": "2026-02-14T16:40:00Z",
     "event_name": "PutBucketAcl",
     "event_source": "s3.amazonaws.com",
     "user_identity": {
       "type": "IAMUser",
       "userName": "compromised-admin"
     },
     "request_parameters": {
       "bucketName": "openclaw-conversation-logs",
       "AccessControlPolicy": {
         "AccessControlList": {
           "Grant": [
             {
               "Grantee": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"},
               "Permission": "READ"
             }
           ]
         }
       }
     },
     "severity": "CRITICAL"
   }
   ```
   
   **S3 Public Access Scan**:
   ```bash
   # Check for publicly accessible buckets
   aws s3api list-buckets | jq -r '.Buckets[].Name' | \
   while read bucket; do
     acl=$(aws s3api get-bucket-acl --bucket "$bucket" 2>/dev/null)
     if echo "$acl" | grep -q "AllUsers\|AllAuthenticatedUsers"; then
       echo "⚠️  CRITICAL: Bucket $bucket is publicly accessible!"
     fi
   done
   ```

4. **Database Compromise Indicators**
   
   **SQL Injection Detected**:
   ```json
   {
     "timestamp": "2026-02-14T16:38:45Z",
     "alert_type": "sql_injection_attempt",
     "severity": "critical",
     "source_ip": "203.0.113.42",
     "query": "SELECT * FROM users WHERE id = '1' OR '1'='1' --",
     "blocked": true,
     "user_agent": "sqlmap/1.6"
   }
   ```
   
   **Database Exfiltration**:
   ```sql
   -- Anomalous query patterns in database logs
   -- Full table dumps within short time window
   
   SELECT query_text, execution_time, result_rows
   FROM pg_stat_statements
   WHERE query_text LIKE '%SELECT * FROM%'
     AND result_rows > 10000
     AND execution_time > CURRENT_TIMESTAMP - INTERVAL '1 hour'
   ORDER BY result_rows DESC;
   ```

### Medium-Confidence Indicators (Investigate)

5. **Excessive Data Transfer Volume**
   
   ```bash
   # Monitor network transfer volumes
   curl -X GET "https://monitoring.openclaw.ai/api/metrics/network-transfer" \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq '
     .agents[] | select(.transfer_bytes_last_hour > 1073741824)  # >1GB in 1 hour
   '
   ```

6. **After-Hours Data Access**
   
   ```sql
   -- Query audit logs for after-hours access
   SELECT user_id, action, resource, timestamp
   FROM audit_logs
   WHERE event_type = 'data_access'
     AND EXTRACT(HOUR FROM timestamp) NOT BETWEEN 9 AND 18  -- Business hours 9am-6pm
     AND timestamp > NOW() - INTERVAL '24 hours'
   ORDER BY timestamp DESC;
   ```

7. **Suspicious Backup Activity**
   
   ```bash
   # Check for unauthorized backup exports
   aws s3api list-objects-v2 \
     --bucket openclaw-backups \
     --query 'Contents[?LastModified>=`2026-02-14T16:00:00Z`]' | \
     jq '.[] | select(.Key | contains("export") or contains("dump"))'
   ```

### Low-Confidence Indicators (Monitor)

8. **General Suspicious Activity**
   - Unusual user agent strings (automated scrapers)
   - Concurrent sessions from geographically distant locations
   - Spikes in API error rates (reconnaissance activity)

---

## Triage & Assessment

### Initial Assessment (5 minutes)

**Incident Commander**: On-call security analyst  
**Additional Participants**: CISO (for P0), Legal (if PII involved), DPO (if GDPR applicable)

1. **Confirm the Alert**
   
   ```bash
   # Check DLP alerts
   curl -X GET "https://gateway.openclaw.ai/shield/dlp/recent-blocks?hours=1" \
     -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
   
   # Query audit logs for data access events
   curl -X POST "https://elk.openclaw.ai/security-events-*/_search" \
     -H "Content-Type: application/json" \
     -d '{
       "query": {
         "bool": {
           "must": [
             {"term": {"event_type": "data_access"}},
             {"terms": {"severity": ["high", "critical"]}},
             {"range": {"timestamp": {"gte": "now-1h"}}}
           ]
         }
       },
       "sort": [{"timestamp": "desc"}]
     }' | jq '.hits.hits[]._source'
   ```

2. **Determine Data Classification** (SEC-003)
   
   Use **[Data Classification Policy](../../docs/policies/data-classification.md)** to classify compromised data:
   
   | Tier | Description | Examples | Breach Notification Required? |
   |------|-------------|----------|-------------------------------|
   | **Restricted** | Highest sensitivity, legal/regulatory requirements | API keys, passwords, credit cards, SSN, health records | ✅ YES - GDPR 72h, PCI-DSS immediate |
   | **Confidential** | Business-critical, competitive advantage | Proprietary algorithms, customer lists, contracts, financial data | ⚠️ MAYBE - Depends on context |
   | **Internal** | Internal use only | Employee emails, meeting notes, internal docs | ⚠️ MAYBE - Low risk to individuals |
   | **Public** | Publicly available | Marketing materials, public docs, open-source code | ❌ NO - Already public |

3. **Assess Breach Scope**
   
   ```bash
   # Run impact analyzer to determine affected data
   ./scripts/incident-response/impact-analyzer.py \
     --start-time "2026-02-14T16:00:00Z" \
     --end-time "2026-02-14T17:00:00Z" \
     --affected-resources "agent-prod-19,s3://openclaw-conversation-logs" \
     --output impact-assessment.json
   ```
   
   **Impact Assessment Output**:
   ```json
   {
     "incident_id": "IRP-004-20260214",
     "assessment_timestamp": "2026-02-14T17:05:00Z",
     "breach_scope": {
       "data_types_affected": ["credentials", "conversation_history", "pii"],
       "data_classification": "Restricted",
       "estimated_records": 8472,
       "affected_individuals": 234,
       "affected_agents": ["agent-prod-19"],
       "exfiltration_confirmed": true,
       "exfiltration_destination": "https://attacker.com/collect",
       "time_window": {
         "first_access": "2026-02-14T16:35:00Z",
         "last_access": "2026-02-14T16:52:00Z",
         "duration_minutes": 17
       }
     },
     "personal_data_details": {
       "gdpr_applicable": true,
       "data_categories": [
         {"category": "identifiers", "examples": ["email addresses", "names", "user IDs"]},
         {"category": "authentication", "examples": ["API keys", "session tokens"]},
         {"category": "communications", "examples": ["conversation transcripts"]}
       ],
       "sensitive_personal_data": false,
       "special_categories_article_9": false
     },
     "compliance_implications": {
       "gdpr_breach_notification_required": true,
       "gdpr_notification_deadline": "2026-02-17T17:00:00Z",
       "pci_dss_applicable": false,
       "hipaa_applicable": false,
       "soc2_incident_reporting_required": true
     }
   }
   ```

4. **Classify Incident Severity** (SEC-004)
   
   **Decision Matrix**:
   ```
   IF (Restricted data exfiltrated AND GDPR applicable) THEN
     severity = P0  # Critical - Regulatory breach notification required
   ELSE IF (Confidential data exfiltrated) THEN
     severity = P0  # Critical - Business impact
   ELSE IF (Internal data accessed unauthorized) THEN
     severity = P1  # High - Policy violation
   ELSE IF (Public data only) THEN
     severity = P3  # Low - No sensitivity
   END IF
   ```

5. **Escalate Immediately**
   
   **P0 Data Breach Escalation** (within 15 minutes):
   - ✅ CISO (security@openclaw.ai)
   - ✅ Legal Counsel (legal@openclaw.ai)
   - ✅ Data Protection Officer (dpo@openclaw.ai) - if GDPR applicable
   - ✅ PR/Communications (pr@openclaw.ai) - if customer notification needed
   - ✅ Audit Committee (for SOC 2 incidents)
   
   ```bash
   # Automated escalation
   ./scripts/incident-response/notification-manager.py \
     --incident-id "IRP-004-20260214" \
     --severity P0 \
     --type data_breach \
     --escalate-to ciso,legal,dpo,pr \
     --include-impact-assessment impact-assessment.json
   ```

---

## Containment

**Goal**: Stop ongoing data exfiltration and prevent further unauthorized access.  
**Time Bound**: Complete within 15 minutes for P0, 1 hour for P1.

### Phase 1: Immediate Actions (0-15 minutes)

1. **Block Data Exfiltration**
   
   **For Network-Based Exfiltration**:
   ```bash
   # Block attacker's destination IPs/domains
   ./scripts/incident-response/auto-containment.py \
     --action block_domain \
     --domain attacker.com \
     --duration permanent \
     --reason "Data exfiltration destination - IRP-004"
   
   # Block at firewall level
   iptables -A OUTPUT -d 203.0.113.0/24 -j DROP  # Attacker IP range
   
   # DNS sinkhole for attacker domains
   echo "0.0.0.0 attacker.com evil.ru" >> /etc/hosts
   ```
   
   **For S3 Bucket Exposure**:
   ```bash
   # Immediately remove public access from S3 bucket
   aws s3api put-public-access-block \
     --bucket openclaw-conversation-logs \
     --public-access-block-configuration \
       BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
   
   # Verify public access removed
   aws s3api get-public-access-block --bucket openclaw-conversation-logs
   
   # Enable S3 MFA Delete (prevent accidental/malicious deletion of versioned objects)
   aws s3api put-bucket-versioning \
     --bucket openclaw-conversation-logs \
     --versioning-configuration Status=Enabled,MFADelete=Enabled \
     --mfa "arn:aws:iam::123456789012:mfa/security-admin 123456"
   ```

2. **Isolate Compromised Systems**
   
   ```bash
   # Isolate affected agent(s)
   ./scripts/incident-response/auto-containment.py \
     --action isolate_container \
     --container-id agent-prod-19 \
     --reason "Data breach incident - IRP-004"
   
   # If database compromised, restrict access
   # PostgreSQL: Revoke all connections except forensics team
   psql -c "REVOKE CONNECT ON DATABASE openclaw_conversations FROM PUBLIC;"
   psql -c "GRANT CONNECT ON DATABASE openclaw_conversations TO forensics_user;"
   ```

3. **Revoke Compromised Credentials**
   
   If credentials were part of the breach:
   ```bash
   # Identify which credentials were accessed
   ACCESS_LOG_ENTRIES=$(./scripts/incident-response/impact-analyzer.py \
     --incident-id IRP-004-20260214 \
     --query credentials_accessed)
   
   # Batch revoke and rotate
   echo "$ACCESS_LOG_ENTRIES" | jq -r '.credentials[]' | while read cred_id; do
     ./scripts/incident-response/auto-containment.py \
       --action revoke_credential \
       --credential-id "$cred_id" \
       --reason "Data breach - IRP-004"
   done
   ```

4. **Preserve Evidence** (chain of custody)
   
   ```bash
   # Collect forensic evidence before making changes
   ./scripts/incident-response/forensics-collector.py \
     --incident-id "IRP-004-20260214" \
     --scope comprehensive \
     --targets "agent-prod-19,s3://openclaw-conversation-logs,db:openclaw_conversations" \
     --output-dir /secure/forensics/IRP-004/ \
     --encrypt-with-key $FORENSICS_PGP_KEY \
     --preserve-chain-of-custody
   ```

### Phase 2: Forensic Analysis (15-60 minutes)

5. **Determine Exfiltration Volume**
   
   ```bash
   # Analyze network logs for total data transferred
   zcat /var/log/openclaw/network-*.log.gz | \
     grep "dst=attacker.com" | \
     awk '{sum+=$12} END {print "Total bytes exfiltrated:", sum}'
   
   # Check S3 access logs (if bucket was public)
   aws s3 cp s3://openclaw-logs/s3-access-logs/ - --recursive | \
     grep "openclaw-conversation-logs" | \
     awk -F' ' '$8 == "REST.GET.OBJECT" {count++} END {print "Total GET requests:", count}'
   ```

6. **Identify Affected Individuals** (for GDPR notification)
   
   ```bash
   # Query conversation database for user_ids in breach window
   psql openclaw_conversations -c "
   SELECT DISTINCT user_id, email, name
   FROM conversations
   WHERE timestamp BETWEEN '2026-02-14 16:35:00' AND '2026-02-14 16:52:00'
     AND agent_id = 'agent-prod-19'
   ORDER BY user_id;
   " > affected-individuals.csv
   
   # Count total affected individuals
   AFFECTED_COUNT=$(wc -l < affected-individuals.csv)
   echo "Total affected individuals: $AFFECTED_COUNT"
   ```

7. **Categorize Personal Data** (GDPR Article 4)
   
   ```bash
   # Analyze exfiltrated data for GDPR personal data categories
   ./scripts/incident-response/impact-analyzer.py \
     --incident-id IRP-004-20260214 \
     --analyze-personal-data \
     --output gdpr-data-categories.json
   ```
   
   **GDPR Data Categories** (Article 9 "special categories"):
   - ❌ Racial or ethnic origin
   - ❌ Political opinions
   - ❌ Religious or philosophical beliefs
   - ❌ Trade union membership
   - ❌ Genetic data
   - ❌ Biometric data
   - ❌ Health data
   - ❌ Sex life or sexual orientation
   
   **If "special categories" involved → Higher risk, stricter notification requirements**

---

## Eradication

**Goal**: Remove attacker access and patch vulnerability.  
**Time Bound**: Complete within 12 hours for P0, 48 hours for P1.

### Root Cause Analysis

1. **Identify Attack Vector**
   
   **Scenario A: S3 Bucket Misconfiguration**
   ```bash
   # Review CloudTrail for ACL change
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=EventName,AttributeValue=PutBucketAcl \
     --max-results 50 | \
     jq '.Events[] | select(.Resources[].ResourceName == "openclaw-conversation-logs")'
   ```
   
   **Root Cause**: Administrator accidentally set bucket ACL to public during testing, forgot to revert.
   
   **Remediation**:
   - Implement S3 bucket public access scanning (daily automated check)
   - Enable AWS Config rule: `s3-bucket-public-read-prohibited`
   - Require peer review for S3 bucket policy changes
   - Deploy IaC (Terraform) with state drift detection
   
   ---
   
   **Scenario B: Prompt Injection Attack**
   ```bash
   # Review telemetry for anomalous behavior linked to prompt injection
   python scripts/monitoring/anomaly_detector.py \
     --logfile ~/.openclaw/logs/telemetry.jsonl \
     --output-json
   ```
   
   **Root Cause**: Indirect prompt injection via email instructed agent to exfiltrate conversation history.
   
   **Remediation**: See **[playbook-prompt-injection.md](playbook-prompt-injection.md)**
   
   ---
   
   **Scenario C: Malicious Skill**
   ```bash
   # Check for unauthorized skill execution
   ./scripts/supply-chain/skill_manifest.py \
     --agent-id agent-prod-19 \
     --find-unapproved-skills
   ```
   
   **Root Cause**: Typosquatted skill `@anthropc/sdk` (typo) exfiltrated data.
   
   **Remediation**: See **[playbook-skill-compromise.md](playbook-skill-compromise.md)**
   
   ---
   
   **Scenario D: Database SQL Injection**
   ```bash
   # Review database logs for injection attempts
   psql -c "SELECT query, client_addr, timestamp 
            FROM pg_stat_statements 
            WHERE query LIKE '%OR%=%' 
            OR query LIKE '%UNION%SELECT%'
            ORDER BY timestamp DESC LIMIT 100;"
   ```
   
   **Root Cause**: SQL injection in custom query endpoint (unparameterized SQL).
   
   **Remediation**:
   - Fix vulnerable endpoint (use parameterized queries/ORM)
   - Deploy WAF with SQLi detection rules
   - Regular penetration testing of API endpoints

2. **Patch Vulnerability**
   
   Based on root cause, implement technical fixes:
   
   **For S3 Misconfiguration**:
   ```bash
   # Deploy preventive controls
   # 1. AWS Config rule
   aws configservice put-config-rule --config-rule '{
     "ConfigRuleName": "s3-bucket-public-read-prohibited",
     "Source": {
       "Owner": "AWS",
       "SourceIdentifier": "S3_BUCKET_PUBLIC_READ_PROHIBITED"
     }
   }'
   
   # 2. Daily scan script
   cat > /etc/cron.daily/s3-public-access-scan <<'EOF'
   #!/bin/bash
   # Scan for publicly accessible S3 buckets
   aws s3api list-buckets | jq -r '.Buckets[].Name' | while read bucket; do
     access=$(aws s3api get-public-access-block --bucket "$bucket" 2>/dev/null)
     if echo "$access" | jq -e '.PublicAccessBlockConfiguration | 
       (.BlockPublicAcls == false or .BlockPublicPolicy == false)' > /dev/null; then
       echo "⚠️  ALERT: Bucket $bucket allows public access!" | \
         mail -s "S3 Public Access Alert" security@openclaw.ai
     fi
   done
   EOF
   chmod +x /etc/cron.daily/s3-public-access-scan
   ```
   
   **For Application Vulnerability** (SQLi, etc.):
   ```python
   # Before (VULNERABLE):
   query = f"SELECT * FROM conversations WHERE user_id = '{user_input}'"  # SQL injection risk
   cursor.execute(query)
   
   # After (SECURE):
   query = "SELECT * FROM conversations WHERE user_id = %s"  # Parameterized query
   cursor.execute(query, (user_input,))
   ```

3. **Verify Fix Effectiveness**
   
   ```bash
   # Re-run security verification
   ./scripts/verification/verify_openclaw_security.sh \
     --full-audit \
     --test-data-protection
   
   # Test for same vulnerability
   ./scripts/vulnerability-scanning/os-scan.sh \
     --target auto \
     --severity HIGH \
     --format json \
     --output data-breach-os-scan.json
   ```

---

## Recovery

**Goal**: Restore normal operations with improved data protection.  
**Time Bound**: Complete within 24 hours for P0, 72 hours for P1.

1. **Restore Services** (with enhanced security)
   
   ```bash
   # Redeploy agent with hardened configuration
   docker pull openclaw/agent:hardened-data-protection-v2
   
   docker run -d \
     --name agent-prod-19-restored \
     --cap-drop ALL \
     --cap-add NET_BIND_SERVICE \
     --read-only \
     --tmpfs /tmp:rw,noexec,nosuid,nodev,size=100m \
     --security-opt no-new-privileges:true \
     --pids-limit=100 \
     -e DLP_ENFORCEMENT_MODE=strict \
     -e DATA_CLASSIFICATION_CHECK=enabled \
     openclaw/agent:hardened-data-protection-v2
   ```

2. **Verify Data Integrity** (ensure no tampering)
   
   ```bash
   # Check database integrity
   psql openclaw_conversations -c "SELECT COUNT(*) FROM conversations;"
   # Compare with backup count
   
   # Verify S3 bucket contents unchanged (versioning)
   aws s3api list-object-versions --bucket openclaw-conversation-logs | \
     jq '.Versions[] | select(.IsLatest == false)'  # Check for unexpected versions
   ```

3. **Enable Enhanced Monitoring** (48-hour increased vigilance)
   
   ```bash
   # Lower anomaly detection thresholds
   curl -X PATCH "https://monitoring.openclaw.ai/config" \
     -H "Authorization: Bearer $ADMIN_TOKEN" \
     -d '{
       "anomaly_sensitivity": "high",
       "data_access_alert_threshold": 0.5,
       "duration_hours": 48
     }'
   ```

---

## Notification & Reporting

**Goal**: Meet regulatory notification requirements (GDPR 72-hour deadline).  
**Time Bound**: Assessment within 24 hours, notification within 72 hours if required.

### GDPR Breach Notification Assessment (Article 33)

**Decision Tree**:
```
1. Is personal data involved?
   NO → GDPR notification NOT required ✅
   YES → Continue to step 2

2. Is there a "risk to rights and freedoms" of individuals?
   NO → Internal documentation only, NO notification required ✅
   YES → Continue to step 3

3. Notify supervisory authority within 72 hours ⚠️
   (AND notify data subjects if "high risk")
```

**Risk Assessment Factors** (GDPR Recital 75):
- ✅ **Type of breach**: Confidentiality (data disclosed), Integrity (data altered), Availability (data lost/deleted)
- ✅ **Nature of personal data**: Ordinary data vs. special categories (Article 9)
- ✅ **Volume of data**: How many individuals affected?
- ✅ **Ease of identification**: Can individuals be identified from the data?
- ✅ **Severity of consequences**: Identity theft, financial loss, reputational damage, discrimination
- ✅ **Affected individuals' characteristics**: Children, vulnerable groups
- ✅ **Data controllers' characteristics**: Healthcare, financial services (higher risk)

### Notification Procedures

1. **Internal Notification** (within 1 hour of P0 classification)
   
   ```bash
   # Automated internal stakeholder notification
   ./scripts/incident-response/notification-manager.py \
     --incident-id IRP-004-20260214 \
     --type data_breach \
     --notify-internal \
     --recipients ciso,legal,dpo,audit_committee \
     --include-impact-assessment
   ```

2. **Supervisory Authority Notification** (within 72 hours if GDPR applicable)
   
   **GDPR Article 33 Requirements**:
   - (a) Nature of the personal data breach
   - (b) Contact point for more information (DPO)
   - (c) Likely consequences of the breach
   - (d) Measures taken or proposed to address the breach
   
   ```bash
   # Generate GDPR breach notification report
   ./scripts/incident-response/notification-manager.py \
     --incident-id IRP-004-20260214 \
     --generate-gdpr-report \
     --output gdpr-breach-notification.pdf
   ```
   
   **Notification Template**: See [Appendix B](#b-gdpr-breach-notification-template)

3. **Data Subject Notification** (if "high risk" to rights and freedoms)
   
   **High Risk Indicators**:
   - Special category data (Article 9) involved
   - Financial data (credit cards, bank accounts)
   - Credentials that enable identity theft
   - Large-scale breach (>1000 individuals)
   
   ```bash
   # Notify affected individuals
   ./scripts/incident-response/notification-manager.py \
     --incident-id IRP-004-20260214 \
     --notify-data-subjects \
     --recipients-file affected-individuals.csv \
     --delivery-method encrypted_email \
     --template data-subject-breach-notification
   ```
   
   **Data Subject Notification Template**: See [Appendix C](#c-data-subject-notification-template)

4. **Customer Notification** (if customer data affected)
   
   ```bash
   # Notify business customers (enterprise clients)
   ./scripts/incident-response/notification-manager.py \
     --incident-id IRP-004-20260214 \
     --notify-customers \
     --delivery-method email,support_ticket \
     --template customer-breach-notification
   ```

---

## Post-Incident Review

Use the standardized template: **[reporting-template.md](reporting-template.md)**

### Key Sections to Complete

1. **Executive Summary**
   - Breach type and root cause
   - Data classification and volume
   - Number of affected individuals
   - Regulatory notifications made
   - Business impact

2. **Timeline** (with GDPR 72-hour deadline tracking)
   ```
   2026-02-14 16:35 UTC - First unauthorized data access detected
   2026-02-14 16:52 UTC - Data exfiltration stopped by network policy
   2026-02-14 17:00 UTC - IS (Incident Commander) initiates response
   2026-02-14 17:15 UTC - Data exfiltration blocked, systems isolated (SLA: 15min, Actual: 15min) ✅
   2026-02-14 18:30 UTC - Breach scope determined (234 affected individuals)
   2026-02-14 20:00 UTC - GDPR breach assessment: NOTIFICATION REQUIRED (high risk)
   2026-02-15 12:00 UTC - GDPR breach notification prepared
   2026-02-15 14:30 UTC - Supervisory authority notified (within 72h deadline) ✅
   2026-02-15 16:00 UTC - Affected individuals notified
   2026-02-16 10:00 UTC - Services restored with enhanced protections
   ```

3. **Root Cause Analysis** (5 Whys)
   ```
   Problem: S3 bucket containing conversation logs exposed publicly
   Why? → Administrator set bucket ACL to allow AllUsers READ
   Why? → Testing public website feature, wanted public access to static assets
   Why? → Used production bucket for testing instead of dedicated test bucket
   Why? → No documented separation between prod/test environments for S3
   Why? → Infrastructure-as-Code not enforced, manual changes allowed
   
   **Root Cause**: Manual infrastructure changes without peer review or IaC enforcement
   ```

4. **Compliance Impact**
   - **GDPR**: Breach notification made within 72 hours ✅
   - **SOC 2**: Incident documented per CC7.3, evidence preserved for auditors ✅
   - **ISO 27001**: A.16.1.6 (Learning from incidents) - PIR completed ✅
   - **Cost**: GDPR fine risk (up to €10M or 2% of annual turnover, likely avoided due to prompt notification and remediation)

5. **Action Items**
   
   | # | Action Item | Owner | Due Date | Priority |
   |---|-------------|-------|----------|----------|
   | 1 | Implement IaC enforcement for all infrastructure (Terraform with state locking) | DevOps | 2026-02-28 | P0 |
   | 2 | Deploy AWS Config rule `s3-bucket-public-read-prohibited` across all accounts | Cloud Security | 2026-02-16 | P0 |
   | 3 | Enable S3 MFA Delete on all buckets containing Restricted data | Cloud Security | 2026-02-18 | P0 |
   | 4 | Implement daily S3 public access scan with PagerDuty alerts | Security | 2026-02-17 | P0 |
   | 5 | Conduct tabletop exercise simulating GDPR breach notification process | Compliance | 2026-03-15 | P1 |
   | 6 | Review all S3 buckets for proper encryption (AES-256 or KMS) | Cloud Security | 2026-02-25 | P1 |
   | 7 | Implement separation of prod/test/dev S3 buckets with enforced naming convention | DevOps | 2026-03-01 | P1 |

6. **Lessons Learned**
   
   **What Went Well** ✅:
   - Network segmentation blocked data exfiltration within 17 minutes
   - Impact analyzer quickly identified affected individuals (2 hours)
   - GDPR breach notification completed within 72-hour deadline
   - Clear escalation to DPO/Legal ensured regulatory compliance
   
   **What Needs Improvement** ⚠️:
   - Manual infrastructure changes bypassed security controls
   - No preventive scan for S3 public access (detection was reactive)
   - Prod/test environment separation not enforced for S3
   - No peer review for bucket policy changes
   
   **Preventive Measures** 🛡️:
   - Shift security left: IaC enforcement blocks insecure configurations before deployment
   - Proactive scanning: Daily automated checks for S3 public access
   - Separation of duties: Require peer review for production infrastructure changes
   - Security-as-Code: Terraform modules with built-in security guardrails

---

## Appendix

### A. Data Classification Quick Reference

| Tier | Examples | Breach Notification? |
|------|----------|---------------------|
| **Restricted** | API keys, passwords, SSN, credit cards, health records | ✅ YES - GDPR 72h, PCI immediate |
| **Confidential** | Proprietary algorithms, customer contracts, financial data | ⚠️ MAYBE - Context-dependent |
| **Internal** | Employee emails, meeting notes, internal docs | ⚠️ MAYBE - Low risk |
| **Public** | Marketing materials, public docs | ❌ NO - Already public |

### B. GDPR Breach Notification Template

**To**: [Supervisory Authority Email]  
**Subject**: Personal Data Breach Notification - OpenClaw Incident IRP-004-20260214  
**Date**: 2026-02-15

**Article 33 GDPR Breach Notification**

**1. Nature of the Personal Data Breach** (Article 33(3)(a)):
- **Breach Type**: Confidentiality breach (unauthorized disclosure)
- **Date/Time**: 2026-02-14, 16:35-16:52 UTC (17-minute window)
- **Root Cause**: S3 bucket misconfiguration (public read access)
- **Data Categories**: Email addresses, names, user IDs, conversation transcripts, API authentication tokens

**2. Contact Point** (Article 33(3)(b)):
- **Data Protection Officer**: dpo@openclaw.ai
- **Phone**: +1-555-0123
- **PGP Key**: [Fingerprint]

**3. Likely Consequences** (Article 33(3)(c)):
- **Affected Individuals**: 234 data subjects (EU residents)
- **Potential Consequences**: 
  - Identity theft (email addresses exposed)
  - Unauthorized account access (authentication tokens compromised, all rotated within 1 hour)
  - Privacy violation (conversation transcripts disclosed)
- **Risk Level**: HIGH (authentication credentials exposed)

**4. Measures Taken** (Article 33(3)(d)):
- **Immediate Containment**: S3 public access removed within 15 minutes of detection
- **Authentication Tokens**: All 127 compromised tokens revoked and rotated within 1 hour
- **Data Subjects Notified**: All 234 affected individuals notified on 2026-02-15 within 24 hours
- **Technical Measures**: AWS Config rule deployed to prevent future S3 misconfigurations
- **Organizational Measures**: Infrastructure-as-Code enforcement, peer review required for bucket policies

**Evidence Attached**:
- Incident timeline
- Impact assessment report
- List of affected individuals (separate secure transmission)
- Technical forensics report

**Sincerely**,  
Data Protection Officer  
OpenClaw Security Team

---

### C. Data Subject Notification Template

**Subject**: Important Security Notification - Action Required

Dear [Name],

We are writing to inform you of a security incident that affected your OpenClaw account.

**What Happened**:
On February 14, 2026, a misconfiguration in our cloud storage system temporarily allowed unauthorized access to conversation transcripts and account information. The issue was resolved within 17 minutes of detection.

**What Information Was Involved**:
- Your email address: [email]
- Your OpenClaw user ID
- Conversation transcripts from [date range]
- Authentication tokens (these have been invalidated and replaced)

**What We're Doing**:
- All authentication tokens have been rotated (your account remains secure)
- The misconfiguration has been fixed
- We've implemented additional monitoring and preventive controls
- We've notified the Data Protection Authority as required by law

**What You Should Do**:
1. **Reset Your Password**: As a precaution, please reset your password at: https://openclaw.ai/reset-password
2. **Enable Multi-Factor Authentication**: We strongly recommend enabling MFA: https://openclaw.ai/security/mfa
3. **Monitor Your Account**: Review your account activity at: https://openclaw.ai/account/activity
4. **Be Vigilant**: Watch for phishing emails claiming to be from OpenClaw (we will never ask for your password via email)

**Your Rights** (GDPR Articles 15-22):
- Right to access your data
- Right to rectification
- Right to erasure ("right to be forgotten")
- Right to restriction of processing
- Right to data portability
- Right to object
- Right to lodge a complaint with supervisory authority

To exercise these rights, contact: dpo@openclaw.ai

**Questions?**  
If you have any questions or concerns, please contact our security team:
- Email: security@openclaw.ai
- Support: https://openclaw.ai/support
- Phone: +1-555-0123

**Incident Reference**: IRP-004-20260214

We sincerely apologize for this incident and any inconvenience caused.

Sincerely,  
OpenClaw Security Team

---

### D. Related Playbooks

- **[playbook-credential-theft.md](playbook-credential-theft.md)** - If credentials were exfiltrated
- **[playbook-prompt-injection.md](playbook-prompt-injection.md)** - If prompt injection was the attack vector
- **[playbook-skill-compromise.md](playbook-skill-compromise.md)** - If malicious skill caused the breach

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-02-14 | Security Team | Initial playbook creation |
| 1.1 | 2026-02-14 | DPO | GDPR notification procedures added |

**Approval**:
- **CISO**: ✅ Approved 2026-02-14
- **Legal**: ✅ Reviewed 2026-02-14
- **DPO**: ✅ GDPR compliance confirmed 2026-02-14

**Next Review**: 2026-05-14 (quarterly review)
