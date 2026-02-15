# Rate Limiting and Throttling Examples

**Purpose**: Implement rate limiting to prevent DoS attacks, API abuse, and resource exhaustion in OpenClaw/ClawdBot deployments.

**Language**: Python 3.11+  
**Dependencies**: `redis`, `asyncio`  
**Last Updated**: 2026-02-14

---

## Table of Contents

1. [Overview](#overview)
2. [Token Bucket Algorithm](#token-bucket-algorithm)
3. [Sliding Window Rate Limiting](#sliding-window-rate-limiting)
4. [Redis-Based Distributed Rate Limiting](#redis-based-distributed-rate-limiting)
5. [Adaptive Rate Limiting](#adaptive-rate-limiting)
6. [Cost-Based Rate Limiting](#cost-based-rate-limiting)
7. [Integration Examples](#integration-examples)

---

## Overview

### Rate Limiting Strategies

| Strategy | Use Case | Pros | Cons |
|----------|----------|------|------|
| **Token Bucket** | General API rate limiting | Simple, allows bursts | Can be gamed with timing |
| **Sliding Window** | Precise rate limiting | Accurate, no gaming | Higher memory usage |
| **Fixed Window** | Simple cases | Very simple | Burst at window boundaries |
| **Adaptive** | DDoS protection | Responds to attacks | Complex to tune |
| **Cost-Based** | LLM API usage | Fair resource allocation | Requires cost tracking |

### Attack Vectors Addressed

- ✅ **Denial of Service (DoS)**: Prevent resource exhaustion
- ✅ **Brute Force**: Slow down credential guessing attacks
- ✅ **API Abuse**: Prevent excessive API usage
- ✅ **Economic DoS**: Limit cost of LLM API calls
- ✅ **Scraping**: Prevent data harvesting

**References**:
- [DoS Playbook](../incident-response/playbook-denial-of-service.md)
- [Scenario 007: Resource Exhaustion](../scenarios/scenario-007-denial-of-service-resource-exhaustion.md)

---

## Token Bucket Algorithm

### 1. Basic Token Bucket

```python
import time
from typing import Optional
from dataclasses import dataclass
from threading import Lock

@dataclass
class RateLimitResult:
    """Result of rate limit check."""
    allowed: bool
    tokens_remaining: int
    retry_after_seconds: Optional[float] = None
    limit: int = 0


class TokenBucket:
    """
    Token bucket rate limiter.
    
    Allows bursts while maintaining average rate. Tokens are added at a constant
    rate and consumed per request. Requests are allowed if tokens are available.
    
    Example: 100 requests/minute with burst of 20
    - Capacity: 20 tokens
    - Refill rate: 100/60 = 1.67 tokens/second
    
    References:
    - docs/guides/03-network-segmentation.md (Layer 2: Rate limiting)
    - Scenario 007: DoS via Resource Exhaustion
    """
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.
        
        Args:
            capacity: Maximum number of tokens (burst size)
            refill_rate: Tokens added per second (average rate)
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = Lock()
    
    def _refill(self):
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        
        # Add tokens based on elapsed time
        tokens_to_add = elapsed * self.refill_rate
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now
    
    def consume(self, tokens: int = 1) -> RateLimitResult:
        """
        Attempt to consume tokens.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            RateLimitResult indicating if request is allowed
        """
        with self.lock:
            self._refill()
            
            if self.tokens >= tokens:
                # Allow request
                self.tokens -= tokens
                return RateLimitResult(
                    allowed=True,
                    tokens_remaining=int(self.tokens),
                    limit=self.capacity
                )
            else:
                # Deny request
                tokens_needed = tokens - self.tokens
                retry_after = tokens_needed / self.refill_rate
                
                return RateLimitResult(
                    allowed=False,
                    tokens_remaining=int(self.tokens),
                    retry_after_seconds=retry_after,
                    limit=self.capacity
                )


# Usage example
bucket = TokenBucket(capacity=20, refill_rate=100/60)  # 100 req/min, burst 20

# Simulate requests
for i in range(25):
    result = bucket.consume(1)
    if result.allowed:
        print(f"Request {i+1}: ✓ Allowed  (tokens: {result.tokens_remaining})")
    else:
        print(f"Request {i+1}: ✗ Blocked (retry after {result.retry_after_seconds:.2f}s)")
    
    time.sleep(0.1)  # 100ms between requests
```

### 2. Per-User Token Bucket

```python
from collections import defaultdict
import time

class PerUserRateLimiter:
    """
    Per-user token bucket rate limiter.
    
    Maintains separate token buckets for each user/IP.
    """
    
    def __init__(self, capacity: int, refill_rate: float, cleanup_interval: int = 300):
        """
        Initialize per-user rate limiter.
        
        Args:
            capacity: Token bucket capacity per user
            refill_rate: Refill rate per user (tokens/second)
            cleanup_interval: Seconds between cleanup of inactive buckets
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.buckets = {}  # user_id -> TokenBucket
        self.last_cleanup = time.time()
        self.cleanup_interval = cleanup_interval
        self.lock = Lock()
    
    def _cleanup_inactive_buckets(self):
        """Remove inactive buckets to prevent memory leak."""
        now = time.time()
        if now - self.last_cleanup < self.cleanup_interval:
            return
        
        # Remove buckets inactive for >5 minutes
        inactive_threshold = now - 300
        inactive_users = [
            user_id for user_id, bucket in self.buckets.items()
            if bucket.last_refill < inactive_threshold
        ]
        
        for user_id in inactive_users:
            del self.buckets[user_id]
        
        self.last_cleanup = now
    
    def check_rate_limit(self, user_id: str, cost: int = 1) -> RateLimitResult:
        """
        Check rate limit for user.
        
        Args:
            user_id: User identifier (user ID, IP address, API key)
            cost: Cost of this request (default 1 token)
            
        Returns:
            RateLimitResult
        """
        with self.lock:
            # Get or create bucket for user
            if user_id not in self.buckets:
                self.buckets[user_id] = TokenBucket(self.capacity, self.refill_rate)
            
            # Periodic cleanup
            self._cleanup_inactive_buckets()
            
            # Check rate limit
            return self.buckets[user_id].consume(cost)


# Usage example
limiter = PerUserRateLimiter(capacity=100, refill_rate=10)  # 10 req/s, burst 100

# Simulate requests from multiple users
users = ['alice', 'bob', 'eve']
for i in range(50):
    user = users[i % len(users)]
    result = limiter.check_rate_limit(user)
    
    if not result.allowed:
        print(f"User {user}: Rate limit exceeded (retry after {result.retry_after_seconds:.2f}s)")
```

---

## Sliding Window Rate Limiting

### 3. Redis-Based Sliding Window

```python
import redis
import time
from typing import Optional

class RedisSlidingWindowLimiter:
    """
    Redis-based sliding window rate limiter.
    
    More accurate than fixed windows, prevents boundary gaming.
    Uses sorted sets to track request timestamps.
    
    Example: 100 requests per minute
    - Window size: 60 seconds
    - Limit: 100 requests
    - Algorithm: Count requests in last 60 seconds
    """
    
    def __init__(self, redis_client: redis.Redis, window_seconds: int = 60):
        """
        Initialize Redis sliding window limiter.
        
        Args:
            redis_client: Redis connection
            window_seconds: Window size in seconds
        """
        self.redis = redis_client
        self.window_seconds = window_seconds
    
    def check_rate_limit(
        self, 
        user_id: str, 
        limit: int,
        cost: int = 1
    ) -> RateLimitResult:
        """
        Check rate limit using sliding window.
        
        Args:
            user_id: User identifier
            limit: Maximum requests in window
            cost: Cost of this request (for weighted rate limiting)
            
        Returns:
            RateLimitResult
        """
        key = f"rate_limit:{user_id}"
        now = time.time()
        window_start = now - self.window_seconds
        
        # Use Redis pipeline for atomic operations
        pipe = self.redis.pipeline()
        
        # Remove old entries outside window
        pipe.zremrangebyscore(key, 0, window_start)
        
        # Count requests in window
        pipe.zcard(key)
        
        # Add current request (with score = timestamp)
        # Note: Not committed yet, just preparing
        
        # Execute pipeline
        pipe.execute()
        
        # Get count
        current_count = self.redis.zcard(key)
        
        if current_count < limit:
            # Allow request
            # Add to sorted set with current timestamp as score
            # Use microsecond precision to avoid collisions
            timestamp_score = now * 1000000 + (current_count % 1000000)
            self.redis.zadd(key, {str(timestamp_score): timestamp_score})
            
            # Set TTL to window size + buffer
            self.redis.expire(key, self.window_seconds + 10)
            
            return RateLimitResult(
                allowed=True,
                tokens_remaining=limit - current_count - 1,
                limit=limit
            )
        else:
            # Deny request
            # Calculate retry after based on oldest request
            oldest = self.redis.zrange(key, 0, 0, withscores=True)
            if oldest:
                oldest_timestamp = oldest[0][1] / 1000000
                retry_after = oldest_timestamp + self.window_seconds - now
            else:
                retry_after = 1.0
            
            return RateLimitResult(
                allowed=False,
                tokens_remaining=0,
                retry_after_seconds=max(0, retry_after),
                limit=limit
            )


# Usage example
r = redis.Redis(host='localhost', port=6379, decode_responses=True)
limiter = RedisSlidingWindowLimiter(r, window_seconds=60)

# Test rate limiting
for i in range(105):
    result = limiter.check_rate_limit('user_123', limit=100)
    if not result.allowed:
        print(f"Request {i+1}: Rate limited (retry after {result.retry_after_seconds:.1f}s)")
```

---

## Adaptive Rate Limiting

### 4. Adaptive DDoS Protection

```python
import time
from collections import deque
from dataclasses import dataclass

@dataclass
class AdaptiveThresholds:
    """Adaptive rate limit thresholds."""
    normal_limit: int
    increased_limit: int
    aggressive_limit: int
    current_mode: str = "normal"


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that responds to attack patterns.
    
    Automatically tightens limits during suspected attacks and
    relaxes during normal operation.
    
    Modes:
    - Normal: Standard rate limits (e.g., 100 req/min)
    - Increased: Moderately strict (e.g., 50 req/min)
    - Aggressive: Very strict (e.g., 10 req/min)
    
    References:
    - playbook-denial-of-service.md (IRP-007)
    - Scenario 007: DoS Resource Exhaustion
    """
    
    def __init__(
        self,
        normal_limit: int = 100,
        increased_limit: int = 50,
        aggressive_limit: int = 10,
        window_seconds: int = 60
    ):
        """
        Initialize adaptive rate limiter.
        
        Args:
            normal_limit: Requests/window during normal operation
            increased_limit: Requests/window during elevated threat
            aggressive_limit: Requests/window during attack
            window_seconds: Window size for rate calculation
        """
        self.thresholds = AdaptiveThresholds(
            normal_limit=normal_limit,
            increased_limit=increased_limit,
            aggressive_limit=aggressive_limit
        )
        self.window_seconds = window_seconds
        
        # Track recent requests for anomaly detection
        self.recent_requests = deque(maxlen=1000)
        
        # Per-user tracking
        self.user_limiters = {}
        
        # Anomaly detection state
        self.baseline_rate = normal_limit / window_seconds
        self.current_rate = 0.0
        self.last_mode_change = time.time()
    
    def _update_mode(self):
        """Update rate limiting mode based on traffic patterns."""
        now = time.time()
        
        # Calculate current request rate
        recent_window = now - self.window_seconds
        recent_count = sum(1 for ts in self.recent_requests if ts > recent_window)
        self.current_rate = recent_count / self.window_seconds
        
        # Determine mode based on rate vs baseline
        rate_multiplier = self.current_rate / max(self.baseline_rate, 1)
        
        old_mode = self.thresholds.current_mode
        
        if rate_multiplier > 5.0:
            # >5x baseline = attack
            self.thresholds.current_mode = "aggressive"
        elif rate_multiplier > 2.0:
            # 2-5x baseline = elevated
            self.thresholds.current_mode = "increased"
        else:
            # <2x baseline = normal
            # But don't immediately relax after attack (hysteresis)
            if self.thresholds.current_mode == "aggressive":
                if now - self.last_mode_change > 300:  # 5 min cooldown
                    self.thresholds.current_mode = "increased"
            elif self.thresholds.current_mode == "increased":
                if now - self.last_mode_change > 600:  # 10 min cooldown
                    self.thresholds.current_mode = "normal"
        
        if old_mode != self.thresholds.current_mode:
            self.last_mode_change = now
            print(f"⚠️  Rate limit mode changed: {old_mode} → {self.thresholds.current_mode}")
            print(f"   Current rate: {self.current_rate:.1f} req/s ({rate_multiplier:.1f}x baseline)")
    
    def check_rate_limit(self, user_id: str) -> RateLimitResult:
        """
        Check rate limit with adaptive thresholds.
        
        Args:
            user_id: User identifier
            
        Returns:
            RateLimitResult with current mode limits
        """
        # Update mode based on traffic
        self._update_mode()
        
        # Get current limit based on mode
        if self.thresholds.current_mode == "aggressive":
            current_limit = self.thresholds.aggressive_limit
        elif self.thresholds.current_mode == "increased":
            current_limit = self.thresholds.increased_limit
        else:
            current_limit = self.thresholds.normal_limit
        
        # Track request
        self.recent_requests.append(time.time())
        
        # Get or create per-user limiter
        if user_id not in self.user_limiters:
            refill_rate = current_limit / self.window_seconds
            self.user_limiters[user_id] = TokenBucket(
                capacity=current_limit,
                refill_rate=refill_rate
            )
        
        return self.user_limiters[user_id].consume(1)


# Usage example - simulating DDoS attack
limiter = AdaptiveRateLimiter(
    normal_limit=100,
    increased_limit=50,
    aggressive_limit=10
)

print("=== Normal traffic ===")
for i in range(50):
    result = limiter.check_rate_limit(f"user_{i % 10}")
    time.sleep(0.01)

print("\n=== Attack begins (10x traffic) ===")
for i in range(500):
    result = limiter.check_rate_limit(f"attacker_{i % 100}")
    if not result.allowed and i % 100 == 0:
        print(f"  Attack traffic blocked (mode: {limiter.thresholds.current_mode})")
    time.sleep(0.001)

print("\n=== Attack subsides ===")
time.sleep(2)
for i in range(50):
    result = limiter.check_rate_limit(f"user_{i % 10}")
    time.sleep(0.01)
```

---

## Cost-Based Rate Limiting

### 5. LLM Token-Based Rate Limiting

```python
from typing import Dict
import time

class CostBasedRateLimiter:
    """
    Cost-based rate limiter for LLM API usage.
    
    Limits based on token usage and API costs rather than request count.
    Prevents economic DoS attacks.
    
    Example costs (Anthropic Claude Sonnet):
    - Input tokens: $3 per 1M tokens
    - Output tokens: $15 per 1M tokens
    
    References:
    - Scenario 007: Economic DoS via Resource Exhaustion
    - docs/guides/04-runtime-sandboxing.md (Resource limits)
    """
    
    # Token costs (USD per 1M tokens)
    COSTS_PER_MILLION_TOKENS = {
        'claude-3-opus': {'input': 15, 'output': 75},
        'claude-3-sonnet': {'input': 3, 'output': 15},
        'claude-3-haiku': {'input': 0.25, 'output': 1.25},
    }
    
    def __init__(
        self,
        daily_budget_usd: float = 100.0,
        billing_window_seconds: int = 86400  # 24 hours
    ):
        """
        Initialize cost-based rate limiter.
        
        Args:
            daily_budget_usd: Daily budget in USD
            billing_window_seconds: Billing window (default 24 hours)
        """
        self.daily_budget = daily_budget_usd
        self.billing_window = billing_window_seconds
        
        # Per-user cost tracking
        self.user_costs = {}  # user_id -> {'cost': float, 'window_start': float}
    
    def _get_token_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int
    ) -> float:
        """
        Calculate cost for token usage.
        
        Args:
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Cost in USD
        """
        if model not in self.COSTS_PER_MILLION_TOKENS:
            # Default to Sonnet costs
            model = 'claude-3-sonnet'
        
        costs = self.COSTS_PER_MILLION_TOKENS[model]
        input_cost = (input_tokens / 1_000_000) * costs['input']
        output_cost = (output_tokens / 1_000_000) * costs['output']
        
        return input_cost + output_cost
    
    def check_budget(
        self,
        user_id: str,
        model: str,
        input_tokens: int,
        output_tokens: int = 0
    ) -> Dict:
        """
        Check if request is within budget.
        
        Args:
            user_id: User identifier
            model: Model name
            input_tokens: Input tokens for this request
            output_tokens: Estimated output tokens
            
        Returns:
            Dict with 'allowed', 'cost', 'budget_remaining', 'budget_used'
        """
        request_cost = self._get_token_cost(model, input_tokens, output_tokens)
        
        now = time.time()
        
        # Initialize or reset window
        if user_id not in self.user_costs:
            self.user_costs[user_id] = {
                'cost': 0.0,
                'window_start': now
            }
        else:
            # Check if window expired
            user_data = self.user_costs[user_id]
            if now - user_data['window_start'] > self.billing_window:
                # Reset window
                user_data['cost'] = 0.0
                user_data['window_start'] = now
        
        current_cost = self.user_costs[user_id]['cost']
        budget_remaining = self.daily_budget - current_cost
        
        if current_cost + request_cost <= self.daily_budget:
            # Allow request
            self.user_costs[user_id]['cost'] += request_cost
            
            return {
                'allowed': True,
                'cost': request_cost,
                'budget_remaining': budget_remaining - request_cost,
                'budget_used': current_cost + request_cost,
                'budget_percent': ((current_cost + request_cost) / self.daily_budget) * 100
            }
        else:
            # Deny request
            window_reset = self.user_costs[user_id]['window_start'] + self.billing_window
            time_until_reset = window_reset - now
            
            return {
                'allowed': False,
                'cost': request_cost,
                'budget_remaining': 0,
                'budget_used': current_cost,
                'budget_percent': (current_cost / self.daily_budget) * 100,
                'reset_in_seconds': time_until_reset
            }


# Usage example
limiter = CostBasedRateLimiter(daily_budget_usd=10.0)

# Simulate legitimate usage
print("=== Normal usage ===")
for i in range(10):
    result = limiter.check_budget(
        user_id='alice',
        model='claude-3-sonnet',
        input_tokens=1000,
        output_tokens=500
    )
    print(f"Request {i+1}: ${result['cost']:.4f}, "
          f"Budget used: {result['budget_percent']:.1f}%")

# Simulate economic DoS attempt
print("\n=== Economic DoS attempt (large context) ===")
result = limiter.check_budget(
    user_id='attacker',
    model='claude-3-opus',  # Most expensive
    input_tokens=100_000,   # 100k tokens = massive context
    output_tokens=50_000
)
print(f"Attack request: ${result['cost']:.2f}")
if not result['allowed']:
    print(f"✓ Blocked - Budget limit exceeded")
    print(f"  Reset in: {result['reset_in_seconds']/3600:.1f} hours")
```

---

## Integration Examples

### 6. Complete Rate Limiting Middleware

```python
from functools import wraps
from flask import Flask, request, jsonify
import redis

app = Flask(__name__)
redis_client = redis.Redis(host='localhost', port=6379, decode_responses=True)

# Initialize limiters
sliding_window_limiter = RedisSlidingWindowLimiter(redis_client)
adaptive_limiter = AdaptiveRateLimiter()
cost_limiter = CostBasedRateLimiter(daily_budget_usd=100.0)


def rate_limit(limit: int = 60, window: int = 60):
    """
    Rate limiting decorator.
    
    Args:
        limit: Maximum requests per window
        window: Window size in seconds
        
    Usage:
        @app.route('/api/endpoint')
        @rate_limit(limit=100, window=60)
        def my_endpoint():
            return {'result': 'ok'}
    """
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            # Identify user (IP address, user ID, API key)
            user_id = request.remote_addr
            if request.headers.get('X-API-Key'):
                user_id = request.headers.get('X-API-Key')
            elif request.headers.get('X-User-ID'):
                user_id = request.headers.get('X-User-ID')
            
            # Check rate limit
            result = sliding_window_limiter.check_rate_limit(user_id, limit)
            
            # Add rate limit headers
            headers = {
                'X-RateLimit-Limit': str(limit),
                'X-RateLimit-Remaining': str(result.tokens_remaining),
                'X-RateLimit-Reset': str(int(time.time()) + window)
            }
            
            if not result.allowed:
                # Rate limit exceeded
                headers['Retry-After'] = str(int(result.retry_after_seconds))
                return jsonify({
                    'error': 'Rate limit exceeded',
                    'retry_after_seconds': result.retry_after_seconds
                }), 429, headers
            
            # Allow request
            response = f(*args, **kwargs)
            if isinstance(response, tuple):
                return response[0], response[1], {**response[2], **headers}
            else:
                return response, 200, headers
        
        return wrapped
    return decorator


@app.route('/api/chat', methods=['POST'])
@rate_limit(limit=60, window=60)  # 60 requests per minute
def chat_endpoint():
    """Chat endpoint with rate limiting."""
    user_input = request.json.get('message')
    
    # Process chat request
    response = {'reply': f'Echo: {user_input}'}
    
    return jsonify(response)


@app.route('/api/expensive', methods=['POST'])
@rate_limit(limit=10, window=60)  # Lower limit for expensive endpoint
def expensive_endpoint():
    """Expensive LLM endpoint with stricter limits."""
    # Check cost-based budget
    user_id = request.headers.get('X-User-ID', request.remote_addr)
    model = request.json.get('model', 'claude-3-sonnet')
    
    # Estimate tokens (simplified)
    input_text = request.json.get('prompt', '')
    estimated_input_tokens = len(input_text.split()) * 1.3  # Rough estimate
    estimated_output_tokens = request.json.get('max_tokens', 1000)
    
    # Check cost budget
    budget_result = cost_limiter.check_budget(
        user_id,
        model,
        int(estimated_input_tokens),
        estimated_output_tokens
    )
    
    if not budget_result['allowed']:
        return jsonify({
            'error': 'Daily budget exceeded',
            'budget_used_usd': budget_result['budget_used'],
            'reset_in_seconds': budget_result['reset_in_seconds']
        }), 429
    
    # Process expensive request
    return jsonify({
        'result': 'success',
        'cost_usd': budget_result['cost'],
        'budget_remaining_usd': budget_result['budget_remaining']
    })


if __name__ == '__main__':
    app.run(debug=True)
```

---

## Best Practices

### 1. Return Informative Headers

```python
# RFC 6585: Additional HTTP Status Codes
# RFC 7231: HTTP/1.1 Semantics and Content

headers = {
    'X-RateLimit-Limit': '100',           # Total limit
    'X-RateLimit-Remaining': '42',        # Remaining in window
    'X-RateLimit-Reset': '1676387400',    # Unix timestamp of reset
    'Retry-After': '60'                    # Seconds until retry (429 response)
}

# Return 429 Too Many Requests on limit exceeded
return jsonify({'error': 'Rate limit exceeded'}), 429, headers
```

### 2. Use Redis for Distributed Systems

```python
# ✅ CORRECT: Distributed rate limiting with Redis
import redis

r = redis.Redis(host='redis.openclaw.internal')
limiter = RedisSlidingWindowLimiter(r)

# All instances share the same rate limit state
result = limiter.check_rate_limit('user_123', limit=100)
```

### 3. Implement Adaptive Limits During Attacks

```python
# ✅ CORRECT: Adaptive limits respond to traffic patterns
limiter = AdaptiveRateLimiter(
    normal_limit=100,      # Normal operation
    increased_limit=50,    # Elevated threat
    aggressive_limit=10     # Active attack
)

# Automatically tightens during DDoS
result = limiter.check_rate_limit(user_id)
```

---

## Testing

```python
import pytest
import time

def test_token_bucket_burst():
    """Test token bucket allows bursts."""
    bucket = TokenBucket(capacity=10, refill_rate=1)
    
    # Should allow burst up to capacity
    for i in range(10):
        result = bucket.consume(1)
        assert result.allowed
    
    # 11th request should be denied
    result = bucket.consume(1)
    assert not result.allowed

def test_sliding_window_accuracy():
    """Test sliding window doesn't allow boundary gaming."""
    r = redis.Redis(host='localhost', decode_responses=True)
    limiter = RedisSlidingWindowLimiter(r, window_seconds=1)
    
    # Make limit requests
    for i in range(10):
        result = limiter.check_rate_limit('test_user', limit=10)
        assert result.allowed
    
    # 11th should be denied (even at window boundary)
    result = limiter.check_rate_limit('test_user', limit=10)
    assert not result.allowed

def test_cost_based_limiting():
    """Test cost-based budget enforcement."""
    limiter = CostBasedRateLimiter(daily_budget_usd=1.0)
    
    # Expensive request should exceed budget
    result = limiter.check_budget(
        'test_user',
        'claude-3-opus',
        input_tokens=10_000_000,  # 10M tokens
        output_tokens=1_000_000
    )
    assert not result['allowed']

if __name__ == "__main__":
    pytest.main([__file__, '-v'])
```

---

## References

- **RFC 6585**: Additional HTTP Status Codes (429 Too Many Requests)
- **RFC 7231**: HTTP/1.1 Semantics  
- **[DoS Playbook](../incident-response/playbook-denial-of-service.md)**: IRP-007 response procedures
- **[Scenario 007](../scenarios/scenario-007-denial-of-service-resource-exhaustion.md)**: Economic DoS
- **[Rate Limit Configuration](../../configs/templates/gateway.hardened.yml)**: Production configs

---

**Last Updated**: 2026-02-14  
**Maintainer**: OpenClaw Security Team  
**License**: MIT
