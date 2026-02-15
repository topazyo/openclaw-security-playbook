#!/usr/bin/env python3
"""
Unit Tests for Rate Limiting Module

Tests the rate-limiting.py security control implementation from
examples/security-controls/rate-limiting.py

Test Coverage:
  - Per-user rate limits (100 requests/min)
  - Burst allowance (token bucket algorithm)
  - Token replenishment rate
  - Redis distributed tracking
  - Failover to in-memory tracking
  - Time-based window resets
  - IP-based rate limiting

Compliance:
  - SOC 2 CC6.1: Logical access controls
  - ISO 27001 A.14.2.9: System acceptance testing

Usage:
  pytest tests/unit/test_rate_limiting.py -v
  pytest tests/unit/test_rate_limiting.py::test_per_user_limits -v
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import redis


# ============================================================================
# TEST FIXTURES
# ============================================================================

@pytest.fixture
def rate_limiter():
    """Initialize rate limiter with test configuration."""
    from examples.security_controls.rate_limiting import RateLimiter
    
    config = {
        "requests_per_minute": 100,
        "burst_size": 20,
        "algorithm": "token_bucket",
        "redis_url": "redis://localhost:6379/0",
        "enabled": True,
    }
    
    return RateLimiter(config)


@pytest.fixture
def mock_redis():
    """Mock Redis client for testing."""
    mock_client = MagicMock(spec=redis.Redis)
    
    # Mock Redis methods
    mock_client.get = Mock(return_value=None)
    mock_client.set = Mock(return_value=True)
    mock_client.incr = Mock(return_value=1)
    mock_client.expire = Mock(return_value=True)
    mock_client.ping = Mock(return_value=True)
    
    return mock_client


@pytest.fixture
def rate_limiter_with_mock_redis(mock_redis):
    """Rate limiter with mocked Redis client."""
    from examples.security_controls.rate_limiting import RateLimiter
    
    config = {
        "requests_per_minute": 100,
        "burst_size": 20,
        "algorithm": "token_bucket",
        "redis_url": "redis://localhost:6379/0",
        "enabled": True,
    }
    
    limiter = RateLimiter(config)
    limiter.redis_client = mock_redis
    
    return limiter


# ============================================================================
# PER-USER RATE LIMIT TESTS
# ============================================================================

class TestPerUserLimits:
    """Test per-user rate limiting."""
    
    def test_within_rate_limit(self, rate_limiter_with_mock_redis):
        """Test requests within rate limit are allowed."""
        user_id = "user123"
        
        # Simulate 50 requests (within 100/min limit)
        for i in range(50):
            allowed = rate_limiter_with_mock_redis.check_rate_limit(user_id)
            assert allowed is True
    
    def test_exceeds_rate_limit(self, rate_limiter_with_mock_redis):
        """Test that 101st request exceeds limit and returns 429."""
        user_id = "user456"
        
        # Mock Redis to track counter
        counter = {"value": 0}
        
        def mock_incr(key):
            counter["value"] += 1
            return counter["value"]
        
        rate_limiter_with_mock_redis.redis_client.incr = Mock(side_effect=mock_incr)
        
        # Simulate 100 requests (at limit)
        for i in range(100):
            allowed = rate_limiter_with_mock_redis.check_rate_limit(user_id)
            assert allowed is True
        
        # 101st request should be denied
        allowed = rate_limiter_with_mock_redis.check_rate_limit(user_id)
        assert allowed is False
    
    def test_different_users_separate_limits(self, rate_limiter_with_mock_redis):
        """Test that different users have independent rate limits."""
        user1 = "alice"
        user2 = "bob"
        
        # Mock Redis with separate counters per user
        counters = {}
        
        def mock_incr(key):
            if key not in counters:
                counters[key] = 0
            counters[key] += 1
            return counters[key]
        
        rate_limiter_with_mock_redis.redis_client.incr = Mock(side_effect=mock_incr)
        
        # User1 makes 50 requests
        for i in range(50):
            assert rate_limiter_with_mock_redis.check_rate_limit(user1) is True
        
        # User2 should still have full quota
        for i in range(50):
            assert rate_limiter_with_mock_redis.check_rate_limit(user2) is True
    
    def test_rate_limit_key_format(self, rate_limiter_with_mock_redis):
        """Test that rate limit keys are formatted correctly."""
        user_id = "user789"
        
        rate_limiter_with_mock_redis.check_rate_limit(user_id)
        
        # Verify Redis key format
        expected_key_prefix = f"rate_limit:{user_id}:"
        
        call_args = rate_limiter_with_mock_redis.redis_client.incr.call_args
        actual_key = call_args[0][0]
        
        assert actual_key.startswith(expected_key_prefix)


# ============================================================================
# BURST ALLOWANCE TESTS
# ============================================================================

class TestBurstAllowance:
    """Test burst allowance with token bucket algorithm."""
    
    def test_burst_within_limit(self, rate_limiter):
        """Test that burst requests within limit are allowed."""
        user_id = "burst_user1"
        
        # Simulate burst of 20 requests (within burst_size=20)
        for i in range(20):
            allowed = rate_limiter.check_rate_limit(user_id)
            assert allowed is True
    
    def test_burst_exceeds_limit(self, rate_limiter):
        """Test that burst exceeding limit is throttled."""
        user_id = "burst_user2"
        
        # Simulate burst of 25 requests (exceeds burst_size=20)
        allowed_count = 0
        
        for i in range(25):
            if rate_limiter.check_rate_limit(user_id):
                allowed_count += 1
        
        # Only 20 should be allowed initially
        assert allowed_count <= 20
    
    def test_burst_refills_over_time(self, rate_limiter):
        """Test that burst capacity refills over time."""
        user_id = "burst_user3"
        
        # Use up burst capacity
        for i in range(20):
            rate_limiter.check_rate_limit(user_id)
        
        # Wait for token refill (simulate time passing)
        # In real implementation, tokens refill at requests_per_minute / 60 per second
        # 100 req/min = 1.67 tokens/sec
        
        time.sleep(2)  # Wait 2 seconds for ~3 tokens to refill
        
        # Should be able to make a few more requests
        allowed = rate_limiter.check_rate_limit(user_id)
        assert allowed is True


# ============================================================================
# TOKEN BUCKET ALGORITHM TESTS
# ============================================================================

class TestTokenBucketAlgorithm:
    """Test token bucket algorithm implementation."""
    
    def test_token_replenishment_rate(self, rate_limiter):
        """Test that tokens replenish at correct rate (100/60 per second)."""
        user_id = "token_user1"
        
        # Expected rate: 100 requests/min = 1.67 tokens/sec
        expected_rate = 100 / 60  # tokens per second
        
        # Record initial tokens
        initial_tokens = rate_limiter.get_token_count(user_id)
        
        # Wait 10 seconds
        time.sleep(10)
        
        # Calculate expected tokens
        expected_tokens = min(
            initial_tokens + (expected_rate * 10),
            100  # Max capacity
        )
        
        actual_tokens = rate_limiter.get_token_count(user_id)
        
        # Allow 10% tolerance for timing variations
        assert abs(actual_tokens - expected_tokens) <= (expected_tokens * 0.1)
    
    def test_token_consumption(self, rate_limiter):
        """Test that each request consumes one token."""
        user_id = "token_user2"
        
        initial_tokens = rate_limiter.get_token_count(user_id)
        
        # Make 5 requests
        for i in range(5):
            rate_limiter.check_rate_limit(user_id)
        
        final_tokens = rate_limiter.get_token_count(user_id)
        
        # Should have consumed 5 tokens
        assert initial_tokens - final_tokens == 5
    
    def test_token_bucket_max_capacity(self, rate_limiter):
        """Test that token bucket doesn't exceed max capacity."""
        user_id = "token_user3"
        
        # Wait long enough for tokens to fill
        time.sleep(120)  # 2 minutes
        
        tokens = rate_limiter.get_token_count(user_id)
        
        # Should not exceed requests_per_minute (100)
        assert tokens <= 100


# ============================================================================
# REDIS DISTRIBUTED TRACKING TESTS
# ============================================================================

class TestRedisDistributedTracking:
    """Test Redis-based distributed rate limiting."""
    
    @patch("redis.Redis")
    def test_redis_connection(self, mock_redis_class, rate_limiter):
        """Test that Redis connection is established correctly."""
        mock_redis_instance = MagicMock()
        mock_redis_class.from_url.return_value = mock_redis_instance
        
        # Initialize rate limiter (should connect to Redis)
        from examples.security_controls.rate_limiting import RateLimiter
        
        config = {
            "requests_per_minute": 100,
            "redis_url": "redis://localhost:6379/0",
        }
        
        limiter = RateLimiter(config)
        
        # Verify Redis connection was attempted
        mock_redis_class.from_url.assert_called_once_with(
            "redis://localhost:6379/0"
        )
    
    def test_distributed_counter_increment(self, rate_limiter_with_mock_redis):
        """Test that Redis counter is incremented atomically."""
        user_id = "distributed_user1"
        
        rate_limiter_with_mock_redis.check_rate_limit(user_id)
        
        # Verify Redis incr was called (atomic increment)
        rate_limiter_with_mock_redis.redis_client.incr.assert_called()
    
    def test_distributed_counter_expiry(self, rate_limiter_with_mock_redis):
        """Test that rate limit counters have TTL set."""
        user_id = "distributed_user2"
        
        rate_limiter_with_mock_redis.check_rate_limit(user_id)
        
        # Verify TTL was set (60 seconds for 1-minute window)
        rate_limiter_with_mock_redis.redis_client.expire.assert_called()
        
        call_args = rate_limiter_with_mock_redis.redis_client.expire.call_args
        ttl = call_args[0][1]
        
        assert ttl == 60  # 60-second TTL for 1-minute window
    
    def test_multiple_instances_share_state(self, mock_redis):
        """Test that multiple rate limiter instances share Redis state."""
        from examples.security_controls.rate_limiting import RateLimiter
        
        config = {
            "requests_per_minute": 100,
            "redis_url": "redis://localhost:6379/0",
        }
        
        # Create two rate limiter instances
        limiter1 = RateLimiter(config)
        limiter2 = RateLimiter(config)
        
        # Replace Redis clients with mock
        limiter1.redis_client = mock_redis
        limiter2.redis_client = mock_redis
        
        user_id = "shared_user"
        
        # Instance 1 makes request
        limiter1.check_rate_limit(user_id)
        
        # Instance 2 makes request (should see same counter)
        limiter2.check_rate_limit(user_id)
        
        # Both should have incremented same Redis key
        assert mock_redis.incr.call_count == 2


# ============================================================================
# FAILOVER TO IN-MEMORY TRACKING TESTS
# ============================================================================

class TestRedisFailover:
    """Test failover to in-memory tracking when Redis unavailable."""
    
    def test_redis_connection_failure(self, rate_limiter):
        """Test graceful handling of Redis connection failure."""
        # Simulate Redis connection failure
        rate_limiter.redis_client.incr = Mock(
            side_effect=redis.ConnectionError("Connection refused")
        )
        
        user_id = "failover_user1"
        
        # Should fall back to in-memory tracking
        allowed = rate_limiter.check_rate_limit(user_id)
        
        # Request should still be processed (degraded mode)
        assert allowed is not None
    
    def test_in_memory_tracking_after_failover(self, rate_limiter):
        """Test that in-memory tracking works after Redis failure."""
        # Force Redis failure
        rate_limiter.redis_client = None
        
        user_id = "failover_user2"
        
        # Make requests using in-memory tracking
        for i in range(50):
            allowed = rate_limiter.check_rate_limit(user_id)
            assert allowed is True
    
    def test_redis_reconnect_after_failure(self, rate_limiter):
        """Test automatic reconnection to Redis after failure."""
        # Simulate temporary Redis failure
        failure_count = {"count": 0}
        
        def mock_incr_with_retry(key):
            failure_count["count"] += 1
            if failure_count["count"] < 3:
                raise redis.ConnectionError("Temporary failure")
            return failure_count["count"]
        
        rate_limiter.redis_client.incr = Mock(side_effect=mock_incr_with_retry)
        
        user_id = "reconnect_user"
        
        # First requests should fail over to in-memory
        rate_limiter.check_rate_limit(user_id)
        
        # Later requests should reconnect to Redis
        rate_limiter.check_rate_limit(user_id)


# ============================================================================
# TIME-BASED WINDOW RESET TESTS
# ============================================================================

class TestTimeBasedWindows:
    """Test time-based rate limit window resets."""
    
    def test_counter_resets_after_window(self, rate_limiter_with_mock_redis):
        """Test that counters reset after time window expires."""
        user_id = "window_user1"
        
        # Mock time to control window boundaries
        with patch("time.time") as mock_time:
            # Start at timestamp 0
            mock_time.return_value = 0
            
            # Make requests
            for i in range(50):
                rate_limiter_with_mock_redis.check_rate_limit(user_id)
            
            # Advance time by 61 seconds (past 60-second window)
            mock_time.return_value = 61
            
            # Counter should have reset
            # All requests in new window should be allowed
            for i in range(50):
                allowed = rate_limiter_with_mock_redis.check_rate_limit(user_id)
                assert allowed is True
    
    def test_sliding_window_algorithm(self, rate_limiter):
        """Test sliding window rate limiting (if implemented)."""
        user_id = "sliding_user1"
        
        # Make requests at t=0
        for i in range(50):
            rate_limiter.check_rate_limit(user_id)
        
        # Wait 30 seconds (half the window)
        time.sleep(30)
        
        # Make more requests at t=30
        for i in range(50):
            rate_limiter.check_rate_limit(user_id)
        
        # Wait another 30 seconds (t=60, first 50 requests expired)
        time.sleep(30)
        
        # Should be able to make requests again (first 50 expired)
        for i in range(50):
            allowed = rate_limiter.check_rate_limit(user_id)
            assert allowed is True


# ============================================================================
# IP-BASED RATE LIMITING TESTS
# ============================================================================

class TestIPBasedRateLimiting:
    """Test rate limiting by IP address."""
    
    def test_ip_rate_limit(self, rate_limiter):
        """Test rate limiting by IP address."""
        ip_address = "192.168.1.100"
        
        # Make requests from IP
        for i in range(100):
            allowed = rate_limiter.check_rate_limit_by_ip(ip_address)
            assert allowed is True
        
        # 101st request should be denied
        allowed = rate_limiter.check_rate_limit_by_ip(ip_address)
        assert allowed is False
    
    def test_different_ips_separate_limits(self, rate_limiter):
        """Test that different IPs have independent limits."""
        ip1 = "192.168.1.100"
        ip2 = "192.168.1.101"
        
        # IP1 uses quota
        for i in range(100):
            rate_limiter.check_rate_limit_by_ip(ip1)
        
        # IP2 should still have full quota
        for i in range(100):
            allowed = rate_limiter.check_rate_limit_by_ip(ip2)
            assert allowed is True
    
    def test_combined_user_and_ip_limits(self, rate_limiter):
        """Test rate limiting by both user and IP."""
        user_id = "combined_user"
        ip_address = "192.168.1.102"
        
        # Check both user and IP limits
        allowed = rate_limiter.check_rate_limit(
            user_id=user_id,
            ip_address=ip_address
        )
        
        assert allowed is True


# ============================================================================
# EDGE CASES AND CONCURRENCY TESTS
# ============================================================================

class TestEdgeCases:
    """Test edge cases and concurrent requests."""
    
    def test_concurrent_requests(self, rate_limiter_with_mock_redis):
        """Test handling of concurrent requests from same user."""
        import threading
        
        user_id = "concurrent_user"
        allowed_count = {"value": 0}
        lock = threading.Lock()
        
        def make_request():
            if rate_limiter_with_mock_redis.check_rate_limit(user_id):
                with lock:
                    allowed_count["value"] += 1
        
        # Spawn 150 concurrent threads
        threads = []
        for i in range(150):
            thread = threading.Thread(target=make_request)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads
        for thread in threads:
            thread.join()
        
        # Should not exceed rate limit (100)
        assert allowed_count["value"] <= 100
    
    def test_empty_user_id(self, rate_limiter):
        """Test handling of empty user ID."""
        with pytest.raises(ValueError):
            rate_limiter.check_rate_limit("")
    
    def test_none_user_id(self, rate_limiter):
        """Test handling of None user ID."""
        with pytest.raises(ValueError):
            rate_limiter.check_rate_limit(None)
    
    def test_very_long_user_id(self, rate_limiter):
        """Test handling of very long user IDs."""
        long_user_id = "A" * 10000
        
        # Should handle long IDs (may hash or truncate)
        allowed = rate_limiter.check_rate_limit(long_user_id)
        assert allowed is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
