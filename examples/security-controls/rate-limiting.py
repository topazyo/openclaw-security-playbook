"""Rate limiting examples used by CI security scans."""

import time
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from typing import Optional


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


@dataclass
class RateLimitResult:
    allowed: bool
    tokens_remaining: int
    retry_after_seconds: Optional[float] = None
    limit: int = 0


class TokenBucket:
    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.monotonic()
        self.lock = Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def consume(self, tokens: int = 1) -> RateLimitResult:
        with self.lock:
            self._refill()
            if self.tokens >= tokens:
                self.tokens -= tokens
                return RateLimitResult(True, int(self.tokens), None, self.capacity)
            tokens_needed = tokens - self.tokens
            retry_after = tokens_needed / self.refill_rate if self.refill_rate else None
            return RateLimitResult(False, int(self.tokens), retry_after, self.capacity)


class SlidingWindowLimiter:
    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = Lock()

    def check_rate_limit(self, user_id: str, limit: int) -> RateLimitResult:
        now = time.monotonic()
        with self.lock:
            window = self.events[user_id]
            while window and now - window[0] >= self.window_seconds:
                window.popleft()
            if len(window) >= limit:
                retry_after = self.window_seconds - (now - window[0])
                return RateLimitResult(False, max(limit - len(window), 0), retry_after, limit)
            window.append(now)
            return RateLimitResult(True, max(limit - len(window), 0), None, limit)


class CostBasedRateLimiter:
    MODEL_COSTS = {
        "claude-3-opus": 0.000015,
        "claude-3-sonnet": 0.000003,
        "gpt-4o-mini": 0.000001,
    }

    def __init__(self, daily_budget_usd: float):
        self.daily_budget_usd = daily_budget_usd
        self.spent_by_user: dict[str, float] = defaultdict(float)

    def check_budget(self, user_id: str, model_name: str, input_tokens: int, output_tokens: int) -> dict[str, float | bool]:
        unit_cost = self.MODEL_COSTS.get(model_name, self.MODEL_COSTS["gpt-4o-mini"])
        request_cost = unit_cost * (input_tokens + output_tokens)
        projected_total = self.spent_by_user[user_id] + request_cost
        if projected_total > self.daily_budget_usd:
            return {"allowed": False, "remaining_budget": max(self.daily_budget_usd - self.spent_by_user[user_id], 0.0)}
        self.spent_by_user[user_id] = projected_total
        return {"allowed": True, "remaining_budget": max(self.daily_budget_usd - projected_total, 0.0)}


def test_token_bucket_burst() -> None:
    bucket = TokenBucket(capacity=10, refill_rate=1)
    for _ in range(10):
        ensure(bucket.consume(1).allowed, "Token bucket should allow requests up to burst capacity")
    ensure(not bucket.consume(1).allowed, "Token bucket should block requests after burst capacity is exhausted")


def test_sliding_window_accuracy() -> None:
    limiter = SlidingWindowLimiter(window_seconds=60)
    for _ in range(10):
        ensure(limiter.check_rate_limit("test-user", limit=10).allowed, "Sliding window should allow requests inside the limit")
    ensure(not limiter.check_rate_limit("test-user", limit=10).allowed, "Sliding window should reject the eleventh request")


def test_cost_based_limiting() -> None:
    limiter = CostBasedRateLimiter(daily_budget_usd=1.0)
    result = limiter.check_budget("test-user", "claude-3-opus", input_tokens=10_000_000, output_tokens=1_000_000)
    ensure(not bool(result["allowed"]), "Expensive request should exceed the daily budget")


if __name__ == "__main__":
    test_token_bucket_burst()
    test_sliding_window_accuracy()
    test_cost_based_limiting()
    print("Rate limiting examples completed")
