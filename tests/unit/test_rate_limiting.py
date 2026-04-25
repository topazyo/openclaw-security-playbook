#!/usr/bin/env python3  # FIX: C5-finding-4
from __future__ import annotations  # FIX: C5-finding-4

import importlib.util  # FIX: C5-finding-4
import sys  # FIX: C5-finding-4
from pathlib import Path  # FIX: C5-finding-4
from unittest.mock import patch  # FIX: C5-finding-4

import pytest  # FIX: C5-finding-4


RATE_LIMITING_PATH = Path(__file__).resolve().parents[2] / "examples" / "security-controls" / "rate-limiting.py"  # FIX: C5-finding-4


@pytest.fixture(scope="module")  # FIX: C5-finding-4
def rate_limiting_module():  # FIX: C5-finding-4
    spec = importlib.util.spec_from_file_location("openclaw_rate_limiting_issue_7_tests", RATE_LIMITING_PATH)  # FIX: C5-finding-4
    assert spec is not None and spec.loader is not None  # FIX: C5-finding-4
    module = importlib.util.module_from_spec(spec)  # FIX: C5-finding-4
    sys.modules[spec.name] = module  # FIX: C5-finding-4
    spec.loader.exec_module(module)  # FIX: C5-finding-4
    return module  # FIX: C5-finding-4


def test_consume_claim_blocks_after_capacity_and_reports_retry_after(rate_limiting_module):  # FIX: C5-finding-4
    bucket = rate_limiting_module.TokenBucket(capacity=3, refill_rate=1.0)  # FIX: C5-finding-4
    assert bucket.consume(1).allowed is True  # FIX: C5-finding-4
    assert bucket.consume(1).allowed is True  # FIX: C5-finding-4
    assert bucket.consume(1).allowed is True  # FIX: C5-finding-4
    blocked = bucket.consume(1)  # FIX: C5-finding-4
    assert blocked.allowed is False  # FIX: C5-finding-4
    assert blocked.limit == 3  # FIX: C5-finding-4
    assert blocked.retry_after_seconds is not None and blocked.retry_after_seconds > 0  # FIX: C5-finding-4


def test_token_bucket_refills_after_elapsed_time(rate_limiting_module):  # FIX: C5-finding-4
    with patch.object(rate_limiting_module.time, "monotonic", side_effect=[100.0, 100.0, 100.0, 100.0, 102.0]):  # FIX: C5-finding-4
        bucket = rate_limiting_module.TokenBucket(capacity=2, refill_rate=1.0)  # FIX: C5-finding-4
        assert bucket.consume(1).allowed is True  # FIX: C5-finding-4
        assert bucket.consume(1).allowed is True  # FIX: C5-finding-4
        assert bucket.consume(1).allowed is False  # FIX: C5-finding-4
        refilled = bucket.consume(1)  # FIX: C5-finding-4
    assert refilled.allowed is True  # FIX: C5-finding-4
    assert refilled.tokens_remaining == 1  # FIX: C5-finding-4


def test_consume_claim_rejects_non_positive_token_requests(rate_limiting_module):  # FIX: C5-finding-4
    bucket = rate_limiting_module.TokenBucket(capacity=5, refill_rate=1.0)  # FIX: C5-finding-4
    with pytest.raises(ValueError, match="positive"):  # FIX: C5-finding-4
        bucket.consume(0)  # FIX: C5-finding-4
    with pytest.raises(ValueError, match="positive"):  # FIX: C5-finding-4
        bucket.consume(-1)  # FIX: C5-finding-4


def test_sliding_window_limiter_blocks_then_resets_after_window(rate_limiting_module):  # FIX: C5-finding-4
    limiter = rate_limiting_module.SlidingWindowLimiter(window_seconds=60)  # FIX: C5-finding-4
    with patch.object(rate_limiting_module.time, "monotonic", side_effect=[0.0, 0.0, 0.0, 61.0]):  # FIX: C5-finding-4
        first = limiter.check_rate_limit("user-1", limit=2)  # FIX: C5-finding-4
        second = limiter.check_rate_limit("user-1", limit=2)  # FIX: C5-finding-4
        blocked = limiter.check_rate_limit("user-1", limit=2)  # FIX: C5-finding-4
        reset = limiter.check_rate_limit("user-1", limit=2)  # FIX: C5-finding-4
    assert first.allowed is True  # FIX: C5-finding-4
    assert second.allowed is True  # FIX: C5-finding-4
    assert blocked.allowed is False  # FIX: C5-finding-4
    assert blocked.retry_after_seconds == 60.0  # FIX: C5-finding-4
    assert reset.allowed is True  # FIX: C5-finding-4


def test_cost_based_rate_limiter_rejects_expensive_request_without_spending_budget(rate_limiting_module):  # FIX: C5-finding-4
    limiter = rate_limiting_module.CostBasedRateLimiter(daily_budget_usd=1.0)  # FIX: C5-finding-4
    result = limiter.check_budget("test-user", "claude-3-opus", input_tokens=10_000_000, output_tokens=1_000_000)  # FIX: C5-finding-4
    assert result == {"allowed": False, "remaining_budget": 1.0}  # FIX: C5-finding-4
    assert limiter.spent_by_user["test-user"] == 0.0  # FIX: C5-finding-4


def test_check_budget_claim_uses_default_cost_for_unknown_model(rate_limiting_module):  # FIX: C5-finding-4
    limiter = rate_limiting_module.CostBasedRateLimiter(daily_budget_usd=0.01)  # FIX: C5-finding-4
    result = limiter.check_budget("test-user", "unknown-model", input_tokens=1000, output_tokens=500)  # FIX: C5-finding-4
    assert result["allowed"] is True  # FIX: C5-finding-4
    assert pytest.approx(result["remaining_budget"], rel=1e-9) == 0.0085  # FIX: C5-finding-4
    assert pytest.approx(limiter.spent_by_user["test-user"], rel=1e-9) == 0.0015  # FIX: C5-finding-4


def test_check_budget_claim_rejects_negative_token_counts(rate_limiting_module):  # FIX: C5-finding-4
    limiter = rate_limiting_module.CostBasedRateLimiter(daily_budget_usd=1.0)  # FIX: C5-finding-4
    with pytest.raises(ValueError, match="non-negative"):  # FIX: C5-finding-4
        limiter.check_budget("test-user", "gpt-4o-mini", input_tokens=-1000, output_tokens=500)  # FIX: C5-finding-4