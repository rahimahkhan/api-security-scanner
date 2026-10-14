"""Tests for the S5 rate limiter (core/rate_limit.py)."""
import time

from core.rate_limit import RateLimiter


def test_allows_up_to_limit_then_blocks():
    rl = RateLimiter()
    for _ in range(5):
        assert rl.allow("k", 5, 60) is True
    assert rl.allow("k", 5, 60) is False


def test_separate_keys_have_separate_buckets():
    rl = RateLimiter()
    for _ in range(3):
        assert rl.allow("a", 3, 60) is True
    assert rl.allow("a", 3, 60) is False
    assert rl.allow("b", 3, 60) is True


def test_zero_limit_disables():
    rl = RateLimiter()
    for _ in range(100):
        assert rl.allow("k", 0, 60) is True


def test_window_rolls_over():
    rl = RateLimiter()
    assert rl.allow("k", 1, 1) is True
    assert rl.allow("k", 1, 1) is False
    time.sleep(1.1)
    assert rl.allow("k", 1, 1) is True


def test_reset_clears_counters():
    rl = RateLimiter()
    assert rl.allow("k", 1, 60) is True
    assert rl.allow("k", 1, 60) is False
    rl.reset()
    assert rl.allow("k", 1, 60) is True
