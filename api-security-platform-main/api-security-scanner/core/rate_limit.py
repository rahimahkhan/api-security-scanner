"""Minimal in-memory rate limiting for public endpoints (S5).

Fixed-window per-key counters, thread-safe. This dampens abuse of the two
expensive public surfaces — POST /api/assistant/ask (burns the owner's
Gemini quota) and scan launching (each scan spawns worker threads on the
free tier) — without affecting legitimate use: the default limits are
generous, logged-in users share the same bucket, and everything is tunable
via environment variables.

Not a distributed guarantee: counters reset on process restart, which is
fine for a single Render instance.
"""

import os
import threading
import time
from functools import wraps

from flask import jsonify, request


def _env_int(name: str, default: int) -> int:
    try:
        return max(0, int(os.getenv(name, str(default))))
    except (TypeError, ValueError):
        return default


def rate_limit_enabled() -> bool:
    return os.getenv("RATE_LIMIT_ENABLED", "1").lower() not in {"0", "false", "no", "off"}


class RateLimiter:
    """Thread-safe fixed-window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}  # (key, window_start) -> count

    def allow(self, key: str, limit: int, window_seconds: int = 3600) -> bool:
        """Return True and record the hit when under the limit, else False."""
        if limit <= 0:
            return True
        now = time.time()
        window = int(now // window_seconds)
        with self._lock:
            # Opportunistic pruning: drop windows older than the current one.
            for k in [k for k in self._hits if k[1] < window - 1]:
                del self._hits[k]
            count = self._hits.get((key, window), 0)
            if count >= limit:
                return False
            self._hits[(key, window)] = count + 1
            return True

    def reset(self):
        """Clear all counters (tests)."""
        with self._lock:
            self._hits.clear()


_limiter = RateLimiter()


def client_key() -> str:
    """Best-effort client identity: logged-in user id, else client IP.

    ProxyFix is configured (x_for=1), so on Render request.remote_addr is
    the real client IP from X-Forwarded-For.
    """
    try:
        from flask import session
        user_id = session.get("user_id")
        if user_id is not None:
            return f"user:{user_id}"
    except Exception:
        pass
    try:
        return f"ip:{request.remote_addr or 'unknown'}"
    except Exception:
        return "ip:unknown"


def rate_limited(limit: int, window_seconds: int = 3600, scope: str = "global"):
    """Decorator: 429 when the caller exceeds `limit` hits per window.

    API routes get a JSON 429; page/form routes get a plain-text 429.
    """
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if rate_limit_enabled():
                key = f"{scope}:{client_key()}"
                if not _limiter.allow(key, limit, window_seconds):
                    msg = "Too many requests — please slow down and try again later."
                    if request.path.startswith("/api/"):
                        return jsonify({"status": "error", "message": msg}), 429
                    return msg, 429
            return view(*args, **kwargs)
        return wrapped
    return decorator


# Tunables (per hour). Generous by design: real users never hit these;
# only abuse does. Set to 0 to disable a specific limit.
def scan_limit() -> int:
    return _env_int("RATE_LIMIT_SCAN_PER_HOUR", 10)


def assistant_limit() -> int:
    return _env_int("RATE_LIMIT_ASSISTANT_PER_HOUR", 30)
