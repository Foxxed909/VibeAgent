"""KV-backed fixed-window rate limiter.

Fails open (allows the request) when KV is not configured, so deployments
without Redis are not broken by the limiter.  Set
VIBE_AGENT_RATE_LIMIT_ENABLED=0 to disable entirely during local development.

Env vars consumed here:
  KV_REST_API_URL / UPSTASH_REDIS_REST_URL   — Redis REST base URL
  KV_REST_API_TOKEN / UPSTASH_REDIS_REST_TOKEN

All rate-limit policy decisions (which limit/window to apply) live in the
callers (api/_security.py); this module only provides the counter primitive.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

_KV_URL = (
    os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or ""
).rstrip("/")
_KV_TOKEN = (
    os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
)


def _kv_enabled() -> bool:
    return bool(_KV_URL and _KV_TOKEN)


def _kv(timeout: int = 5, *args: Any) -> Any:
    """Execute a single Redis REST command and return its result field."""
    body = json.dumps(list(args)).encode("utf-8")
    req = urllib.request.Request(
        _KV_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {_KV_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if isinstance(data, dict) and data.get("error"):
        raise RuntimeError(f"KV error: {data['error']}")
    return data.get("result") if isinstance(data, dict) else data


@dataclass
class RateLimitResult:
    allowed: bool
    remaining: int
    reset_s: int
    limit: int


def check(key: str, limit: int, window_s: int) -> RateLimitResult:
    """Increment the fixed-window counter for *key* and return the result.

    Uses the classic INCR + EXPIRE pattern.  The only race condition is a
    sub-millisecond gap between INCR and EXPIRE on the very first request of a
    window; the worst outcome is a window that is slightly longer than intended,
    never under-counting.

    Fails open (allowed=True) when KV is unavailable so a Redis outage or an
    unconfigured deployment does not become a self-inflicted DoS.
    """
    if not _kv_enabled():
        return RateLimitResult(allowed=True, remaining=limit, reset_s=window_s, limit=limit)
    try:
        count = int(_kv(5, "INCR", key) or 0)
        if count == 1:
            # First request in this window: set the expiry.
            _kv(5, "EXPIRE", key, window_s)
        ttl = int(_kv(5, "TTL", key) or window_s)
        # TTL is -1 (no expiry set) only if EXPIRE lost the race; treat as full window.
        reset_s = ttl if ttl > 0 else window_s
        return RateLimitResult(
            allowed=count <= limit,
            remaining=max(0, limit - count),
            reset_s=reset_s,
            limit=limit,
        )
    except Exception:
        # Fail open: a KV hiccup must not block legitimate requests.
        return RateLimitResult(allowed=True, remaining=limit, reset_s=window_s, limit=limit)
