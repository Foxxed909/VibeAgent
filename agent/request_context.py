"""Per-request probe context.

ContextVar avoids process-global cookie leakage between warm/concurrent requests.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Optional

_COOKIE: ContextVar[str] = ContextVar("vibeagent_cookie", default="")


def set_cookie(cookie: Optional[str]):
    return _COOKIE.set((cookie or "").strip())


def reset_cookie(token) -> None:
    _COOKIE.reset(token)


def current_cookie() -> str:
    return _COOKIE.get()
