"""Per-request secret context.

ContextVar avoids process-global secret leakage between warm/concurrent requests.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Mapping, Optional

_COOKIE: ContextVar[str] = ContextVar("vibeagent_cookie", default="")
_PROVIDER_KEYS: ContextVar[dict[str, str]] = ContextVar(
    "vibeagent_provider_keys", default={}
)


def set_cookie(cookie: Optional[str]):
    return _COOKIE.set((cookie or "").strip())


def reset_cookie(token) -> None:
    _COOKIE.reset(token)


def current_cookie() -> str:
    return _COOKIE.get()


def set_provider_keys(keys: Optional[Mapping[str, str]]):
    clean = {
        provider: value.strip()
        for provider, value in (keys or {}).items()
        if provider in {"openai", "google", "openrouter", "gateway"}
        and isinstance(value, str)
        and value.strip()
    }
    return _PROVIDER_KEYS.set(clean)


def reset_provider_keys(token) -> None:
    _PROVIDER_KEYS.reset(token)


def current_provider_key(provider: str) -> str:
    return _PROVIDER_KEYS.get().get(provider, "")
