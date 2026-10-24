"""Per-request secret context.

ContextVar avoids process-global secret leakage between warm/concurrent requests.
"""
from __future__ import annotations

from contextvars import ContextVar
from typing import Mapping, Optional, Sequence, Tuple

_COOKIE: ContextVar[str] = ContextVar("vibeagent_cookie", default="")
_PROVIDER_KEYS: ContextVar[dict[str, str]] = ContextVar(
    "vibeagent_provider_keys", default={}
)
_CHATGPT_PLAN_TOKEN: ContextVar[str] = ContextVar("vibeagent_chatgpt_plan_token", default="")
_CHATGPT_PLAN_MODELS: ContextVar[Tuple[str, ...]] = ContextVar("vibeagent_chatgpt_plan_models", default=())
_CHATGPT_PLAN_DEFAULT_MODEL: ContextVar[str] = ContextVar("vibeagent_chatgpt_plan_default_model", default="")


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


def set_chatgpt_plan_context(access_token: str, models: Sequence[str], default_model: str):
    return (
        _CHATGPT_PLAN_TOKEN.set(access_token),
        _CHATGPT_PLAN_MODELS.set(tuple(models)),
        _CHATGPT_PLAN_DEFAULT_MODEL.set(default_model),
    )


def reset_chatgpt_plan_context(tokens) -> None:
    token, models_token, default_model_token = tokens
    _CHATGPT_PLAN_TOKEN.reset(token)
    _CHATGPT_PLAN_MODELS.reset(models_token)
    _CHATGPT_PLAN_DEFAULT_MODEL.reset(default_model_token)


def current_chatgpt_plan_token() -> str:
    return _CHATGPT_PLAN_TOKEN.get()


def current_chatgpt_plan_models() -> Tuple[str, ...]:
    return _CHATGPT_PLAN_MODELS.get()


def current_chatgpt_plan_default_model() -> str:
    return _CHATGPT_PLAN_DEFAULT_MODEL.get()
