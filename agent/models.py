"""Model router: OpenAI (preferred when key set) or OpenRouter free models.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

FREE_MODELS = [
    "inclusionai/ling-3.0-flash-fin:free",
    "inclusionai/ling-3.0-flash-sante:free",
    "poolside/laguna-xs-2.1:free",
    "poolside/laguna-s-2.1:free",
]
DEFAULT_OPENROUTER = FREE_MODELS[0]


class OpenRouterError(RuntimeError):
    pass


def chat(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
    tools: Optional[List[Dict[str, Any]]] = None,
    reasoning_effort: Optional[str] = "medium",
) -> Dict[str, Any]:
    """Route to OpenAI if OPENAI_API_KEY is set, else OpenRouter."""
    if os.environ.get("OPENAI_API_KEY", "").strip():
        from .openai_client import chat as openai_chat, DEFAULT_MODEL as OAI_DEFAULT

        return openai_chat(
            messages,
            model=model or os.environ.get("VIBEAGENT_MODEL") or OAI_DEFAULT,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            reasoning_effort=reasoning_effort,
        )
    return _openrouter_chat(
        messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        tools=tools,
    )


def _openrouter_chat(
    messages: List[Dict[str, str]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
    tools: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise OpenRouterError(
            "Neither OPENAI_API_KEY nor OPENROUTER_API_KEY is set."
        )
    model = model or os.environ.get("VIBEAGENT_MODEL") or DEFAULT_OPENROUTER
    body: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"

    req = urllib.request.Request(
        OPENROUTER_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://github.com/Foxxed909/VibeAgent",
            "X-Title": "VibeAgent",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise OpenRouterError(f"OpenRouter HTTP {e.code}: {detail}") from e


# Back-compat alias
DEFAULT_MODEL = DEFAULT_OPENROUTER
