"""OpenRouter free-model client (no secrets committed).

Set OPENROUTER_API_KEY in the environment. Free models only by default.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

# Free-tier model IDs (as of research)
FREE_MODELS = [
    "inclusionai/ling-3.0-flash-fin:free",
    "inclusionai/ling-3.0-flash-sante:free",
    "poolside/laguna-xs-2.1:free",
    "poolside/laguna-s-2.1:free",
]

DEFAULT_MODEL = FREE_MODELS[0]


class OpenRouterError(RuntimeError):
    pass


def chat(
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
            "OPENROUTER_API_KEY is not set. Export it before running the agent."
        )
    model = model or os.environ.get("VIBEAGENT_MODEL") or DEFAULT_MODEL
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
