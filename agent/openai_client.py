"""OpenAI API client for GPT-6 Luna / GPT-5.6 Luna.

Set OPENAI_API_KEY in the environment. Default model: gpt-6-luna (cost-efficient).
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

OPENAI_URL = "https://api.openai.com/v1/chat/completions"

# Preferred models for VibeAgent (budget-aware)
MODEL_GPT6_LUNA = "gpt-6-luna"
MODEL_GPT56_LUNA = "gpt-5.6-luna"
DEFAULT_MODEL = MODEL_GPT6_LUNA


class OpenAIError(RuntimeError):
    pass


def chat(
    messages: List[Dict[str, Any]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 4096,
    tools: Optional[List[Dict[str, Any]]] = None,
    reasoning_effort: Optional[str] = "medium",
) -> Dict[str, Any]:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise OpenAIError("OPENAI_API_KEY is not set.")

    model = model or os.environ.get("VIBEAGENT_MODEL") or DEFAULT_MODEL
    body: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    # reasoning.effort for Luna-family when supported
    if reasoning_effort and reasoning_effort != "none":
        body["reasoning_effort"] = reasoning_effort

    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"

    req = urllib.request.Request(
        OPENAI_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        # Retry without reasoning_effort if model rejects it
        if e.code == 400 and "reasoning" in detail.lower() and "reasoning_effort" in body:
            body.pop("reasoning_effort", None)
            req2 = urllib.request.Request(
                OPENAI_URL,
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {key}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req2, timeout=120) as resp:
                return json.loads(resp.read().decode("utf-8"))
        raise OpenAIError(f"OpenAI HTTP {e.code}: {detail}") from e
