"""OpenAI API client for GPT-6 Luna / GPT-5.6 Luna.

Chat Completions + function tools requires reasoning_effort=none on Luna.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List, Optional

OPENAI_URL = "https://api.openai.com/v1/chat/completions"

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
    reasoning_effort: Optional[str] = None,
) -> Dict[str, Any]:
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not key:
        raise OpenAIError("OPENAI_API_KEY is not set.")

    model = model or os.environ.get("VIBEAGENT_MODEL") or DEFAULT_MODEL
    # Keep reasoning OFF for tool-calling scans (stable + cheaper)
    effort = "none" if tools else (reasoning_effort or "none")

    body: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_completion_tokens": max_tokens,
        "reasoning_effort": effort,
    }
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
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")
        raise OpenAIError(f"OpenAI HTTP {e.code}: {detail}") from e

    # Normalize metadata for the thread UI
    data["_vibeagent"] = {
        "provider": "openai",
        "model": data.get("model") or model,
        "reasoning_effort": effort,
    }
    return data
