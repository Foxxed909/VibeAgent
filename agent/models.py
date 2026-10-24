"""Model router for OpenAI, Vercel AI Gateway, and OpenRouter.

Gateway model IDs are exact ``provider/model`` values from its live catalog.  A
Vercel deployment can authenticate with its injected OIDC token, so provider
keys never need to reach the browser or scanner subprocesses.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional

from .request_context import current_provider_key

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
AI_GATEWAY_URL = "https://ai-gateway.vercel.sh/v1/chat/completions"
GOOGLE_OPENAI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
MAX_PROVIDER_RESPONSE_BYTES = 4 * 1024 * 1024

FREE_MODELS = [
    "inclusionai/ling-3.0-flash-fin:free",
    "inclusionai/ling-3.0-flash-sante:free",
    "poolside/laguna-xs-2.1:free",
    "poolside/laguna-s-2.1:free",
]
DEFAULT_OPENROUTER = FREE_MODELS[0]


class OpenRouterError(RuntimeError):
    pass


def allowed_models() -> set[str]:
    configured = {
        value.strip()
        for value in (os.environ.get("VIBE_AGENT_ALLOWED_MODELS") or "").split(",")
        if value.strip()
    }
    if configured:
        return configured
    defaults = set(FREE_MODELS)
    defaults.update({"gpt-6-luna", "gpt-5.6-luna"})
    defaults.update({
        "openai/gpt-6-luna",
        "google/gemini-3-flash",
        "google/gemini-3.1-pro-preview",
    })
    env_default = (os.environ.get("VIBEAGENT_MODEL") or "").strip()
    if env_default:
        defaults.add(env_default)
    return defaults


def validate_requested_model(model: Optional[str]) -> Optional[str]:
    if model is None:
        return None
    if not isinstance(model, str) or not model.strip() or len(model) > 160:
        raise OpenRouterError("invalid model identifier")
    selected = model.strip()
    if selected not in allowed_models():
        raise OpenRouterError("requested model is not in VIBE_AGENT_ALLOWED_MODELS")
    return selected


def chat(
    messages: List[Dict[str, Any]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
    tools: Optional[List[Dict[str, Any]]] = None,
    reasoning_effort: Optional[str] = None,
) -> Dict[str, Any]:
    model = validate_requested_model(model)
    selected = model or (os.environ.get("VIBEAGENT_MODEL") or "").strip()
    if selected.startswith("google/") and current_provider_key("google"):
        return _google_chat(
            messages,
            model=selected.split("/", 1)[1],
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            reasoning_effort=reasoning_effort,
        )
    if "/" in selected or (os.environ.get("VIBE_AGENT_MODEL_PROVIDER") or "").strip().lower() == "gateway":
        return _gateway_chat(
            messages,
            model=selected or "openai/gpt-6-luna",
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            reasoning_effort=reasoning_effort,
        )
    if current_provider_key("openai") or os.environ.get("OPENAI_API_KEY", "").strip():
        from .openai_client import chat as openai_chat, DEFAULT_MODEL as OAI_DEFAULT

        return openai_chat(
            messages,
            model=model or os.environ.get("VIBEAGENT_MODEL") or OAI_DEFAULT,
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            reasoning_effort=reasoning_effort or "none",
        )
    return _openrouter_chat(
        messages,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
        tools=tools,
    )


def _google_chat(
    messages: List[Dict[str, Any]],
    *,
    model: str,
    temperature: float,
    max_tokens: int,
    tools: Optional[List[Dict[str, Any]]],
    reasoning_effort: Optional[str],
) -> Dict[str, Any]:
    key = current_provider_key("google")
    if not key:
        raise OpenRouterError("A Google Gemini API key is required for this model.")

    body: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    if reasoning_effort and reasoning_effort != "none":
        body["reasoning_effort"] = reasoning_effort

    req = urllib.request.Request(
        GOOGLE_OPENAI_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
            if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
                raise OpenRouterError("Google Gemini response exceeded 4 MB")
            data = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OpenRouterError(f"Google Gemini API request failed with HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise OpenRouterError(f"Google Gemini request failed: {exc.reason}") from exc

    data["_vibeagent"] = {
        "provider": "google-gemini-api",
        "model": data.get("model") or model,
        "reasoning_effort": reasoning_effort or "none",
    }
    return data


def _gateway_chat(
    messages: List[Dict[str, Any]],
    *,
    model: str,
    temperature: float,
    max_tokens: int,
    tools: Optional[List[Dict[str, Any]]],
    reasoning_effort: Optional[str],
) -> Dict[str, Any]:
    key = (
        current_provider_key("gateway")
        or os.environ.get("AI_GATEWAY_API_KEY", "").strip()
        or os.environ.get("VERCEL_OIDC_TOKEN", "").strip()
    )
    if not key:
        raise OpenRouterError(
            "AI Gateway model requested but neither AI_GATEWAY_API_KEY nor VERCEL_OIDC_TOKEN is available."
        )
    if "/" not in model:
        raise OpenRouterError("AI Gateway model IDs must use the exact provider/model form.")

    body: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    if reasoning_effort and reasoning_effort != "none":
        body["reasoning"] = {"effort": reasoning_effort}

    req = urllib.request.Request(
        AI_GATEWAY_URL,
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "X-Title": "VibeAgent",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            raw = resp.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
            if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
                raise OpenRouterError("AI Gateway response exceeded 4 MB")
            data = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OpenRouterError(f"AI Gateway request failed with HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise OpenRouterError(f"AI Gateway request failed: {exc.reason}") from exc

    data["_vibeagent"] = {
        "provider": "vercel-ai-gateway",
        "model": data.get("model") or model,
        "reasoning_effort": reasoning_effort or "none",
    }
    return data


def _openrouter_chat(
    messages: List[Dict[str, Any]],
    *,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
    tools: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    key = current_provider_key("openrouter") or os.environ.get("OPENROUTER_API_KEY", "").strip()
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
            raw = resp.read(MAX_PROVIDER_RESPONSE_BYTES + 1)
            if len(raw) > MAX_PROVIDER_RESPONSE_BYTES:
                raise OpenRouterError("OpenRouter response exceeded 4 MB")
            data = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise OpenRouterError(f"OpenRouter request failed with HTTP {e.code}.") from e

    data["_vibeagent"] = {
        "provider": "openrouter",
        "model": data.get("model") or model,
        "reasoning_effort": "none",
    }
    return data


DEFAULT_MODEL = DEFAULT_OPENROUTER
