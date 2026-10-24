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

from .request_context import (
    current_provider_key,
    current_chatgpt_plan_token,
    current_chatgpt_plan_models,
    current_chatgpt_plan_default_model,
)

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
AI_GATEWAY_URL = "https://ai-gateway.vercel.sh/v1/chat/completions"
GOOGLE_OPENAI_URL = "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions"
NVIDIA_OPENAI_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
NEMOTRON_NVIDIA_MODEL = "nvidia/nemotron-3-ultra-550b-a55b"
NEMOTRON_OPENROUTER_FREE_MODEL = NEMOTRON_NVIDIA_MODEL + ":free"
MAX_PROVIDER_RESPONSE_BYTES = 4 * 1024 * 1024

FREE_MODELS = [
    "inclusionai/ling-3.0-flash-fin:free",
    "inclusionai/ling-3.0-flash-sante:free",
    "poolside/laguna-xs-2.1:free",
    "poolside/laguna-s-2.1:free",
    NEMOTRON_OPENROUTER_FREE_MODEL,
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
    plan_models = set(current_chatgpt_plan_models())
    if configured:
        return configured | plan_models
    defaults = set(FREE_MODELS)
    defaults.update({"gpt-6-luna", "gpt-5.6-luna", NEMOTRON_NVIDIA_MODEL})
    defaults.update(plan_models)
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
    plan_token = current_chatgpt_plan_token()
    if plan_token:
        selected = model or current_chatgpt_plan_default_model()
        if not selected or selected not in set(current_chatgpt_plan_models()):
            raise OpenRouterError("Choose a model available to the signed-in ChatGPT account.")
        return _chatgpt_plan_responses_chat(
            messages,
            access_token=plan_token,
            model=selected,
            tools=tools,
        )

    model = validate_requested_model(model)
    selected = model or (os.environ.get("VIBEAGENT_MODEL") or "").strip()
    # Route Nemotron explicitly rather than treating its provider/model slug as
    # a Vercel AI Gateway model. OpenRouter uses :free, NVIDIA NIM does not.
    # Never downgrade :free to a paid OpenRouter endpoint implicitly.
    if selected == NEMOTRON_OPENROUTER_FREE_MODEL:
        # An explicitly submitted key takes priority over ambient credentials.
        # Otherwise prefer OpenRouter free, and then NVIDIA's direct API.
        openrouter_requested = bool(current_provider_key("openrouter"))
        nvidia_requested = bool(current_provider_key("nvidia"))
        openrouter_configured = bool(os.environ.get("OPENROUTER_API_KEY", "").strip())
        if openrouter_requested or (not nvidia_requested and openrouter_configured):
            return _openrouter_chat(
                messages, model=selected, temperature=temperature,
                max_tokens=max_tokens, tools=tools,
                reasoning_effort=reasoning_effort,
            )
        return _nvidia_chat(
            messages, model=NEMOTRON_NVIDIA_MODEL, temperature=temperature,
            max_tokens=max_tokens, tools=tools, reasoning_effort=reasoning_effort,
        )
    if selected == NEMOTRON_NVIDIA_MODEL:
        return _nvidia_chat(
            messages, model=selected, temperature=temperature,
            max_tokens=max_tokens, tools=tools, reasoning_effort=reasoning_effort,
        )
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


def _nvidia_chat(
    messages: List[Dict[str, Any]],
    *,
    model: str,
    temperature: float,
    max_tokens: int,
    tools: Optional[List[Dict[str, Any]]],
    reasoning_effort: Optional[str],
) -> Dict[str, Any]:
    """NVIDIA Build/NIM OpenAI-compatible chat endpoint.

    The NVIDIA-hosted model omits OpenRouter's :free suffix. Some NVIDIA NIM
    implementations return the thinking text separately as reasoning_content.
    """
    key = current_provider_key("nvidia") or os.environ.get("NVIDIA_API_KEY", "").strip()
    if not key:
        raise OpenRouterError(
            "NVIDIA_API_KEY is required for the direct NVIDIA endpoint. "
            "For the :free model, alternatively provide OPENROUTER_API_KEY."
        )
    if model != NEMOTRON_NVIDIA_MODEL:
        raise OpenRouterError("unsupported NVIDIA model")
    body: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False,
        "chat_template_kwargs": {"enable_thinking": reasoning_effort != "none", "force_nonempty_content": True},
    }
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"
    req = urllib.request.Request(
        NVIDIA_OPENAI_URL,
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
                raise OpenRouterError("NVIDIA response exceeded 4 MB")
            data = json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise OpenRouterError(f"NVIDIA API request failed with HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise OpenRouterError("NVIDIA API connection failed.") from exc
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise OpenRouterError("NVIDIA returned an invalid JSON response.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("choices"), list):
        raise OpenRouterError("NVIDIA returned no usable model choices.")
    data["_vibeagent"] = {
        "provider": "nvidia-nim",
        "model": data.get("model") or model,
        "reasoning_effort": "enabled" if reasoning_effort != "none" else "none",
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
    reasoning_effort: Optional[str] = None,
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
    if model == NEMOTRON_OPENROUTER_FREE_MODEL and reasoning_effort != "none":
        # Supported for the OpenRouter Nemotron endpoint. Keep thinking
        # enabled during tool use as well as report synthesis.
        body["reasoning"] = {"enabled": True}

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
        "reasoning_effort": "enabled" if model == NEMOTRON_OPENROUTER_FREE_MODEL and reasoning_effort != "none" else "none",
    }
    return data


def _responses_input(messages: List[Dict[str, Any]]) -> tuple[str, List[Dict[str, Any]]]:
    instructions = []
    items: List[Dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        if role in {"system", "developer"}:
            if content:
                instructions.append(str(content))
            continue
        if role == "tool":
            call_id = message.get("tool_call_id")
            if isinstance(call_id, str) and call_id:
                items.append({
                    "type": "function_call_output",
                    "call_id": call_id,
                    "output": str(content or ""),
                })
            continue
        tool_calls = message.get("tool_calls")
        if role == "assistant" and isinstance(tool_calls, list) and tool_calls:
            if content:
                items.append({"role": "assistant", "content": str(content)})
            for tool_call in tool_calls:
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function") or {}
                name = function.get("name")
                call_id = tool_call.get("id")
                arguments = function.get("arguments") or "{}"
                if not isinstance(name, str) or not isinstance(call_id, str):
                    continue
                if not isinstance(arguments, str):
                    arguments = json.dumps(arguments, separators=(",", ":"))
                items.append({
                    "type": "function_call",
                    "call_id": call_id,
                    "name": name,
                    "arguments": arguments,
                })
            continue
        if role in {"user", "assistant"}:
            items.append({"role": role, "content": content if content is not None else ""})
    return "\n\n".join(instructions), items


def _responses_tools(tools: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    result = []
    for tool in tools or []:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            continue
        function = tool.get("function") or {}
        name = function.get("name")
        if not isinstance(name, str) or not name:
            continue
        result.append({
            "type": "function",
            "name": name,
            "description": str(function.get("description") or ""),
            "parameters": function.get("parameters") or {
                "type": "object",
                "properties": {},
            },
        })
    return result


def _normalize_responses_result(response: Dict[str, Any], model: str) -> Dict[str, Any]:
    content_parts = []
    tool_calls = []
    for item in response.get("output") or []:
        if not isinstance(item, dict):
            continue
        if item.get("type") == "message":
            for part in item.get("content") or []:
                if isinstance(part, dict) and part.get("type") in {"output_text", "text"}:
                    text = part.get("text")
                    if isinstance(text, str):
                        content_parts.append(text)
        elif item.get("type") == "function_call":
            name = item.get("name")
            call_id = item.get("call_id") or item.get("id")
            arguments = item.get("arguments") or "{}"
            if isinstance(name, str) and isinstance(call_id, str):
                if not isinstance(arguments, str):
                    arguments = json.dumps(arguments, separators=(",", ":"))
                tool_calls.append({
                    "id": call_id,
                    "type": "function",
                    "function": {"name": name, "arguments": arguments},
                })
    content = "".join(content_parts) or response.get("output_text")
    if not isinstance(content, str) or not content:
        content = None
    return {
        "id": response.get("id"),
        "model": response.get("model") or model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content,
                "tool_calls": tool_calls or None,
            },
            "finish_reason": "tool_calls" if tool_calls else "stop",
        }],
    }


def _chatgpt_plan_responses_chat(
    messages: List[Dict[str, Any]],
    *,
    access_token: str,
    model: str,
    tools: Optional[List[Dict[str, Any]]],
) -> Dict[str, Any]:
    instructions, input_items = _responses_input(messages)
    body: Dict[str, Any] = {
        "model": model,
        "input": input_items,
        "store": False,
        "stream": True,
    }
    if instructions:
        body["instructions"] = instructions
    response_tools = _responses_tools(tools)
    if response_tools:
        body["tools"] = response_tools
        body["tool_choice"] = "auto"

    req = urllib.request.Request(
        "https://api.openai.com/v1/responses",
        data=json.dumps(body).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        },
        method="POST",
    )
    completed: Optional[Dict[str, Any]] = None
    pending_data: List[str] = []
    response_bytes = 0

    def consume_event(raw_data: str) -> None:
        nonlocal completed
        if not raw_data or raw_data == "[DONE]":
            return
        try:
            event = json.loads(raw_data)
        except json.JSONDecodeError as exc:
            raise OpenRouterError("ChatGPT plan returned an invalid stream event.") from exc
        if not isinstance(event, dict):
            return
        event_type = event.get("type")
        if event_type == "response.completed":
            response = event.get("response")
            if isinstance(response, dict):
                completed = response
        elif event_type in {"response.failed", "error"}:
            response = event.get("response") or {}
            error = response.get("error") if isinstance(response, dict) else None
            error = error or event.get("error") or {}
            code = error.get("code") if isinstance(error, dict) else None
            if code in {
                "subscription_sharing_usage_limit_exceeded",
                "subscription_sharing_usage_unavailable",
                "subscription_sharing_user_not_eligible",
            }:
                raise OpenRouterError(f"ChatGPT plan request failed ({code}).")
            raise OpenRouterError("ChatGPT plan request failed.")

    try:
        with urllib.request.urlopen(req, timeout=120) as stream:
            while True:
                line = stream.readline(MAX_PROVIDER_RESPONSE_BYTES + 1)
                if not line:
                    break
                response_bytes += len(line)
                if response_bytes > MAX_PROVIDER_RESPONSE_BYTES:
                    raise OpenRouterError("ChatGPT plan response exceeded 4 MB.")
                decoded = line.decode("utf-8", errors="replace").rstrip("\r\n")
                if not decoded:
                    if pending_data:
                        consume_event("\n".join(pending_data))
                        pending_data = []
                    continue
                if decoded.startswith("data:"):
                    pending_data.append(decoded[5:].lstrip())
            if pending_data:
                consume_event("\n".join(pending_data))
    except urllib.error.HTTPError as exc:
        raise OpenRouterError(f"ChatGPT plan request failed with HTTP {exc.code}.") from exc
    except urllib.error.URLError as exc:
        raise OpenRouterError("Could not reach the OpenAI Responses API.") from exc
    except TimeoutError as exc:
        raise OpenRouterError("ChatGPT plan request timed out.") from exc

    if completed is None:
        raise OpenRouterError("ChatGPT plan stream ended without response.completed.")
    result = _normalize_responses_result(completed, model)
    result["_vibeagent"] = {
        "provider": "openai-chatgpt-plan",
        "model": result.get("model") or model,
        "reasoning_effort": "account-default",
    }
    return result


DEFAULT_MODEL = DEFAULT_OPENROUTER
