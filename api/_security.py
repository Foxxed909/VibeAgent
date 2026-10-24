"""Shared HTTP security helpers for Vercel API handlers."""
from __future__ import annotations

import os
import hmac
import json
from typing import Optional
from urllib.parse import urlsplit

MAX_JSON_BODY_BYTES = int(os.environ.get("VIBE_AGENT_MAX_JSON_BODY_BYTES", "16384"))


def _configured_origins() -> set[str]:
    raw = os.environ.get("VIBE_AGENT_ALLOWED_ORIGINS", "")
    return {x.strip().rstrip("/") for x in raw.split(",") if x.strip()}


def request_origin(handler) -> str:
    return (handler.headers.get("Origin") or "").strip().rstrip("/")


def request_host(handler) -> str:
    return (handler.headers.get("Host") or "").strip().lower()


def origin_is_allowed(handler) -> bool:
    origin = request_origin(handler)
    if not origin:
        # CLI/server-to-server clients often omit Origin.
        return True
    if origin in _configured_origins():
        return True
    try:
        parsed = urlsplit(origin)
    except Exception:
        return False
    host = request_host(handler)
    return bool(
        parsed.scheme.lower() in {"http", "https"}
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and host
        and parsed.netloc.lower() == host
    )


def _header_token(handler, name: str) -> str:
    direct = (handler.headers.get(name) or "").strip()
    if direct:
        return direct
    auth = (handler.headers.get("Authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _write_json_error(handler, code: int, message: str) -> None:
    payload = json.dumps({"ok": False, "error": message}).encode("utf-8")
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    apply_cors(handler)
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)


def require_scan_access(handler, access_code: Optional[str]) -> bool:
    """Fail closed for paid/model-backed scans unless an operator configured access."""
    api_token = (os.environ.get("VIBE_AGENT_API_TOKEN") or "").strip()
    supplied = _header_token(handler, "X-VibeAgent-Token")
    if api_token and supplied and hmac.compare_digest(supplied, api_token):
        return True

    from agent.scope import is_valid_trial_code

    if is_valid_trial_code(access_code):
        return True
    if (os.environ.get("VIBE_AGENT_ALLOW_UNAUTHENTICATED_SCANS") or "").strip().lower() in {"1", "true", "yes"}:
        return True

    configured = bool(
        api_token
        or os.environ.get("VIBE_AGENT_INVITE_CODE_SHA256")
        or os.environ.get("VIBE_AGENT_TRIAL_CODE_SHA256")
    )
    _write_json_error(
        handler,
        401 if configured else 503,
        "valid scan access is required" if configured else "scan access is not configured",
    )
    return False


def require_workspace_access(handler) -> bool:
    expected = (os.environ.get("VIBE_AGENT_WORKSPACE_TOKEN") or "").strip()
    supplied = _header_token(handler, "X-VibeAgent-Workspace-Token")
    if expected and supplied and hmac.compare_digest(supplied, expected):
        return True
    _write_json_error(
        handler,
        401 if expected else 503,
        "workspace token required" if expected else "workspace access is not configured",
    )
    return False


def apply_cors(handler) -> None:
    origin = request_origin(handler)
    if origin and origin_is_allowed(handler):
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, X-VibeAgent-Token, X-VibeAgent-Workspace-Token, X-VibeAgent-Verification",
    )


def require_allowed_origin(handler) -> bool:
    if origin_is_allowed(handler):
        return True
    payload = b'{"ok":false,"error":"origin not allowed"}'
    handler.send_response(403)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(payload)))
    handler.end_headers()
    handler.wfile.write(payload)
    return False


def read_json_body(handler) -> tuple[Optional[bytes], Optional[str], int]:
    raw_length = handler.headers.get("Content-Length") or "0"
    try:
        length = int(raw_length)
    except (TypeError, ValueError):
        return None, "invalid Content-Length", 400
    if length < 0:
        return None, "invalid Content-Length", 400
    if length > MAX_JSON_BODY_BYTES:
        return None, f"request too large (max {MAX_JSON_BODY_BYTES} bytes)", 413
    raw = handler.rfile.read(length) if length else b"{}"
    if len(raw) != length:
        return None, "incomplete request body", 400
    return raw, None, 200
