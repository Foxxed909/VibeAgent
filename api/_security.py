"""Shared HTTP security helpers for Vercel API handlers."""
from __future__ import annotations

import os
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
    return bool(parsed.hostname and host and parsed.netloc.lower() == host)


def apply_cors(handler) -> None:
    origin = request_origin(handler)
    if origin and origin_is_allowed(handler):
        handler.send_header("Access-Control-Allow-Origin", origin)
        handler.send_header("Vary", "Origin")
    handler.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    handler.send_header("Access-Control-Allow-Headers", "Content-Type")


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
