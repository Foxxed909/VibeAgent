"""Client for the protected VibeHacking persistent worker."""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, Optional

WORKER_URL_ENV = "VIBEHACKING_WORKER_URL"
WORKER_TOKEN_ENV = "VIBEHACKING_WORKER_TOKEN"
WORKER_AUTH_PHRASE = "I AM AUTHORIZED TO TEST THIS TARGET"
MAX_RESPONSE_BYTES = 128 * 1024


class WorkerError(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkerConfig:
    base_url: str
    token: str


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Never forward a worker token across redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _is_loopback(hostname: str) -> bool:
    host = (hostname or "").strip().lower()
    return host in {"localhost", "127.0.0.1", "::1"}


def get_config() -> Optional[WorkerConfig]:
    base = (os.environ.get(WORKER_URL_ENV) or "").strip().rstrip("/")
    token = (os.environ.get(WORKER_TOKEN_ENV) or "").strip()
    if not base and not token:
        return None
    if not base or len(token) < 32:
        raise WorkerError("VibeHacking worker config requires a URL and token of at least 32 characters.")

    parsed = urllib.parse.urlsplit(base)
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        raise WorkerError("VibeHacking worker URL must be a bare origin without credentials, path, query or fragment.")
    if parsed.scheme == "https":
        pass
    elif parsed.scheme == "http" and _is_loopback(parsed.hostname):
        pass
    else:
        raise WorkerError("VibeHacking worker must use HTTPS (HTTP is allowed only for loopback development).")
    return WorkerConfig(base_url=base, token=token)


def is_configured() -> bool:
    try:
        return get_config() is not None
    except WorkerError:
        return False


def _request_json(
    path: str,
    *,
    method: str = "GET",
    payload: Optional[Dict[str, Any]] = None,
    timeout: int = 12,
) -> Dict[str, Any]:
    config = get_config()
    if not config:
        raise WorkerError("VibeHacking worker is not configured.")
    if not path.startswith("/") or "//" in path:
        raise WorkerError("Invalid worker API path.")

    body = None
    headers = {
        "Accept": "application/json",
        "X-Vibe-Worker-Token": config.token,
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        if len(body) > 16 * 1024:
            raise WorkerError("Worker request exceeds the 16 KB limit.")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(
        config.base_url + path,
        data=body,
        headers=headers,
        method=method,
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=timeout) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        message = f"Worker returned HTTP {exc.code}."
        try:
            data = json.loads(raw.decode("utf-8"))
            if isinstance(data, dict) and data.get("error"):
                message = str(data["error"])
        except Exception:
            pass
        raise WorkerError(message) from exc
    except Exception as exc:
        raise WorkerError("VibeHacking worker could not be reached.") from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise WorkerError("Worker response exceeded the 128 KB limit.")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkerError("Worker returned invalid JSON.") from exc
    if not isinstance(data, dict):
        raise WorkerError("Worker response must be a JSON object.")
    return data


def get_capabilities() -> Dict[str, Any]:
    data = _request_json("/api/capabilities", timeout=8)
    tools = data.get("remote_tools")
    if tools is not None and not isinstance(tools, list):
        raise WorkerError("Worker capabilities returned an invalid remote_tools value.")
    return data


def run_tool(tool: str, url: str, args: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if not tool or not url:
        raise WorkerError("Worker tool and URL are required.")
    payload = {
        "tool": tool,
        "url": url,
        "args": args or {},
        # The standalone Authorization object is validated before this client is
        # called; the worker applies its own second authorization gate.
        "auth": WORKER_AUTH_PHRASE,
    }
    data = _request_json("/api/tools/run", method="POST", payload=payload, timeout=50)
    if data.get("error"):
        raise WorkerError(str(data["error"]))
    return data
