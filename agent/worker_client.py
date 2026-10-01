"""Protected client for the persistent VibeHacking agent worker.

Native execution is fail-closed:
- worker URL must be HTTPS with no embedded credentials/path/query
- token must be at least 32 characters
- every target hostname must be present in VIBE_AGENT_WORKER_ALLOWED_HOSTS
- wildcard targets are never accepted by the native bridge
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Optional, Set


MAX_RESPONSE_BYTES = 2 * 1024 * 1024
WORKER_AUTH_PHRASE = "I AM AUTHORIZED TO TEST THIS TARGET"


class WorkerError(RuntimeError):
    pass


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, "redirect refused", headers, fp)


@dataclass(frozen=True)
class WorkerConfig:
    base_url: str
    token: str
    allowed_hosts: Set[str]
    model: str
    timeout_s: int
    poll_interval_s: float


def _allowed_hosts() -> Set[str]:
    raw = os.environ.get("VIBE_AGENT_WORKER_ALLOWED_HOSTS", "")
    out = set()
    for item in raw.split(","):
        host = item.strip().lower().rstrip(".")
        if host and "*" not in host and "/" not in host and "://" not in host:
            out.add(host)
    return out


def get_worker_config() -> Optional[WorkerConfig]:
    base = os.environ.get("VIBE_AGENT_WORKER_URL", "").strip().rstrip("/")
    token = os.environ.get("VIBE_AGENT_WORKER_TOKEN", "").strip()
    allowed = _allowed_hosts()
    if not base or len(token) < 32 or not allowed:
        return None

    parsed = urllib.parse.urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        return None

    try:
        timeout_s = max(30, min(int(os.environ.get("VIBE_AGENT_WORKER_TIMEOUT", "240")), 280))
    except ValueError:
        timeout_s = 240
    try:
        poll_s = max(0.5, min(float(os.environ.get("VIBE_AGENT_WORKER_POLL_INTERVAL", "1.5")), 10.0))
    except ValueError:
        poll_s = 1.5

    return WorkerConfig(
        base_url=base,
        token=token,
        allowed_hosts=allowed,
        model=(os.environ.get("VIBE_AGENT_WORKER_MODEL") or "laguna-s-2.1").strip(),
        timeout_s=timeout_s,
        poll_interval_s=poll_s,
    )


def target_host(target: str) -> str:
    raw = (target or "").strip()
    if "*" in raw:
        return ""
    parsed = urllib.parse.urlsplit(raw if "://" in raw else "https://" + raw)
    return (parsed.hostname or "").lower().rstrip(".")


def target_is_worker_allowed(target: str, config: Optional[WorkerConfig] = None) -> bool:
    cfg = config or get_worker_config()
    host = target_host(target)
    return bool(cfg and host and host in cfg.allowed_hosts)


def native_worker_capabilities(targets: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    cfg = get_worker_config()
    if not cfg:
        return {
            "configured": False,
            "can_launch": False,
            "message": (
                "Native worker disabled. Configure HTTPS VIBE_AGENT_WORKER_URL, a >=32-character "
                "VIBE_AGENT_WORKER_TOKEN, and exact VIBE_AGENT_WORKER_ALLOWED_HOSTS."
            ),
        }
    target_list = list(targets or [])
    rejected = [t for t in target_list if not target_is_worker_allowed(t, cfg)]
    return {
        "configured": True,
        "can_launch": not rejected,
        "allowed_hosts": sorted(cfg.allowed_hosts),
        "rejected_targets": rejected,
        "model": cfg.model,
        "message": "Protected native VibeHacking worker is configured.",
    }


def _request(
    cfg: WorkerConfig,
    path: str,
    *,
    method: str = "GET",
    body: Optional[Dict[str, Any]] = None,
    timeout: int = 15,
) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {
        "Accept": "application/json",
        "X-Vibe-Worker-Token": cfg.token,
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(cfg.base_url + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_RESPONSE_BYTES + 1)
        try:
            detail = json.loads(raw.decode("utf-8", errors="replace"))
        except Exception:
            detail = {"error": raw[:500].decode("utf-8", errors="replace")}
        raise WorkerError(f"worker HTTP {exc.code}: {detail.get('error') or detail}") from exc
    except Exception as exc:
        raise WorkerError("native worker could not be reached") from exc

    if len(raw) > MAX_RESPONSE_BYTES:
        raise WorkerError("worker response exceeded 2 MB")
    try:
        result = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise WorkerError("worker returned invalid JSON") from exc
    if not isinstance(result, dict):
        raise WorkerError("worker returned a non-object response")
    return result


def verify_worker(cfg: Optional[WorkerConfig] = None) -> Dict[str, Any]:
    config = cfg or get_worker_config()
    if not config:
        raise WorkerError("native worker is not configured")
    return _request(config, "/api/capabilities")


def start_thread(target: str, agent_mode: str, cfg: Optional[WorkerConfig] = None) -> str:
    config = cfg or get_worker_config()
    if not config:
        raise WorkerError("native worker is not configured")
    if not target_is_worker_allowed(target, config):
        raise WorkerError("target hostname is not in VIBE_AGENT_WORKER_ALLOWED_HOSTS")

    mode = "BreakAgent" if (agent_mode or "").lower() == "break" else "VibeAgent"
    result = _request(
        config,
        "/api/threads/start",
        method="POST",
        body={
            "url": target,
            "auth": WORKER_AUTH_PHRASE,
            "model": config.model,
            "mode": mode,
        },
    )
    launched = result.get("launched") or []
    if not launched or not isinstance(launched, list):
        raise WorkerError("worker did not return a launched thread")
    thread_id = str((launched[0] or {}).get("thread_id") or "")
    if not thread_id:
        raise WorkerError("worker response did not include thread_id")
    return thread_id


def get_thread(thread_id: str, cfg: Optional[WorkerConfig] = None) -> Dict[str, Any]:
    config = cfg or get_worker_config()
    if not config:
        raise WorkerError("native worker is not configured")
    safe = "".join(ch for ch in (thread_id or "") if ch.isalnum() or ch in "-_")
    if not safe or safe != thread_id or len(safe) > 100:
        raise WorkerError("invalid worker thread id")
    return _request(config, "/api/threads/" + urllib.parse.quote(safe, safe="-_"))


def run_native_target(
    target: str,
    agent_mode: str,
    *,
    on_worker_event: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> Dict[str, Any]:
    cfg = get_worker_config()
    if not cfg:
        raise WorkerError("native worker is not configured")
    verify_worker(cfg)
    thread_id = start_thread(target, agent_mode, cfg)
    deadline = time.monotonic() + cfg.timeout_s
    seen_ids = set()

    while True:
        state = get_thread(thread_id, cfg)
        for event in state.get("events") or []:
            event_id = event.get("id")
            if event_id in seen_ids:
                continue
            seen_ids.add(event_id)
            if on_worker_event:
                on_worker_event(event)

        if str(state.get("status") or "").lower() == "completed":
            return state
        if time.monotonic() >= deadline:
            raise WorkerError(f"native worker timed out; thread_id={thread_id}")
        time.sleep(cfg.poll_interval_s)
