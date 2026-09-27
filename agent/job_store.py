"""Durable job storage.

Backends (first available wins for writes; reads try all):
1. Vercel KV / Upstash REST — if KV_REST_API_URL + KV_REST_API_TOKEN set
2. Filesystem under VIBEAGENT_JOBS_DIR (local /tmp)

Without KV, jobs still work via sessionStorage on the client; server poll may 404.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

JOBS_DIR = Path(os.environ.get("VIBEAGENT_JOBS_DIR", "/tmp/vibeagent_jobs"))
KV_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
TTL_SECONDS = int(os.environ.get("VIBEAGENT_JOB_TTL", "86400"))  # 24h


def _kv_enabled() -> bool:
    return bool(KV_URL and KV_TOKEN)


def _kv_key(job_id: str) -> str:
    return f"vibeagent:job:{job_id}"


def _kv_command(*args: Any) -> Any:
    body = json.dumps(list(args)).encode("utf-8")
    req = urllib.request.Request(
        KV_URL,
        data=body,
        headers={
            "Authorization": f"Bearer {KV_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data.get("result")


def save_job(report: Dict[str, Any]) -> str:
    job_id = report.get("job_id") or "unknown"
    payload = json.dumps(report)

    if _kv_enabled():
        try:
            # SET key value EX ttl
            _kv_command("SET", _kv_key(job_id), payload, "EX", TTL_SECONDS)
        except Exception as e:
            # fall through to filesystem
            report.setdefault("errors", []).append(f"KV save failed: {e}")

    try:
        JOBS_DIR.mkdir(parents=True, exist_ok=True)
        path = JOBS_DIR / f"{job_id}.json"
        path.write_text(payload, encoding="utf-8")
        return str(path)
    except Exception:
        return ""


def load_job(job_id: str) -> Optional[Dict[str, Any]]:
    job_id = (job_id or "").strip()
    if not job_id:
        return None

    if _kv_enabled():
        try:
            raw = _kv_command("GET", _kv_key(job_id))
            if raw:
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8")
                if isinstance(raw, str):
                    return json.loads(raw)
                if isinstance(raw, dict):
                    return raw
        except Exception:
            pass

    path = JOBS_DIR / f"{job_id}.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def backend_name() -> str:
    if _kv_enabled():
        return "vercel_kv"
    return "filesystem"
