"""Durable job storage.

Backends (first available wins for writes; reads try all):
1. Vercel KV / Upstash REST — if KV_REST_API_URL + KV_REST_API_TOKEN set
2. Filesystem under VIBEAGENT_JOBS_DIR (local /tmp)

Without KV, jobs still work via sessionStorage on the client; server poll may 404.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional

JOBS_DIR = Path(os.environ.get("VIBEAGENT_JOBS_DIR", "/tmp/vibeagent_jobs"))
KV_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""
TTL_SECONDS = int(os.environ.get("VIBEAGENT_JOB_TTL", "86400"))  # 24h
JOB_ID_RE = re.compile(r"^[A-Za-z0-9_-]{6,64}$")


def _valid_job_id(job_id: str) -> bool:
    return bool(JOB_ID_RE.fullmatch((job_id or "").strip()))


def _kv_enabled() -> bool:
    return bool(KV_URL and KV_TOKEN)


def _kv_key(job_id: str) -> str:
    return f"vibeagent:job:{job_id}"


JOBS_INDEX_KEY = "vibeagent:jobs:index"


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
    job_id = str(report.get("job_id") or "").strip()
    if not _valid_job_id(job_id):
        raise ValueError("invalid job_id")
    payload = json.dumps(report)

    if _kv_enabled():
        try:
            # SET key value EX ttl
            _kv_command("SET", _kv_key(job_id), payload, "EX", TTL_SECONDS)
            _kv_command("LREM", JOBS_INDEX_KEY, 0, job_id)
            _kv_command("LPUSH", JOBS_INDEX_KEY, job_id)
            _kv_command("LTRIM", JOBS_INDEX_KEY, 0, 99)
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
    if not _valid_job_id(job_id):
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


def _job_summary(report: Dict[str, Any], *, include_findings: bool = False) -> Dict[str, Any]:
    summary = {
        "job_id": report.get("job_id"),
        "status": report.get("status"),
        "agent_mode": report.get("agent_mode"),
        "agent_name": report.get("agent_name"),
        "execution_backend": report.get("execution_backend") or "portable",
        "targets": report.get("targets") or [],
        "app_name": report.get("app_name"),
        "company_name": report.get("company_name"),
        "depth": report.get("depth"),
        "model": report.get("model"),
        "provider": report.get("provider"),
        "summary": report.get("summary") or {
            "total_findings": len(report.get("findings") or []),
            "severity": {},
            "errors": len(report.get("errors") or []),
        },
    }
    if include_findings:
        summary["findings"] = report.get("findings") or []
    return summary


def list_jobs(limit: int = 30, *, include_findings: bool = False) -> List[Dict[str, Any]]:
    limit = max(1, min(int(limit or 30), 100))
    reports: List[Dict[str, Any]] = []
    seen = set()

    if _kv_enabled():
        try:
            ids = _kv_command("LRANGE", JOBS_INDEX_KEY, 0, limit - 1) or []
            for job_id in ids:
                job_id = job_id.decode("utf-8") if isinstance(job_id, bytes) else str(job_id)
                if job_id in seen:
                    continue
                report = load_job(job_id)
                if report:
                    seen.add(job_id)
                    reports.append(_job_summary(report, include_findings=include_findings))
                if len(reports) >= limit:
                    return reports
        except Exception:
            pass

    try:
        JOBS_DIR.mkdir(parents=True, exist_ok=True)
        paths = sorted(
            JOBS_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        for path in paths:
            job_id = path.stem
            if job_id in seen or not _valid_job_id(job_id):
                continue
            report = load_job(job_id)
            if report:
                seen.add(job_id)
                reports.append(_job_summary(report, include_findings=include_findings))
            if len(reports) >= limit:
                break
    except Exception:
        pass
    return reports


def backend_name() -> str:
    if _kv_enabled():
        return "vercel_kv"
    return "filesystem"
