"""Redis/Upstash-backed durable job queue and replayable progress log.

Requires KV_REST_API_URL + KV_REST_API_TOKEN on both API and worker.
Only authorization metadata and target-specific ownership proofs are persisted.
No provider API keys, cookies, or private invite codes are ever queued.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from . import job_store
from .scope import Authorization, CONFIRM_PHRASE

PENDING = "vibeagent:queue:pending"
PROCESSING = "vibeagent:queue:processing"
EVENT_LIMIT = 800
TERMINAL = {"completed", "partial", "failed", "cancelled", "dry_run_ok"}


def _key(kind: str, job_id: str) -> str:
    if not job_store._valid_job_id(job_id):
        raise ValueError("invalid job_id")
    return f"vibeagent:queue:{kind}:{job_id}"


def require_queue() -> None:
    if os.environ.get("VIBE_AGENT_QUEUE_ENABLED", "").lower() not in {"1", "true", "yes"}:
        raise RuntimeError("durable worker queue is not enabled")
    if not job_store._kv_enabled():
        raise RuntimeError("Upstash/KV is required for durable queued scans")


def append_event(job_id: str, event: Dict[str, Any]) -> str:
    require_queue()
    record = dict(event)
    record.setdefault("ts", time.time())
    raw = json.dumps(record, default=str)
    if len(raw) > 16000:
        record = {"type": "notice", "text": "Oversized event was suppressed", "ts": time.time()}
        raw = json.dumps(record)
    return str(job_store._kv_command(
        "XADD", _key("events", job_id), "MAXLEN", "~", EVENT_LIMIT,
        "*", "data", raw
    ))


def read_events(job_id: str, after: str = "0-0", limit: int = 100) -> List[Dict[str, Any]]:
    require_queue()
    if not after or len(after) > 48 or not all(part.isdecimal() for part in after.split("-")) or len(after.split("-")) != 2:
        raise ValueError("invalid event cursor")
    start = "-" if after == "0-0" else "(" + after
    rows = job_store._kv_command(
        "XRANGE", _key("events", job_id), start, "+", "COUNT", max(1, min(int(limit), 200))
    ) or []
    events = []
    for row in rows:
        if not isinstance(row, list) or len(row) != 2:
            continue
        eid, pairs = row
        fields = dict(zip(pairs[::2], pairs[1::2])) if isinstance(pairs, list) else pairs
        try:
            event = json.loads(fields["data"])
            if isinstance(event, dict):
                event["cursor"] = eid
                events.append(event)
        except (KeyError, ValueError, TypeError):
            continue
    return events


def enqueue(auth: Authorization, *, model: str, depth: str, mode: str,
            execution_backend: str, ownership_proofs: Dict[str, str]) -> Tuple[str, str]:
    """Commit job before publishing its ID to the atomic FIFO queue."""
    require_queue()
    auth = auth.validated()
    if execution_backend not in {"portable", "worker-tools", "native-worker"}:
        raise ValueError("unknown execution backend")
    job_id = secrets.token_urlsafe(18)
    cancel_token = secrets.token_urlsafe(32)
    task = {
        "job_id": job_id, "tier": auth.tier, "targets": auth.targets,
        "confirmation": CONFIRM_PHRASE, "app_name": auth.app_name,
        "company_name": auth.company_name, "model": model, "depth": depth,
        "agent_mode": mode, "execution_backend": execution_backend,
        "ownership_proofs": ownership_proofs, "created_at": time.time(),
    }
    report = {
        "job_id": job_id, "tier": auth.tier, "targets": auth.targets,
        "app_name": auth.app_name, "company_name": auth.company_name,
        "model": model, "depth": depth, "agent_mode": mode,
        "agent_name": "BreakAgent" if mode == "break" else "VibeAgent",
        "execution_backend": execution_backend, "status": "queued",
        "created_at": task["created_at"], "events": [], "findings": [], "errors": [],
        "summary": {"total_findings": 0, "severity": {}, "errors": 0},
    }
    ttl = job_store.TTL_SECONDS
    job_store._kv_command("SET", _key("task", job_id), json.dumps(task), "EX", ttl)
    job_store._kv_command("SET", _key("cancel-auth", job_id), hashlib.sha256(cancel_token.encode()).hexdigest(), "EX", ttl)
    job_store.save_job(report)
    append_event(job_id, {"type": "queued", "text": "Assessment queued for a persistent worker"})
    job_store._kv_command("LPUSH", PENDING, job_id)
    return job_id, cancel_token


def cancel(job_id: str, cancel_token: str) -> bool:
    require_queue()
    expected = job_store._kv_command("GET", _key("cancel-auth", job_id))
    if not isinstance(expected, str) or not cancel_token or not hmac.compare_digest(
        expected, hashlib.sha256(cancel_token.encode()).hexdigest()
    ):
        return False
    report = job_store.load_job(job_id)
    if not report or report.get("status") in TERMINAL:
        return False
    job_store._kv_command("SET", _key("cancel", job_id), "1", "EX", job_store.TTL_SECONDS)
    append_event(job_id, {"type": "notice", "text": "Cancellation requested; waiting for a safe checkpoint"})
    return True


def is_cancelled(job_id: str) -> bool:
    return bool(job_store._kv_command("GET", _key("cancel", job_id)))


def load_task(job_id: str) -> Optional[Dict[str, Any]]:
    raw = job_store._kv_command("GET", _key("task", job_id))
    try:
        return json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None


def claim(worker_id: str, lease_seconds: int = 300) -> Optional[str]:
    require_queue()
    job_id = job_store._kv_command("RPOPLPUSH", PENDING, PROCESSING)
    if not job_id:
        return None
    lease = job_store._kv_command("SET", _key("lease", str(job_id)), worker_id, "NX", "EX", lease_seconds)
    return str(job_id) if lease == "OK" else None


def heartbeat(job_id: str, worker_id: str, lease_seconds: int = 300) -> bool:
    # EVAL renews the lease only if this process still owns the claim.
    script = ("if redis.call('GET', KEYS[1]) == ARGV[1] then "
              "return redis.call('EXPIRE', KEYS[1], ARGV[2]) else return 0 end")
    return bool(job_store._kv_command("EVAL", script, 1, _key("lease", job_id), worker_id, lease_seconds))


def complete_claim(job_id: str, worker_id: str) -> None:
    script = ("if redis.call('GET', KEYS[1]) == ARGV[1] then "
              "return redis.call('DEL', KEYS[1]) else return 0 end")
    job_store._kv_command("EVAL", script, 1, _key("lease", job_id), worker_id)
    job_store._kv_command("LREM", PROCESSING, 1, job_id)
    job_store._kv_command("DEL", _key("task", job_id))


def recover_orphans(limit: int = 50) -> int:
    """Safely retire orphaned scans; never automatically rerun invasive probes."""
    require_queue()
    ids = job_store._kv_command("LRANGE", PROCESSING, 0, max(0, min(limit, 100) - 1)) or []
    recovered = 0
    for raw_id in ids:
        job_id = str(raw_id)
        if job_store._kv_command("GET", _key("lease", job_id)):
            continue
        report = job_store.load_job(job_id)
        if report and report.get("status") not in TERMINAL:
            report["status"] = "failed"
            report.setdefault("errors", []).append("Worker lease expired; assessment was not automatically replayed.")
            job_store.save_job(report)
            append_event(job_id, {"type": "done", "status": "failed", "text": "Worker interrupted; no automatic replay"})
            recovered += 1
        job_store._kv_command("LREM", PROCESSING, 1, job_id)
        job_store._kv_command("DEL", _key("task", job_id))
    return recovered
