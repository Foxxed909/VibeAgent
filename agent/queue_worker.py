"""Dedicated durable scan worker. Run with python -m agent.queue_worker."""
from __future__ import annotations

import argparse
import os
import secrets
import threading
import time

from . import job_store, queue_store
from .orchestrator import run_job, JobCancelled
from .scope import Authorization
from .target_verification import is_target_verified


def execute(job_id: str, worker_id: str) -> None:
    """Process one claimed scan; full reports and progress are persisted."""
    task = queue_store.load_task(job_id)
    if not task:
        raise RuntimeError("queued job payload unavailable")
    old = job_store.load_job(job_id)
    if not old or old.get("status") != "queued":
        return

    auth = Authorization(
        tier=task["tier"], targets=task["targets"], confirmation=task["confirmation"],
        app_name=task.get("app_name"), company_name=task.get("company_name"),
    ).validated()
    proofs = task.get("ownership_proofs") or {}
    if os.environ.get("VIBE_AGENT_REQUIRE_OWNERSHIP", "1").lower() not in {"0", "false", "no"}:
        if not all(is_target_verified(target, proofs.get(target)) for target in auth.targets):
            raise RuntimeError("target ownership proof is missing or has expired")

    if queue_store.is_cancelled(job_id):
        old["status"] = "cancelled"
        job_store.save_job(old)
        queue_store.append_event(job_id, {"type": "done", "status": "cancelled"})
        return

    old["status"] = "running"
    old["started_at"] = time.time()
    job_store.save_job(old)
    queue_store.append_event(job_id, {"type": "started", "text": "Worker began assessment"})
    stop = threading.Event()
    lease_lost = threading.Event()

    def pulse() -> None:
        while not stop.wait(20):
            try:
                queue_store.touch_worker(worker_id)
                if not queue_store.heartbeat(job_id, worker_id):
                    lease_lost.set()
                    return
            except Exception:
                lease_lost.set()
                return

    queue_store.touch_worker(worker_id)
    heart = threading.Thread(target=pulse, daemon=True)
    heart.start()
    try:
        report = run_job(
            auth, job_id=job_id, model=task["model"], depth=task["depth"],
            agent_mode=task["agent_mode"], execution_backend=task["execution_backend"],
            ownership_proofs=proofs,
            on_event=lambda ev: queue_store.append_event(job_id, ev),
            should_cancel=lambda: lease_lost.is_set() or queue_store.is_cancelled(job_id),
        )
        if lease_lost.is_set():
            raise RuntimeError("worker lost queue lease during assessment")
        report["started_at"] = old["started_at"]
        report["finished_at"] = time.time()
        job_store.save_job(report)
        queue_store.append_event(job_id, {
            "type": "final", "ok": True, "job_id": job_id, "status": report["status"]
        })
    except JobCancelled:
        old["status"] = "cancelled"
        old["finished_at"] = time.time()
        job_store.save_job(old)
        queue_store.append_event(job_id, {"type": "done", "status": "cancelled"})
    finally:
        stop.set()
        heart.join(timeout=1)


def run_once(worker_id: str) -> bool:
    queue_store.require_queue()
    queue_store.recover_orphans()
    job_id = queue_store.claim(worker_id)
    if not job_id:
        return False
    try:
        execute(job_id, worker_id)
    except Exception as exc:
        report = job_store.load_job(job_id)
        if report and report.get("status") not in queue_store.TERMINAL:
            report["status"] = "failed"
            report.setdefault("errors", []).append(f"Worker processing failed: {type(exc).__name__}")
            report["finished_at"] = time.time()
            job_store.save_job(report)
        queue_store.append_event(job_id, {
            "type": "done", "status": "failed",
            "text": "Worker could not finish; check worker logs"
        })
    finally:
        queue_store.complete_claim(job_id, worker_id)
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Persistent VibeAgent scan worker")
    parser.add_argument("--once", action="store_true", help="Consume at most one job")
    parser.add_argument("--poll-seconds", type=float, default=2.0)
    args = parser.parse_args()
    worker_id = secrets.token_urlsafe(20)
    queue_store.require_queue()
    while True:
        processed = run_once(worker_id)
        if args.once:
            return
        if not processed:
            time.sleep(max(0.5, min(args.poll_seconds, 30.0)))


if __name__ == "__main__":
    main()
