"""Authorized stress / load checks.

Modes:
- capped (default): platform safety limits — Hobby/trial and Enterprise default
- org: Enterprise-only — organization chooses higher limits (still finite for runtime safety)

Never unbounded from this SaaS process; Vercel maxDuration still applies.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from .net_safety import request_url

UA = "VibeAgent-Stress/0.1 (+authorized-load-test)"


CAPPED = {
    "multipliers": {5, 10, 20},
    "max_duration_s": 30,
    "max_workers": 8,
    "max_total_requests": 200,
}

# Enterprise org-managed: higher ceiling; org accepts operational risk on their targets
ORG = {
    "multipliers": {5, 10, 20, 50},
    "max_duration_s": 120,
    "max_workers": 32,
    "max_total_requests": 2000,
}

# Back-compat export
ALLOWED_MULTIPLIERS = CAPPED["multipliers"]


@dataclass
class StressResult:
    url: str
    multiplier: int
    mode: str
    planned_requests: int
    completed: int
    ok: int
    fail: int
    challenge: int
    duration_s: float
    rps: float
    status_counts: Dict[int, int]
    note: str


def _limits(mode: str) -> dict:
    return ORG if mode == "org" else CAPPED


def _one_get(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, bool]:
    try:
        response = request_url(url, headers=headers, timeout=timeout, max_bytes=4000)
        body = response.body.decode("utf-8", errors="replace")
        st = response.status
        from .cf_detect import is_challenge_page
        return st, is_challenge_page(st, body, response.headers)
    except Exception:
        return 0, False


def run_stress(
    url: str,
    *,
    multiplier: int = 5,
    duration_s: Optional[int] = None,
    cookie: Optional[str] = None,
    mode: str = "capped",
) -> StressResult:
    mode = "org" if mode == "org" else "capped"
    lim = _limits(mode)
    if multiplier not in lim["multipliers"]:
        raise ValueError(f"multiplier must be one of {sorted(lim['multipliers'])} for mode={mode}")

    max_dur = lim["max_duration_s"]
    if duration_s is None:
        duration_s = min(15 if mode == "capped" else 60, max_dur)
    duration_s = max(3, min(int(duration_s), max_dur))

    planned = min(lim["max_total_requests"], max(multiplier * duration_s, multiplier * 3))
    workers = min(lim["max_workers"], max(2, multiplier // 2))

    headers = {"User-Agent": UA, "Accept": "*/*"}
    if cookie:
        headers["Cookie"] = cookie

    status_counts: Dict[int, int] = {}
    ok = fail = challenge = completed = 0
    t0 = time.monotonic()
    deadline = t0 + duration_s

    def job(_: int) -> Tuple[int, bool]:
        return _one_get(url, headers, timeout=max(0.5, min(8.0, deadline - time.monotonic())))

    pool = ThreadPoolExecutor(max_workers=workers)
    pending = set()
    submitted = 0
    try:
        while time.monotonic() < deadline and (submitted < planned or pending):
            while submitted < planned and len(pending) < workers and time.monotonic() < deadline:
                pending.add(pool.submit(job, submitted))
                submitted += 1
            if not pending:
                break
            finished, pending = wait(pending, timeout=min(0.2, max(0.0, deadline - time.monotonic())), return_when=FIRST_COMPLETED)
            for fut in finished:
                st, ch = fut.result()
                completed += 1
                status_counts[st] = status_counts.get(st, 0) + 1
                if ch:
                    challenge += 1
                elif 200 <= st < 400:
                    ok += 1
                else:
                    fail += 1
    finally:
        for fut in pending:
            fut.cancel()
        pool.shutdown(wait=False, cancel_futures=True)

    elapsed = max(time.monotonic() - t0, 0.001)
    note = (
        f"Stress mode={mode}. "
        + ("Platform safety caps." if mode == "capped" else "Org-managed higher limits; org accepts operational risk on owned targets.")
    )
    if challenge:
        note += " Bot/CDN challenges observed."

    return StressResult(
        url=url,
        multiplier=multiplier,
        mode=mode,
        planned_requests=planned,
        completed=completed,
        ok=ok,
        fail=fail,
        challenge=challenge,
        duration_s=round(elapsed, 2),
        rps=round(completed / elapsed, 2),
        status_counts=status_counts,
        note=note,
    )


def format_stress(result: StressResult) -> str:
    return "\n".join([
        f"Stress x{result.multiplier} mode={result.mode} on {result.url}",
        f"completed={result.completed}/{result.planned_requests} in {result.duration_s}s (~{result.rps} rps)",
        f"ok={result.ok} fail={result.fail} challenge={result.challenge}",
        f"status_counts={result.status_counts}",
        result.note,
    ])
