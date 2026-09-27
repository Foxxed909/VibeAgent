"""Authorized stress / load checks.

Modes:
- capped (default): platform safety limits — Hobby/trial and Enterprise default
- org: Enterprise-only — organization chooses higher limits (still finite for runtime safety)

Never unbounded from this SaaS process; Vercel maxDuration still applies.
"""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

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
    req = urllib.request.Request(url, method="GET", headers=headers)
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4000).decode("utf-8", errors="replace")
            st = resp.getcode() or 0
            hdrs = {k.lower(): v for k, v in resp.headers.items()}
            from .cf_detect import is_challenge_page
            return st, is_challenge_page(st, body, hdrs)
    except urllib.error.HTTPError as e:
        body = e.read(4000).decode("utf-8", errors="replace") if e.fp else ""
        hdrs = {k.lower(): v for k, v in (e.headers.items() if e.headers else [])}
        from .cf_detect import is_challenge_page
        return e.code or 0, is_challenge_page(e.code or 0, body, hdrs)
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
    t0 = time.time()

    def job(_: int) -> Tuple[int, bool]:
        return _one_get(url, headers, timeout=8.0)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(job, i) for i in range(planned)]
        for fut in as_completed(futs):
            st, ch = fut.result()
            completed += 1
            status_counts[st] = status_counts.get(st, 0) + 1
            if ch:
                challenge += 1
            elif 200 <= st < 400:
                ok += 1
            else:
                fail += 1
            if time.time() - t0 > duration_s + 5:
                break

    elapsed = max(time.time() - t0, 0.001)
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
