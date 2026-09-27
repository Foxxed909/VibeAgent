"""Authorized stress / load checks — NOT a DDoS tool.

Hard caps:
- Requires enterprise tier OR valid trial code
- Multipliers limited to x5 / x10 / x20 (no unbounded flood)
- Short max duration, modest concurrency
- Exact targets only (already scope-checked by caller)
"""
from __future__ import annotations

import ssl
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

UA = "VibeAgent-Stress/0.1 (+authorized-load-test)"

# Hard product limits — do not raise without a deliberate security review
ALLOWED_MULTIPLIERS = {5, 10, 20}
MAX_DURATION_S = 30
MAX_WORKERS = 8
MAX_TOTAL_REQUESTS = 200


@dataclass
class StressResult:
    url: str
    multiplier: int
    planned_requests: int
    completed: int
    ok: int
    fail: int
    challenge: int
    duration_s: float
    rps: float
    status_counts: Dict[int, int]
    note: str


def _one_get(url: str, headers: Dict[str, str], timeout: float) -> Tuple[int, bool]:
    """Returns (status, is_challenge_like)."""
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
    duration_s: int = 10,
    cookie: Optional[str] = None,
) -> StressResult:
    if multiplier not in ALLOWED_MULTIPLIERS:
        raise ValueError(f"multiplier must be one of {sorted(ALLOWED_MULTIPLIERS)}")
    duration_s = max(3, min(int(duration_s), MAX_DURATION_S))
    # Base ~2 rps equivalent * multiplier, capped by MAX_TOTAL_REQUESTS
    planned = min(MAX_TOTAL_REQUESTS, max(multiplier * duration_s, multiplier * 3))
    workers = min(MAX_WORKERS, max(2, multiplier // 2))

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
        "Authorized stress sample only — capped concurrency and duration. "
        "Not a DDoS tool. Challenge pages counted separately."
    )
    if challenge:
        note += " Bot/CDN challenges observed; allowlist scanner or supply cf_clearance for owned zones."

    return StressResult(
        url=url,
        multiplier=multiplier,
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
    lines = [
        f"Stress x{result.multiplier} on {result.url}",
        f"completed={result.completed}/{result.planned_requests} in {result.duration_s}s (~{result.rps} rps)",
        f"ok={result.ok} fail={result.fail} challenge={result.challenge}",
        f"status_counts={result.status_counts}",
        result.note,
    ]
    return "\n".join(lines)
