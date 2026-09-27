"""Vercel Python function for /api/* only (ASGI).

Static pages (index.html, scan.html, thread.html) are served by Vercel CDN.
This app must NOT be the project-wide entrypoint.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _json_response(status: int, body: dict) -> Dict[str, Any]:
    payload = json.dumps(body).encode("utf-8")
    return {
        "status": status,
        "headers": [
            [b"content-type", b"application/json"],
            [b"access-control-allow-origin", b"*"],
            [b"access-control-allow-methods", b"GET, POST, OPTIONS"],
            [b"access-control-allow-headers", b"content-type"],
            [b"content-length", str(len(payload)).encode("utf-8")],
        ],
        "body": payload,
    }


def _options() -> Dict[str, Any]:
    return {
        "status": 204,
        "headers": [
            [b"access-control-allow-origin", b"*"],
            [b"access-control-allow-methods", b"GET, POST, OPTIONS"],
            [b"access-control-allow-headers", b"content-type"],
        ],
        "body": b"",
    }


async def _body(receive) -> bytes:
    chunks = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            break
        chunks.append(message.get("body", b""))
        if not message.get("more_body"):
            break
    return b"".join(chunks)


async def _send_response(send, status: int, headers: List, body: bytes) -> None:
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


def _handle_waitlist(data: dict) -> Tuple[int, dict]:
    email = (data.get("email") or "").strip()
    tier = (data.get("tier") or "hobby").strip().lower()
    if not email or "@" not in email:
        return 400, {"ok": False, "error": "valid email required"}
    if tier not in ("hobby", "enterprise"):
        tier = "hobby"
    print(f"[waitlist] tier={tier} email={email}")
    return 200, {"ok": True, "message": "You're on the list."}


def _handle_scan(data: dict) -> Tuple[int, dict]:
    try:
        from agent.scope import Authorization, ScopeError
        from agent.orchestrator import run_job, save_job
    except Exception as e:
        return 500, {"ok": False, "error": f"agent import failed: {e}"}

    targets = data.get("targets") or []
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.splitlines() if t.strip()]

    auth = Authorization(
        tier=(data.get("tier") or "hobby").lower(),
        targets=targets,
        confirmation=(data.get("confirmation") or "").strip(),
        app_name=data.get("app_name") or None,
        company_name=data.get("company_name") or None,
        contact_email=data.get("contact_email") or None,
        emergency_contact=data.get("emergency_contact") or None,
        note=data.get("note") or None,
        access_code=data.get("access_code") or None,
    )
    dry = bool(data.get("dry_run"))
    model = data.get("model") or None

    try:
        report = run_job(auth, dry_run=dry, model=model)
        try:
            save_job(report)
        except Exception:
            pass
        return 200, {"ok": True, "job_id": report.get("job_id"), "report": report}
    except ScopeError as e:
        return 403, {"ok": False, "error": str(e)}
    except Exception as e:
        return 500, {"ok": False, "error": str(e)}


def _handle_job(qs: dict) -> Tuple[int, dict]:
    try:
        from agent.orchestrator import load_job
    except Exception as e:
        return 500, {"ok": False, "error": f"agent import failed: {e}"}

    job_id = (qs.get("id") or [""])[0].strip() if qs.get("id") else ""
    if not job_id:
        return 400, {"ok": False, "error": "id required"}
    report = load_job(job_id)
    if not report:
        return 404, {"ok": False, "error": "job not found"}
    return 200, {"ok": True, "report": report}


async def app(scope: dict, receive, send) -> None:
    if scope["type"] != "http":
        return

    method = scope.get("method", "GET").upper()
    path = scope.get("path", "") or ""
    raw_qs = scope.get("query_string", b"").decode("utf-8", errors="replace")
    qs = parse_qs(raw_qs)

    if method == "OPTIONS":
        r = _options()
        await _send_response(send, r["status"], r["headers"], r["body"])
        return

    route = (qs.get("route") or [""])[0].lower()
    path_l = path.lower().rstrip("/")

    is_scan = route == "scan" or path_l.endswith("/scan") or "/api/scan" in path_l
    is_job = route == "job" or path_l.endswith("/job") or "/api/job" in path_l
    is_waitlist = route == "waitlist" or path_l.endswith("/waitlist") or "/api/waitlist" in path_l
    is_api_root = path_l in ("/api", "/api/index") or path_l.endswith("/api/index")

    status, body = 404, {"ok": False, "error": f"not found: {path}"}

    try:
        if is_waitlist and method == "POST":
            raw = await _body(receive)
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                data = {}
            status, body = _handle_waitlist(data)
        elif is_scan and method == "POST":
            raw = await _body(receive)
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except json.JSONDecodeError:
                data = {}
            status, body = _handle_scan(data)
        elif is_job and method == "GET":
            status, body = _handle_job(qs)
        elif method == "GET" and is_api_root:
            status, body = 200, {
                "ok": True,
                "service": "VibeAgent",
                "routes": ["POST /api/scan", "GET /api/job?id=", "POST /api/waitlist"],
            }
    except Exception as e:
        status, body = 500, {"ok": False, "error": str(e)}

    r = _json_response(status, body)
    await _send_response(send, r["status"], r["headers"], r["body"])
