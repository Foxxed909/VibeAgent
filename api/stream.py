"""POST /api/stream — run scan and stream SSE events live.

Each event: data: {json}\n\n
Final event type=final includes full report.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.scope import Authorization, ScopeError
from agent.orchestrator import run_job
from agent.job_store import save_job
from agent.product import resolve_depth, resolve_stress


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            self._json(400, {"ok": False, "error": "invalid JSON"})
            return

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

        depth = resolve_depth(auth.tier, data.get("depth"), auth.access_code)
        stress_m, stress_mode = resolve_stress(
            auth.tier, auth.access_code, data.get("stress_multiplier"), data.get("stress_mode")
        )
        cookie = (data.get("cookie") or "").strip() or None
        model = data.get("model") or None
        dry = bool(data.get("dry_run"))
        agent_mode = data.get("agent_mode") or "vibe"

        # Start SSE
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self._cors()
        self.end_headers()

        def send_event(obj: dict) -> None:
            try:
                chunk = f"data: {json.dumps(obj, default=str)}\n\n".encode("utf-8")
                self.wfile.write(chunk)
                self.wfile.flush()
            except Exception:
                pass

        def on_event(ev: dict) -> None:
            send_event(ev)

        try:
            report = run_job(
                auth,
                dry_run=dry,
                model=model,
                depth=depth,
                stress_multiplier=stress_m,
                stress_mode=stress_mode,
                cookie=cookie,
                on_event=on_event,
                agent_mode=agent_mode,
            )
            try:
                save_job(report)
            except Exception:
                pass
            send_event({"type": "final", "ok": True, "job_id": report.get("job_id"), "report": report})
        except ScopeError as e:
            send_event({"type": "final", "ok": False, "error": str(e)})
        except Exception as e:
            send_event({"type": "final", "ok": False, "error": str(e)})

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
