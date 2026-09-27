"""POST /api/scan — start authorized scan job."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return self._json(400, {"ok": False, "error": "invalid JSON"})

        try:
            from agent.scope import Authorization, ScopeError
            from agent.orchestrator import run_job, save_job
        except Exception as e:
            return self._json(500, {"ok": False, "error": f"agent import failed: {e}"})

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

        try:
            report = run_job(
                auth,
                dry_run=bool(data.get("dry_run")),
                model=data.get("model") or None,
            )
            try:
                save_job(report)
            except Exception:
                pass
            return self._json(200, {"ok": True, "job_id": report.get("job_id"), "report": report})
        except ScopeError as e:
            return self._json(403, {"ok": False, "error": str(e)})
        except Exception as e:
            return self._json(500, {"ok": False, "error": str(e)})

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

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
