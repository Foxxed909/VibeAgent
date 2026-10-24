"""GET /api/events?id=...&after=0-0 — replayable cursor-based progress."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.job_store import load_job
from agent.queue_store import read_events, require_queue
from api._security import apply_cors, require_allowed_origin


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not require_allowed_origin(self):
            return
        query = parse_qs(urlparse(self.path).query)
        job_id = (query.get("id") or [""])[0]
        after = (query.get("after") or ["0-0"])[0]
        report = load_job(job_id)
        if not report:
            return self._json(404, {"ok": False, "error": "job not found"})
        try:
            require_queue()
            events = read_events(job_id, after)
        except ValueError:
            return self._json(400, {"ok": False, "error": "invalid cursor"})
        except Exception:
            return self._json(503, {"ok": False, "error": "progress storage unavailable"})
        return self._json(200, {
            "ok": True, "job_id": job_id, "status": report.get("status"),
            "events": events, "next_cursor": events[-1]["cursor"] if events else after,
        })

    def do_OPTIONS(self):
        if not require_allowed_origin(self):
            return
        self.send_response(204)
        apply_cors(self)
        self.end_headers()

    def _json(self, code, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        apply_cors(self)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
