"""GET /api/job?id= — fetch job report for thread UI."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

from api._security import apply_cors, require_allowed_origin

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.job_store import load_job, backend_name


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not require_allowed_origin(self):
            return
        qs = parse_qs(urlparse(self.path).query)
        job_id = (qs.get("id") or [""])[0].strip()
        if not job_id:
            return self._json(400, {"ok": False, "error": "id required"})
        report = load_job(job_id)
        if not report:
            return self._json(404, {"ok": False, "error": "job not found", "store": backend_name()})
        return self._json(200, {"ok": True, "report": report, "store": backend_name()})

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
        apply_cors(self)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
