"""GET /api/jobs — recent assessment summaries for the workspace."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.job_store import backend_name, list_jobs
from api._security import apply_cors, require_allowed_origin


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not require_allowed_origin(self):
            return
        qs = parse_qs(urlparse(self.path).query)
        try:
            limit = int((qs.get("limit") or ["30"])[0])
        except ValueError:
            limit = 30
        include_findings = (qs.get("include") or [""])[0].strip().lower() == "findings"
        jobs = list_jobs(limit=limit, include_findings=include_findings)
        return self._json(200, {
            "ok": True,
            "jobs": jobs,
            "count": len(jobs),
            "store": backend_name(),
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
