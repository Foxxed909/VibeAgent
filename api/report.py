"""GET /api/report?id=<job>&format=json|sarif — export a persisted assessment."""
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
from agent.reporting import json_bytes, sarif_bytes


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        job_id = (qs.get("id") or [""])[0].strip()
        fmt = (qs.get("format") or ["json"])[0].strip().lower()

        if not job_id:
            return self._json_error(400, "id required")
        if fmt not in {"json", "sarif"}:
            return self._json_error(400, "format must be json or sarif")

        report = load_job(job_id)
        if not report:
            return self._json_error(404, "job not found")

        if fmt == "sarif":
            payload = sarif_bytes(report)
            content_type = "application/sarif+json; charset=utf-8"
            filename = f"vibeagent-{job_id}.sarif"
        else:
            payload = json_bytes(report)
            content_type = "application/json; charset=utf-8"
            filename = f"vibeagent-{job_id}.json"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json_error(self, code: int, message: str):
        payload = json.dumps({"ok": False, "error": message}).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
