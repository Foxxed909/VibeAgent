"""POST /api/waitlist

This endpoint has been removed.  Return 410 Gone so callers
learn immediately rather than receiving a silent failure.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        self._gone()

    def do_GET(self) -> None:
        self._gone()

    def do_OPTIONS(self) -> None:
        self._gone()

    def _gone(self) -> None:
        payload = json.dumps({"ok": False, "error": "endpoint removed"}).encode("utf-8")
        self.send_response(410)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return
