"""GET /api/capabilities — runtime features and native-worker availability."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.worker_client import native_worker_capabilities


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        target = (qs.get("target") or [""])[0].strip()
        agent_mode = (qs.get("agent") or ["vibe"])[0].strip().lower()
        targets = [target] if target else []
        caps = native_worker_capabilities(targets, agent_mode=agent_mode)

        # Do not expose the configured allowlist itself to public clients.
        native = {
            "configured": bool(caps.get("configured")),
            "can_launch": bool(caps.get("can_launch")) if target else False,
            "native_breakagent_enabled": bool(caps.get("native_breakagent_enabled")),
            "model": caps.get("model"),
            "message": caps.get("message"),
        }
        body = {
            "ok": True,
            "portable": True,
            "native_worker": native,
            "report_formats": ["json", "sarif"],
        }
        return self._json(200, body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _json(self, code, body):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
