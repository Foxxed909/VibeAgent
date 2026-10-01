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

from agent.worker_client import native_worker_capabilities, remote_audit_capabilities
from agent.target_verification import is_target_verified
from api._security import apply_cors, require_allowed_origin


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if not require_allowed_origin(self):
            return
        qs = parse_qs(urlparse(self.path).query)
        target = (qs.get("target") or [""])[0].strip()
        agent_mode = (qs.get("agent") or ["vibe"])[0].strip().lower()
        targets = [target] if target else []
        caps = native_worker_capabilities(targets, agent_mode=agent_mode)
        tool_caps = remote_audit_capabilities(targets) if target else {
            "configured": bool(caps.get("configured")),
            "can_launch": False,
            "remote_tools": [],
            "message": "Enter one exact target to check the VibeHacking worker.",
        }
        verified = bool(target and is_target_verified(target))

        # Do not expose the configured allowlist itself to public clients.
        native = {
            "configured": bool(caps.get("configured")),
            "can_launch": bool(caps.get("can_launch")) and verified if target else False,
            "allowlisted": bool(caps.get("can_launch")) if target else False,
            "ownership_verified": verified,
            "native_breakagent_enabled": bool(caps.get("native_breakagent_enabled")),
            "model": caps.get("model"),
            "message": caps.get("message"),
        }
        worker_tools = {
            "configured": bool(tool_caps.get("configured")),
            "can_launch": bool(tool_caps.get("can_launch")) and verified if target else False,
            "allowlisted": bool(tool_caps.get("can_launch")) if target else False,
            "ownership_verified": verified,
            "tool_count": len(tool_caps.get("remote_tools") or []),
            "message": tool_caps.get("message"),
        }
        body = {
            "ok": True,
            "portable": True,
            "worker_tools": worker_tools,
            "native_worker": native,
            "report_formats": ["json", "sarif"],
        }
        return self._json(200, body)

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
