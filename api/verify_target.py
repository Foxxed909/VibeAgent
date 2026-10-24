"""POST /api/verify-target — create or confirm ownership verification."""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent.target_verification import VerificationError, approve_operator_target, confirm_challenge, create_challenge
from api._security import apply_cors, read_json_body, require_allowed_origin, require_scan_access, require_operator_scan_access


class handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        if not require_allowed_origin(self):
            return
        self.send_response(204)
        apply_cors(self)
        self.end_headers()

    def do_POST(self):
        if not require_allowed_origin(self):
            return
        raw, error, code = read_json_body(self)
        if error:
            return self._json(code, {"ok": False, "error": error})
        try:
            data = json.loads((raw or b"{}").decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"ok": False, "error": "invalid JSON"})
        if not isinstance(data, dict):
            return self._json(400, {"ok": False, "error": "JSON body must be an object"})
        target = str(data.get("target") or "").strip()
        action = str(data.get("action") or "challenge").strip().lower()
        if action == "approve":
            if not require_operator_scan_access(self):
                return
        elif not require_scan_access(self, data.get("access_code")):
            return
        if not target:
            return self._json(400, {"ok": False, "error": "target required"})
        try:
            if action == "challenge":
                result = create_challenge(target)
            elif action == "confirm":
                result = confirm_challenge(target)
            elif action == "approve":
                result = approve_operator_target(target)
            else:
                return self._json(400, {"ok": False, "error": "unsupported verification action"})
        except VerificationError as exc:
            return self._json(400, {"ok": False, "error": str(exc)})
        return self._json(200, {"ok": True, **result})

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
