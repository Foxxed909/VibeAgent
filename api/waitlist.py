"""Simple waitlist endpoint for Vercel serverless (Python).

POST /api/waitlist  {"email": "...", "tier": "hobby"|"enterprise"}
Stores nothing durable in this scaffold — logs and returns ok.
Replace with a real store (KV / DB) when you wire production.
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            data = {}
        email = (data.get("email") or "").strip()
        tier = (data.get("tier") or "hobby").strip().lower()
        if not email or "@" not in email:
            self._json(400, {"ok": False, "error": "valid email required"})
            return
        if tier not in ("hobby", "enterprise"):
            tier = "hobby"
        # Scaffold: no persistent store yet
        print(f"[waitlist] tier={tier} email={email}")
        self._json(200, {"ok": True, "message": "You're on the list."})

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code: int, body: dict):
        payload = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self._cors()
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return
