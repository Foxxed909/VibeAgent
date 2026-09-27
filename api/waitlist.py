"""POST /api/waitlist — collect email interest."""
from http.server import BaseHTTPRequestHandler
import json


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
            return self._json(400, {"ok": False, "error": "valid email required"})
        if tier not in ("hobby", "enterprise"):
            tier = "hobby"

        print(f"[waitlist] tier={tier} email={email}")
        return self._json(200, {"ok": True, "message": "You're on the list."})

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
