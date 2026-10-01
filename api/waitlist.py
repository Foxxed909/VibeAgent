"""POST /api/waitlist — durably collect email interest when KV/Upstash is configured."""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler
import hashlib
import json
import os
import re
import time
import urllib.request

from api._security import apply_cors, require_allowed_origin

KV_URL = (os.environ.get("KV_REST_API_URL") or os.environ.get("UPSTASH_REDIS_REST_URL") or "").rstrip("/")
KV_TOKEN = os.environ.get("KV_REST_API_TOKEN") or os.environ.get("UPSTASH_REDIS_REST_TOKEN") or ""

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def _kv_enabled():
    return bool(KV_URL and KV_TOKEN)


def _kv_command(*args):
    req = urllib.request.Request(
        KV_URL,
        data=json.dumps(list(args)).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {KV_TOKEN}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    return payload.get("result")


def _save_waitlist(email: str, tier: str) -> None:
    normalized = email.strip().lower()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    record = json.dumps({
        "email": normalized,
        "tier": tier,
        "created_at": int(time.time()),
    })
    _kv_command("SET", f"vibeagent:waitlist:{digest}", record)
    _kv_command("SADD", "vibeagent:waitlist:index", digest)


class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if not require_allowed_origin(self):
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json(400, {"ok": False, "error": "invalid Content-Length"})
        if length < 0 or length > 8192:
            return self._json(413, {"ok": False, "error": "request too large"})

        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._json(400, {"ok": False, "error": "invalid JSON"})

        email = (data.get("email") or "").strip().lower()
        tier = (data.get("tier") or "hobby").strip().lower()
        if not EMAIL_RE.match(email):
            return self._json(400, {"ok": False, "error": "valid email required"})
        if len(email) > 254:
            return self._json(400, {"ok": False, "error": "email is too long"})
        if tier not in ("hobby", "enterprise"):
            tier = "hobby"

        if not _kv_enabled():
            return self._json(
                503,
                {
                    "ok": False,
                    "error": "Waitlist storage is not configured yet. Try again later.",
                },
            )

        try:
            _save_waitlist(email, tier)
        except Exception:
            return self._json(503, {"ok": False, "error": "Could not save your signup. Try again shortly."})

        return self._json(200, {"ok": True, "message": "You're on the list."})

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
