"""GET /api — health check only. Route listing requires auth."""
from http.server import BaseHTTPRequestHandler
import json
import os

from api._security import apply_cors, require_api_token


_ROUTES = [
    "GET  /api",
    "GET  /api/capabilities",
    "POST /api/verify_target  (native target ownership)",
    "POST /api/scan",
    "POST /api/stream  (SSE live events)",
    "GET  /api/job?id=",
    "GET  /api/jobs?include=findings",
    "GET  /api/events?id=  (SSE job events)",
    "GET  /api/report?id=&format=json|sarif",
    "POST /api/waitlist",
]


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        authed = bool(
            os.environ.get("VIBE_AGENT_API_TOKEN")
            and require_api_token(self, silent=True)
        )

        body_data = {
            "ok": True,
            "service": "VibeAgent",
            "job_store": "Set KV_REST_API_URL + KV_REST_API_TOKEN for durable jobs",
        }
        if authed:
            body_data["routes"] = _ROUTES

        body = json.dumps(body_data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        apply_cors(self)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        apply_cors(self)
        self.end_headers()

    def log_message(self, format, *args):
        return
