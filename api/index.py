"""GET /api — health + route list."""
from http.server import BaseHTTPRequestHandler
import json


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "ok": True,
            "service": "VibeAgent",
            "routes": [
                "GET  /api",
                "POST /api/scan",
                "POST /api/stream  (SSE live events)",
                "GET  /api/job?id=",
                "POST /api/waitlist",
            ],
            "job_store": "Set KV_REST_API_URL + KV_REST_API_TOKEN for durable jobs",
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def log_message(self, format, *args):
        return
