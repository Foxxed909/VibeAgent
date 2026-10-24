"""Real HTTP smoke test against a local server owned by this test process.

No company URL, fake vulnerability claim, external provider or API key used.
"""
from __future__ import annotations

import os
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from agent.http_tools import tool_vibe_headers
from agent.net_safety import NetworkSafetyError, request_url


class PrivateFixture(BaseHTTPRequestHandler):
    hits = 0

    def do_GET(self):
        type(self).hits += 1
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(b"Owned local HTTP endpoint")

    def log_message(self, *_args):
        return


class RealHttpSmokeTests(unittest.TestCase):
    def test_real_socket_response_drives_header_audit_without_a_mock(self):
        PrivateFixture.hits = 0
        server = ThreadingHTTPServer(("127.0.0.1", 0), PrivateFixture)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            url = "http://127.0.0.1:%d/" % server.server_address[1]
            with patch.dict(os.environ, {"VIBE_AGENT_ALLOW_PRIVATE_TARGETS": "1"}):
                report = tool_vibe_headers(url)
            self.assertIn("HTTP status: 200", report)
            self.assertIn("x-frame-options: DENY", report)
            self.assertEqual(1, PrivateFixture.hits)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)

    def test_network_transport_rejects_mutating_post_method(self):
        with self.assertRaises(NetworkSafetyError):
            request_url("https://example.com/", method="POST")


if __name__ == "__main__":
    unittest.main()
