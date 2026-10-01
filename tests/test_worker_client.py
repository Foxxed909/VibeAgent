from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from agent import orchestrator, worker_client
from agent.scope import Authorization, CONFIRM_PHRASE


class WorkerClientTests(unittest.TestCase):
    def test_missing_config_is_optional(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(worker_client.get_config())

    def test_https_worker_config_requires_long_token(self):
        with patch.dict(
            os.environ,
            {
                worker_client.WORKER_URL_ENV: "https://worker.example.com",
                worker_client.WORKER_TOKEN_ENV: "short",
            },
            clear=True,
        ):
            with self.assertRaises(worker_client.WorkerError):
                worker_client.get_config()

    def test_public_plain_http_is_rejected(self):
        with patch.dict(
            os.environ,
            {
                worker_client.WORKER_URL_ENV: "http://worker.example.com",
                worker_client.WORKER_TOKEN_ENV: "x" * 32,
            },
            clear=True,
        ):
            with self.assertRaises(worker_client.WorkerError):
                worker_client.get_config()

    def test_loopback_http_is_allowed_for_development(self):
        with patch.dict(
            os.environ,
            {
                worker_client.WORKER_URL_ENV: "http://127.0.0.1:8080",
                worker_client.WORKER_TOKEN_ENV: "x" * 32,
            },
            clear=True,
        ):
            cfg = worker_client.get_config()
            self.assertEqual("http://127.0.0.1:8080", cfg.base_url)

    def test_run_tool_sends_second_authorization_gate(self):
        with patch.object(
            worker_client,
            "_request_json",
            return_value={"ok": True, "returncode": 0, "stdout": "ok", "stderr": ""},
        ) as req:
            result = worker_client.run_tool(
                "vibe_headers",
                "https://example.com",
                {"depth": 1},
            )
        self.assertTrue(result["ok"])
        args, kwargs = req.call_args
        self.assertEqual("/api/tools/run", args[0])
        self.assertEqual("POST", kwargs["method"])
        self.assertEqual(
            worker_client.WORKER_AUTH_PHRASE,
            kwargs["payload"]["auth"],
        )
        self.assertEqual("vibe_headers", kwargs["payload"]["tool"])

    def test_no_redirect_handler_never_forwards_token(self):
        handler = worker_client._NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://other.example"))


class NativeOutputCompatibilityTests(unittest.TestCase):
    def test_native_api_finder_redacted_host_preserves_follow_up(self):
        output = "[12:00:00] [🔥 HACK] FOUND — https://<host>/api/v1/users"
        hits = orchestrator._parse_api_hits("https://demo.vercel.app", output)
        self.assertEqual(["https://demo.vercel.app/api/v1/users"], hits)


class WorkerBackendTests(unittest.TestCase):
    def _auth(self):
        return Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
        )

    def test_dry_run_reports_worker_backend(self):
        with patch.object(orchestrator, "VIBEHACKING_ROOT", ""), \
             patch.object(orchestrator, "get_worker_config", return_value=object()), \
             patch.object(
                 orchestrator,
                 "get_worker_capabilities",
                 return_value={"remote_tools": ["vibe_headers", "corscan"]},
             ):
            report = orchestrator.run_job(self._auth(), dry_run=True)
        self.assertEqual("vibehacking-worker", report["execution_backend"])
        self.assertEqual(["corscan", "vibe_headers"], report["worker_tools"])
        self.assertIsNone(report["worker_warning"])

    def test_remote_dispatch_uses_worker(self):
        with patch.object(orchestrator, "VIBEHACKING_ROOT", ""), \
             patch.object(
                 orchestrator,
                 "run_worker_tool",
                 return_value={"returncode": 0, "stdout": "native", "stderr": ""},
             ):
            result = orchestrator._dispatch_tool(
                "vibe_headers",
                {"url": "https://demo.vercel.app"},
                self._auth().validated(),
                worker_tools={"vibe_headers"},
            )
        self.assertEqual("vibehacking-worker", result["backend"])
        self.assertEqual("native", result["stdout"])

    def test_worker_failure_falls_back_to_portable(self):
        with patch.object(orchestrator, "VIBEHACKING_ROOT", ""), \
             patch.object(
                 orchestrator,
                 "run_worker_tool",
                 side_effect=worker_client.WorkerError("worker down"),
             ), \
             patch.object(
                 orchestrator,
                 "run_builtin",
                 return_value={"returncode": 0, "stdout": "portable", "stderr": ""},
             ):
            result = orchestrator._dispatch_tool(
                "vibe_headers",
                {"url": "https://demo.vercel.app"},
                self._auth().validated(),
                worker_tools={"vibe_headers"},
            )
        self.assertEqual("portable", result["backend"])
        self.assertIn("worker down", result["worker_error"])
        self.assertIn("WORKER_FALLBACK", result["stdout"])


if __name__ == "__main__":
    unittest.main()
