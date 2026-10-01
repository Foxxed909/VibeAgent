from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from agent import orchestrator
from agent.scope import Authorization, CONFIRM_PHRASE
from agent.worker_client import (
    WorkerError,
    get_worker_config,
    native_breakagent_enabled,
    native_worker_capabilities,
    remote_audit_capabilities,
    run_remote_audit_tool,
    target_host,
    target_is_worker_allowed,
)


class WorkerDispatchTests(unittest.TestCase):
    def _auth(self):
        return Authorization(
            tier="hobby",
            targets=["https://app.example.com"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        ).validated()

    def test_remote_dispatch_uses_worker_backend(self):
        with patch.object(
            orchestrator,
            "run_remote_audit_tool",
            return_value={"returncode": 0, "stdout": "native", "stderr": "", "findings": []},
        ):
            result = orchestrator._dispatch_tool(
                "vibe_headers",
                {"url": "https://app.example.com"},
                self._auth(),
                worker_tools={"vibe_headers"},
            )
        self.assertEqual("vibehacking-worker", result["backend"])
        self.assertEqual("native", result["stdout"])

    def test_remote_failure_falls_back_to_portable(self):
        with patch.object(
            orchestrator,
            "run_remote_audit_tool",
            side_effect=WorkerError("worker down"),
        ), patch.object(
            orchestrator,
            "run_builtin",
            return_value={"returncode": 0, "stdout": "portable", "stderr": ""},
        ):
            result = orchestrator._dispatch_tool(
                "vibe_headers",
                {"url": "https://app.example.com"},
                self._auth(),
                worker_tools={"vibe_headers"},
            )
        self.assertEqual("portable", result["backend"])
        self.assertIn("WORKER_FALLBACK", result["stdout"])
        self.assertIn("worker down", result["worker_error"])

    def test_native_api_finder_redacted_host_preserves_follow_up(self):
        output = "[12:00:00] [HACK] FOUND — https://<host>/api/v1/users"
        hits = orchestrator._parse_api_hits("https://app.example.com", output)
        self.assertEqual(["https://app.example.com/api/v1/users"], hits)


class WorkerClientTests(unittest.TestCase):
    def test_worker_config_fails_closed_without_all_required_settings(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(get_worker_config())

    def test_exact_allowlist_only(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com,api.example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            cfg = get_worker_config()
            self.assertIsNotNone(cfg)
            self.assertTrue(target_is_worker_allowed("https://app.example.com/path", cfg))
            self.assertFalse(target_is_worker_allowed("https://sub.app.example.com", cfg))
            self.assertFalse(target_is_worker_allowed("*.example.com", cfg))
            self.assertFalse(target_is_worker_allowed("https://evil.example", cfg))

    def test_invalid_worker_url_is_rejected(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "http://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            self.assertIsNone(get_worker_config())

    def test_native_breakagent_requires_explicit_opt_in(self):
        base = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        with patch.dict(os.environ, base, clear=True):
            self.assertFalse(native_breakagent_enabled())
            caps = native_worker_capabilities(["https://app.example.com"], agent_mode="break")
            self.assertFalse(caps["can_launch"])

        enabled = dict(base)
        enabled["VIBE_AGENT_ENABLE_NATIVE_BREAKAGENT"] = "1"
        with patch.dict(os.environ, enabled, clear=True):
            self.assertTrue(native_breakagent_enabled())
            caps = native_worker_capabilities(["https://app.example.com"], agent_mode="break")
            self.assertTrue(caps["can_launch"])

    def test_remote_audit_capabilities_require_worker_bridge(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        worker_caps = {
            "remote_tool_bridge_configured": True,
            "remote_tools": ["vibe_headers", "corscan"],
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "agent.worker_client.verify_worker", return_value=worker_caps
        ):
            caps = remote_audit_capabilities(["https://app.example.com"])
        self.assertTrue(caps["can_launch"])
        self.assertEqual(["corscan", "vibe_headers"], caps["remote_tools"])

    def test_remote_audit_capabilities_reject_unapproved_target(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            caps = remote_audit_capabilities(["https://other.example.com"])
        self.assertFalse(caps["can_launch"])

    def test_run_remote_audit_tool_uses_protected_endpoint(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "agent.worker_client._request",
            return_value={"returncode": 0, "stdout": "ok", "findings": []},
        ) as req:
            result = run_remote_audit_tool(
                "https://app.example.com",
                "vibe_headers",
                args={"url": "https://app.example.com"},
            )
        self.assertEqual("ok", result["stdout"])
        args, kwargs = req.call_args
        self.assertEqual("/api/tools/run", args[1])
        self.assertEqual("POST", kwargs["method"])
        self.assertEqual("I AM AUTHORIZED TO TEST THIS TARGET", kwargs["body"]["auth"])

    def test_target_host_rejects_wildcards(self):
        self.assertEqual("", target_host("*.vercel.app"))
        self.assertEqual("app.example.com", target_host("https://app.example.com/x"))


if __name__ == "__main__":
    unittest.main()
