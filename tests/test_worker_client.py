from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from agent.worker_client import (
    get_worker_config,
    native_breakagent_enabled,
    native_worker_capabilities,
    target_host,
    target_is_worker_allowed,
)


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

    def test_target_host_rejects_wildcards(self):
        self.assertEqual("", target_host("*.vercel.app"))
        self.assertEqual("app.example.com", target_host("https://app.example.com/x"))


if __name__ == "__main__":
    unittest.main()
