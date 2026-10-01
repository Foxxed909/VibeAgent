from __future__ import annotations

import unittest
from unittest.mock import patch

from agent import http_tools
from agent.tools_catalog import get_tool_catalog


class ToolCatalogTests(unittest.TestCase):
    def _names(self, native: bool, agent_mode: str = "vibe"):
        return {t["function"]["name"] for t in get_tool_catalog(native=native, agent_mode=agent_mode)}

    def test_portable_catalog_exposes_real_serverless_tools(self):
        names = self._names(native=False)
        expected = {
            "cloud_scout", "ash", "spider", "openapi_scout", "vibe_headers",
            "corscan", "phantom", "leep", "env_probe", "ghost", "api_finder", "senoria",
        }
        self.assertEqual(expected, names)
        self.assertNotIn("bot_breaker", names)
        self.assertNotIn("poc_gen", names)

    def test_native_catalog_adds_vibehacking_only_tools(self):
        names = self._names(native=True)
        self.assertIn("bot_breaker", names)
        self.assertIn("poc_gen", names)

    def test_breakagent_portable_policy_is_validation_focused(self):
        names = self._names(native=False, agent_mode="break")
        self.assertIn("corscan", names)
        self.assertIn("phantom", names)
        self.assertIn("leep", names)
        self.assertIn("env_probe", names)
        self.assertNotIn("ash", names)
        self.assertNotIn("spider", names)
        self.assertNotIn("bot_breaker", names)
        self.assertNotIn("poc_gen", names)

    def test_breakagent_native_only_adds_benign_poc(self):
        names = self._names(native=True, agent_mode="break")
        self.assertIn("poc_gen", names)
        self.assertNotIn("bot_breaker", names)

    def test_cloud_scout_fingerprints_vercel(self):
        def fake_fetch(url, method="GET", headers=None, timeout=12):
            if url.endswith("/"):
                return 200, "<html>ok</html>", {
                    "server": "Vercel",
                    "x-vercel-id": "iad1::test",
                    "content-type": "text/html",
                }
            return 404, "", {}

        with patch.object(http_tools, "_fetch", side_effect=fake_fetch):
            out = http_tools.tool_cloud_scout("https://example.vercel.app")
        self.assertIn("Vercel", out)

    def test_corscan_flags_reflected_credentials(self):
        def fake_fetch(url, method="GET", headers=None, timeout=12):
            origin = (headers or {}).get("Origin", "")
            return 200, "{}", {
                "content-type": "application/json",
                "access-control-allow-origin": origin,
                "access-control-allow-credentials": "true",
            }

        with patch.object(http_tools, "_fetch", side_effect=fake_fetch):
            out = http_tools.tool_corscan("https://example.com/api/me")
        self.assertIn("CRITICAL: reflected Origin with credentials=true", out)


if __name__ == "__main__":
    unittest.main()
