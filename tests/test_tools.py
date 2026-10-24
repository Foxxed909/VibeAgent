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
            "api_check", "nextjs_rsc_audit", "redirect", "cache_audit",
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


    def test_unreachable_headers_are_not_reported_as_vulnerabilities(self):
        with patch.object(http_tools, "_fetch", return_value=(0, "DNS lookup failed", {})):
            result = http_tools.tool_vibe_headers("https://example.com")
        self.assertIn("INCONCLUSIVE", result)
        self.assertNotIn("MISSING:", result)

    def test_new_portable_tools_are_executable(self):
        with patch.object(http_tools, "_fetch", return_value=(200, "<html>ok</html>", {"content-type": "text/html"})):
            for tool in ("api_check", "nextjs_rsc_audit", "redirect", "cache_audit"):
                result = http_tools.run_builtin(tool, {"url": "https://example.com"})
                self.assertEqual(0, result["returncode"], tool)
                self.assertFalse(result.get("stub"), tool)

    def test_redirect_probe_recognizes_untrusted_location_without_following(self):
        def fake_fetch(url, **kwargs):
            if "next=" in url:
                return 302, "", {"location": "https://redirect-test.invalid/vibeagent-canary"}
            return 200, "ok", {}
        with patch.object(http_tools, "_fetch", side_effect=fake_fetch):
            result = http_tools.tool_redirect("https://example.com/login")
        self.assertIn("POSSIBLE exposure:", result)


if __name__ == "__main__":
    unittest.main()
