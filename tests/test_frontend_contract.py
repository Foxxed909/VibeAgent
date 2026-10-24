"""Smoke-check the inline browser scripts and asynchronous scan contracts."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class InlineScripts(HTMLParser):
    def __init__(self):
        super().__init__()
        self.inline = False
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self.inline = not dict(attrs).get("src")
            if self.inline:
                self.scripts.append("")

    def handle_data(self, data):
        if self.inline and self.scripts:
            self.scripts[-1] += data

    def handle_endtag(self, tag):
        if tag == "script":
            self.inline = False


class BrowserContractTests(unittest.TestCase):
    def test_scan_supports_secure_queue_with_legacy_option(self):
        content = (ROOT / "scan.html").read_text(encoding="utf-8")
        self.assertIn('id="queued_mode"', content)
        self.assertIn('fetch("/api/queue"', content)
        self.assertIn('delete payload.provider_keys;', content)
        self.assertIn('delete payload.cookie;', content)
        self.assertIn('sessionStorage.setItem("vibeagent_cancel_"', content)
        self.assertIn('/thread?job=', content)

    def test_thread_replays_event_cursor_and_can_cancel(self):
        content = (ROOT / "thread.html").read_text(encoding="utf-8")
        self.assertIn("async function startQueue()", content)
        self.assertIn("/api/events?id=", content)
        self.assertIn("next_cursor", content)
        self.assertIn("cancel_token: token", content)

    def test_legacy_stream_failure_does_not_repeat_scan(self):
        content = (ROOT / "thread.html").read_text(encoding="utf-8")
        self.assertNotIn("fetch('/api/scan',", content)
        self.assertIn("No retry was submitted", content)

    def test_self_host_clone_uses_own_project_configuration(self):
        page = (ROOT / "deploy.html").read_text(encoding="utf-8")
        self.assertIn("https://vercel.com/new/clone", page)
        self.assertIn("OPENROUTER_API_KEY", page)
        self.assertIn("NVIDIA_API_KEY", page)
        self.assertIn("OPENAI_API_KEY", page)
        self.assertIn("window.crypto.getRandomValues", page)
        self.assertIn("envDefaults", page)
        self.assertIn("VIBE_AGENT_REQUIRE_OWNERSHIP", page)

    def test_self_host_access_token_only_in_header(self):
        scan = (ROOT / "scan.html").read_text(encoding="utf-8")
        thread = (ROOT / "thread.html").read_text(encoding="utf-8")
        self.assertIn('id="scan_api_token"', scan)
        self.assertIn("delete payload.scan_api_token;", thread)
        self.assertLess(thread.index("delete payload.scan_api_token;"),
                        thread.index("let requestBody = JSON.stringify(payload);"))
        self.assertIn("'X-VibeAgent-Token': scanApiToken", thread)

    def test_owner_verification_sends_scan_access_token(self):
        scan = (ROOT / "scan.html").read_text(encoding="utf-8")
        verification_start = scan.index("async function verificationRequest(action)")
        verification_end = scan.index('document.getElementById("create-verify").onclick', verification_start)
        verification = scan[verification_start:verification_end]
        self.assertIn('document.getElementById("scan_api_token").value.trim()', verification)
        self.assertIn('"X-VibeAgent-Token": scanApiToken', verification)
        self.assertIn('access_code: document.getElementById("access_code").value.trim()', verification)
        self.assertIn("Add your self-hosted scan API token or private invite", verification)

    def test_demo_is_separate_and_never_calls_scanning_apis(self):
        scan = (ROOT / "scan.html").read_text(encoding="utf-8")
        thread = (ROOT / "thread.html").read_text(encoding="utf-8")
        landing = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="launch-demo"', scan)
        self.assertIn('"/thread?demo=" + encodeURIComponent(agentMode)', scan)
        self.assertIn('href="/thread?demo=vibe"', landing)
        self.assertIn("if (demoMode) startDemo();", thread)
        self.assertLess(thread.index("if (demoMode) startDemo();"),
                        thread.index("else if (live) startLive();"))
        demo = thread.split("async function startDemo() {", 1)[1].split("async function startQueue() {", 1)[0]
        self.assertIn("https://example.invalid", demo)
        self.assertIn("No website, API key, ownership challenge", demo)
        self.assertIn("demo: true", demo)
        self.assertIn("client-only simulation", demo)
        self.assertNotIn("fetch(", demo)
        self.assertNotIn("sessionStorage.", demo)
        self.assertNotIn("save_job(", demo)
        self.assertNotIn("/api/stream", demo)
        self.assertNotIn("setReportLinks(", demo)

    def test_browser_inline_scripts_have_valid_javascript(self):
        if not shutil.which("node"):
            self.skipTest("Node.js unavailable")
        for name in ("index.html", "app.html", "scan.html", "thread.html", "deploy.html"):
            with self.subTest(page=name):
                parser = InlineScripts()
                parser.feed((ROOT / name).read_text(encoding="utf-8"))
                with tempfile.TemporaryDirectory() as tmp:
                    for idx, script in enumerate(parser.scripts):
                        if not script.strip():
                            continue
                        target = Path(tmp) / f"{idx}.js"
                        target.write_text(script, encoding="utf-8")
                        result = subprocess.run(
                            ["node", "--check", str(target)],
                            capture_output=True, text=True, timeout=15,
                        )
                        self.assertEqual(0, result.returncode, result.stderr)


if __name__ == "__main__":
    unittest.main()
