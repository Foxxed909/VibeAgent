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

    def test_browser_inline_scripts_have_valid_javascript(self):
        if not shutil.which("node"):
            self.skipTest("Node.js unavailable")
        for name in ("index.html", "app.html", "scan.html", "thread.html"):
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
