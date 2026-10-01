from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class LandingPageTests(unittest.TestCase):
    def test_clean_urls_are_used_for_scan_links(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertNotIn('href="/scan.html"', html)
        self.assertIn('href="/scan"', html)

    def test_waitlist_does_not_claim_unsaved_local_success(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertNotIn("Saved locally", html)
        self.assertIn("Could not reach the waitlist service", html)

    def test_landing_copy_matches_current_agent_surface(self):
        html = (ROOT / "index.html").read_text(encoding="utf-8")
        self.assertIn("Expanded autonomous VibeAgent audit toolset", html)
        self.assertNotIn("Full VibeHacking tool surface", html)


if __name__ == "__main__":
    unittest.main()
