"""Real web scan policy and transport: no persistence under signed operator approval."""
from __future__ import annotations

import io
import json
import os
import unittest
from unittest.mock import patch

from agent.target_verification import approve_operator_target
from agent.web_scan_policy import check_browser_only_request
from api.stream import handler as StreamHandler
from agent.scope import CONFIRM_PHRASE

HOST = "https://app.example.com"
ENV = {
    "VIBE_AGENT_BROWSER_ONLY_ENABLED": "1",
    "VIBE_AGENT_OWNER_APPROVED_HOSTS": "app.example.com",
    "VIBE_AGENT_API_TOKEN": "t" * 48,
    "VIBE_AGENT_VERIFICATION_SECRET": "s" * 48,
    "VIBE_AGENT_ALLOWED_MODELS": "nvidia/nemotron-3-ultra-550b-a55b:free",
}


def request(approval, **changes):
    body = {
        "targets": [HOST], "tier": "hobby", "confirmation": CONFIRM_PHRASE,
        "app_name": "Authorized browser assessment", "depth": "quick",
        "execution_backend": "portable",
        "model": "nvidia/nemotron-3-ultra-550b-a55b:free",
        "browser_only": True,
        "provider_keys": {"openrouter": "user-provided-test-key"},
        "ownership_proofs": {HOST: approval},
    }
    body.update(changes)
    return body


class BrowserOnlyPolicyTests(unittest.TestCase):
    def setUp(self):
        self.patch_env = patch.dict(os.environ, ENV, clear=True)
        self.patch_env.start()
        self.addCleanup(self.patch_env.stop)
        self.proof = approve_operator_target(HOST)["proof"]

    def evaluate(self, **changed):
        d = request(self.proof, **changed)
        return check_browser_only_request(d, d["targets"], d["ownership_proofs"],
                                          depth=d["depth"], stress_multiplier=d.get("stress_multiplier"))

    def test_exact_authorized_https_host_works(self):
        self.assertIsNone(self.evaluate())

    def test_refuses_disabled_feature(self):
        os.environ.pop("VIBE_AGENT_BROWSER_ONLY_ENABLED")
        self.assertIn("not enabled", self.evaluate())

    def test_refuses_unapproved_hosts_and_revoked_approval(self):
        self.assertIn("operator approval", self.evaluate(targets=["https://other.example.com"]))
        os.environ["VIBE_AGENT_OWNER_APPROVED_HOSTS"] = ""
        self.assertIn("operator approval", self.evaluate())

    def test_refuses_deeper_and_stress_scans(self):
        self.assertIn("Quick", self.evaluate(depth="standard"))
        self.assertIn("stress", self.evaluate(stress_multiplier=5))

    def test_refuses_cookie_private_scheme_extra_host_backend(self):
        self.assertIn("cookies", self.evaluate(cookie="session=abc"))
        self.assertIn("one approved", self.evaluate(targets=[HOST, "https://other.example.com"]))
        self.assertIn("HTTPS", self.evaluate(targets=["http://app.example.com"]))
        self.assertIn("portable", self.evaluate(execution_backend="worker-tools"))

    def test_browser_only_requires_full_operator_token_and_does_not_persist(self):
        data = request(self.proof)
        raw = json.dumps(data).encode()
        instance = object.__new__(StreamHandler)
        instance.headers = {
            "Content-Length": str(len(raw)),
            "Host": "my-vibeagent.example",
            "X-VibeAgent-Token": "t" * 48,
        }
        instance.path = "/api/stream"
        instance.rfile = io.BytesIO(raw)
        instance.wfile = io.BytesIO()
        instance.send_response = lambda code: setattr(instance, "_status", code)
        instance.send_header = lambda *_: None
        instance.end_headers = lambda: None
        model_report = {"job_id": "real-job-123", "status": "completed",
                        "findings": [], "events": [], "model": data["model"]}
        with patch("api.stream.run_job", return_value=model_report) as scanner, patch(
            "api.stream.save_job"
        ) as storage, patch("api.stream.ensure_durable_store") as durability:
            instance.do_POST()
        self.assertEqual(200, instance._status)
        self.assertTrue(scanner.called)
        self.assertFalse(storage.called)
        self.assertFalse(durability.called)
        output = instance.wfile.getvalue().decode()
        events = [json.loads(row[6:]) for row in output.splitlines() if row.startswith("data: ")]
        self.assertTrue(events[-1]["ok"])
        self.assertTrue(events[-1]["report"]["browser_only"])
        self.assertFalse(events[-1]["report"]["stored"])

    def test_browser_only_denies_missing_admin_token_before_running(self):
        data = request(self.proof)
        raw = json.dumps(data).encode()
        instance = object.__new__(StreamHandler)
        instance.headers = {"Content-Length": str(len(raw)), "Host": "my-vibeagent.example"}
        instance.path = "/api/stream"
        instance.rfile = io.BytesIO(raw)
        instance.wfile = io.BytesIO()
        instance.send_response = lambda code: setattr(instance, "_status", code)
        instance.send_header = lambda *_: None
        instance.end_headers = lambda: None
        with patch("api.stream.run_job") as scanner:
            instance.do_POST()
        self.assertEqual(401, instance._status)
        scanner.assert_not_called()

    def test_web_ui_downloads_real_report_without_history_links(self):
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        thread = (root / "thread.html").read_text()
        scan = (root / "scan.html").read_text()
        self.assertIn("browser_only: browserOnlyCheckbox.checked", scan)
        self.assertIn("if (ev.report.browser_only)", thread)
        self.assertIn("vibeagent-real-report.json", thread)
        self.assertIn("No server-side report history", thread)


if __name__ == "__main__":
    unittest.main()
