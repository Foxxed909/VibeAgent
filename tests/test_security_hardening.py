from __future__ import annotations

import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent.orchestrator import run_job
from agent.request_context import current_cookie, reset_cookie, set_cookie
from agent.scope import Authorization, CONFIRM_PHRASE, ScopeError, host_in_scope, is_valid_trial_code
from agent import target_verification
from api._security import origin_is_allowed, read_json_body


class _Handler:
    def __init__(self, headers=None, body=b""):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)


class InviteCodeTests(unittest.TestCase):
    def test_private_invite_is_validated_by_server_side_hash(self):
        code = "private-invite-123"
        digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
        with patch.dict(os.environ, {"VIBE_AGENT_INVITE_CODE_SHA256": digest}, clear=False):
            self.assertTrue(is_valid_trial_code(code))
            self.assertFalse(is_valid_trial_code("wrong-code"))

    def test_invite_is_disabled_when_hash_is_not_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(is_valid_trial_code("anything"))


class ScopeHardeningTests(unittest.TestCase):
    def test_exact_host_does_not_authorize_subdomains(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        ).validated()
        self.assertTrue(host_in_scope("example.com", auth))
        self.assertFalse(host_in_scope("api.example.com", auth))

    def test_vercel_wildcard_is_rejected(self):
        auth = Authorization(
            tier="hobby",
            targets=["*.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        )
        with self.assertRaises(ScopeError):
            auth.validated()

    def test_invalid_supplied_private_invite_is_rejected(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
            access_code="wrong-code",
        )
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(ScopeError):
                auth.validated()


class RequestContextTests(unittest.TestCase):
    def test_cookie_context_resets(self):
        token = set_cookie("cf_clearance=abc")
        try:
            self.assertEqual("cf_clearance=abc", current_cookie())
        finally:
            reset_cookie(token)
        self.assertEqual("", current_cookie())

    def test_orchestrator_does_not_leak_cookie_after_job(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
        )
        run_job(auth, dry_run=True, cookie="cf_clearance=secret")
        self.assertEqual("", current_cookie())


class OriginGuardTests(unittest.TestCase):
    def test_same_origin_allowed_and_foreign_origin_rejected(self):
        with patch.dict(os.environ, {}, clear=True):
            same = _Handler({"Origin": "https://app.example.com", "Host": "app.example.com"})
            foreign = _Handler({"Origin": "https://evil.example", "Host": "app.example.com"})
            self.assertTrue(origin_is_allowed(same))
            self.assertFalse(origin_is_allowed(foreign))

    def test_configured_origin_can_be_allowed(self):
        with patch.dict(
            os.environ,
            {"VIBE_AGENT_ALLOWED_ORIGINS": "https://admin.example.com"},
            clear=True,
        ):
            handler = _Handler({"Origin": "https://admin.example.com", "Host": "app.example.com"})
            self.assertTrue(origin_is_allowed(handler))

    def test_json_body_limit_is_enforced(self):
        handler = _Handler({"Content-Length": "999999"}, body=b"")
        raw, error, code = read_json_body(handler)
        self.assertIsNone(raw)
        self.assertEqual(413, code)
        self.assertIn("request too large", error)


class OwnershipVerificationTests(unittest.TestCase):
    def test_allowlisted_https_target_can_complete_challenge(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env, clear=True), patch.object(
            target_verification, "KV_URL", ""
        ), patch.object(
            target_verification, "KV_TOKEN", ""
        ), patch.object(
            target_verification, "STATE_DIR", Path(tmp)
        ):
            challenge = target_verification.create_challenge("https://app.example.com")
            self.assertTrue(challenge["token"].startswith("vibeagent-"))
            self.assertEqual("/.well-known/vibeagent-verification.txt", challenge["path"])
            with patch.object(
                target_verification,
                "_fetch_verification",
                return_value=challenge["token"],
            ):
                confirmed = target_verification.confirm_challenge("https://app.example.com")
            self.assertTrue(confirmed["verified"])
            self.assertTrue(target_verification.is_target_verified("https://app.example.com"))

    def test_verification_rejects_non_allowlisted_target(self):
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "app.example.com",
        }
        with patch.dict(os.environ, env, clear=True):
            with self.assertRaises(target_verification.VerificationError):
                target_verification.create_challenge("https://other.example.com")


class DeploymentHeaderTests(unittest.TestCase):
    def test_content_security_policy_is_configured(self):
        config = (Path(__file__).resolve().parents[1] / "vercel.json").read_text(encoding="utf-8")
        self.assertIn("Content-Security-Policy", config)
        self.assertIn("frame-ancestors 'none'", config)


if __name__ == "__main__":
    unittest.main()
