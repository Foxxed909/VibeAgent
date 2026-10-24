from __future__ import annotations

import hashlib
import io
import json
import os
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from agent.orchestrator import run_job
from agent import orchestrator
from agent.net_safety import NetworkSafetyError, request_url, validate_outbound_url
from agent.models import OpenRouterError, chat as model_chat, validate_requested_model
from agent.openai_client import OpenAIError
from agent.request_context import (
    current_cookie,
    current_provider_key,
    reset_cookie,
    reset_provider_keys,
    set_cookie,
    set_provider_keys,
)
from agent.scope import Authorization, CONFIRM_PHRASE, ScopeError, host_in_scope, is_valid_trial_code
from agent import target_verification
from api._security import (
    origin_is_allowed,
    read_json_body,
    require_scan_access,
    require_operator_scan_access,
    require_workspace_access,
    parse_provider_keys,
)


class _Handler:
    def __init__(self, headers=None, body=b""):
        self.headers = headers or {}
        self.rfile = io.BytesIO(body)


class _ResponseHandler(_Handler):
    def __init__(self, headers=None, body=b""):
        super().__init__(headers=headers, body=body)
        self.wfile = io.BytesIO()
        self.status = None
        self.response_headers = []

    def send_response(self, code):
        self.status = code

    def send_header(self, name, value):
        self.response_headers.append((name, value))

    def end_headers(self):
        pass


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

    def test_unknown_tier_is_rejected(self):
        auth = Authorization(
            tier="unlimited",
            targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE,
        )
        with self.assertRaises(ScopeError):
            auth.validated()

    def test_non_http_url_is_rejected(self):
        auth = Authorization(
            tier="hobby",
            targets=["file:///etc/passwd"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        )
        with self.assertRaises(ScopeError):
            auth.validated()

    def test_generated_job_ids_have_capability_entropy(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        )
        report = run_job(auth, dry_run=True)
        self.assertGreaterEqual(len(report["job_id"]), 24)

    def test_native_tool_name_cannot_escape_tools_directory(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        ).validated()
        with tempfile.TemporaryDirectory() as tmp, patch.object(orchestrator, "VIBEHACKING_ROOT", tmp):
            with self.assertRaises(ScopeError):
                orchestrator._dispatch_tool("../../payload", {"url": "https://example.com"}, auth)

    def test_unknown_native_tool_is_blocked_even_when_script_exists(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        ).validated()
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir = Path(tmp) / "TOOLS"
            tools_dir.mkdir()
            (tools_dir / "stealer.py").write_text("print('nope')", encoding="utf-8")
            with patch.object(orchestrator, "VIBEHACKING_ROOT", tmp):
                with self.assertRaises(ScopeError):
                    orchestrator._dispatch_tool("stealer", {"url": "https://example.com"}, auth)

    def test_native_tools_do_not_inherit_provider_or_storage_secrets(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE,
            app_name="Example",
        ).validated()
        with tempfile.TemporaryDirectory() as tmp:
            tools_dir = Path(tmp) / "TOOLS"
            tools_dir.mkdir()
            (tools_dir / "vibe_headers.py").write_text("print('ok')", encoding="utf-8")
            completed = SimpleNamespace(returncode=0, stdout="ok", stderr="")
            env = {
                "OPENAI_API_KEY": "secret-provider-key",
                "KV_REST_API_TOKEN": "secret-storage-key",
                "VIBE_AGENT_WORKER_TOKEN": "secret-worker-key",
                "PATH": os.environ.get("PATH", ""),
            }
            with patch.dict(os.environ, env, clear=True), patch.object(
                orchestrator, "VIBEHACKING_ROOT", tmp
            ), patch("agent.orchestrator.subprocess.run", return_value=completed) as run:
                orchestrator._dispatch_tool("vibe_headers", {"url": "https://example.com"}, auth)
            child_env = run.call_args.kwargs["env"]
            self.assertNotIn("OPENAI_API_KEY", child_env)
            self.assertNotIn("KV_REST_API_TOKEN", child_env)
            self.assertNotIn("VIBE_AGENT_WORKER_TOKEN", child_env)


class OutboundNetworkPolicyTests(unittest.TestCase):
    def test_private_literal_is_blocked(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(NetworkSafetyError):
                validate_outbound_url("http://169.254.169.254/latest/meta-data")

    def test_hostname_resolving_private_is_blocked(self):
        answer = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with patch.dict(os.environ, {}, clear=True), patch("socket.getaddrinfo", return_value=answer):
            with self.assertRaises(NetworkSafetyError):
                validate_outbound_url("https://public-looking.example")

    def test_public_address_is_allowed(self):
        answer = [(2, 1, 6, "", ("93.184.216.34", 443))]
        with patch.dict(os.environ, {}, clear=True), patch("socket.getaddrinfo", return_value=answer):
            checked = validate_outbound_url("https://example.com")
        self.assertEqual("example.com", checked.host)

    def test_mixed_public_and_private_dns_answers_are_blocked(self):
        answers = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("10.0.0.8", 443)),
        ]
        with patch.dict(os.environ, {}, clear=True), patch("socket.getaddrinfo", return_value=answers):
            with self.assertRaises(NetworkSafetyError):
                validate_outbound_url("https://mixed.example")

    def test_request_is_pinned_to_validated_ip_and_keeps_host_header(self):
        answer = [(2, 1, 6, "", ("93.184.216.34", 80))]
        calls = {}

        class FakeSocket:
            def close(self):
                calls["socket_closed"] = True

        class FakeResponse:
            status = 302

            def read(self, limit):
                return b"redirect"

            def getheaders(self):
                return [("Location", "http://127.0.0.1/")]

        class FakeConnection:
            def __init__(self, host, port, timeout):
                calls["connection_host"] = host
                self.sock = None

            def request(self, method, path, headers):
                calls.update(method=method, path=path, headers=headers)

            def getresponse(self):
                return FakeResponse()

            def close(self):
                self.sock.close()

        def fake_connect(address, timeout):
            calls["address"] = address
            return FakeSocket()

        with patch.dict(os.environ, {}, clear=True), patch("socket.getaddrinfo", return_value=answer), patch(
            "socket.create_connection", side_effect=fake_connect
        ), patch("agent.net_safety.http.client.HTTPConnection", FakeConnection):
            response = request_url("http://example.com/start")

        self.assertEqual(("93.184.216.34", 80), calls["address"])
        self.assertEqual("example.com", calls["headers"]["Host"])
        self.assertEqual(302, response.status)
        self.assertEqual("http://127.0.0.1/", response.headers["location"])


class ModelPolicyTests(unittest.TestCase):
    def test_unapproved_model_is_rejected(self):
        with patch.dict(os.environ, {"VIBE_AGENT_ALLOWED_MODELS": "approved/model"}, clear=True):
            with self.assertRaises(OpenRouterError):
                validate_requested_model("expensive/unapproved")

    def test_configured_model_is_allowed(self):
        with patch.dict(os.environ, {"VIBE_AGENT_ALLOWED_MODELS": "approved/model"}, clear=True):
            self.assertEqual("approved/model", validate_requested_model("approved/model"))

    def test_gateway_routes_exact_google_model_with_oidc(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit):
                return b'{"choices":[{"message":{"content":"reviewed"}}],"model":"google/gemini-3-flash"}'

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return Response()

        env = {
            "VERCEL_OIDC_TOKEN": "oidc-token",
            "VIBE_AGENT_ALLOWED_MODELS": "google/gemini-3-flash",
        }
        with patch.dict(os.environ, env, clear=True), patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = model_chat(
                [{"role": "user", "content": "review"}],
                model="google/gemini-3-flash",
            )
        self.assertEqual("https://ai-gateway.vercel.sh/v1/chat/completions", captured["url"])
        self.assertEqual("Bearer oidc-token", captured["authorization"])
        self.assertEqual("google/gemini-3-flash", captured["body"]["model"])
        self.assertEqual("vercel-ai-gateway", result["_vibeagent"]["provider"])

    def test_user_google_key_routes_directly_to_gemini(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit):
                return b'{"choices":[{"message":{"content":"reviewed"}}],"model":"gemini-3-flash"}'

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.headers.get("Authorization")
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return Response()

        with patch.dict(os.environ, {"VIBE_AGENT_ALLOWED_MODELS": "google/gemini-3-flash"}, clear=True):
            token = set_provider_keys({"google": "user-google-key"})
            try:
                with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                    result = model_chat(
                        [{"role": "user", "content": "review"}],
                        model="google/gemini-3-flash",
                    )
            finally:
                reset_provider_keys(token)
        self.assertEqual(
            "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
            captured["url"],
        )
        self.assertEqual("Bearer user-google-key", captured["authorization"])
        self.assertEqual("gemini-3-flash", captured["body"]["model"])
        self.assertEqual("google-gemini-api", result["_vibeagent"]["provider"])

    def test_user_openai_key_is_used_by_openai_client(self):
        captured = {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, _limit):
                return b'{"choices":[{"message":{"content":"planned"}}],"model":"gpt-6-luna"}'

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["authorization"] = request.headers.get("Authorization")
            return Response()

        with patch.dict(os.environ, {"VIBE_AGENT_ALLOWED_MODELS": "gpt-6-luna"}, clear=True):
            token = set_provider_keys({"openai": "user-openai-key"})
            try:
                with patch("urllib.request.urlopen", side_effect=fake_urlopen):
                    model_chat([{"role": "user", "content": "plan"}], model="gpt-6-luna")
            finally:
                reset_provider_keys(token)
        self.assertEqual("https://api.openai.com/v1/chat/completions", captured["url"])
        self.assertEqual("Bearer user-openai-key", captured["authorization"])

    def test_provider_error_body_does_not_echo_user_key(self):
        secret = "user-openai-key"
        body = f'{{"error":"Incorrect key: {secret}"}}'.encode()
        error = urllib.error.HTTPError(
            "https://api.openai.com/v1/chat/completions", 401, "Unauthorized", {}, io.BytesIO(body)
        )
        with patch.dict(os.environ, {"VIBE_AGENT_ALLOWED_MODELS": "gpt-6-luna"}, clear=True):
            token = set_provider_keys({"openai": secret})
            try:
                with patch("urllib.request.urlopen", side_effect=error):
                    with self.assertRaises(OpenAIError) as caught:
                        model_chat([{"role": "user", "content": "plan"}], model="gpt-6-luna")
            finally:
                reset_provider_keys(token)
        self.assertNotIn(secret, str(caught.exception))


class RequestContextTests(unittest.TestCase):
    def test_cookie_context_resets(self):
        token = set_cookie("cf_clearance=abc")
        try:
            self.assertEqual("cf_clearance=abc", current_cookie())
        finally:
            reset_cookie(token)
        self.assertEqual("", current_cookie())

    def test_provider_keys_are_request_local_and_reset(self):
        token = set_provider_keys({"openai": "openai-secret", "unsupported": "ignored"})
        try:
            self.assertEqual("openai-secret", current_provider_key("openai"))
            self.assertEqual("", current_provider_key("unsupported"))
        finally:
            reset_provider_keys(token)
        self.assertEqual("", current_provider_key("openai"))

    def test_orchestrator_does_not_persist_or_retain_provider_keys(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
        )
        secret = "user-provider-secret"
        report = run_job(auth, dry_run=True, provider_keys={"openai": secret})
        self.assertNotIn(secret, json.dumps(report))
        self.assertEqual("", current_provider_key("openai"))

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


class APIAccessTests(unittest.TestCase):
    def test_provider_key_parser_accepts_only_known_bounded_values(self):
        keys, error = parse_provider_keys({"provider_keys": {"openai": " sk-user ", "google": "gemini"}})
        self.assertIsNone(error)
        self.assertEqual({"openai": "sk-user", "google": "gemini"}, keys)
        keys, error = parse_provider_keys({"provider_keys": {"evil": "secret"}})
        self.assertIsNone(keys)
        self.assertIn("unsupported provider", error)
        keys, error = parse_provider_keys({"provider_keys": {"openai": "x" * 513}})
        self.assertIsNone(keys)
        self.assertIn("too long", error)
        keys, error = parse_provider_keys({"provider_keys": []})
        self.assertIsNone(keys)
        self.assertIn("must be an object", error)

    def test_scan_access_fails_closed_when_unconfigured(self):
        handler = _ResponseHandler()
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(require_scan_access(handler, None))
        self.assertEqual(503, handler.status)

    def test_scan_api_token_is_constant_time_checked(self):
        handler = _ResponseHandler({"X-VibeAgent-Token": "correct"})
        with patch.dict(os.environ, {"VIBE_AGENT_API_TOKEN": "correct"}, clear=True):
            self.assertTrue(require_scan_access(handler, None))

    def test_operator_approval_requires_strong_private_token_not_an_invite(self):
        invited = _ResponseHandler()
        operator = _ResponseHandler({"X-VibeAgent-Token": "t" * 40})
        short_token = _ResponseHandler({"X-VibeAgent-Token": "short"})
        with patch.dict(os.environ, {"VIBE_AGENT_API_TOKEN": "t" * 40}, clear=True):
            self.assertFalse(require_operator_scan_access(invited))
            self.assertEqual(401, invited.status)
            self.assertTrue(require_operator_scan_access(operator))
        with patch.dict(os.environ, {"VIBE_AGENT_API_TOKEN": "short"}, clear=True):
            self.assertFalse(require_operator_scan_access(short_token))
            self.assertEqual(503, short_token.status)

    def test_workspace_requires_separate_token(self):
        denied = _ResponseHandler({"X-VibeAgent-Workspace-Token": "wrong"})
        allowed = _ResponseHandler({"X-VibeAgent-Workspace-Token": "workspace-secret"})
        with patch.dict(os.environ, {"VIBE_AGENT_WORKSPACE_TOKEN": "workspace-secret"}, clear=True):
            self.assertFalse(require_workspace_access(denied))
            self.assertTrue(require_workspace_access(allowed))
        self.assertEqual(401, denied.status)


class OwnershipVerificationTests(unittest.TestCase):
    def test_operator_approved_real_host_proof_is_exact_and_revocable(self):
        config = {
            "VIBE_AGENT_VERIFICATION_SECRET": "s" * 48,
            "VIBE_AGENT_OWNER_APPROVED_HOSTS": "app.example.com,portal.example.com",
        }
        with patch.dict(os.environ, config, clear=True), patch.object(
            target_verification, "_fetch_verification"
        ) as fetch:
            approval = target_verification.approve_operator_target("https://app.example.com")
            fetch.assert_not_called()
            self.assertEqual("operator-approved", approval["mode"])
            self.assertLessEqual(approval["expires_in"], 3600)
            self.assertTrue(target_verification.is_target_verified(
                "https://app.example.com", approval["proof"]
            ))
            self.assertFalse(target_verification.is_target_verified(
                "https://sub.app.example.com", approval["proof"]
            ))
            self.assertFalse(target_verification.is_target_verified(
                "https://portal.example.com", approval["proof"]
            ))
            with self.assertRaises(target_verification.VerificationError):
                target_verification.approve_operator_target("https://unapproved.example.com")
            with self.assertRaises(target_verification.VerificationError):
                target_verification.approve_operator_target("http://app.example.com")
            with self.assertRaises(target_verification.VerificationError):
                target_verification.approve_operator_target("https://app.example.com:8443")
            with self.assertRaises(target_verification.VerificationError):
                target_verification.approve_operator_target("https://*.example.com")
            os.environ.pop("VIBE_AGENT_OWNER_APPROVED_HOSTS", None)
            self.assertFalse(target_verification.is_target_verified(
                "https://app.example.com", approval["proof"]
            ))

    def test_operator_approval_requires_verification_secret_and_allowlist(self):
        with patch.dict(os.environ, {"VIBE_AGENT_OWNER_APPROVED_HOSTS": "app.example.com"}, clear=True):
            with self.assertRaises(target_verification.VerificationError):
                target_verification.approve_operator_target("https://app.example.com")
        with patch.dict(os.environ, {"VIBE_AGENT_VERIFICATION_SECRET": "s" * 40}, clear=True):
            with self.assertRaises(target_verification.VerificationError):
                target_verification.approve_operator_target("https://app.example.com")

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

    def test_verification_rejects_non_https_target(self):
        with self.assertRaises(target_verification.VerificationError):
            target_verification.create_challenge("http://other.example.com")

    def test_stateless_challenge_issues_host_bound_proof(self):
        env = {"VIBE_AGENT_VERIFICATION_SECRET": "s" * 48}
        with patch.dict(os.environ, env, clear=True):
            challenge = target_verification.create_challenge("https://app.example.com")
            self.assertEqual("stateless", challenge["mode"])
            with patch.object(target_verification, "_fetch_verification", return_value=challenge["token"]):
                confirmed = target_verification.confirm_challenge("https://app.example.com")
            self.assertTrue(target_verification.is_target_verified("https://app.example.com", confirmed["proof"]))
            self.assertFalse(target_verification.is_target_verified("https://other.example.com", confirmed["proof"]))

    def test_stateless_challenge_rejects_tampering(self):
        env = {"VIBE_AGENT_VERIFICATION_SECRET": "s" * 48}
        with patch.dict(os.environ, env, clear=True):
            challenge = target_verification.create_challenge("https://app.example.com")
            tampered = challenge["token"][:-1] + ("A" if challenge["token"][-1] != "A" else "B")
            with patch.object(target_verification, "_fetch_verification", return_value=tampered):
                with self.assertRaises(target_verification.VerificationError):
                    target_verification.confirm_challenge("https://app.example.com")


class DeploymentHeaderTests(unittest.TestCase):
    def test_content_security_policy_is_configured(self):
        config = (Path(__file__).resolve().parents[1] / "vercel.json").read_text(encoding="utf-8")
        self.assertIn("Content-Security-Policy", config)
        self.assertIn("frame-ancestors 'none'", config)


if __name__ == "__main__":
    unittest.main()
