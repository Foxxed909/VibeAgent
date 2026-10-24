"""Contract tests for Nemotron 3 Ultra on OpenRouter and NVIDIA NIM.

Calls are mocked: no real API key, network target or model inference required.
"""
from __future__ import annotations

import io
import json
import os
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from agent.models import (
    NEMOTRON_NVIDIA_MODEL,
    NEMOTRON_OPENROUTER_FREE_MODEL,
    OpenRouterError,
    allowed_models,
    chat,
)
from agent.request_context import current_provider_key, reset_provider_keys, set_provider_keys
from agent.tools_catalog import BREAKAGENT_PROMPT, VIBEAGENT_PROMPT


class FakeResponse:
    def __init__(self, body=None):
        self.body = json.dumps(body or {
            "model": NEMOTRON_NVIDIA_MODEL,
            "choices": [{"message": {"role": "assistant", "content": "evidence-based finding"}}],
        }).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _bytes):
        return self.body


TOOLS = [{
    "type": "function",
    "function": {
        "name": "api_check",
        "description": "check a bounded endpoint",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
}]


class NemotronProviderTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {
            "VIBE_AGENT_ALLOWED_MODELS": ",".join([NEMOTRON_NVIDIA_MODEL, NEMOTRON_OPENROUTER_FREE_MODEL]),
            "OPENROUTER_API_KEY": "",
            "NVIDIA_API_KEY": "",
            "OPENAI_API_KEY": "",
            "AI_GATEWAY_API_KEY": "",
            "VERCEL_OIDC_TOKEN": "",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()

    def test_both_identifiers_are_allowed_by_default(self):
        with patch.dict(os.environ, {"VIBE_AGENT_ALLOWED_MODELS": ""}):
            self.assertIn(NEMOTRON_OPENROUTER_FREE_MODEL, allowed_models())
            self.assertIn(NEMOTRON_NVIDIA_MODEL, allowed_models())

    def test_openrouter_free_model_uses_exact_slug_and_tool_reasoning(self):
        captured = {}

        def request(req, timeout):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["auth"] = req.headers.get("Authorization")
            return FakeResponse()

        token = set_provider_keys({"openrouter": "or-byok"})
        try:
            with patch("urllib.request.urlopen", side_effect=request):
                result = chat([{"role": "user", "content": "review"}],
                              model=NEMOTRON_OPENROUTER_FREE_MODEL, tools=TOOLS)
        finally:
            reset_provider_keys(token)
        self.assertEqual("https://openrouter.ai/api/v1/chat/completions", captured["url"])
        self.assertEqual("Bearer or-byok", captured["auth"])
        self.assertEqual(NEMOTRON_OPENROUTER_FREE_MODEL, captured["body"]["model"])
        self.assertEqual("auto", captured["body"]["tool_choice"])
        self.assertEqual({"enabled": True}, captured["body"]["reasoning"])
        self.assertEqual("openrouter", result["_vibeagent"]["provider"])

    def test_nvidia_direct_uses_unsuffixed_slug_and_tools(self):
        captured = {}

        def request(req, timeout):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            captured["auth"] = req.headers.get("Authorization")
            return FakeResponse()

        token = set_provider_keys({"nvidia": "nvapi-byok"})
        try:
            with patch("urllib.request.urlopen", side_effect=request):
                result = chat([{"role": "user", "content": "review"}],
                              model=NEMOTRON_NVIDIA_MODEL, tools=TOOLS)
        finally:
            reset_provider_keys(token)
        self.assertEqual("https://integrate.api.nvidia.com/v1/chat/completions", captured["url"])
        self.assertEqual("Bearer nvapi-byok", captured["auth"])
        self.assertEqual(NEMOTRON_NVIDIA_MODEL, captured["body"]["model"])
        self.assertEqual("auto", captured["body"]["tool_choice"])
        self.assertEqual(
            {"enable_thinking": True, "force_nonempty_content": True},
            captured["body"]["chat_template_kwargs"],
        )
        self.assertEqual("nvidia-nim", result["_vibeagent"]["provider"])

    def test_openrouter_free_selection_uses_nvidia_when_only_nvidia_key(self):
        captured = {}

        def request(req, timeout):
            captured["url"] = req.full_url
            captured["body"] = json.loads(req.data.decode())
            return FakeResponse()

        token = set_provider_keys({"nvidia": "nvapi-byok"})
        try:
            with patch("urllib.request.urlopen", side_effect=request):
                result = chat([{"role": "user", "content": "review"}],
                              model=NEMOTRON_OPENROUTER_FREE_MODEL)
        finally:
            reset_provider_keys(token)
        self.assertEqual("https://integrate.api.nvidia.com/v1/chat/completions", captured["url"])
        self.assertEqual(NEMOTRON_NVIDIA_MODEL, captured["body"]["model"])
        self.assertEqual("nvidia-nim", result["_vibeagent"]["provider"])

    def test_explicit_nvidia_byok_precedes_server_openrouter_key(self):
        captured = {}

        def request(req, timeout):
            captured["url"] = req.full_url
            return FakeResponse()

        with patch.dict(os.environ, {"OPENROUTER_API_KEY": "ambient-key"}):
            token = set_provider_keys({"nvidia": "explicit-nvidia"})
            try:
                with patch("urllib.request.urlopen", side_effect=request):
                    result = chat(
                        [{"role": "user", "content": "review"}],
                        model=NEMOTRON_OPENROUTER_FREE_MODEL,
                    )
            finally:
                reset_provider_keys(token)
        self.assertEqual("https://integrate.api.nvidia.com/v1/chat/completions", captured["url"])
        self.assertEqual("nvidia-nim", result["_vibeagent"]["provider"])

    def test_explicit_nvidia_selection_does_not_use_openrouter_key(self):
        token = set_provider_keys({"openrouter": "or-byok"})
        try:
            with self.assertRaises(OpenRouterError) as error:
                chat([{"role": "user", "content": "review"}],
                     model=NEMOTRON_NVIDIA_MODEL)
        finally:
            reset_provider_keys(token)
        self.assertIn("NVIDIA_API_KEY", str(error.exception))
        self.assertNotIn("or-byok", str(error.exception))

    def test_nvidia_http_error_never_includes_sensitive_response(self):
        token = set_provider_keys({"nvidia": "nvapi-super-secret"})
        response = io.BytesIO(b'{"error":"key nvapi-super-secret invalid"}')
        error = urllib.error.HTTPError(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            401, "Unauthorized", {}, response,
        )
        try:
            with patch("urllib.request.urlopen", side_effect=error):
                with self.assertRaises(OpenRouterError) as caught:
                    chat([{"role": "user", "content": "review"}], model=NEMOTRON_NVIDIA_MODEL)
        finally:
            reset_provider_keys(token)
        self.assertIn("HTTP 401", str(caught.exception))
        self.assertNotIn("nvapi-super-secret", str(caught.exception))

    def test_request_scoped_nvidia_key_is_reset(self):
        token = set_provider_keys({"nvidia": "per-request-secret"})
        self.assertEqual("per-request-secret", current_provider_key("nvidia"))
        reset_provider_keys(token)
        self.assertFalse(current_provider_key("nvidia"))

    def test_non_nemotron_slug_is_not_allowed_in_nvidia_endpoint(self):
        from agent.models import _nvidia_chat
        token = set_provider_keys({"nvidia": "key"})
        try:
            with self.assertRaises(OpenRouterError):
                _nvidia_chat([], model="nvidia/other-model", temperature=0.2,
                             max_tokens=200, tools=None, reasoning_effort=None)
        finally:
            reset_provider_keys(token)


class NemotronFrontendAndPromptTests(unittest.TestCase):
    def test_scan_form_exposes_both_providers_and_expected_model(self):
        html = (Path(__file__).resolve().parents[1] / "scan.html").read_text()
        self.assertIn(NEMOTRON_OPENROUTER_FREE_MODEL, html)
        self.assertIn(NEMOTRON_NVIDIA_MODEL, html)
        self.assertIn('id="openrouter_api_key"', html)
        self.assertIn('id="nvidia_api_key"', html)
        self.assertIn('openrouter: document.getElementById("openrouter_api_key")', html)
        self.assertIn('nvidia: document.getElementById("nvidia_api_key")', html)

    def test_security_agents_have_concrete_adversarial_evidence_instructions(self):
        for prompt in (VIBEAGENT_PROMPT, BREAKAGENT_PROMPT):
            self.assertIn("trust boundar", prompt.lower())
            self.assertIn("attacker", prompt.lower())
            self.assertIn("evidence", prompt.lower())
            self.assertIn("authorized", prompt.lower())


if __name__ == "__main__":
    unittest.main()
