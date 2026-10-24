"""Customer BYOK policy: platform-owner keys are never implicit customer keys."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from api._security import customer_keys_required, personal_key_error

class CustomerKeysTests(unittest.TestCase):
    def test_configurable_strict_customer_mode(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(customer_keys_required())
        with patch.dict(os.environ, {"VIBE_AGENT_REQUIRE_CUSTOMER_KEYS": "1"}, clear=True):
            self.assertTrue(customer_keys_required())

    def test_openrouter_or_nvidia_key_for_free_nemotron(self):
        model = "nvidia/nemotron-3-ultra-550b-a55b:free"
        self.assertIn("own OpenRouter", personal_key_error(model, {}))
        self.assertIsNone(personal_key_error(model, {"openrouter": "customer-OR"}))
        self.assertIsNone(personal_key_error(model, {"nvidia": "customer-NV"}))
        self.assertIn("own OpenRouter", personal_key_error(model, {"openai": "wrong-provider"}))

    def test_openai_and_nvidia_routes_are_isolated(self):
        self.assertIn("own OpenAI", personal_key_error("gpt-6-luna", {}))
        self.assertIsNone(personal_key_error("gpt-6-luna", {"openai": "customer-openai"}))
        self.assertIn("own NVIDIA", personal_key_error("nvidia/nemotron-3-ultra-550b-a55b", {"openai": "wrong"}))
        self.assertIsNone(personal_key_error("nvidia/nemotron-3-ultra-550b-a55b", {"nvidia": "customer-nvidia"}))
        self.assertIn("isolated customer-key", personal_key_error("unmapped/model", {"openrouter": "customer"}))

    def test_platform_environment_key_does_not_count_as_customer_key(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "platform-owner-secret",
                                     "NVIDIA_API_KEY": "platform-owner-secret"}, clear=True):
            self.assertIn("own OpenAI", personal_key_error("gpt-6-luna", {}))
            self.assertIn("own NVIDIA", personal_key_error("nvidia/nemotron-3-ultra-550b-a55b", {}))

if __name__ == "__main__":
    unittest.main()
