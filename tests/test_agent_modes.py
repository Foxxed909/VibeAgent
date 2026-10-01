from __future__ import annotations

import unittest

from agent.orchestrator import run_job
from agent.scope import Authorization, CONFIRM_PHRASE
from agent.tools_catalog import (
    agent_name,
    get_forced_tools,
    get_system_prompt,
    normalize_agent_mode,
)


class AgentModeTests(unittest.TestCase):
    def test_mode_aliases_normalize(self):
        self.assertEqual("break", normalize_agent_mode("BreakAgent"))
        self.assertEqual("break", normalize_agent_mode("break-agent"))
        self.assertEqual("vibe", normalize_agent_mode("anything-else"))

    def test_names_and_prompts_are_distinct(self):
        self.assertEqual("VibeAgent", agent_name("vibe"))
        self.assertEqual("BreakAgent", agent_name("break"))
        self.assertIn("surface discovery", get_system_prompt("vibe"))
        self.assertIn("validation-focused", get_system_prompt("break"))

    def test_breakagent_dry_run_uses_break_policy(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
        )
        report = run_job(auth, dry_run=True, agent_mode="break")
        self.assertEqual("break", report["agent_mode"])
        self.assertEqual("BreakAgent", report["agent_name"])
        self.assertIn("corscan", report["available_tools"])
        self.assertNotIn("bot_breaker", report["available_tools"])

    def test_breakagent_forced_sequence_is_targeted(self):
        tools = get_forced_tools("break", force_api_finder=True)
        self.assertEqual("vibe_headers", tools[0])
        self.assertIn("api_finder", tools)
        self.assertIn("corscan", tools)
        self.assertIn("phantom", tools)
        self.assertIn("leep", tools)
        self.assertNotIn("ash", tools)
        self.assertNotIn("spider", tools)


if __name__ == "__main__":
    unittest.main()
