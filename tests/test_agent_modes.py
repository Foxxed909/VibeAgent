from __future__ import annotations

import os
import unittest
from unittest.mock import patch

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
        self.assertEqual("portable", report["execution_backend"])

    def test_native_worker_dry_run_records_backend_without_network(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
        )
        with patch.dict(os.environ, {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "demo.vercel.app",
        }, clear=False):
            report = run_job(auth, dry_run=True, agent_mode="vibe", execution_backend="native-worker")
        self.assertEqual("native-worker", report["execution_backend"])
        self.assertEqual(["native-worker-managed"], report["available_tools"])
        self.assertFalse(report["native_worker_capabilities"]["can_launch"])
        self.assertFalse(report["native_worker_capabilities"]["ownership_verified"])

    def test_native_worker_filters_shared_findings_to_exact_target(self):
        auth = Authorization(
            tier="hobby",
            targets=["https://demo.vercel.app"],
            confirmation=CONFIRM_PHRASE,
            app_name="Demo",
        )
        worker_state = {
            "thread_id": "vibe-123",
            "status": "completed",
            "model": {"id": "laguna-s-2.1"},
            "verdict": "completed",
            "resilience_score": 82,
            "events": [],
            "findings": [
                {
                    "tool": "vibe_headers",
                    "title": "Target finding",
                    "severity": "medium",
                    "location": "https://demo.vercel.app/api",
                    "evidence": "target evidence",
                    "cwe": "CWE-693",
                },
                {
                    "tool": "ghost",
                    "title": "Foreign finding",
                    "severity": "high",
                    "location": "https://other.vercel.app/.env",
                    "evidence": "must be filtered",
                },
            ],
            "confirmed_breaks": [
                {"tool": "corscan", "summary": "Confirmed local break", "evidence": "worker evidence"}
            ],
        }
        env = {
            "VIBE_AGENT_WORKER_URL": "https://worker.example.com",
            "VIBE_AGENT_WORKER_TOKEN": "x" * 32,
            "VIBE_AGENT_WORKER_ALLOWED_HOSTS": "demo.vercel.app",
        }
        with patch.dict(os.environ, env, clear=True), patch(
            "agent.orchestrator.is_target_verified", return_value=True
        ), patch(
            "agent.orchestrator.run_native_target", return_value=worker_state
        ):
            report = run_job(
                auth,
                agent_mode="vibe",
                execution_backend="native-worker",
            )
        self.assertEqual("completed", report["status"])
        self.assertEqual(2, len(report["findings"]))
        titles = {f["title"] for f in report["findings"]}
        self.assertIn("Target finding", titles)
        self.assertIn("Confirmed local break", titles)
        self.assertNotIn("Foreign finding", titles)

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
