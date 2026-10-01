from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import job_store
from agent.findings import add_finding, finding_from_line, severity_counts
from agent.reporting import normalized_report, sarif_dict


class FindingSchemaTests(unittest.TestCase):
    def test_credentialed_reflected_cors_is_structured_high_confirmed(self):
        finding = finding_from_line(
            "corscan",
            "CRITICAL: reflected Origin with credentials=true (https://evil.example)",
            url="https://demo.example/api/me",
        )
        self.assertTrue(finding["id"].startswith("VA-"))
        self.assertEqual("high", finding["severity"])
        self.assertEqual("confirmed", finding["validation_status"])
        self.assertEqual("CWE-942", finding["cwe"])
        self.assertEqual("https://demo.example/api/me", finding["location"])

    def test_missing_hsts_is_observed_medium(self):
        finding = finding_from_line(
            "vibe_headers",
            "MISSING: strict-transport-security  [CRITICAL]",
            url="https://demo.example",
        )
        self.assertEqual("medium", finding["severity"])
        self.assertEqual("observed", finding["validation_status"])
        self.assertIn("strict-transport-security", finding["title"])

    def test_findings_dedupe_and_counts(self):
        report = {"findings": []}
        finding = finding_from_line("leep", "POSSIBLE exposure: /admin returned 200", url="https://demo.example")
        self.assertTrue(add_finding(report, finding))
        self.assertFalse(add_finding(report, finding))
        counts = severity_counts(report)
        self.assertEqual(1, counts["high"])


class ReportingTests(unittest.TestCase):
    def _report(self):
        finding = finding_from_line(
            "corscan",
            "CRITICAL: reflected Origin with credentials=true (https://evil.example)",
            url="https://demo.example/api/me",
        )
        return {
            "job_id": "abc123def456",
            "status": "completed",
            "agent_mode": "break",
            "agent_name": "BreakAgent",
            "tier": "hobby",
            "depth": "standard",
            "targets": ["https://demo.example"],
            "model": "test-model",
            "provider": "test",
            "reasoning_effort": "none",
            "findings": [finding],
            "errors": [],
            "report_text": "## Findings",
        }

    def test_normalized_json_summary(self):
        doc = normalized_report(self._report())
        self.assertEqual("1.0", doc["schema_version"])
        self.assertEqual("BreakAgent", doc["agent"]["name"])
        self.assertEqual(1, doc["summary"]["total_findings"])
        self.assertEqual(1, doc["summary"]["severity"]["high"])

    def test_sarif_21_output(self):
        doc = sarif_dict(self._report())
        self.assertEqual("2.1.0", doc["version"])
        run = doc["runs"][0]
        self.assertEqual("BreakAgent", run["tool"]["driver"]["name"])
        self.assertEqual(1, len(run["results"]))
        self.assertEqual("error", run["results"][0]["level"])
        self.assertEqual("CWE-942", run["results"][0]["ruleId"])


class JobIdHardeningTests(unittest.TestCase):
    def test_path_traversal_job_id_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(job_store, "JOBS_DIR", Path(tmp)):
                self.assertIsNone(job_store.load_job("../../etc/passwd"))
                with self.assertRaises(ValueError):
                    job_store.save_job({"job_id": "../escape", "findings": []})


if __name__ == "__main__":
    unittest.main()
