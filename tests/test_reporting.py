from __future__ import annotations

import json
import unittest

from agent.findings import add_finding, finding_from_line, finding_from_worker, severity_counts
from agent.reporting import json_bytes, normalized_report, sarif_dict


class StructuredFindingTests(unittest.TestCase):
    def test_missing_csp_is_structured_medium_finding(self):
        finding = finding_from_line(
            "vibe_headers",
            "MISSING: content-security-policy  [CRITICAL]",
            url="https://example.com/",
        )
        self.assertTrue(finding["id"].startswith("VA-"))
        self.assertEqual("medium", finding["severity"])
        self.assertEqual("observed", finding["validation_status"])
        self.assertEqual("CWE-693", finding["cwe"])
        self.assertEqual("https://example.com/", finding["location"])

    def test_credentialed_reflected_cors_is_confirmed_high(self):
        finding = finding_from_line(
            "corscan",
            "CRITICAL: reflected Origin with credentials=true (https://evil.example)",
            url="https://example.com/api/me",
        )
        self.assertEqual("high", finding["severity"])
        self.assertEqual("confirmed", finding["validation_status"])
        self.assertEqual("CWE-942", finding["cwe"])

    def test_deduplication_uses_stable_finding_id(self):
        report = {"findings": []}
        finding = finding_from_line("leep", "POSSIBLE exposure: /admin returned 200", url="https://example.com")
        self.assertTrue(add_finding(report, finding))
        self.assertFalse(add_finding(report, dict(finding)))
        self.assertEqual(1, len(report["findings"]))

    def test_worker_finding_restores_redacted_authorized_host(self):
        finding = finding_from_worker(
            {
                "tool": "VibeHeaders",
                "title": "Missing policy",
                "severity": "medium",
                "location": "https://<host>/admin",
                "evidence": "header missing",
                "cwe": "CWE-693",
            },
            default_url="https://app.example.com",
            default_tool="vibe_headers",
        )
        self.assertEqual("https://app.example.com/admin", finding["location"])
        self.assertEqual("vibe_headers", finding["tool"])

    def test_severity_counts(self):
        report = {"findings": [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "medium"},
            {"severity": "info"},
        ]}
        counts = severity_counts(report)
        self.assertEqual(1, counts["high"])
        self.assertEqual(2, counts["medium"])
        self.assertEqual(1, counts["info"])


class ReportingTests(unittest.TestCase):
    def sample_report(self):
        finding = finding_from_line(
            "corscan",
            "CRITICAL: reflected Origin with credentials=true (https://evil.example)",
            url="https://example.com/api/me",
        )
        return {
            "job_id": "abc123def456",
            "status": "completed",
            "agent_mode": "break",
            "agent_name": "BreakAgent",
            "tier": "hobby",
            "depth": "standard",
            "targets": ["https://example.com"],
            "app_name": "Example",
            "company_name": None,
            "provider": "openai",
            "model": "test-model",
            "reasoning_effort": "none",
            "execution_backend": "worker-tools",
            "worker_tools": ["corscan", "vibe_headers"],
            "worker_warning": None,
            "findings": [finding],
            "errors": [],
            "report_text": "## Findings\n- confirmed",
        }

    def test_normalized_json_schema(self):
        payload = normalized_report(self.sample_report())
        self.assertEqual("1.0", payload["schema_version"])
        self.assertEqual("BreakAgent", payload["agent"]["name"])
        self.assertEqual(1, payload["summary"]["total_findings"])
        self.assertEqual(1, payload["summary"]["severity"]["high"])
        self.assertEqual("worker-tools", payload["execution"]["backend"])
        self.assertIn("corscan", payload["execution"]["worker_tools"])
        parsed = json.loads(json_bytes(self.sample_report()).decode("utf-8"))
        self.assertEqual("abc123def456", parsed["job_id"])

    def test_sarif_21_output(self):
        sarif = sarif_dict(self.sample_report())
        self.assertEqual("2.1.0", sarif["version"])
        run = sarif["runs"][0]
        self.assertEqual("BreakAgent", run["tool"]["driver"]["name"])
        self.assertEqual(1, len(run["results"]))
        result = run["results"][0]
        self.assertEqual("error", result["level"])
        self.assertEqual("confirmed", result["properties"]["validationStatus"])
        self.assertEqual("https://example.com/api/me", result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])


if __name__ == "__main__":
    unittest.main()
