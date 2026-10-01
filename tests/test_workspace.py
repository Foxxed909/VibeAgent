from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import job_store


class WorkspaceStoreTests(unittest.TestCase):
    def test_list_jobs_reads_recent_local_jobs_with_findings(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(job_store, "JOBS_DIR", Path(tmp)), patch.object(job_store, "_kv_enabled", return_value=False):
            job_store.save_job({
                "job_id": "abcdef123456",
                "status": "completed",
                "agent_name": "VibeAgent",
                "agent_mode": "vibe",
                "execution_backend": "portable",
                "targets": ["https://example.com"],
                "findings": [{"id": "VA-1", "severity": "high", "title": "Example"}],
                "errors": [],
                "summary": {"total_findings": 1, "severity": {"high": 1}, "errors": 0},
            })
            rows = job_store.list_jobs(limit=10, include_findings=True)
            self.assertEqual(1, len(rows))
            self.assertEqual("abcdef123456", rows[0]["job_id"])
            self.assertEqual(1, rows[0]["summary"]["total_findings"])
            self.assertEqual("VA-1", rows[0]["findings"][0]["id"])

    def test_workspace_page_has_three_primary_views(self):
        root = Path(__file__).resolve().parents[1]
        html = (root / "app.html").read_text(encoding="utf-8")
        self.assertIn('data-tab="runs"', html)
        self.assertIn('data-tab="findings"', html)
        self.assertIn('data-tab="reports"', html)
        self.assertIn("/api/jobs?limit=40&include=findings", html)
        self.assertIn("/api/report?id=", html)


if __name__ == "__main__":
    unittest.main()
