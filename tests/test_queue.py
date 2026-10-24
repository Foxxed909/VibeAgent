"""Durable queue contracts: no network targets, provider calls or Redis dependency."""
from __future__ import annotations

import json
import os
import unittest
from collections import defaultdict
from unittest.mock import patch

from agent import job_store, queue_store, queue_worker
from agent.scope import Authorization, CONFIRM_PHRASE


class FakeRedis:
    def __init__(self):
        self.values = {}
        self.lists = defaultdict(list)
        self.streams = defaultdict(list)
        self.counter = 0

    def __call__(self, *args):
        cmd = args[0].upper()
        if cmd == "SET":
            _, key, value, *flags = args
            if "NX" in flags and key in self.values:
                return None
            self.values[key] = value
            return "OK"
        if cmd == "GET":
            return self.values.get(args[1])
        if cmd == "EXPIRE":
            return 1
        if cmd == "DEL":
            self.values.pop(args[1], None)
            return 1
        if cmd == "LPUSH":
            self.lists[args[1]].insert(0, args[2])
            return len(self.lists[args[1]])
        if cmd == "LREM":
            _, key, _, value = args
            try:
                self.lists[key].remove(value)
                return 1
            except ValueError:
                return 0
        if cmd == "LRANGE":
            _, key, start, stop = args
            return self.lists[key][start:stop + 1]
        if cmd == "LTRIM":
            _, key, start, stop = args
            self.lists[key] = self.lists[key][start:stop + 1]
            return "OK"
        if cmd == "XADD":
            _, key, *rest = args
            eid = f"{self.counter + 1}-0"
            self.counter += 1
            self.streams[key].append([eid, ["data", rest[-1]]])
            return eid
        if cmd == "XRANGE":
            _, key, after, end, _, limit = args
            rows = self.streams[key]
            if after.startswith("("):
                cursor = tuple(map(int, after[1:].split("-")))
                rows = [row for row in rows if tuple(map(int, row[0].split("-"))) > cursor]
            return rows[:limit]
        if cmd == "EVAL":
            script = args[1]
            if "RPOPLPUSH" in script:
                _, _, _, pending, processing, worker_id, lease = args
                if not self.lists[pending]:
                    return None
                job_id = self.lists[pending].pop()
                self.lists[processing].insert(0, job_id)
                self.values[queue_store._key("lease", job_id)] = worker_id
                return job_id
            if "LPUSH" in script and "KEYS[3]" in script:
                _, _, _, lease_key, report_key, index_key, worker_id, payload, ttl, job_id = args
                if self.values.get(lease_key) != worker_id:
                    return 0
                self.values[report_key] = payload
                if job_id in self.lists[index_key]:
                    self.lists[index_key].remove(job_id)
                self.lists[index_key].insert(0, job_id)
                self.lists[index_key] = self.lists[index_key][:100]
                return 1
            _, _, _, lease_key, worker_id, *remaining = args
            if self.values.get(lease_key) != worker_id:
                return 0
            if "EXPIRE" in script:
                return 1
            if "DEL" in script:
                del self.values[lease_key]
                return 1
        raise AssertionError(f"unexpected Redis command: {args!r}")


class DurableQueueTests(unittest.TestCase):
    def setUp(self):
        self.redis = FakeRedis()
        self.env = patch.dict(os.environ, {"VIBE_AGENT_QUEUE_ENABLED": "1", "VIBE_AGENT_REQUIRE_OWNERSHIP": "0"}, clear=False)
        self.kv = patch.object(job_store, "_kv_enabled", return_value=True)
        self.command = patch.object(job_store, "_kv_command", side_effect=self.redis)
        self.env.start()
        self.kv.start()
        self.command.start()

    def tearDown(self):
        self.command.stop()
        self.kv.stop()
        self.env.stop()

    def enqueue(self):
        auth = Authorization(
            tier="hobby", targets=["https://example.com"],
            confirmation=CONFIRM_PHRASE, app_name="Demo",
        )
        return queue_store.enqueue(
            auth, model="gpt-6-luna", depth="quick", mode="vibe",
            execution_backend="portable", ownership_proofs={},
        )

    def test_queue_persists_no_provider_keys_or_cookies(self):
        jid, token = self.enqueue()
        task = queue_store.load_task(jid)
        self.assertEqual("queued", job_store.load_job(jid)["status"])
        self.assertNotIn("provider_keys", task)
        self.assertNotIn("cookie", task)
        self.assertNotIn("access_code", task)
        self.assertGreater(len(token), 32)

    def test_fifo_claim_and_deduplicated_lease(self):
        first, _ = self.enqueue()
        second, _ = self.enqueue()
        self.assertEqual(first, queue_store.claim("worker-a"))
        self.assertEqual(second, queue_store.claim("worker-b"))
        self.assertIsNone(queue_store.claim("worker-c"))
        self.assertTrue(queue_store.heartbeat(first, "worker-a"))
        self.assertFalse(queue_store.heartbeat(first, "wrong-owner"))
        queue_store.complete_claim(first, "worker-a")
        self.assertNotIn(first, self.redis.lists[queue_store.PROCESSING])

    def test_stale_worker_cannot_overwrite_terminal_report(self):
        jid, _ = self.enqueue()
        self.assertEqual(jid, queue_store.claim("worker-a"))
        report = job_store.load_job(jid)
        report["status"] = "completed"
        self.assertTrue(queue_store.save_report_if_owned(jid, "worker-a", report))
        self.redis.values.pop(queue_store._key("lease", jid))
        stale = dict(report, status="partial")
        self.assertFalse(queue_store.save_report_if_owned(jid, "worker-a", stale))
        self.assertEqual("completed", job_store.load_job(jid)["status"])

    def test_event_cursors_resume_without_replaying_old_events(self):
        jid, _ = self.enqueue()
        first = queue_store.read_events(jid)
        self.assertEqual(1, len(first))
        cursor = first[-1]["cursor"]
        queue_store.append_event(jid, {"type": "tool_result", "tool": "vibe_headers"})
        new = queue_store.read_events(jid, after=cursor)
        self.assertEqual(1, len(new))
        self.assertEqual("tool_result", new[0]["type"])
        self.assertEqual([], queue_store.read_events(jid, after=new[-1]["cursor"]))
        with self.assertRaises(ValueError):
            queue_store.read_events(jid, after="not-a-redis-id")

    def test_cancellation_requires_private_per_job_token(self):
        jid, token = self.enqueue()
        self.assertFalse(queue_store.cancel(jid, "wrong"))
        self.assertFalse(queue_store.is_cancelled(jid))
        self.assertTrue(queue_store.cancel(jid, token))
        self.assertTrue(queue_store.is_cancelled(jid))

    def test_worker_runs_outside_http_lifecycle_and_saves_final(self):
        jid, _ = self.enqueue()
        def fake_run(auth, **kwargs):
            kwargs["on_event"]({"type": "agent_message", "text": "hypothesis evaluated"})
            return {
                "job_id": jid, "status": "completed", "targets": auth.targets,
                "events": [], "findings": [], "errors": [],
            }
        with patch.object(queue_worker, "run_job", side_effect=fake_run):
            self.assertTrue(queue_worker.run_once("worker-a"))
        self.assertEqual("completed", job_store.load_job(jid)["status"])
        self.assertIn("final", [event["type"] for event in queue_store.read_events(jid)])
        self.assertIsNone(queue_store.load_task(jid))

    def test_orphan_worker_is_failed_not_automatically_rescanned(self):
        jid, _ = self.enqueue()
        queue_store.claim("crashed-worker")
        self.redis.values.pop(queue_store._key("lease", jid))
        self.assertEqual(1, queue_store.recover_orphans())
        self.assertEqual("failed", job_store.load_job(jid)["status"])
        self.assertEqual([], self.redis.lists[queue_store.PENDING])


if __name__ == "__main__":
    unittest.main()
