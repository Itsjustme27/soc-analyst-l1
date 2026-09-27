"""
Offline tests for digest.py. No network - notify.py's webhook call is
mocked where needed, MOCK_MODE only.

Run: python -m unittest tests.test_digest -v
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)


def _tmp_log(entries):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for e in entries:
        tmp.write(json.dumps(e) + "\n")
    tmp.close()
    return tmp.name


class TestSinceTs(unittest.TestCase):
    def test_daily_and_weekly_are_before_now(self):
        import digest

        now = time.time()
        self.assertLess(digest._since_ts("daily"), now)
        self.assertLess(digest._since_ts("weekly"), digest._since_ts("daily"))

    def test_all_returns_none(self):
        import digest

        self.assertIsNone(digest._since_ts("all"))

    def test_unknown_period_raises(self):
        import digest

        with self.assertRaises(ValueError):
            digest._since_ts("hourly")


class TestBuildDigestText(unittest.TestCase):
    def setUp(self):
        from config import cfg

        self._orig_triage_log = cfg.TRIAGE_LOG_PATH
        self._orig_feedback_log = cfg.FEEDBACK_LOG_PATH

    def tearDown(self):
        from config import cfg

        cfg.TRIAGE_LOG_PATH = self._orig_triage_log
        cfg.FEEDBACK_LOG_PATH = self._orig_feedback_log
        for p in getattr(self, "_cleanup", []):
            Path(p).unlink(missing_ok=True)

    def _seed(self, entries, feedback=None):
        from config import cfg

        path = _tmp_log(entries)
        self._cleanup = getattr(self, "_cleanup", []) + [path]
        cfg.TRIAGE_LOG_PATH = path
        if feedback is not None:
            fb_path = _tmp_log(feedback)
            self._cleanup.append(fb_path)
            cfg.FEEDBACK_LOG_PATH = fb_path
        else:
            cfg.FEEDBACK_LOG_PATH = str(Path(tempfile.mkdtemp()) / "no-feedback.jsonl")

    def test_empty_log_says_so(self):
        import digest

        self._seed([])
        text = digest.build_digest_text("all")
        self.assertIn("No triaged alerts", text)

    def test_period_with_no_ts_entries_notes_the_gap(self):
        import digest

        self._seed([{"result": {"verdict": "true_positive"}}])  # no "ts"
        text = digest.build_digest_text("daily")
        self.assertIn("No triaged alerts", text)
        self.assertIn("--period all", text)

    def test_includes_totals_and_verdicts(self):
        import digest

        self._seed(
            [
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "result": {"verdict": "true_positive", "confidence": 0.9},
                    "needs_human_review": False,
                },
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "result": {"verdict": "escalate", "confidence": 0.3},
                    "needs_human_review": True,
                },
            ]
        )
        text = digest.build_digest_text("daily")
        self.assertIn("Total alerts: 2", text)
        self.assertIn("true_positive", text)
        self.assertIn("escalate", text)
        self.assertIn("Needs human review: 50%", text)

    def test_includes_top_rules_section(self):
        import digest

        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._seed(
            [
                {
                    "ts": now,
                    "result": {"verdict": "true_positive"},
                    "rule_matches": [{"name": "Brute force", "triggered": True}],
                },
            ]
        )
        text = digest.build_digest_text("daily")
        self.assertIn("Top triggered rules", text)
        self.assertIn("Brute force", text)

    def test_includes_analyst_agreement_when_present(self):
        import digest

        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        self._seed(
            [{"ts": now, "result": {"verdict": "true_positive"}}],
            feedback=[{"agreed": True}, {"agreed": False}],
        )
        text = digest.build_digest_text("all")
        self.assertIn("Analyst agreement", text)

    def test_all_period_ignores_missing_timestamps(self):
        import digest

        self._seed([{"result": {"verdict": "true_positive"}}])  # no ts
        text = digest.build_digest_text("all")
        self.assertIn("Total alerts: 1", text)


class TestSendDigest(unittest.TestCase):
    def setUp(self):
        from config import cfg

        self._orig_webhook = cfg.NOTIFY_WEBHOOK_URL
        self._orig_notif_log = cfg.NOTIFICATIONS_LOG_PATH
        self._orig_triage_log = cfg.TRIAGE_LOG_PATH
        cfg.NOTIFY_WEBHOOK_URL = ""
        self.tmp_notif_log = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        self.tmp_notif_log.close()
        cfg.NOTIFICATIONS_LOG_PATH = self.tmp_notif_log.name
        cfg.TRIAGE_LOG_PATH = _tmp_log([])
        self._cleanup = [self.tmp_notif_log.name, cfg.TRIAGE_LOG_PATH]

    def tearDown(self):
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = self._orig_webhook
        cfg.NOTIFICATIONS_LOG_PATH = self._orig_notif_log
        cfg.TRIAGE_LOG_PATH = self._orig_triage_log
        for p in self._cleanup:
            Path(p).unlink(missing_ok=True)

    def test_send_digest_logs_locally_with_no_webhook(self):
        import digest

        result = digest.send_digest("all", target="#soc-daily")
        self.assertTrue(result["ok"])
        self.assertFalse(result["sent"])
        logged = [json.loads(l) for l in Path(digest.notify._log_path()).read_text().splitlines()]
        self.assertEqual(logged[-1]["target"], "#soc-daily")
        self.assertIn("SOC triage digest", logged[-1]["text"])

    def test_send_digest_posts_when_webhook_configured(self):
        import digest
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = "https://hooks.example.com/xxx"

        class FakeResponse:
            status_code = 200

            def raise_for_status(self):
                pass

        with mock.patch("notify.requests.post", return_value=FakeResponse()) as m:
            result = digest.send_digest("all")
        self.assertTrue(result["sent"])
        m.assert_called_once()


if __name__ == "__main__":
    unittest.main()
