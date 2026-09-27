"""
Offline tests for notify.py - no real network calls (requests.post is
mocked), MOCK_MODE only.

Run: python -m unittest tests.test_notify -v
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)


class FakeResponse:
    def __init__(self, status=200):
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class TestSendNotification(unittest.TestCase):
    def setUp(self):
        from config import cfg

        self._orig_webhook = cfg.NOTIFY_WEBHOOK_URL
        self.tmp_log = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        self.tmp_log.close()
        self._orig_log_path = cfg.NOTIFICATIONS_LOG_PATH
        cfg.NOTIFICATIONS_LOG_PATH = self.tmp_log.name

    def tearDown(self):
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = self._orig_webhook
        cfg.NOTIFICATIONS_LOG_PATH = self._orig_log_path
        Path(self.tmp_log.name).unlink(missing_ok=True)

    def _read_log(self):
        lines = Path(self.tmp_log.name).read_text().strip().splitlines()
        return [json.loads(l) for l in lines if l.strip()]

    def test_no_webhook_configured_logs_only(self):
        import notify
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = ""
        result = notify.send_notification("hello")
        self.assertTrue(result["ok"])
        self.assertFalse(result["sent"])
        entries = self._read_log()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["text"], "hello")
        self.assertFalse(entries[0]["result"]["sent"])

    def test_webhook_success_is_logged(self):
        import notify
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = "https://hooks.example.com/T000/B000/xxx"
        with mock.patch("notify.requests.post", return_value=FakeResponse(200)) as m:
            result = notify.send_notification("brute force detected", target="#soc-alerts")
        self.assertTrue(result["ok"])
        self.assertTrue(result["sent"])
        m.assert_called_once()
        _, kwargs = m.call_args
        self.assertEqual(kwargs["json"], {"text": "[#soc-alerts] brute force detected"})
        entries = self._read_log()
        self.assertEqual(entries[0]["target"], "#soc-alerts")
        self.assertTrue(entries[0]["result"]["sent"])

    def test_webhook_failure_is_caught_and_logged_not_raised(self):
        import notify
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = "https://hooks.example.com/broken"
        with mock.patch("notify.requests.post", side_effect=ConnectionError("refused")):
            result = notify.send_notification("hello")  # must not raise
        self.assertFalse(result["ok"])
        self.assertFalse(result["sent"])
        self.assertIn("refused", result["detail"])
        entries = self._read_log()
        self.assertFalse(entries[0]["result"]["ok"])

    def test_webhook_http_error_is_caught(self):
        import notify
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = "https://hooks.example.com/xxx"
        with mock.patch("notify.requests.post", return_value=FakeResponse(500)):
            result = notify.send_notification("hello")
        self.assertFalse(result["ok"])


class TestNotifyRuleMatches(unittest.TestCase):
    def setUp(self):
        from config import cfg

        self._orig_webhook = cfg.NOTIFY_WEBHOOK_URL
        cfg.NOTIFY_WEBHOOK_URL = ""  # log-only is enough to test the wrapper's selection logic
        self.tmp_log = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        self.tmp_log.close()
        self._orig_log_path = cfg.NOTIFICATIONS_LOG_PATH
        cfg.NOTIFICATIONS_LOG_PATH = self.tmp_log.name

    def tearDown(self):
        from config import cfg

        cfg.NOTIFY_WEBHOOK_URL = self._orig_webhook
        cfg.NOTIFICATIONS_LOG_PATH = self._orig_log_path
        Path(self.tmp_log.name).unlink(missing_ok=True)

    def test_only_triggered_matches_with_notify_set_fire(self):
        import notify

        alert = {"alert_id": "SPLK-1", "rule_name": "Brute force"}
        matches = [
            {"name": "no notify set", "triggered": True, "action": {"tag": "x", "notify": ""}},
            {"name": "not triggered", "triggered": False, "action": {"tag": "x", "notify": "#soc"}},
            {
                "name": "fires",
                "triggered": True,
                "rule_id": "rule-1",
                "action": {"tag": "brute_force", "notify": "#soc-alerts"},
            },
        ]
        results = notify.notify_rule_matches(alert, matches)
        self.assertEqual(len(results), 1)  # only the third one qualifies

    def test_message_includes_rule_name_and_alert_id(self):
        import notify

        alert = {"alert_id": "SPLK-42", "rule_name": "Malware detection"}
        matches = [
            {
                "name": "EDR rule",
                "triggered": True,
                "rule_id": "rule-9",
                "action": {"tag": "malware", "notify": "#soc-alerts"},
            }
        ]
        notify.notify_rule_matches(alert, matches)
        entries = [json.loads(l) for l in Path(self.tmp_log.name).read_text().strip().splitlines()]
        self.assertIn("SPLK-42", entries[0]["text"])
        self.assertIn("EDR rule", entries[0]["text"])
        self.assertIn("malware", entries[0]["text"])

    def test_no_triggered_matches_sends_nothing(self):
        import notify

        results = notify.notify_rule_matches({"alert_id": "x"}, [])
        self.assertEqual(results, [])
        self.assertFalse(Path(self.tmp_log.name).read_text().strip())


if __name__ == "__main__":
    unittest.main()
