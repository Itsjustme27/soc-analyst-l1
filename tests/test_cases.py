"""
Offline tests for cases.py - synthetic data/triage_log.jsonl, no network.

Run: python -m unittest tests.test_cases -v
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")


def _tmp_log(entries):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for e in entries:
        tmp.write(json.dumps(e) + "\n")
    tmp.close()
    return tmp.name


class TestGroupCases(unittest.TestCase):
    def tearDown(self):
        for p in getattr(self, "_cleanup", []):
            Path(p).unlink(missing_ok=True)

    def _log(self, entries):
        path = _tmp_log(entries)
        self._cleanup = getattr(self, "_cleanup", []) + [path]
        return path

    def test_empty_log_returns_no_cases(self):
        import cases

        path = self._log([])
        self.assertEqual(cases.group_cases(log_path=path), [])

    def test_missing_log_returns_no_cases(self):
        import cases

        self.assertEqual(cases.group_cases(log_path="/tmp/definitely-not-there-9999.jsonl"), [])

    def test_single_alert_is_its_own_case(self):
        import cases

        path = self._log(
            [
                {
                    "alert": {"alert_id": "A1", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                },
            ]
        )
        result = cases.group_cases(log_path=path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["alert_count"], 1)
        self.assertEqual(result[0]["alert_ids"], ["A1"])

    def test_same_host_within_window_groups_together(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                },
                {
                    "ts": "2026-09-24T10:05:00",
                    "alert": {"alert_id": "A2", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                },
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(len(result), 1)
        self.assertEqual(set(result[0]["alert_ids"]), {"A1", "A2"})
        self.assertEqual(result[0]["host"], "WKS-1")

    def test_same_host_outside_window_stays_separate(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1"},
                    "result": {"verdict": "x"},
                },
                {
                    "ts": "2026-09-24T11:00:00",
                    "alert": {"alert_id": "A2", "host": "WKS-1"},
                    "result": {"verdict": "x"},
                },
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(len(result), 2)

    def test_different_host_and_user_stays_separate(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1", "user": "alice"},
                    "result": {"verdict": "x"},
                },
                {
                    "ts": "2026-09-24T10:01:00",
                    "alert": {"alert_id": "A2", "host": "WKS-2", "user": "bob"},
                    "result": {"verdict": "x"},
                },
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(len(result), 2)

    def test_shared_user_links_alerts_with_different_hosts(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1", "user": "alice"},
                    "result": {"verdict": "x"},
                },
                {
                    "ts": "2026-09-24T10:05:00",
                    "alert": {"alert_id": "A2", "host": "WKS-2", "user": "alice"},
                    "result": {"verdict": "x"},
                },
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["user"], "alice")

    def test_transitive_chain_merges_via_union_find(self):
        # A-B share host, B-C share user, A and C share nothing directly -
        # all three should still end up in one case.
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A", "host": "WKS-1", "user": "alice"},
                    "result": {"verdict": "x"},
                },
                {
                    "ts": "2026-09-24T10:05:00",
                    "alert": {"alert_id": "B", "host": "WKS-1", "user": "bob"},
                    "result": {"verdict": "x"},
                },
                {
                    "ts": "2026-09-24T10:10:00",
                    "alert": {"alert_id": "C", "host": "WKS-2", "user": "bob"},
                    "result": {"verdict": "x"},
                },
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(len(result), 1)
        self.assertEqual(set(result[0]["alert_ids"]), {"A", "B", "C"})

    def test_verdicts_and_needs_review_are_aggregated(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                    "needs_human_review": True,
                },
                {
                    "ts": "2026-09-24T10:05:00",
                    "alert": {"alert_id": "A2", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                    "needs_human_review": False,
                },
                {
                    "ts": "2026-09-24T10:10:00",
                    "alert": {"alert_id": "A3", "host": "WKS-1"},
                    "result": {"verdict": "false_positive"},
                    "needs_human_review": False,
                },
            ]
        )
        [case] = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(case["verdicts"], {"true_positive": 2, "false_positive": 1})
        self.assertEqual(case["needs_review_count"], 1)

    def test_rule_tags_collected_from_triggered_matches(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1"},
                    "result": {"verdict": "x"},
                    "rule_matches": [{"triggered": True, "action": {"tag": "brute_force"}}],
                },
                {
                    "ts": "2026-09-24T10:01:00",
                    "alert": {"alert_id": "A2", "host": "WKS-1"},
                    "result": {"verdict": "x"},
                    "rule_matches": [
                        {"triggered": False, "action": {"tag": "not_triggered"}},
                        {"triggered": True, "action": {"tag": "malware"}},
                    ],
                },
            ]
        )
        [case] = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(case["rule_tags"], ["brute_force", "malware"])

    def test_hostless_userless_alerts_without_ts_fall_back_to_sequential_spacing(self):
        # No "ts" field at all (main.py/dashboard.py shape) - entries should
        # still process without crashing, one second apart by convention.
        import cases

        path = self._log(
            [
                {"alert": {"alert_id": "A1", "host": "WKS-1"}, "result": {"verdict": "x"}},
                {"alert": {"alert_id": "A2", "host": "WKS-1"}, "result": {"verdict": "x"}},
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=30)
        self.assertEqual(len(result), 1)  # 1 second apart, well within any reasonable window

    def test_non_triage_lines_are_skipped(self):
        import cases

        path = self._log(
            [
                {"message": "not a triage entry"},
                {"alert": {"alert_id": "A1", "host": "WKS-1"}, "result": {"verdict": "x"}},
            ]
        )
        result = cases.group_cases(log_path=path)
        self.assertEqual(len(result), 1)

    def test_limit_only_scans_most_recent_n_entries(self):
        import cases

        path = self._log(
            [
                {"alert": {"alert_id": f"A{i}", "host": "WKS-1"}, "result": {"verdict": "x"}}
                for i in range(10)
            ]
        )
        result = cases.group_cases(log_path=path, limit=3)
        self.assertEqual(sum(c["alert_count"] for c in result), 3)

    def test_cases_sorted_newest_first(self):
        import cases

        path = self._log(
            [
                {
                    "ts": "2026-09-24T09:00:00",
                    "alert": {"alert_id": "OLD", "host": "WKS-OLD"},
                    "result": {"verdict": "x"},
                },
                {
                    "ts": "2026-09-24T12:00:00",
                    "alert": {"alert_id": "NEW", "host": "WKS-NEW"},
                    "result": {"verdict": "x"},
                },
            ]
        )
        result = cases.group_cases(log_path=path, window_minutes=1)
        self.assertEqual(result[0]["alert_ids"], ["NEW"])
        self.assertEqual(result[1]["alert_ids"], ["OLD"])


class TestCasesRouteOffline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_cases_route(self):
        from config import cfg

        path = _tmp_log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "alert": {"alert_id": "A1", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                },
                {
                    "ts": "2026-09-24T10:05:00",
                    "alert": {"alert_id": "A2", "host": "WKS-1"},
                    "result": {"verdict": "true_positive"},
                },
            ]
        )
        orig = cfg.TRIAGE_LOG_PATH
        cfg.TRIAGE_LOG_PATH = path
        try:
            r = self.client.get("/api/cases")
            self.assertEqual(r.status_code, 200)
            body = r.get_json()["cases"]
            self.assertEqual(len(body), 1)
            self.assertEqual(body[0]["alert_count"], 2)
        finally:
            cfg.TRIAGE_LOG_PATH = orig
            Path(path).unlink(missing_ok=True)

    def test_cases_route_min_alerts_filter(self):
        from config import cfg

        path = _tmp_log(
            [{"alert": {"alert_id": "SOLO", "host": "WKS-SOLO"}, "result": {"verdict": "x"}}]
        )
        orig = cfg.TRIAGE_LOG_PATH
        cfg.TRIAGE_LOG_PATH = path
        try:
            r = self.client.get("/api/cases?min_alerts=2")
            self.assertEqual(r.get_json()["cases"], [])
        finally:
            cfg.TRIAGE_LOG_PATH = orig
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
