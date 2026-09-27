"""
Offline tests for metrics.py - synthetic data/triage_log.jsonl and
data/feedback_log.jsonl, no network, MOCK_MODE only.

Run: python -m unittest tests.test_metrics -v
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)


def _tmp_jsonl(entries):
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
    for e in entries:
        tmp.write(json.dumps(e) + "\n")
    tmp.close()
    return tmp.name


class TestComputeMetricsOffline(unittest.TestCase):
    def tearDown(self):
        for p in getattr(self, "_to_cleanup", []):
            Path(p).unlink(missing_ok=True)

    def _log(self, entries):
        path = _tmp_jsonl(entries)
        self._to_cleanup = getattr(self, "_to_cleanup", []) + [path]
        return path

    def test_empty_log_returns_zeroed_result(self):
        import metrics

        path = self._log([])
        # Hermetic: also point feedback at an empty file so this test never
        # depends on the developer's real on-disk data/feedback_log.jsonl.
        fb_path = _tmp_jsonl([])
        self._to_cleanup = getattr(self, "_to_cleanup", []) + [fb_path]
        m = metrics.compute_metrics(log_path=path, feedback_path=fb_path)
        self.assertEqual(m["total_alerts"], 0)
        self.assertEqual(m["needs_human_review_rate"], 0.0)
        self.assertEqual(m["verdict_totals"], {})
        self.assertEqual(m["top_rules"], [])
        self.assertIsNone(m["analyst_agreement"])

    def test_missing_log_file_is_treated_as_empty(self):
        import metrics

        m = metrics.compute_metrics(log_path="/tmp/definitely-does-not-exist-12345.jsonl")
        self.assertEqual(m["total_alerts"], 0)

    def test_verdict_totals_and_needs_review_rate(self):
        import metrics

        path = self._log(
            [
                {
                    "result": {"verdict": "true_positive", "confidence": 0.95},
                    "needs_human_review": False,
                },
                {
                    "result": {"verdict": "false_positive", "confidence": 0.92},
                    "needs_human_review": False,
                },
                {"result": {"verdict": "escalate", "confidence": 0.3}, "needs_human_review": True},
            ]
        )
        m = metrics.compute_metrics(log_path=path)
        self.assertEqual(m["total_alerts"], 3)
        self.assertEqual(
            m["verdict_totals"], {"true_positive": 1, "false_positive": 1, "escalate": 1}
        )
        self.assertAlmostEqual(m["needs_human_review_rate"], 1 / 3)

    def test_verdict_by_day_groups_on_ts_prefix(self):
        import metrics

        path = self._log(
            [
                {
                    "ts": "2026-09-24T10:00:00",
                    "result": {"verdict": "true_positive", "confidence": 0.9},
                },
                {
                    "ts": "2026-09-24T15:00:00",
                    "result": {"verdict": "false_positive", "confidence": 0.9},
                },
                {
                    "ts": "2026-09-25T09:00:00",
                    "result": {"verdict": "true_positive", "confidence": 0.9},
                },
                {
                    "result": {"verdict": "escalate", "confidence": 0.4}
                },  # no ts (main.py/dashboard.py shape)
            ]
        )
        m = metrics.compute_metrics(log_path=path)
        self.assertEqual(
            m["verdict_by_day"]["2026-09-24"], {"true_positive": 1, "false_positive": 1}
        )
        self.assertEqual(m["verdict_by_day"]["2026-09-25"], {"true_positive": 1})
        self.assertEqual(m["verdict_by_day"]["unknown"], {"escalate": 1})

    def test_confidence_distribution_buckets(self):
        import metrics

        path = self._log(
            [
                {"result": {"verdict": "x", "confidence": 0.2}},  # 0.0-0.5
                {"result": {"verdict": "x", "confidence": 0.6}},  # 0.5-0.7
                {"result": {"verdict": "x", "confidence": 0.85}},  # 0.7-0.9
                {"result": {"verdict": "x", "confidence": 0.99}},  # 0.9-1.0
                {"result": {"verdict": "x", "confidence": 1.0}},  # 0.9-1.0 (exact 1.0 edge case)
            ]
        )
        m = metrics.compute_metrics(log_path=path)
        dist = m["confidence_distribution"]
        self.assertEqual(dist["0.0-0.5"], 1)
        self.assertEqual(dist["0.5-0.7"], 1)
        self.assertEqual(dist["0.7-0.9"], 1)
        self.assertEqual(dist["0.9-1.0"], 2)

    def test_by_provider_handles_both_log_shapes(self):
        import metrics

        path = self._log(
            [
                # dashboard.py's on-demand triage shape
                {
                    "siem_provider": {"id": "env-splunk", "name": "Splunk (env)"},
                    "result": {"verdict": "x"},
                    "needs_human_review": True,
                },
                # run.py's watch-loop shape
                {"provider": "wazuh", "result": {"verdict": "x"}, "needs_human_review": False},
                # main.py demo/live shape - no provider info at all
                {"result": {"verdict": "x"}, "needs_human_review": False},
            ]
        )
        m = metrics.compute_metrics(log_path=path)
        self.assertEqual(m["by_provider"]["Splunk (env)"]["count"], 1)
        self.assertEqual(m["by_provider"]["Splunk (env)"]["needs_review_rate"], 1.0)
        self.assertEqual(m["by_provider"]["wazuh"]["count"], 1)
        self.assertEqual(m["by_provider"]["unknown"]["count"], 1)

    def test_top_rules_ranked_by_trigger_count_with_true_positive_rate(self):
        import metrics

        path = self._log(
            [
                {
                    "result": {"verdict": "true_positive"},
                    "rule_matches": [
                        {"name": "Brute force", "triggered": True},
                    ],
                },
                {
                    "result": {"verdict": "false_positive"},
                    "rule_matches": [
                        {"name": "Brute force", "triggered": True},
                    ],
                },
                {
                    "result": {"verdict": "true_positive"},
                    "rule_matches": [
                        {"name": "Malware", "triggered": True},
                        {
                            "name": "Brute force",
                            "triggered": False,
                        },  # matched but not triggered - excluded
                    ],
                },
            ]
        )
        m = metrics.compute_metrics(log_path=path)
        by_name = {r["name"]: r for r in m["top_rules"]}
        self.assertEqual(by_name["Brute force"]["triggered"], 2)
        self.assertEqual(by_name["Brute force"]["true_positive"], 1)
        self.assertAlmostEqual(by_name["Brute force"]["true_positive_rate"], 0.5)
        self.assertEqual(by_name["Malware"]["triggered"], 1)
        # ranked by trigger count, descending
        self.assertEqual(m["top_rules"][0]["name"], "Brute force")

    def test_analyst_agreement_from_feedback_log(self):
        import metrics

        log_path = self._log([{"result": {"verdict": "x"}}])
        fb_path = _tmp_jsonl(
            [
                {"case_id": "1", "agreed": True},
                {"case_id": "2", "agreed": True},
                {"case_id": "3", "agreed": False},
            ]
        )
        self._to_cleanup.append(fb_path)
        m = metrics.compute_metrics(log_path=log_path, feedback_path=fb_path)
        self.assertEqual(m["analyst_agreement"]["reviewed"], 3)
        self.assertEqual(m["analyst_agreement"]["agreed"], 2)
        self.assertAlmostEqual(m["analyst_agreement"]["agreement_rate"], 2 / 3)

    def test_analyst_agreement_breaks_down_by_analyst(self):
        import metrics

        log_path = self._log([{"result": {"verdict": "x"}}])
        fb_path = _tmp_jsonl(
            [
                {"case_id": "1", "agreed": True, "analyst": "jsmith"},
                {"case_id": "2", "agreed": False, "analyst": "jsmith"},
                {"case_id": "3", "agreed": True, "analyst": "asmith"},
                {"case_id": "4", "agreed": True},  # no analyst recorded (older data, or blank)
            ]
        )
        self._to_cleanup.append(fb_path)
        m = metrics.compute_metrics(log_path=log_path, feedback_path=fb_path)
        by_analyst = m["analyst_agreement"]["by_analyst"]
        self.assertEqual(by_analyst["jsmith"]["reviewed"], 2)
        self.assertEqual(by_analyst["jsmith"]["agreed"], 1)
        self.assertAlmostEqual(by_analyst["jsmith"]["agreement_rate"], 0.5)
        self.assertEqual(by_analyst["asmith"]["reviewed"], 1)
        self.assertEqual(by_analyst["unknown"]["reviewed"], 1)

    def test_malformed_lines_are_skipped_not_fatal(self):
        import metrics

        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        tmp.write("not valid json\n")
        tmp.write(json.dumps({"result": {"verdict": "true_positive"}}) + "\n")
        tmp.close()
        self._to_cleanup = getattr(self, "_to_cleanup", []) + [tmp.name]
        m = metrics.compute_metrics(log_path=tmp.name)
        self.assertEqual(m["total_alerts"], 1)

    def test_since_ts_excludes_entries_before_cutoff(self):
        import metrics

        path = self._log(
            [
                {
                    "ts": "2026-09-20T10:00:00",
                    "result": {"verdict": "true_positive"},
                },  # before cutoff
                {
                    "ts": "2026-09-24T10:00:00",
                    "result": {"verdict": "false_positive"},
                },  # after cutoff
            ]
        )
        cutoff = time.mktime(time.strptime("2026-09-22T00:00:00", "%Y-%m-%dT%H:%M:%S"))
        m = metrics.compute_metrics(log_path=path, since_ts=cutoff)
        self.assertEqual(m["total_alerts"], 1)
        self.assertEqual(m["verdict_totals"], {"false_positive": 1})

    def test_since_ts_excludes_entries_with_no_timestamp(self):
        import metrics

        path = self._log(
            [
                {"result": {"verdict": "true_positive"}},  # no "ts" at all - can't confirm recency
                {"ts": "2026-09-24T10:00:00", "result": {"verdict": "false_positive"}},
            ]
        )
        cutoff = time.mktime(time.strptime("2026-01-01T00:00:00", "%Y-%m-%dT%H:%M:%S"))
        m = metrics.compute_metrics(log_path=path, since_ts=cutoff)
        self.assertEqual(m["total_alerts"], 1)  # only the ts-bearing entry counts

    def test_no_since_ts_includes_everything_regardless_of_timestamp(self):
        import metrics

        path = self._log(
            [
                {"result": {"verdict": "true_positive"}},
                {"ts": "2026-09-24T10:00:00", "result": {"verdict": "false_positive"}},
            ]
        )
        m = metrics.compute_metrics(log_path=path)  # since_ts not set (default)
        self.assertEqual(m["total_alerts"], 2)


class TestMetricsRouteOffline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_metrics_route(self):
        from config import cfg

        path = _tmp_jsonl([{"result": {"verdict": "true_positive", "confidence": 0.9}}])
        orig = cfg.TRIAGE_LOG_PATH
        cfg.TRIAGE_LOG_PATH = path
        try:
            r = self.client.get("/api/metrics")
            self.assertEqual(r.status_code, 200)
            body = r.get_json()
            self.assertEqual(body["total_alerts"], 1)
            self.assertIn("verdict_totals", body)
            self.assertIn("top_rules", body)
        finally:
            cfg.TRIAGE_LOG_PATH = orig
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
