"""Regression tests for the triage-stats divergence and the "unknown" verdict.

THE BUG CLASS THIS EXISTS TO KILL
Two widgets on the dashboard disagreed: "Total alerts triaged" read 0 while
"Verdict mix" showed 3 alerts as "unknown". Two independent causes:

1. `result.get("verdict", "unknown")` turned a MISSING verdict into a
   plausible-looking category, so a pipeline failure rendered as a legitimate
   analytical result rather than an error.
2. Nothing enforced `submit_verdict`'s `enum: [true_positive, false_positive,
   escalate]`. The model could emit any string. Because needs_human_review
   escalates only on `verdict == "escalate"`, an invalid verdict with high
   confidence and close_no_action AUTO-CLOSED the alert.

The invariant these tests pin: `total_alerts == len(entries)`, always, and
`verdicted + failed == total`, always. If any consumer can recount or refilter
the log independently, those break.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")


def _entry(verdict, *, confidence=0.9, needs_review=False, alert_id="A1", error=None):
    result = {
        "verdict": verdict,
        "confidence": confidence,
        "recommended_action": "close_no_action",
        "rationale": "r",
        "evidence_used": [],
    }
    if error is not None:
        result["verdict_error"] = error
    return {
        "alert": {"alert_id": alert_id},
        "result": result,
        "rule_matches": [],
        "needs_human_review": needs_review,
        "siem_provider": {"id": "p1", "name": "Mock SIEM", "platform": "mock"},
    }


def _write(entries):
    d = tempfile.mkdtemp(prefix="triage-stats-")
    p = Path(d) / "triage_log.jsonl"
    p.write_text("\n".join(json.dumps(e, default=str) for e in entries) + "\n", encoding="utf-8")
    return str(p)


class TestTriageStatsSingleSource(unittest.TestCase):
    def _stats(self, entries):
        import metrics

        return metrics.get_triage_stats(log_path=_write(entries), feedback_path="/nonexistent")

    def test_total_always_equals_the_number_of_log_entries(self):
        """The exact bug. Every widget reads this one number."""
        entries = [_entry("true_positive"), _entry("false_positive"), _entry("escalate")]
        self.assertEqual(self._stats(entries)["total_alerts"], len(entries))

    def test_total_includes_failed_entries_because_they_were_still_triaged(self):
        entries = [_entry("true_positive"), _entry(None, error="llm timeout"), _entry("escalate")]
        s = self._stats(entries)
        self.assertEqual(s["total_alerts"], 3, "a failed triage is still a triaged alert")
        self.assertEqual(s["verdicted"], 2)
        self.assertEqual(s["failed_verdicts"]["count"], 1)

    def test_verdicted_plus_failed_always_equals_total(self):
        for entries in (
            [],
            [_entry("escalate")],
            [_entry(None, error="boom")],
            [_entry("true_positive"), _entry(None), _entry("escalate")],
            [_entry("nonsense"), _entry(None), _entry("false_positive")],
        ):
            with self.subTest(n=len(entries)):
                s = self._stats(entries)
                self.assertEqual(
                    s["verdicted"] + s["failed_verdicts"]["count"],
                    s["total_alerts"],
                    "verdicted + failed must reconcile with total",
                )

    def test_verdict_mix_never_contains_a_failed_entry(self):
        entries = [_entry("true_positive"), _entry(None, error="timeout"), _entry("escalate")]
        totals = self._stats(entries)["verdict_totals"]
        self.assertEqual(totals, {"true_positive": 1, "escalate": 1})
        for bad in ("unknown", "failed", "none", "None"):
            self.assertNotIn(bad, totals)

    def test_an_invalid_verdict_is_a_failure_not_a_category(self):
        """The "3 unknown" symptom, from both directions."""
        for bogus in ("unknown", "", "maybe", "TRUE_POSITIVE", None):
            with self.subTest(repr(bogus)):
                s = self._stats([_entry(bogus), _entry("escalate")])
                self.assertEqual(s["failed_verdicts"]["count"], 1, bogus)
                self.assertNotIn("unknown", s["verdict_totals"])

    def test_a_missing_verdict_with_no_recorded_error_still_fails_loudly(self):
        e = _entry("true_positive")
        del e["result"]["verdict"]
        s = self._stats([e])
        self.assertEqual(s["failed_verdicts"]["count"], 1)
        self.assertIn("no verdict recorded", s["failed_verdicts"]["entries"][0]["reason"])

    def test_a_recorded_verdict_error_is_the_reported_reason(self):
        s = self._stats([_entry(None, error="anthropic 429 rate limited")])
        self.assertEqual(s["failed_verdicts"]["entries"][0]["reason"], "anthropic 429 rate limited")

    def test_the_failure_reason_names_the_bad_value(self):
        s = self._stats([_entry("unknown")])
        self.assertIn("'unknown'", s["failed_verdicts"]["entries"][0]["reason"])

    def test_percentages_are_over_verdicted_entries_only(self):
        """So a broken pipeline can never read as '100% unknown'."""
        entries = [_entry("true_positive"), _entry("true_positive"), _entry(None, error="x")]
        s = self._stats(entries)
        pct = s["verdict_mix_pct"]
        self.assertAlmostEqual(pct["true_positive"], 1.0)
        self.assertAlmostEqual(sum(pct.values()), 1.0)

    def test_percentages_are_empty_when_nothing_verdicted(self):
        s = self._stats([_entry(None, error="x")])
        self.assertEqual(s["verdict_mix_pct"], {})
        self.assertEqual(s["verdict_totals"], {})

    def test_every_widget_is_a_projection_of_the_same_read(self):
        """One read: changing the file changes every number together."""
        entries = [_entry("true_positive", confidence=0.95), _entry("escalate", confidence=0.2)]
        s = self._stats(entries)
        day_counts = sum(sum(d.values()) for d in s["verdict_by_day"].values())
        self.assertEqual(day_counts, s["verdicted"])
        self.assertEqual(sum(s["verdict_totals"].values()), s["verdicted"])
        self.assertEqual(sum(s["confidence_distribution"].values()), len(entries))
        self.assertEqual(sum(p["count"] for p in s["by_provider"].values()), s["total_alerts"])

    def test_by_day_excludes_failed_entries(self):
        e = _entry(None, error="x")
        e["ts"] = 1790000000
        ok = _entry("escalate")
        ok["ts"] = 1790000000
        s = self._stats([e, ok])
        for counts in s["verdict_by_day"].values():
            self.assertNotIn("failed", counts)
            self.assertNotIn("unknown", counts)
        self.assertEqual(sum(sum(d.values()) for d in s["verdict_by_day"].values()), 1)

    def test_failed_entries_carry_the_alert_id_for_linking(self):
        s = self._stats([_entry(None, alert_id="WKS-9", error="timeout")])
        self.assertEqual(s["failed_verdicts"]["entries"][0]["alert_id"], "WKS-9")

    def test_a_corrupt_line_does_not_crash_the_whole_read(self):
        d = tempfile.mkdtemp(prefix="triage-corrupt-")
        p = Path(d) / "triage_log.jsonl"
        p.write_text(
            json.dumps(_entry("escalate"))
            + "\n{not json\n"
            + json.dumps(_entry("escalate"))
            + "\n",
            encoding="utf-8",
        )
        import metrics

        s = metrics.get_triage_stats(log_path=str(p), feedback_path="/nonexistent")
        self.assertGreaterEqual(s["total_alerts"], 2)


class TestVerdictEnumIsEnforced(unittest.TestCase):
    """The model could emit any string; an invalid one auto-closed the alert."""

    def _triage_with(self, verdict_value):
        import shutil
        import tempfile as tf

        from agent.triage_agent import TriageAgent
        from config import cfg
        from llm.base import LLMResponse, ToolCall

        d = tf.mkdtemp(prefix="verdict-enum-")
        orig = cfg.CHROMA_DB_PATH
        cfg.CHROMA_DB_PATH = d
        try:

            class OneShotLLM:
                def chat(self, *, system, messages, tools, max_tokens):
                    return LLMResponse(
                        content="",
                        tool_calls=[
                            ToolCall(
                                id="c1",
                                name="submit_verdict",
                                input={
                                    "verdict": verdict_value,
                                    "confidence": 0.99,
                                    "recommended_action": "close_no_action",
                                    "rationale": "looks benign",
                                    "evidence_used": [],
                                },
                            )
                        ],
                    )

            agent = TriageAgent(provider="mock")
            agent.llm = OneShotLLM()
            return agent.triage({"alert_id": "A1", "rule_name": "x"})
        finally:
            cfg.CHROMA_DB_PATH = orig
            shutil.rmtree(d, ignore_errors=True)

    def test_an_invalid_verdict_is_forced_to_escalate(self):
        result = self._triage_with("unknown")
        self.assertEqual(result.verdict, "escalate")
        self.assertNotEqual(result.recommended_action, "close_no_action")

    def test_the_failure_is_recorded_with_its_reason(self):
        result = self._triage_with("unknown")
        self.assertIn("'unknown'", result.verdict_error)
        self.assertIn("forced to escalate", result.rationale)

    def test_an_invalid_verdict_can_never_auto_close(self):
        """needs_human_review escalates only on verdict == 'escalate'."""
        from agent.triage_agent import human_review_reasons, needs_human_review

        result = self._triage_with("unknown")
        self.assertTrue(needs_human_review(result))
        self.assertTrue(any("escalate" in r for r in human_review_reasons(result)))

    def test_confidence_is_capped_so_it_cannot_clear_the_threshold(self):
        result = self._triage_with("nonsense")
        self.assertLess(result.confidence, 0.9)

    def test_a_valid_verdict_is_untouched(self):
        result = self._triage_with("false_positive")
        self.assertEqual(result.verdict, "false_positive")
        self.assertEqual(result.verdict_error, "")


class TestTriageFailuresAreLogged(unittest.TestCase):
    """dashboard.py used to `continue` past a raised triage without writing
    anything, so a run where every alert failed looked like a clean run."""

    def test_the_writer_appends_one_line_per_entry(self):
        import dashboard

        d = tempfile.mkdtemp(prefix="triage-write-")
        p = Path(d) / "triage_log.jsonl"
        import config

        old = config.cfg.TRIAGE_LOG_PATH
        config.cfg.TRIAGE_LOG_PATH = str(p)
        try:
            dashboard._write_triage_entry({"alert": {"alert_id": "A"}, "result": {}})
            dashboard._write_triage_entry({"alert": {"alert_id": "B"}, "result": {}})
            lines = [x for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[1])["alert"]["alert_id"], "B")
        finally:
            config.cfg.TRIAGE_LOG_PATH = old

    def test_a_failure_entry_is_reported_as_failed_by_the_stats(self):
        import config
        import dashboard
        import metrics

        d = tempfile.mkdtemp(prefix="triage-fail-")
        p = Path(d) / "triage_log.jsonl"
        old = config.cfg.TRIAGE_LOG_PATH
        config.cfg.TRIAGE_LOG_PATH = str(p)
        try:
            dashboard._write_triage_entry(
                {
                    "alert": {"alert_id": "WKS-1"},
                    "result": {"verdict": None, "verdict_error": "LLMError: timeout"},
                    "rule_matches": [],
                    "needs_human_review": True,
                }
            )
            s = metrics.get_triage_stats(log_path=str(p), feedback_path="/nonexistent")
            self.assertEqual(s["total_alerts"], 1)
            self.assertEqual(s["failed_verdicts"]["count"], 1)
            self.assertIn("timeout", s["failed_verdicts"]["entries"][0]["reason"])
        finally:
            config.cfg.TRIAGE_LOG_PATH = old


class TestEmptyStateCopyIsSpecific(unittest.TestCase):
    """A blank chart canvas reads as 'loaded, and the answer is nothing'."""

    def setUp(self):
        self.html = (Path(__file__).resolve().parents[1] / "templates" / "index.html").read_text(
            encoding="utf-8"
        )
        self.js = max(
            re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", self.html, re.S), key=len
        )

    def test_no_generic_no_data_copy_survives(self):
        for generic in ("No data logged yet", "No data yet"):
            self.assertFalse(generic in self.html, generic)

    def test_each_chart_card_has_its_own_specific_message(self):
        for title in (
            "No verdicts to plot yet",
            "No confidence scores yet",
            "No triggered rules recorded",
            "No alerts triaged yet",
        ):
            self.assertTrue(title in self.js, title)

    def test_the_empty_state_names_the_command_that_fills_it(self):
        self.assertTrue("main.py demo" in self.js)
        self.assertTrue("Overnight Watcher" in self.js)

    def test_the_empty_state_offers_a_way_to_get_there(self):
        """An empty state with no next step is just a slower blank box."""
        self.assertTrue("empty-act" in self.html)
        # The onclick attribute is built inside a single-quoted JS string, so
        # the quotes are escaped in source. Match the view name inside the call
        # rather than the exact escaping, so re-quoting the literal does not
        # fail this test.
        for view in ("watcher", "rule-builder"):
            self.assertTrue(
                re.search(rf"showView\([^)]*{re.escape(view)}[^)]*\)", self.js),
                f"empty state should link to the {view} view",
            )

    def test_charts_hide_rather_than_render_an_empty_axis_frame(self):
        self.assertIn("hideChart", self.js)
        self.assertIn('showChart("chart-verdicts-by-day")', self.js)

    def test_the_failed_callout_exists_and_is_hidden_when_clean(self):
        self.assertIn('id="failed-verdicts"', self.html)
        self.assertIn("failed to get a verdict", self.js)
        self.assertIn("excluded from the verdict mix", self.js)

    def test_verdict_mix_marks_the_excluded_failures(self):
        self.assertIn("failed (excluded)", self.js)

    def test_no_verdict_colour_is_defined_for_unknown(self):
        """There is no such category any more."""
        self.assertNotIn('unknown: "#', self.js)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
