"""
Offline tests for analyst-identity tracking: MemoryStore.capture_feedback's
"analyst" field, approve_and_store_lesson's "approved_by" metadata, and
feedback_cli.py's --analyst / ANALYST_NAME / prompt resolution order.

Uses the offline hashing embedding (MOCK_MODE) so no network/model download
is needed - same approach as tests/test_triage_agent.py's end-to-end tests.

Run: python -m unittest tests.test_analyst_identity -v
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)


class TestCaptureFeedbackAnalystField(unittest.TestCase):
    def setUp(self):
        from config import cfg

        self._orig_chroma = cfg.CHROMA_DB_PATH
        self._orig_feedback = cfg.FEEDBACK_LOG_PATH
        self.tmp_chroma = tempfile.mkdtemp(prefix="mem-test-")
        self.tmp_feedback = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        self.tmp_feedback.close()
        cfg.CHROMA_DB_PATH = self.tmp_chroma
        cfg.FEEDBACK_LOG_PATH = self.tmp_feedback.name

    def tearDown(self):
        from config import cfg

        cfg.CHROMA_DB_PATH = self._orig_chroma
        cfg.FEEDBACK_LOG_PATH = self._orig_feedback
        shutil.rmtree(self.tmp_chroma, ignore_errors=True)
        Path(self.tmp_feedback.name).unlink(missing_ok=True)

    def _last_feedback_record(self) -> dict:
        lines = Path(self.tmp_feedback.name).read_text().strip().splitlines()
        return json.loads(lines[-1])

    def test_analyst_name_is_recorded(self):
        from agent.memory import MemoryStore

        store = MemoryStore()
        store.capture_feedback(
            "case-1",
            {"alert_id": "A1"},
            {"verdict": "escalate"},
            "true_positive",
            "confirmed after checking host history",
            analyst="jsmith",
        )
        record = self._last_feedback_record()
        self.assertEqual(record["analyst"], "jsmith")

    def test_analyst_defaults_to_empty_string(self):
        from agent.memory import MemoryStore

        store = MemoryStore()
        store.capture_feedback(
            "case-2",
            {"alert_id": "A2"},
            {"verdict": "true_positive"},
            "true_positive",
            "confirmed",  # no analyst kwarg - backward compatible
        )
        record = self._last_feedback_record()
        self.assertEqual(record["analyst"], "")

    def test_agreed_field_still_computed_correctly(self):
        from agent.memory import MemoryStore

        store = MemoryStore()
        store.capture_feedback(
            "case-3",
            {"alert_id": "A3"},
            {"verdict": "escalate"},
            "false_positive",
            "actually benign",
            analyst="asmith",
        )
        record = self._last_feedback_record()
        self.assertFalse(record["agreed"])


class TestApproveLessonApprovedBy(unittest.TestCase):
    def setUp(self):
        from config import cfg

        self._orig_chroma = cfg.CHROMA_DB_PATH
        self.tmp_chroma = tempfile.mkdtemp(prefix="mem-test-")
        cfg.CHROMA_DB_PATH = self.tmp_chroma

    def tearDown(self):
        from config import cfg

        cfg.CHROMA_DB_PATH = self._orig_chroma
        shutil.rmtree(self.tmp_chroma, ignore_errors=True)

    def test_approved_by_is_stored_in_lesson_metadata(self):
        from agent.memory import MemoryStore

        store = MemoryStore()
        store.approve_and_store_lesson(
            "Alerts from rule X on subnet Y are consistently false positive.",
            {"supporting_case_ids": "[]"},
            approved_by="jsmith",
        )
        results = store.kb.query("lessons", "rule X subnet Y")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["metadata"]["approved_by"], "jsmith")

    def test_no_approved_by_leaves_metadata_untouched(self):
        from agent.memory import MemoryStore

        store = MemoryStore()
        store.approve_and_store_lesson(
            "Some other lesson text entirely.",
            {"supporting_case_ids": "[]"},
        )
        results = store.kb.query("lessons", "other lesson text entirely")
        self.assertNotIn("approved_by", results[0]["metadata"])


class TestResolveAnalyst(unittest.TestCase):
    def test_cli_value_wins(self):
        import feedback_cli

        with mock.patch.dict(os.environ, {"ANALYST_NAME": "env-name"}):
            self.assertEqual(feedback_cli._resolve_analyst("cli-name"), "cli-name")

    def test_falls_back_to_env_var(self):
        import feedback_cli

        with mock.patch.dict(os.environ, {"ANALYST_NAME": "env-name"}):
            self.assertEqual(feedback_cli._resolve_analyst(None), "env-name")

    def test_falls_back_to_empty_when_not_a_tty_and_nothing_set(self):
        import feedback_cli

        env = {k: v for k, v in os.environ.items() if k != "ANALYST_NAME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.stdin.isatty", return_value=False),
        ):
            self.assertEqual(feedback_cli._resolve_analyst(None), "")

    def test_prompts_when_tty_and_nothing_else_set(self):
        import feedback_cli

        env = {k: v for k, v in os.environ.items() if k != "ANALYST_NAME"}
        with (
            mock.patch.dict(os.environ, env, clear=True),
            mock.patch("sys.stdin.isatty", return_value=True),
            mock.patch("builtins.input", return_value="typed-name"),
        ):
            self.assertEqual(feedback_cli._resolve_analyst(None), "typed-name")


if __name__ == "__main__":
    unittest.main()
