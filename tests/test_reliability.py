"""
Phase 2 reliability regressions: every writer honors its configured log
path (readers and writers can no longer drift apart), the audit + engineer
logs are rotated, and secrets are redacted centrally in the audit trail.

Run: python -m unittest tests.test_reliability -v
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

from config import cfg  # noqa: E402


class _TmpCfg(unittest.TestCase):
    KEYS: tuple[str, ...] = ()

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="reliability-"))
        self._orig = {k: getattr(cfg, k) for k in self.KEYS}

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(cfg, k, v)
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)


class TestConfiguredLogPaths(_TmpCfg):
    KEYS = ("TRIAGE_LOG_PATH", "CHAT_LOG_PATH", "ENGINEER_LOG_PATH")

    def test_main_writes_where_metrics_reads(self):
        import main
        import metrics
        from agent.triage_agent import TriageResult

        cfg.TRIAGE_LOG_PATH = str(self.dir / "custom_triage.jsonl")

        class FakeAgent:
            def __init__(self, *a, **k):
                pass

            def triage(self, alert):
                return TriageResult(
                    verdict="true_positive",
                    confidence=0.95,
                    recommended_action="monitor",
                    rationale="",
                    evidence_used=[],
                )

        with (
            mock.patch.object(main, "TriageAgent", FakeAgent),
            mock.patch("rules.evaluate_all", return_value=[]),
        ):
            main._run_batch([{"alert_id": "A1", "rule_name": "x"}])
        self.assertTrue(Path(cfg.TRIAGE_LOG_PATH).exists())
        self.assertFalse(
            Path("data/triage_log.jsonl").resolve() == Path(cfg.TRIAGE_LOG_PATH).resolve()
        )
        self.assertEqual(metrics.compute_metrics()["total_alerts"], 1)

    def test_feedback_cli_reads_configured_path(self):
        import feedback_cli

        cfg.TRIAGE_LOG_PATH = str(self.dir / "t.jsonl")
        self.assertEqual(feedback_cli._triage_log_path(), Path(cfg.TRIAGE_LOG_PATH))

    def test_dashboard_paths_follow_config(self):
        import dashboard

        cfg.TRIAGE_LOG_PATH = str(self.dir / "a.jsonl")
        cfg.CHAT_LOG_PATH = str(self.dir / "b.jsonl")
        cfg.ENGINEER_LOG_PATH = str(self.dir / "c.jsonl")
        self.assertEqual(dashboard._triage_log_path(), Path(cfg.TRIAGE_LOG_PATH))
        self.assertEqual(dashboard._chat_log_path(), Path(cfg.CHAT_LOG_PATH))
        self.assertEqual(dashboard._engineer_log_path(), Path(cfg.ENGINEER_LOG_PATH))


class TestRotationCoverage(unittest.TestCase):
    def test_audit_and_engineer_logs_are_managed(self):
        import log_rotation

        self.assertIn("AUDIT_LOG_PATH", log_rotation.LOG_PATHS_TO_MANAGE)
        self.assertIn("ENGINEER_LOG_PATH", log_rotation.LOG_PATHS_TO_MANAGE)

    def test_every_managed_key_exists_in_config(self):
        import log_rotation

        for key in log_rotation.LOG_PATHS_TO_MANAGE:
            self.assertTrue(getattr(cfg, key, None), key)


class TestCentralRedaction(_TmpCfg):
    KEYS = ("AUDIT_LOG_PATH",)

    def test_secret_keys_are_masked(self):
        import audit

        out = audit.redact_secrets(
            {
                "user": "bob",
                "password": "hunter2",
                "api_key": "sk-1",
                "nested": {"client_secret": "zzz", "Authorization": "Bearer abcdefghij"},
            }
        )
        self.assertEqual(out["user"], "bob")
        for v in (
            out["password"],
            out["api_key"],
            out["nested"]["client_secret"],
            out["nested"]["Authorization"],
        ):
            self.assertEqual(v, audit.REDACTED)

    def test_secret_shaped_strings_are_masked(self):
        import audit

        out = audit.redact_secrets(
            {"msg": "curl -H 'Authorization: Bearer abcdefghijklmn' url?token=xyz123 ok"}
        )
        self.assertNotIn("abcdefghijklmn", out["msg"])
        self.assertNotIn("xyz123", out["msg"])
        self.assertIn("ok", out["msg"])

    def test_numeric_telemetry_is_not_masked(self):
        import audit

        self.assertEqual(
            audit.redact_secrets({"tokens_used": 5, "max_tokens": 10}),
            {"tokens_used": 5, "max_tokens": 10},
        )

    def test_input_is_not_mutated(self):
        import audit

        src = {"password": "hunter2"}
        audit.redact_secrets(src)
        self.assertEqual(src["password"], "hunter2")

    def test_audit_file_never_contains_the_secret(self):
        import audit

        cfg.AUDIT_LOG_PATH = str(self.dir / "audit.jsonl")
        audit.audit_log(
            tool="t",
            params={"password": "hunter2", "host": "h"},
            result={"headers": {"Authorization": "Bearer supersecretvalue"}},
        )
        text = Path(cfg.AUDIT_LOG_PATH).read_text()
        self.assertNotIn("hunter2", text)
        self.assertNotIn("supersecretvalue", text)
        self.assertIn('"host": "h"', text)

    def test_oversized_result_stays_valid_json(self):
        import audit

        out = audit._safe({"blob": "x" * 20000})
        self.assertTrue(out["truncated"])
        json.dumps(out)


if __name__ == "__main__":
    unittest.main()
