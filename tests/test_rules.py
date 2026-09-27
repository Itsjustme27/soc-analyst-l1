"""
Offline tests for rules.py (alert rules engine) and the /api/rules dashboard
routes. Runs with MOCK_MODE only - no API keys, no network.

Run: cd soc-analyst-l1 && python -m unittest tests.test_rules -v
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)

SAMPLE_ALERT = {
    "alert_id": "SPLK-10231",
    "rule_name": "Brute Force - Multiple Auth Failures Then Success",
    "severity": "high",
    "description": "12 failed logins then success",
    "user": "jsmith",
    "src_ip": "185.220.101.7",
    "host": None,
    "raw_fields": {"failed_count": 12, "mfa_satisfied": False},
}


class TestConditionEvaluationOffline(unittest.TestCase):
    """Unit tests for evaluate_condition/evaluate_match - no files touched."""

    def test_eq_top_level_field(self):
        import rules

        self.assertTrue(
            rules.evaluate_condition(
                {"field": "severity", "op": "eq", "value": "high"}, SAMPLE_ALERT
            )
        )
        self.assertFalse(
            rules.evaluate_condition(
                {"field": "severity", "op": "eq", "value": "low"}, SAMPLE_ALERT
            )
        )

    def test_raw_fields_fallback(self):
        import rules

        # "mfa_satisfied" isn't a top-level key - should fall back into raw_fields.
        self.assertTrue(
            rules.evaluate_condition(
                {"field": "mfa_satisfied", "op": "eq", "value": False}, SAMPLE_ALERT
            )
        )

    def test_dotted_path(self):
        import rules

        self.assertEqual(rules._get_field(SAMPLE_ALERT, "raw_fields.failed_count"), 12)

    def test_in_and_not_in(self):
        import rules

        self.assertTrue(
            rules.evaluate_condition(
                {"field": "severity", "op": "in", "value": ["high", "critical"]}, SAMPLE_ALERT
            )
        )
        self.assertFalse(
            rules.evaluate_condition(
                {"field": "severity", "op": "not_in", "value": ["high", "critical"]}, SAMPLE_ALERT
            )
        )

    def test_contains(self):
        import rules

        self.assertTrue(
            rules.evaluate_condition(
                {"field": "description", "op": "contains", "value": "failed"}, SAMPLE_ALERT
            )
        )
        self.assertFalse(
            rules.evaluate_condition(
                {"field": "description", "op": "contains", "value": "ransomware"}, SAMPLE_ALERT
            )
        )

    def test_gt_gte_lt_lte(self):
        import rules

        self.assertTrue(
            rules.evaluate_condition(
                {"field": "raw_fields.failed_count", "op": "gte", "value": 12}, SAMPLE_ALERT
            )
        )
        self.assertFalse(
            rules.evaluate_condition(
                {"field": "raw_fields.failed_count", "op": "gt", "value": 12}, SAMPLE_ALERT
            )
        )
        self.assertTrue(
            rules.evaluate_condition(
                {"field": "raw_fields.failed_count", "op": "lte", "value": 12}, SAMPLE_ALERT
            )
        )

    def test_exists_not_exists(self):
        import rules

        self.assertTrue(rules.evaluate_condition({"field": "src_ip", "op": "exists"}, SAMPLE_ALERT))
        self.assertTrue(
            rules.evaluate_condition({"field": "host", "op": "not_exists"}, SAMPLE_ALERT)
        )  # host is None
        self.assertTrue(
            rules.evaluate_condition({"field": "detection_id", "op": "not_exists"}, SAMPLE_ALERT)
        )  # missing entirely

    def test_regex(self):
        import rules

        self.assertTrue(
            rules.evaluate_condition(
                {"field": "src_ip", "op": "regex", "value": r"^185\.220\."}, SAMPLE_ALERT
            )
        )
        self.assertFalse(
            rules.evaluate_condition(
                {"field": "src_ip", "op": "regex", "value": r"^10\."}, SAMPLE_ALERT
            )
        )

    def test_bad_regex_is_false_not_crash(self):
        import rules

        self.assertFalse(
            rules.evaluate_condition({"field": "src_ip", "op": "regex", "value": "["}, SAMPLE_ALERT)
        )

    def test_match_mode_all_vs_any(self):
        import rules

        conditions = [
            {"field": "severity", "op": "eq", "value": "high"},
            {"field": "severity", "op": "eq", "value": "critical"},
        ]
        self.assertFalse(
            rules.evaluate_match({"mode": "all", "conditions": conditions}, SAMPLE_ALERT)
        )
        self.assertTrue(
            rules.evaluate_match({"mode": "any", "conditions": conditions}, SAMPLE_ALERT)
        )

    def test_empty_conditions_always_match(self):
        import rules

        self.assertTrue(rules.evaluate_match({"mode": "all", "conditions": []}, SAMPLE_ALERT))

    def test_in_lookup(self):
        # evaluate_condition's in_lookup op intentionally always reads the
        # live configured lookup-tables file (same as the dashboard/chat
        # agent), not a caller-supplied path - so this test writes to the
        # real cfg.LOOKUP_TABLES_PATH, backing up and restoring its content
        # rather than trying to redirect it (mirrors how in_lookup is
        # actually used from a rule at runtime).
        import lookup_tables as lk
        import rules
        from config import cfg

        real_path = Path(cfg.LOOKUP_TABLES_PATH)
        backup = real_path.read_text() if real_path.exists() else None
        try:
            lk.create_lookup_table("test_known_bad_ips_rules")
            lk.upsert_lookup_entry(
                "test_known_bad_ips_rules", "185.220.101.7", {"reason": "scanner"}
            )
            self.assertTrue(
                rules.evaluate_condition(
                    {"field": "src_ip", "op": "in_lookup", "value": "test_known_bad_ips_rules"},
                    SAMPLE_ALERT,
                )
            )
            self.assertFalse(
                rules.evaluate_condition(
                    {"field": "user", "op": "in_lookup", "value": "test_known_bad_ips_rules"},
                    SAMPLE_ALERT,
                )
            )
        finally:
            if backup is None:
                real_path.unlink(missing_ok=True)
            else:
                real_path.write_text(backup)


class TestRuleCrudOffline(unittest.TestCase):
    """CRUD against a temp file - no Flask needed, same pattern as lookup tables tests."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.tmp.write("{}")
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_create_requires_name(self):
        import rules

        with self.assertRaises(rules.RuleError):
            rules.create_rule({"match": {"conditions": []}}, path=self.path)

    def test_create_rejects_unknown_op(self):
        import rules

        with self.assertRaises(rules.RuleError):
            rules.create_rule(
                {"name": "bad", "match": {"conditions": [{"field": "x", "op": "nonsense"}]}},
                path=self.path,
            )

    def test_create_and_read(self):
        import rules

        r = rules.create_rule(
            {
                "name": "Brute force",
                "match": {
                    "mode": "all",
                    "conditions": [{"field": "severity", "op": "eq", "value": "high"}],
                },
                "action": {"tag": "brute_force", "escalate": True},
            },
            path=self.path,
        )
        self.assertTrue(r["id"].startswith("rule-"))
        self.assertTrue(r["enabled"])
        got = rules.read_rule(r["id"], path=self.path)
        self.assertEqual(got["name"], "Brute force")
        self.assertTrue(got["action"]["escalate"])

    def test_list_rules_summary(self):
        import rules

        rules.create_rule({"name": "A", "match": {"conditions": []}}, path=self.path)
        rules.create_rule({"name": "B", "match": {"conditions": []}}, path=self.path)
        listed = rules.list_rules(path=self.path)
        self.assertEqual([r["name"] for r in listed], ["A", "B"])

    def test_update_partial(self):
        import rules

        r = rules.create_rule({"name": "orig", "match": {"conditions": []}}, path=self.path)
        updated = rules.update_rule(r["id"], {"enabled": False}, path=self.path)
        self.assertEqual(updated["name"], "orig")  # unchanged
        self.assertFalse(updated["enabled"])

    def test_update_missing_returns_none(self):
        import rules

        self.assertIsNone(
            rules.update_rule("rule-doesnotexist", {"enabled": False}, path=self.path)
        )

    def test_delete(self):
        import rules

        r = rules.create_rule({"name": "delme", "match": {"conditions": []}}, path=self.path)
        self.assertTrue(rules.delete_rule(r["id"], path=self.path))
        self.assertIsNone(rules.read_rule(r["id"], path=self.path))

    def test_delete_missing_returns_false(self):
        import rules

        self.assertFalse(rules.delete_rule("rule-nope", path=self.path))

    def test_validate_rule_public_wrapper(self):
        import rules

        valid = rules.validate_rule({"name": "x", "match": {"conditions": []}})
        self.assertEqual(valid["name"], "x")
        with self.assertRaises(rules.RuleError):
            rules.validate_rule({"match": {"conditions": []}})  # no name


class TestThresholdLogicOffline(unittest.TestCase):
    """Threshold/grouping counters - explicit `now`, no file I/O, deterministic."""

    def test_fires_once_count_reached(self):
        import rules

        rule = {
            "id": "rule-thr",
            "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
            "threshold": {"group_by": "src_ip", "window_minutes": 15, "count": 3},
            "action": {"escalate": True},
        }
        state = {}
        for i in range(3):
            result = rules.evaluate_rule(rule, SAMPLE_ALERT, state=state, now=1000.0 + i)
        self.assertTrue(result["matched"])
        self.assertTrue(result["threshold_met"])
        self.assertTrue(result["triggered"])
        self.assertEqual(result["count"], 3)

    def test_not_yet_at_threshold(self):
        import rules

        rule = {
            "id": "rule-thr2",
            "match": {"conditions": []},
            "threshold": {"group_by": "src_ip", "window_minutes": 15, "count": 5},
        }
        state = {}
        result = rules.evaluate_rule(rule, SAMPLE_ALERT, state=state, now=1000.0)
        self.assertTrue(result["matched"])
        self.assertFalse(result["threshold_met"])
        self.assertFalse(result["triggered"])
        self.assertEqual(result["count"], 1)

    def test_window_expiry_resets_count(self):
        import rules

        rule = {
            "id": "rule-thr3",
            "match": {"conditions": []},
            "threshold": {"group_by": "src_ip", "window_minutes": 1, "count": 2},
        }
        state = {}
        rules.evaluate_rule(rule, SAMPLE_ALERT, state=state, now=0.0)
        # Second event 5 minutes later - outside the 1-minute window, so the
        # first event should have been pruned and the count should be 1, not 2.
        result = rules.evaluate_rule(rule, SAMPLE_ALERT, state=state, now=300.0)
        self.assertEqual(result["count"], 1)
        self.assertFalse(result["triggered"])

    def test_no_match_no_threshold_touch(self):
        import rules

        rule = {
            "id": "rule-thr4",
            "match": {"conditions": [{"field": "severity", "op": "eq", "value": "critical"}]},
            "threshold": {"group_by": "src_ip", "window_minutes": 15, "count": 1},
        }
        state = {}
        result = rules.evaluate_rule(rule, SAMPLE_ALERT, state=state, now=1000.0)
        self.assertFalse(result["matched"])
        self.assertIsNone(result["threshold_met"])
        self.assertNotIn("rule-thr4", state)  # unmatched alerts never consume a threshold slot

    def test_dry_run_does_not_persist(self):
        import rules

        tmp_rules = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp_rules.write("{}")
        tmp_rules.close()
        tmp_state = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp_state.write("{}")
        tmp_state.close()
        try:
            rule = rules.create_rule(
                {
                    "name": "dry",
                    "match": {"conditions": []},
                    "threshold": {"group_by": "src_ip", "window_minutes": 15, "count": 1},
                },
                path=tmp_rules.name,
            )
            rules.evaluate_all(
                SAMPLE_ALERT, rules_path=tmp_rules.name, state_path=tmp_state.name, dry_run=True
            )
            # State file should still be empty - dry_run must not write it.
            self.assertEqual(rules._load_state(Path(tmp_state.name)), {})
            # A real (non-dry-run) call does persist.
            rules.evaluate_all(
                SAMPLE_ALERT, rules_path=tmp_rules.name, state_path=tmp_state.name, dry_run=False
            )
            self.assertIn(rule["id"], rules._load_state(Path(tmp_state.name)))
        finally:
            Path(tmp_rules.name).unlink(missing_ok=True)
            Path(tmp_state.name).unlink(missing_ok=True)


class TestEvaluateAllOffline(unittest.TestCase):
    """evaluate_all() end-to-end against temp rule/state files."""

    def setUp(self):
        self.tmp_rules = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.tmp_rules.write("{}")
        self.tmp_rules.close()
        self.tmp_state = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.tmp_state.write("{}")
        self.tmp_state.close()

    def tearDown(self):
        Path(self.tmp_rules.name).unlink(missing_ok=True)
        Path(self.tmp_state.name).unlink(missing_ok=True)

    def test_disabled_rule_is_skipped(self):
        import rules

        rules.create_rule(
            {"name": "off", "enabled": False, "match": {"conditions": []}}, path=self.tmp_rules.name
        )
        matches = rules.evaluate_all(
            SAMPLE_ALERT, rules_path=self.tmp_rules.name, state_path=self.tmp_state.name
        )
        self.assertEqual(matches, [])

    def test_unmatched_rule_excluded_from_results(self):
        import rules

        rules.create_rule(
            {
                "name": "never",
                "match": {"conditions": [{"field": "severity", "op": "eq", "value": "low"}]},
            },
            path=self.tmp_rules.name,
        )
        matches = rules.evaluate_all(
            SAMPLE_ALERT, rules_path=self.tmp_rules.name, state_path=self.tmp_state.name
        )
        self.assertEqual(matches, [])

    def test_matched_simple_rule_triggers_immediately(self):
        import rules

        rules.create_rule(
            {
                "name": "high sev",
                "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
                "action": {"tag": "high_sev", "escalate": True},
            },
            path=self.tmp_rules.name,
        )
        matches = rules.evaluate_all(
            SAMPLE_ALERT, rules_path=self.tmp_rules.name, state_path=self.tmp_state.name
        )
        self.assertEqual(len(matches), 1)
        self.assertTrue(matches[0]["triggered"])
        self.assertEqual(matches[0]["action"]["tag"], "high_sev")


class TestImportExportOffline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.tmp.write("{}")
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_export_strips_bookkeeping_fields(self):
        import rules

        rules.create_rule({"name": "A", "match": {"conditions": []}}, path=self.path)
        [exported] = rules.export_rules(path=self.path)
        self.assertEqual(set(exported.keys()), set(rules._PORTABLE_KEYS))
        self.assertNotIn("id", exported)
        self.assertNotIn("created", exported)
        self.assertNotIn("updated", exported)

    def test_export_specific_ids_only(self):
        import rules

        a = rules.create_rule({"name": "A", "match": {"conditions": []}}, path=self.path)
        rules.create_rule({"name": "B", "match": {"conditions": []}}, path=self.path)
        exported = rules.export_rules(rule_ids=[a["id"]], path=self.path)
        self.assertEqual([r["name"] for r in exported], ["A"])

    def test_import_creates_new_rules(self):
        import rules

        defs = [
            {"name": "Imported A", "match": {"conditions": []}},
            {"name": "Imported B", "match": {"conditions": []}},
        ]
        result = rules.import_rules(defs, path=self.path)
        self.assertEqual(set(result["created"]), {"Imported A", "Imported B"})
        self.assertEqual(result["updated"], [])
        self.assertEqual(result["skipped"], [])
        self.assertEqual(len(rules.list_rules(path=self.path)), 2)

    def test_import_skips_existing_name_by_default(self):
        import rules

        rules.create_rule(
            {"name": "Dup", "description": "original", "match": {"conditions": []}}, path=self.path
        )
        result = rules.import_rules(
            [{"name": "Dup", "description": "new", "match": {"conditions": []}}], path=self.path
        )
        self.assertEqual(result["skipped"], ["Dup"])
        self.assertEqual(result["created"], [])
        [rule] = rules.list_rules(path=self.path)
        self.assertEqual(rule["description"], "original")  # untouched

    def test_import_overwrite_updates_existing_name(self):
        import rules

        original = rules.create_rule(
            {"name": "Dup", "description": "original", "match": {"conditions": []}}, path=self.path
        )
        result = rules.import_rules(
            [{"name": "Dup", "description": "new", "match": {"conditions": []}}],
            on_conflict="overwrite",
            path=self.path,
        )
        self.assertEqual(result["updated"], ["Dup"])
        updated = rules.read_rule(original["id"], path=self.path)
        self.assertEqual(updated["description"], "new")
        self.assertEqual(updated["id"], original["id"])  # same rule, not a duplicate

    def test_import_bad_on_conflict_raises(self):
        import rules

        with self.assertRaises(rules.RuleError):
            rules.import_rules([], on_conflict="explode", path=self.path)

    def test_import_invalid_rule_reported_not_fatal(self):
        import rules

        defs = [
            {"name": "Good", "match": {"conditions": []}},
            {"match": {"conditions": []}},  # missing name - invalid
        ]
        result = rules.import_rules(defs, path=self.path)
        self.assertEqual(result["created"], ["Good"])
        self.assertEqual(len(result["errors"]), 1)

    def test_export_then_import_round_trips(self):
        import rules

        rules.create_rule(
            {
                "name": "Roundtrip",
                "description": "d",
                "match": {
                    "mode": "all",
                    "conditions": [{"field": "severity", "op": "eq", "value": "high"}],
                },
                "threshold": {"group_by": "src_ip", "window_minutes": 15, "count": 5},
                "action": {"tag": "t", "escalate": True, "notify": "#soc"},
            },
            path=self.path,
        )
        exported = rules.export_rules(path=self.path)

        fresh = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        fresh.write("{}")
        fresh.close()
        try:
            rules.import_rules(exported, path=fresh.name)
            [imported] = rules.list_rules(path=fresh.name)
            self.assertEqual(imported["name"], "Roundtrip")
            self.assertTrue(imported["has_threshold"])
            self.assertEqual(imported["action"]["tag"], "t")
        finally:
            Path(fresh.name).unlink(missing_ok=True)

    def test_import_from_file_bare_list(self):
        import rules

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump([{"name": "FromFile", "match": {"conditions": []}}], f)
        f.close()
        try:
            result = rules.import_rules_from_file(f.name, path=self.path)
            self.assertEqual(result["created"], ["FromFile"])
        finally:
            Path(f.name).unlink(missing_ok=True)

    def test_import_from_file_wrapped_dict(self):
        import rules

        f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        json.dump({"rules": [{"name": "FromWrappedFile", "match": {"conditions": []}}]}, f)
        f.close()
        try:
            result = rules.import_rules_from_file(f.name, path=self.path)
            self.assertEqual(result["created"], ["FromWrappedFile"])
        finally:
            Path(f.name).unlink(missing_ok=True)

    def test_seed_rules_file_imports_cleanly(self):
        import rules

        seed_file = BASE / "seed_data" / "rules" / "baseline_rules.json"
        result = rules.import_rules_from_file(seed_file, path=self.path)
        self.assertEqual(len(result["errors"]), 0)
        self.assertEqual(len(result["created"]), 3)


class TestBacktestOffline(unittest.TestCase):
    """backtest_rule() against a synthetic historical triage_log.jsonl."""

    def setUp(self):
        self.tmp_log = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        self.tmp_log.close()

    def tearDown(self):
        Path(self.tmp_log.name).unlink(missing_ok=True)

    def _write_log(self, entries):
        with open(self.tmp_log.name, "w") as f:
            for e in entries:
                f.write(json.dumps(e) + "\n")

    def test_missing_log_file_returns_zeroed_result_with_note(self):
        import rules

        Path(self.tmp_log.name).unlink()  # doesn't exist
        result = rules.backtest_rule(
            {"id": "x", "match": {"conditions": []}}, log_path=self.tmp_log.name
        )
        self.assertEqual(result["total_alerts"], 0)
        self.assertIn("note", result)

    def test_counts_matched_and_triggered_separately(self):
        import rules

        self._write_log(
            [
                {"alert": {**SAMPLE_ALERT, "alert_id": "A1"}},
                {"alert": {**SAMPLE_ALERT, "alert_id": "A2", "severity": "low"}},  # won't match
                {"alert": {**SAMPLE_ALERT, "alert_id": "A3"}},
            ]
        )
        rule = {
            "id": "rule-bt",
            "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
        }
        result = rules.backtest_rule(rule, log_path=self.tmp_log.name)
        self.assertEqual(result["total_alerts"], 3)
        self.assertEqual(result["matched"], 2)  # A1, A3
        self.assertEqual(result["triggered"], 2)  # no threshold - matched == triggered

    def test_threshold_rule_only_fires_after_enough_matches(self):
        import rules

        self._write_log([{"alert": {**SAMPLE_ALERT, "alert_id": f"A{i}"}} for i in range(1, 4)])
        rule = {
            "id": "rule-bt-thr",
            "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
            "threshold": {"group_by": "src_ip", "window_minutes": 60, "count": 3},
        }
        result = rules.backtest_rule(rule, log_path=self.tmp_log.name)
        self.assertEqual(result["matched"], 3)
        self.assertEqual(result["triggered"], 1)  # only the 3rd one reaches the threshold
        self.assertEqual(len(result["sample"]), 1)

    def test_limit_only_scans_most_recent_n_entries(self):
        import rules

        self._write_log([{"alert": {**SAMPLE_ALERT, "alert_id": f"A{i}"}} for i in range(1, 6)])
        rule = {"id": "rule-bt-lim", "match": {"conditions": []}}
        result = rules.backtest_rule(rule, log_path=self.tmp_log.name, limit=2)
        self.assertEqual(result["total_alerts"], 2)

    def test_non_triage_lines_are_skipped(self):
        import rules

        self._write_log(
            [
                {"message": "some chat log entry with no 'alert' field"},
                {"alert": {**SAMPLE_ALERT, "alert_id": "A1"}},
            ]
        )
        rule = {"id": "rule-bt-skip", "match": {"conditions": []}}
        result = rules.backtest_rule(rule, log_path=self.tmp_log.name)
        self.assertEqual(result["total_alerts"], 1)

    def test_real_state_file_never_touched(self):
        import rules

        self._write_log([{"alert": {**SAMPLE_ALERT, "alert_id": "A1"}}])
        tmp_state = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        tmp_state.write("{}")
        tmp_state.close()
        try:
            rule = {
                "id": "rule-bt-state",
                "match": {"conditions": []},
                "threshold": {"group_by": "src_ip", "window_minutes": 60, "count": 1},
            }
            rules.backtest_rule(rule, log_path=self.tmp_log.name)
            self.assertEqual(rules._load_state(Path(tmp_state.name)), {})
        finally:
            Path(tmp_state.name).unlink(missing_ok=True)


class TestRulesRoutesOffline(unittest.TestCase):
    """Flask test-client coverage for /api/rules*, same pattern as the
    lookup-tables route tests in test_dashboard_panels.py."""

    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()
        cls.tmp_rules = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        cls.tmp_rules.write("{}")
        cls.tmp_rules.close()
        cls.tmp_state = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        cls.tmp_state.write("{}")
        cls.tmp_state.close()
        cls.orig_rules_path = os.getenv("RULES_PATH", "")
        cls.orig_state_path = os.getenv("RULE_STATE_PATH", "")
        os.environ["RULES_PATH"] = cls.tmp_rules.name
        os.environ["RULE_STATE_PATH"] = cls.tmp_state.name

    @classmethod
    def tearDownClass(cls):
        Path(cls.tmp_rules.name).unlink(missing_ok=True)
        Path(cls.tmp_state.name).unlink(missing_ok=True)
        for key, orig in (
            ("RULES_PATH", cls.orig_rules_path),
            ("RULE_STATE_PATH", cls.orig_state_path),
        ):
            if orig:
                os.environ[key] = orig
            else:
                os.environ.pop(key, None)

    def test_ops_list(self):
        r = self.client.get("/api/rules/ops")
        self.assertEqual(r.status_code, 200)
        self.assertIn("in_lookup", r.get_json()["ops"])

    def test_list_empty(self):
        r = self.client.get("/api/rules")
        self.assertEqual(r.status_code, 200)
        self.assertIn("rules", r.get_json())

    def test_create_requires_name(self):
        r = self.client.post("/api/rules", json={"match": {"conditions": []}})
        self.assertEqual(r.status_code, 400)
        self.assertIn("error", r.get_json())

    def test_create_read_update_delete(self):
        r1 = self.client.post(
            "/api/rules",
            json={
                "name": "route-test-rule",
                "match": {
                    "mode": "all",
                    "conditions": [{"field": "severity", "op": "eq", "value": "high"}],
                },
                "action": {"tag": "t", "escalate": True},
            },
        )
        self.assertEqual(r1.status_code, 201)
        rule_id = r1.get_json()["rule"]["id"]

        r2 = self.client.get(f"/api/rules/{rule_id}")
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.get_json()["rule"]["name"], "route-test-rule")

        r3 = self.client.patch(f"/api/rules/{rule_id}", json={"enabled": False})
        self.assertEqual(r3.status_code, 200)
        self.assertFalse(r3.get_json()["rule"]["enabled"])

        r4 = self.client.delete(f"/api/rules/{rule_id}")
        self.assertEqual(r4.status_code, 200)

        r5 = self.client.get(f"/api/rules/{rule_id}")
        self.assertEqual(r5.status_code, 404)

    def test_read_missing_404(self):
        r = self.client.get("/api/rules/rule-doesnotexist")
        self.assertEqual(r.status_code, 404)

    def test_test_route_dry_run(self):
        r1 = self.client.post(
            "/api/rules",
            json={
                "name": "for-test-route",
                "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
            },
        )
        rule_id = r1.get_json()["rule"]["id"]
        r2 = self.client.post(f"/api/rules/{rule_id}/test", json={"alert": SAMPLE_ALERT})
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.get_json()["result"]["matched"])
        self.client.delete(f"/api/rules/{rule_id}")

    def test_test_route_requires_alert_object(self):
        r1 = self.client.post("/api/rules", json={"name": "x", "match": {"conditions": []}})
        rule_id = r1.get_json()["rule"]["id"]
        r2 = self.client.post(f"/api/rules/{rule_id}/test", json={})
        self.assertEqual(r2.status_code, 400)
        self.client.delete(f"/api/rules/{rule_id}")

    def test_preview_route_unsaved_draft(self):
        r = self.client.post(
            "/api/rules/preview",
            json={
                "rule": {
                    "name": "draft",
                    "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
                },
                "alert": SAMPLE_ALERT,
            },
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["result"]["matched"])

    def test_preview_route_bad_draft(self):
        r = self.client.post(
            "/api/rules/preview",
            json={"rule": {"match": {"conditions": []}}, "alert": SAMPLE_ALERT},
        )
        self.assertEqual(r.status_code, 400)

    def test_backtest_route(self):
        tmp_log = tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False)
        tmp_log.write(json.dumps({"alert": SAMPLE_ALERT}) + "\n")
        tmp_log.close()
        from config import cfg

        orig_triage_log = cfg.TRIAGE_LOG_PATH
        cfg.TRIAGE_LOG_PATH = tmp_log.name
        try:
            r1 = self.client.post(
                "/api/rules",
                json={
                    "name": "backtest-route-rule",
                    "match": {"conditions": [{"field": "severity", "op": "eq", "value": "high"}]},
                },
            )
            rule_id = r1.get_json()["rule"]["id"]
            r2 = self.client.post(f"/api/rules/{rule_id}/backtest", json={})
            self.assertEqual(r2.status_code, 200)
            body = r2.get_json()["result"]
            self.assertEqual(body["total_alerts"], 1)
            self.assertEqual(body["triggered"], 1)
            self.client.delete(f"/api/rules/{rule_id}")
        finally:
            Path(tmp_log.name).unlink(missing_ok=True)
            cfg.TRIAGE_LOG_PATH = orig_triage_log

    def test_backtest_route_missing_rule_404(self):
        r = self.client.post("/api/rules/rule-doesnotexist/backtest", json={})
        self.assertEqual(r.status_code, 404)

    def test_export_route(self):
        r1 = self.client.post(
            "/api/rules", json={"name": "export-route-rule", "match": {"conditions": []}}
        )
        rule_id = r1.get_json()["rule"]["id"]
        r2 = self.client.get("/api/rules/export")
        self.assertEqual(r2.status_code, 200)
        names = [r["name"] for r in r2.get_json()["rules"]]
        self.assertIn("export-route-rule", names)
        exported = next(r for r in r2.get_json()["rules"] if r["name"] == "export-route-rule")
        self.assertNotIn("id", exported)
        self.client.delete(f"/api/rules/{rule_id}")

    def test_export_route_filtered_by_id(self):
        r1 = self.client.post(
            "/api/rules", json={"name": "export-filter-A", "match": {"conditions": []}}
        )
        r2 = self.client.post(
            "/api/rules", json={"name": "export-filter-B", "match": {"conditions": []}}
        )
        id_a = r1.get_json()["rule"]["id"]
        id_b = r2.get_json()["rule"]["id"]
        r3 = self.client.get(f"/api/rules/export?id={id_a}")
        names = [r["name"] for r in r3.get_json()["rules"]]
        self.assertEqual(names, ["export-filter-A"])
        self.client.delete(f"/api/rules/{id_a}")
        self.client.delete(f"/api/rules/{id_b}")

    def test_import_route_requires_rules_list(self):
        r = self.client.post("/api/rules/import", json={"rules": "not-a-list"})
        self.assertEqual(r.status_code, 400)

    def test_import_route_creates_rules(self):
        r = self.client.post(
            "/api/rules/import",
            json={
                "rules": [{"name": "import-route-rule", "match": {"conditions": []}}],
            },
        )
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["created"], ["import-route-rule"])
        created = next(
            x
            for x in self.client.get("/api/rules").get_json()["rules"]
            if x["name"] == "import-route-rule"
        )
        self.client.delete(f"/api/rules/{created['id']}")

    def test_import_route_overwrite_flag(self):
        r1 = self.client.post(
            "/api/rules", json={"name": "import-overwrite-rule", "match": {"conditions": []}}
        )
        rule_id = r1.get_json()["rule"]["id"]
        r2 = self.client.post(
            "/api/rules/import",
            json={
                "rules": [
                    {
                        "name": "import-overwrite-rule",
                        "description": "updated",
                        "match": {"conditions": []},
                    }
                ],
                "overwrite": True,
            },
        )
        self.assertEqual(r2.get_json()["updated"], ["import-overwrite-rule"])
        self.assertEqual(
            self.client.get(f"/api/rules/{rule_id}").get_json()["rule"]["description"], "updated"
        )
        self.client.delete(f"/api/rules/{rule_id}")


if __name__ == "__main__":
    unittest.main()
