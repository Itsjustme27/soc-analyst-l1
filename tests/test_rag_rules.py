"""
Offline tests for the wazuh-rules RAG snapshot: rule doc rendering, the shared
ingestor (paginated pull, idempotent upsert, stale pruning, caps), the
ingest_wazuh_rules tool, and its registry wiring. Real chroma on a tmp path,
fully offline via the hashing embedding (MOCK_MODE).

Run: cd soc-agent && MOCK_MODE=true python3 -m unittest tests.test_rag_rules -v
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")


def _rule(
    rid,
    level=5,
    groups=("syslog", "sshd"),
    filename="local_rules.xml",
    status="enabled",
    mitre=None,
    details=None,
    desc=None,
):
    return {
        "id": rid,
        "level": level,
        "description": desc or f"rule {rid}",
        "groups": list(groups),
        "mitre": mitre or [],
        "filename": filename,
        "status": status,
        "details": details or {},
    }


class FakeManagerRulesAPI:
    """Paginated /rules endpoint with the exact API response shape."""

    def __init__(self, rules):
        self.rules = rules
        self.calls = []

    def get_rules(
        self,
        limit=50,
        offset=0,
        search=None,
        group=None,
        filename=None,
        level=None,
        status=None,
        sort=None,
        q=None,
    ):
        self.calls.append(
            {
                "limit": limit,
                "offset": offset,
                "search": search,
                "group": group,
                "filename": filename,
            }
        )
        batch = self.rules[offset : offset + limit]
        return {
            "data": {
                "affected_items": batch,
                "total_affected_items": len(self.rules),
            }
        }


class FakeKB:
    """Records upserts; enough for tests that exercise pagination math only."""

    def __init__(self):
        self.added: list[str] = []
        self.deleted: list[str] = []

    def add(self, collection, text, metadata, doc_id=None):
        self.added.append(doc_id)

    def get(self, collection, where=None):
        return []

    def delete(self, collection, ids):
        self.deleted.extend(ids)
        return len(ids)


class KbTestCase(unittest.TestCase):
    """Real, offline chroma on a temp path."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rag-rules-test-")
        from config import cfg

        self._orig = cfg.CHROMA_DB_PATH
        cfg.CHROMA_DB_PATH = self.tmp

    def tearDown(self):
        from config import cfg

        cfg.CHROMA_DB_PATH = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _kb(self):
        from rag.knowledge_base import KnowledgeBase

        return KnowledgeBase()


class TestBuildRuleDoc(unittest.TestCase):
    def test_renders_core_fields(self):
        from rag.rules_ingest import build_rule_doc

        doc = build_rule_doc(
            _rule(
                100002,
                level=7,
                mitre=[{"id": "T1110", "name": "Brute Force"}],
                details={"frequency": 12, "if_matched_sid": 5701},
                desc="sshd: brute force detected",
            )
        )
        self.assertIn("Wazuh rule 100002 (level 7) - enabled", doc)
        self.assertIn("File: local_rules.xml", doc)
        self.assertIn("Groups: syslog, sshd", doc)
        self.assertIn("T1110 (Brute Force)", doc)
        self.assertIn("Description: sshd: brute force detected", doc)
        self.assertIn("frequency=12", doc)
        self.assertIn("if_matched_sid=5701", doc)

    def test_skips_empty_sections(self):
        from rag.rules_ingest import build_rule_doc

        doc = build_rule_doc(_rule(9, groups=[], mitre=[], details={}))
        self.assertIn("Wazuh rule 9", doc)
        self.assertNotIn("Groups:", doc)
        self.assertNotIn("MITRE:", doc)
        self.assertNotIn("Details:", doc)

    def test_mitre_variants(self):
        from rag.rules_ingest import _fmt_mitre

        self.assertEqual(
            _fmt_mitre([{"id": "T1059", "name": "Cmd and Scripting"}]), "T1059 (Cmd and Scripting)"
        )
        self.assertEqual(_fmt_mitre([{"technique": "T1190", "technique_name": "X"}]), "T1190 (X)")
        self.assertEqual(_fmt_mitre([{"id": "T1190"}]), "T1190")
        self.assertEqual(_fmt_mitre(["T1110"]), "T1110")
        self.assertEqual(_fmt_mitre(None), "")


class TestIngestRules(KbTestCase):
    def test_defaults_to_local_rules_and_upserts_by_rule_id(self):
        from rag.rules_ingest import ingest_wazuh_rules

        api = FakeManagerRulesAPI([_rule(100001), _rule(100002), _rule(100003)])
        kb = self._kb()
        out = ingest_wazuh_rules(api, kb)
        self.assertEqual(api.calls[0]["filename"], "local_rules.xml")
        self.assertEqual(out["rules_pulled"], 3)
        self.assertEqual(out["rules_stored"], 3)
        self.assertEqual(out["rules_pruned"], 0)
        self.assertFalse(out["truncated"])
        self.assertEqual(kb.counts()["wazuh_docs"], 3)
        rows = kb.query("wazuh_docs", "brute force sshd")
        self.assertEqual(
            {r["id"] for r in rows}, {"wazuh_rule_100001", "wazuh_rule_100002", "wazuh_rule_100003"}
        )

    def test_reingest_is_idempotent(self):
        from rag.rules_ingest import ingest_wazuh_rules

        api = FakeManagerRulesAPI([_rule(100001), _rule(100002)])
        kb = self._kb()
        first = ingest_wazuh_rules(api, kb)
        second = ingest_wazuh_rules(api, kb)
        self.assertEqual(first["rules_stored"], 2)
        self.assertEqual(second["rules_stored"], 2)
        self.assertEqual(kb.counts()["wazuh_docs"], 2)

    def test_all_rules_paginates_and_reports_truncation(self):
        from rag.rules_ingest import ingest_wazuh_rules

        # > one 500-item page, so paging is exercised; fake KB keeps it fast
        rules = [_rule(i, filename="0095-sshd_rules.xml") for i in range(1001, 2202)]
        api = FakeManagerRulesAPI(rules)
        kb = FakeKB()
        out = ingest_wazuh_rules(api, kb, all_rules=True, max_rules=2000)
        self.assertEqual(out["rules_pulled"], 1201)
        self.assertFalse(out["truncated"])
        self.assertTrue(all(c["filename"] is None for c in api.calls))
        self.assertEqual([c["offset"] for c in api.calls], [0, 500, 1000])
        # tail page returned exactly the remainder (1201 - 1000)
        self.assertEqual(
            [len(api.rules[c["offset"] : c["offset"] + c["limit"]]) for c in api.calls],
            [500, 500, 201],
        )

        api2 = FakeManagerRulesAPI(rules)
        out2 = ingest_wazuh_rules(api2, kb, all_rules=True, max_rules=40)
        self.assertEqual(out2["rules_pulled"], 40)
        self.assertTrue(out2["truncated"])

    def test_group_and_search_forwarded(self):
        from rag.rules_ingest import ingest_wazuh_rules

        api = FakeManagerRulesAPI([_rule(100001)])
        kb = self._kb()
        ingest_wazuh_rules(api, kb, group="web", search="sql")
        self.assertEqual(api.calls[-1]["group"], "web")
        self.assertEqual(api.calls[-1]["search"], "sql")

    def test_empty_local_rules_hint(self):
        from rag.rules_ingest import ingest_wazuh_rules

        api = FakeManagerRulesAPI([])
        kb = self._kb()
        out = ingest_wazuh_rules(api, kb)
        self.assertEqual(out["rules_pulled"], 0)
        self.assertIn("local_rules.xml currently holds no rules", out["note"])

    def test_delete_missing_prunes_only_stale_in_scope(self):
        from rag.rules_ingest import ingest_wazuh_rules

        kb = self._kb()
        # stale local rule (should be pruned)
        kb.add(
            "wazuh_docs",
            "stale local",
            {"kind": "wazuh-rule", "filename": "local_rules.xml"},
            doc_id="wazuh_rule_999",
        )
        # another-file rule snapshot (out of scope -> survives)
        kb.add(
            "wazuh_docs",
            "other file",
            {"kind": "wazuh-rule", "filename": "0095-sshd_rules.xml"},
            doc_id="wazuh_rule_777",
        )
        # non-rule doc (untouched)
        kb.add(
            "wazuh_docs",
            "reference",
            {"kind": "rule-authoring", "source": "wazuh-rules.md"},
            doc_id="wazuh-rules",
        )

        api = FakeManagerRulesAPI([_rule(100001), _rule(100002)])
        out = ingest_wazuh_rules(api, kb)
        self.assertEqual(out["rules_pruned"], 1)
        rows = {r["id"] for r in kb.query("wazuh_docs", "rule", n_results=10)}
        self.assertIn("wazuh_rule_100001", rows)
        self.assertIn("wazuh_rule_100002", rows)
        self.assertIn("wazuh_rule_777", rows)
        self.assertIn("wazuh-rules", rows)
        self.assertNotIn("wazuh_rule_999", rows)

    def test_delete_missing_off_keeps_stale(self):
        from rag.rules_ingest import ingest_wazuh_rules

        kb = self._kb()
        kb.add(
            "wazuh_docs",
            "stale",
            {"kind": "wazuh-rule", "filename": "local_rules.xml"},
            doc_id="wazuh_rule_999",
        )
        api = FakeManagerRulesAPI([_rule(100001)])
        out = ingest_wazuh_rules(api, kb, delete_missing=False)
        self.assertEqual(out["rules_pruned"], 0)
        self.assertEqual(kb.counts()["wazuh_docs"], 2)


class TestIngestWazuhRulesTool(KbTestCase):
    def _ctx(self, rules):
        ctx = mock.MagicMock()
        ctx.wazuh = FakeManagerRulesAPI(rules)
        ctx.wazuh.base_url = "https://manager:55000"
        return ctx

    def test_runs_and_returns_summary(self):
        from tools.rag.ingest import IngestWazuhRules

        ctx = self._ctx([_rule(100001), _rule(100002)])
        out = IngestWazuhRules().run(ctx)
        self.assertEqual(out["rules_stored"], 2)
        self.assertEqual(out["selected"]["filename"], "local_rules.xml")
        self.assertEqual(out["manager"], "https://manager:55000")
        kb = self._kb()
        self.assertEqual(kb.counts()["wazuh_docs"], 2)

    def test_filename_all_magic_collects_full_ruleset(self):
        from tools.rag.ingest import IngestWazuhRules

        for magic in ("all", "all-rules"):
            ctx = self._ctx([_rule(i) for i in (100001, 100002)])
            out = IngestWazuhRules().run(ctx, filename=magic)
            self.assertIsNone(out["selected"]["filename"])
            self.assertTrue(out["selected"]["all_rules"])
            self.assertEqual(out["rules_stored"], 2)

    def test_all_rules_param_collects_full_ruleset(self):
        from tools.rag.ingest import IngestWazuhRules

        ctx = self._ctx([_rule(i) for i in (100001, 100002)])
        out = IngestWazuhRules().run(ctx, all_rules=True)
        self.assertIsNone(out["selected"]["filename"])
        self.assertTrue(out["selected"]["all_rules"])
        self.assertEqual(out["rules_stored"], 2)
        self.assertTrue(all(c["filename"] is None for c in ctx.wazuh.calls))

    def test_all_rules_param_accepts_string_true_like_llm_wire(self):
        # The agent sends JSON {all_rules: "True"}; validate() must coerce the
        # string to a real boolean, NOT drop it and fall back to local_rules.xml.
        from tools.rag.ingest import IngestWazuhRules

        for raw in ("True", "true", 1):
            ctx = self._ctx([_rule(i) for i in (100001, 100002)])
            out = IngestWazuhRules().run(ctx, all_rules=raw)
            self.assertTrue(out["selected"]["all_rules"], f"raw={raw!r}")
            self.assertIsNone(out["selected"]["filename"], f"raw={raw!r}")
            self.assertEqual(out["rules_stored"], 2, f"raw={raw!r}")
            self.assertTrue(
                all(c["filename"] is None for c in ctx.wazuh.calls),
                f"raw={raw!r} must not filter by local_rules.xml",
            )

    def test_all_rules_false_defaults_to_local_rules(self):
        from tools.rag.ingest import IngestWazuhRules

        ctx = self._ctx([_rule(100001), _rule(100002)])
        out = IngestWazuhRules().run(ctx, all_rules=False)
        self.assertFalse(out["selected"]["all_rules"])
        self.assertEqual(out["selected"]["filename"], "local_rules.xml")
        self.assertEqual(ctx.wazuh.calls[0]["filename"], "local_rules.xml")

    def test_max_rules_clamped(self):
        from tools.rag.ingest import IngestWazuhRules

        rules = [_rule(i) for i in range(1000, 1200)]
        ctx = self._ctx(rules)
        IngestWazuhRules().run(ctx, max_rules=999999)
        self.assertLessEqual(ctx.wazuh.calls[0]["limit"], 500)

    def test_max_rules_floor(self):
        from tools.rag.ingest import IngestWazuhRules

        api_rules = [_rule(100001), _rule(100002)]
        ctx = self._ctx(api_rules)
        out = IngestWazuhRules().run(ctx, max_rules=-5)  # clamped to 1
        self.assertEqual(out["rules_pulled"], 1)

    def test_api_failure_surfaces_as_tool_error(self):
        from tools.base import ToolError
        from tools.rag.ingest import IngestWazuhRules

        ctx = mock.MagicMock()
        ctx.wazuh = mock.MagicMock()
        ctx.wazuh.get_rules.side_effect = RuntimeError("manager down")
        with self.assertRaises(ToolError) as cm:
            IngestWazuhRules().run(ctx)
        self.assertIn("knowledge base", str(cm.exception))


class TestIngestWazuhRulesRegistry(unittest.TestCase):
    def test_tool_is_registered_as_read(self):
        from tools import registry
        from tools.base import Permission

        self.assertIn("ingest_wazuh_rules", registry.tool_names())
        tool = registry.get_tool("ingest_wazuh_rules")
        self.assertIsInstance(tool.permission, Permission)
        self.assertEqual(tool.permission, Permission.READ)

    def test_read_executes_immediately_via_registry(self):
        from tools import registry

        api = FakeManagerRulesAPI([_rule(100001), _rule(100002)])
        fake_kb = mock.MagicMock()
        fake_kb.add = mock.MagicMock()
        fake_kb.query.return_value = []
        fake_kb.delete.return_value = 0
        ctx = mock.MagicMock()
        ctx.wazuh = api
        ctx.approval = None
        with (
            mock.patch("rag.knowledge_base.KnowledgeBase", return_value=fake_kb),
            mock.patch("audit.audit_log"),
            mock.patch("approvals.create_proposal"),
        ):
            out = registry.execute(ctx, "ingest_wazuh_rules", {"max_rules": 10})
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["result"]["rules_stored"], 2)
        added_ids = {c.kwargs["doc_id"] for c in fake_kb.add.call_args_list}
        self.assertEqual(added_ids, {"wazuh_rule_100001", "wazuh_rule_100002"})
        self.assertEqual(api.calls[0]["filename"], "local_rules.xml")


if __name__ == "__main__":
    unittest.main()
