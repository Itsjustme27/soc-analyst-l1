"""
Offline tests for the wazuh_docs RAG chunk: the new collection, the ingest
script (idempotent, real chroma on a tmp path - still fully offline via the
hashing embedding), and the retrieve_wazuh_docs tool + its registry wiring.

Run: cd soc-agent && MOCK_MODE=true python3 -m unittest tests.test_rag_docs -v
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

DOC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wazuh_docs")


class TestWazuhDocsCollection(unittest.TestCase):
    def test_collections_includes_wazuh_docs(self):
        from rag.knowledge_base import COLLECTIONS

        self.assertIn("wazuh_docs", COLLECTIONS)

    def test_seed_dir_has_reference_docs(self):
        files = sorted(os.listdir(DOC_DIR))
        self.assertGreaterEqual(len(files), 5)  # rules, logtest, api, indexer, mitre
        for name in (
            "wazuh-rules.md",
            "wazuh-logtest.md",
            "wazuh-api.md",
            "wazuh-indexer.md",
            "mitre-attack-mapping.md",
        ):
            self.assertIn(name, files)


class TestIngestWazuhDocs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wazuh-docs-ingest-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_ingest(self):
        from config import cfg

        orig = cfg.CHROMA_DB_PATH
        cfg.CHROMA_DB_PATH = self.tmp
        try:
            import scripts_ingest_wazuh_docs as mod

            mod.main()
            from rag.knowledge_base import KnowledgeBase

            return KnowledgeBase()
        finally:
            cfg.CHROMA_DB_PATH = orig

    def test_ingest_seeds_all_docs_and_is_idempotent(self):
        files = [f for f in sorted(os.listdir(DOC_DIR)) if f.endswith(".md")]
        kb1 = self._run_ingest()
        self.assertEqual(kb1.counts()["wazuh_docs"], len(files))
        kb2 = self._run_ingest()  # re-run: upsert by stem, same count
        self.assertEqual(kb2.counts()["wazuh_docs"], len(files))

    def test_ingested_docs_are_retrievable(self):
        kb = self._run_ingest()
        rows = kb.query("wazuh_docs", "frequency rule if_matched_sid", n_results=2)
        self.assertGreaterEqual(len(rows), 1)
        blob = " ".join(r["text"] for r in rows)
        self.assertIn("if_matched_sid", blob)


class TestRetrieveWazuhDocsTool(unittest.TestCase):
    def _patched_ctx(self):
        ctx = mock.MagicMock()
        rows = [
            {
                "id": "wazuh-rules",
                "metadata": {"source": "wazuh-rules.md", "kind": "rule-authoring"},
                "distance": 0.11,
                "text": "frequency, timeframe, and divide MUST be rule ATTRIBUTES.",
            },
            {
                "id": "wazuh-logtest",
                "metadata": {"source": "wazuh-logtest.md", "kind": "rule-verification"},
                "distance": 0.42,
                "text": "frequency=3 fires on the 3rd occurrence in the same session.",
            },
        ]
        fake = mock.MagicMock()
        fake.query.return_value = rows
        return ctx, fake

    def test_returns_normalized_results(self):
        from tools.rag.retrieve import RetrieveWazuhDocs

        ctx, fake = self._patched_ctx()
        with mock.patch("rag.knowledge_base.KnowledgeBase", return_value=fake):
            out = RetrieveWazuhDocs().run(ctx, query="frequency rule")
        self.assertEqual(out["collection"], "wazuh_docs")
        self.assertEqual(out["count"], 2)
        self.assertEqual(out["results"][0]["source"], "wazuh-rules.md")
        self.assertEqual(out["results"][0]["kind"], "rule-authoring")
        self.assertIsInstance(out["results"][0]["distance"], float)
        fake.query.assert_called_once_with("wazuh_docs", "frequency rule", n_results=4)

    def test_redirects_to_other_collections(self):
        from tools.rag.retrieve import RetrieveWazuhDocs

        ctx, fake = self._patched_ctx()
        with mock.patch("rag.knowledge_base.KnowledgeBase", return_value=fake):
            RetrieveWazuhDocs().run(ctx, query="brute force", collection="playbooks", n_results=2)
        fake.query.assert_called_once_with("playbooks", "brute force", n_results=2)

    def test_unknown_collection_rejected(self):
        from tools.base import ToolError
        from tools.rag.retrieve import RetrieveWazuhDocs

        ctx, fake = self._patched_ctx()
        with mock.patch("rag.knowledge_base.KnowledgeBase", return_value=fake):
            with self.assertRaises(ToolError):
                RetrieveWazuhDocs().run(ctx, query="x", collection="nonexistent")

    def test_empty_query_rejected(self):
        from tools.base import ToolError
        from tools.rag.retrieve import RetrieveWazuhDocs

        with self.assertRaises(ToolError):
            RetrieveWazuhDocs().run(mock.MagicMock(), query="")

    def test_kb_failure_is_surfaced_not_silent(self):
        from tools.base import ToolError
        from tools.rag.retrieve import RetrieveWazuhDocs

        ctx = mock.MagicMock()
        fake = mock.MagicMock()
        fake.query.side_effect = RuntimeError("chroma down")
        with mock.patch("rag.knowledge_base.KnowledgeBase", return_value=fake):
            with self.assertRaises(ToolError) as cm:
                RetrieveWazuhDocs().run(ctx, query="anything")
        self.assertIn("scripts_ingest_wazuh_docs.py", str(cm.exception))


class TestRetrieveWazuhDocsRegistry(unittest.TestCase):
    def test_tool_is_registered_as_read(self):
        from tools import registry
        from tools.base import Permission

        self.assertIn("retrieve_wazuh_docs", registry.tool_names())
        self.assertEqual(registry.get_tool("retrieve_wazuh_docs").permission, Permission.READ)

    def test_read_executes_immediately_via_registry(self):
        from tools import registry

        fake = mock.MagicMock()
        fake.query.return_value = [
            {
                "id": "x",
                "metadata": {"source": "wazuh-api.md", "kind": "manager-api"},
                "distance": 0.2,
                "text": "q=id=NNN filters rules by id.",
            },
        ]
        ctx = mock.MagicMock()
        ctx.approval = None
        with (
            mock.patch("rag.knowledge_base.KnowledgeBase", return_value=fake),
            mock.patch("audit.audit_log"),
            mock.patch("approvals.create_proposal"),
        ):
            out = registry.execute(ctx, "retrieve_wazuh_docs", {"query": "q filter"})
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["result"]["count"], 1)
        self.assertEqual(out["result"]["results"][0]["source"], "wazuh-api.md")


if __name__ == "__main__":
    unittest.main()
