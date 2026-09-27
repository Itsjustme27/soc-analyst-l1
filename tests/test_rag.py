"""
Offline tests for rag/embeddings.py (the deterministic hashing fallback) and
rag/knowledge_base.py's embedding-mode selection. No network, no downloaded
model - that's the whole point of this module.

Run: python -m unittest tests.test_rag -v
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")


class TestHashingEmbeddingFunction(unittest.TestCase):
    def test_deterministic(self):
        from rag.embeddings import HashingEmbeddingFunction

        ef = HashingEmbeddingFunction()
        a = [list(v) for v in ef(["brute force login attempt"])]
        b = [list(v) for v in ef(["brute force login attempt"])]
        self.assertEqual(a, b)

    def test_different_text_different_vector(self):
        from rag.embeddings import HashingEmbeddingFunction

        ef = HashingEmbeddingFunction()
        a = [list(v) for v in ef(["brute force login attempt"])]
        b = [list(v) for v in ef(["completely unrelated malware detection"])]
        self.assertNotEqual(a, b)

    def test_vectors_are_normalized(self):
        import math

        from rag.embeddings import HashingEmbeddingFunction

        ef = HashingEmbeddingFunction()
        [vec] = ef(["some text with several different words in it"])
        norm = math.sqrt(sum(v * v for v in vec))
        self.assertAlmostEqual(norm, 1.0, places=5)

    def test_empty_text_does_not_crash(self):
        from rag.embeddings import HashingEmbeddingFunction

        ef = HashingEmbeddingFunction()
        [vec] = ef([""])
        self.assertEqual(len(vec), 256)

    def test_md5_bucket_marked_non_security(self):
        # The hashing-fallback embedding buckets tokens via md5; it must be
        # flagged usedforsecurity=False so scanners never mistake it for a
        # cryptographic use (and FIPS mode won't reject it).
        import hashlib
        from unittest import mock

        from rag.embeddings import _embed_one

        with mock.patch("hashlib.md5", wraps=hashlib.md5) as md5:
            vec = _embed_one("brute force login")
        self.assertEqual(len(vec), 256)
        self.assertTrue(any(c.kwargs.get("usedforsecurity") is False for c in md5.call_args_list))

    def test_shared_words_are_closer_than_disjoint_words(self):
        # crude sanity check of the actual retrieval property this is used for
        from rag.embeddings import HashingEmbeddingFunction

        ef = HashingEmbeddingFunction()
        query = ef(["brute force login MFA bypass"])[0]
        close = ef(["brute force login playbook MFA check"])[0]
        far = ef(["completely different malware process tree"])[0]

        def cos_sim(a, b):
            return sum(x * y for x, y in zip(a, b))  # both already unit-normalized

        self.assertGreater(cos_sim(query, close), cos_sim(query, far))


class TestKnowledgeBaseEmbeddingSelection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="kb-select-test-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_mock_mode_auto_selects_hashing(self):
        from config import cfg
        from rag.embeddings import HashingEmbeddingFunction
        from rag.knowledge_base import _embedding_function

        orig_mock, orig_mode = cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE
        cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE = True, "auto"
        try:
            self.assertIsInstance(_embedding_function(), HashingEmbeddingFunction)
        finally:
            cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE = orig_mock, orig_mode

    def test_explicit_hashing_mode_selected_even_outside_mock_mode(self):
        from config import cfg
        from rag.embeddings import HashingEmbeddingFunction
        from rag.knowledge_base import _embedding_function

        orig_mock, orig_mode = cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE
        cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE = False, "hashing"
        try:
            self.assertIsInstance(_embedding_function(), HashingEmbeddingFunction)
        finally:
            cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE = orig_mock, orig_mode

    def test_default_mode_outside_mock_mode_defers_to_chroma(self):
        from config import cfg
        from rag.knowledge_base import _embedding_function

        orig_mock, orig_mode = cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE
        cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE = False, "auto"
        try:
            self.assertIsNone(_embedding_function())  # None = let chromadb use its own default
        finally:
            cfg.MOCK_MODE, cfg.KB_EMBEDDING_MODE = orig_mock, orig_mode

    def test_knowledge_base_works_fully_offline_under_mock_mode(self):
        from config import cfg

        orig_path = cfg.CHROMA_DB_PATH
        cfg.CHROMA_DB_PATH = self.tmp
        try:
            from rag.knowledge_base import KnowledgeBase

            kb = KnowledgeBase()
            kb.add(
                "playbooks", "brute force login playbook MFA check", {"source": "x"}, doc_id="p1"
            )
            results = kb.query("playbooks", "brute force login MFA")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["id"], "p1")
        finally:
            cfg.CHROMA_DB_PATH = orig_path

    def test_reopening_a_hashing_embedded_collection_in_a_new_instance_works(self):
        # Simulates a fresh process (e.g. main.py run twice) reopening data
        # created earlier - not just querying the same live Python object.
        from rag.embeddings import HashingEmbeddingFunction
        from rag.knowledge_base import KnowledgeBase

        kb1 = KnowledgeBase(path=self.tmp, embedding_function=HashingEmbeddingFunction())
        kb1.add("playbooks", "brute force login playbook", {"source": "x"}, doc_id="p1")

        kb2 = KnowledgeBase(path=self.tmp)  # fresh instance, no explicit embedding_function
        results = kb2.query("playbooks", "brute force login")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["id"], "p1")

    def test_mismatched_embedding_function_falls_back_instead_of_crashing(self):
        # An existing collection created with a different embedding function
        # than the one now requested must not raise - see KnowledgeBase's
        # embedding-conflict fallback.
        import chromadb

        from rag.embeddings import HashingEmbeddingFunction
        from rag.knowledge_base import KnowledgeBase

        class OtherEF(chromadb.EmbeddingFunction):
            def __init__(self) -> None:
                pass

            def __call__(self, input):
                return [[0.0] * 8 for _ in input]

            @staticmethod
            def name() -> str:
                return "other-ef-for-test"

            def get_config(self):
                return {}

            @staticmethod
            def build_from_config(config):
                return OtherEF()

        kb1 = KnowledgeBase(path=self.tmp, embedding_function=HashingEmbeddingFunction())
        kb1.add("playbooks", "some doc", {"source": "x"}, doc_id="p1")

        kb2 = KnowledgeBase(path=self.tmp, embedding_function=OtherEF())  # must not raise
        self.assertEqual(kb2.counts()["playbooks"], 1)


if __name__ == "__main__":
    unittest.main()
