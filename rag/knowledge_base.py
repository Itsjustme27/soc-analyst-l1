"""
Local RAG store (ChromaDB, on-disk - nothing leaves the box).

Four logical collections, kept separate so retrieval can be targeted:
  - playbooks   : your org's SOPs for handling alert types
  - cases       : closed historical alerts with analyst verdict + reasoning
  - lessons     : short, self-written notes distilled from analyst feedback
                  (this is the "self-improvement" memory - see agent/memory.py)
  - wazuh_docs  : curated engineering reference for the AI SOC engineer
                  (rule authoring, logtest semantics, API quirks, indexer
                  query conventions, MITRE mapping - see wazuh_docs/ and
                  scripts_ingest_wazuh_docs.py)

By default this downloads a small local sentence-embedding model on first use
(one-time, needs internet); everything after that runs fully offline. Set
KB_EMBEDDING_MODE=hashing (or just MOCK_MODE=true, which implies it) to skip
that download entirely and use the deterministic offline embedding in
rag/embeddings.py instead - retrieval quality is worse, but it needs no
network and no model file, which matters for CI, air-gapped deployments, and
tests. A collection's embedding function is fixed at creation time in its
on-disk data; if CHROMA_DB_PATH already has data created under a different
mode, KnowledgeBase falls back to whatever's actually persisted there rather
than erroring - so flipping MOCK_MODE on an existing data dir degrades
gracefully to the embedding it was already using, it doesn't crash.
"""

from __future__ import annotations

import uuid
from typing import Any

import chromadb

from config import cfg
from rag.embeddings import HashingEmbeddingFunction

COLLECTIONS = ("playbooks", "cases", "lessons", "wazuh_docs")


def _embedding_function():
    """None means "let chromadb use its own default" (the downloaded
    sentence-transformer model) - the historical, unconfigured behavior."""
    mode = (getattr(cfg, "KB_EMBEDDING_MODE", "") or "auto").strip().lower()
    if mode == "hashing" or (mode == "auto" and cfg.MOCK_MODE):
        return HashingEmbeddingFunction()
    return None


class KnowledgeBase:
    def __init__(self, path: str | None = None, embedding_function: Any = None):
        self.client = chromadb.PersistentClient(path=path or cfg.CHROMA_DB_PATH)
        ef = embedding_function if embedding_function is not None else _embedding_function()
        kwargs = {"embedding_function": ef} if ef is not None else {}
        self._collections = {}
        for name in COLLECTIONS:
            try:
                self._collections[name] = self.client.get_or_create_collection(name, **kwargs)
            except ValueError as e:
                # An existing on-disk collection was created with a different
                # embedding function than the one we'd use now (e.g. this
                # CHROMA_DB_PATH already has real-model data and someone set
                # MOCK_MODE=true / KB_EMBEDDING_MODE=hashing afterwards).
                # Respect what's actually persisted rather than crashing -
                # get_or_create_collection with no embedding_function lets
                # chromadb use the one already stored for this collection.
                if "embedding function" not in str(e).lower() or not kwargs:
                    raise
                self._collections[name] = self.client.get_or_create_collection(name)

    # ------------------------------------------------------------------ #
    def add(
        self, collection: str, text: str, metadata: dict[str, Any], doc_id: str | None = None
    ) -> str:
        assert collection in COLLECTIONS, f"unknown collection {collection}"
        doc_id = doc_id or str(uuid.uuid4())
        self._collections[collection].upsert(ids=[doc_id], documents=[text], metadatas=[metadata])
        return doc_id

    def query(
        self, collection: str, text: str, n_results: int = 4, where: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        assert collection in COLLECTIONS, f"unknown collection {collection}"
        coll = self._collections[collection]
        if coll.count() == 0:
            return []
        n_results = min(n_results, coll.count())
        res = coll.query(query_texts=[text], n_results=n_results, where=where)
        out = []
        for doc, meta, dist, _id in zip(
            res["documents"][0],
            res["metadatas"][0],
            res["distances"][0],
            res["ids"][0],
            strict=True,
        ):
            out.append({"id": _id, "text": doc, "metadata": meta, "distance": dist})
        return out

    def get(self, collection: str, where: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Fetch documents by metadata filter without embedding the query
        (cheap listing - used to enumerate synced snapshots for pruning)."""
        assert collection in COLLECTIONS, f"unknown collection {collection}"
        res = self._collections[collection].get(where=where, include=["documents", "metadatas"])
        ids = res.get("ids", []) or []
        docs = res.get("documents", []) or []
        metas = res.get("metadatas", []) or []
        return [
            {"id": i, "text": d, "metadata": m} for i, d, m in zip(ids, docs, metas, strict=True)
        ]

    def delete(self, collection: str, ids: list[str]) -> int:
        """Remove documents by id (idempotent - missing ids are no-ops).
        Used to prune stale snapshots, e.g. rules deleted on the manager."""
        assert collection in COLLECTIONS, f"unknown collection {collection}"
        ids = [i for i in ids if i]
        if not ids:
            return 0
        self._collections[collection].delete(ids=ids)
        return len(ids)

    def counts(self) -> dict[str, int]:
        return {name: c.count() for name, c in self._collections.items()}
