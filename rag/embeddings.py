"""
Deterministic, dependency-free embedding function - a fallback for when the
default embedding model ChromaDB downloads on first use (a small
sentence-transformer, ~90MB, one-time, needs internet) isn't available:
air-gapped deployments, CI, or offline dev. Also used automatically under
MOCK_MODE so `KnowledgeBase()` never needs network access in tests.

This is NOT a semantic embedding - it's a normalized hashing-trick
bag-of-words vector (same family of technique as scikit-learn's
HashingVectorizer). It only picks up literal shared words between two
texts; it has no notion of meaning, so it won't connect "brute force" with
"credential stuffing" the way the real sentence-transformer model would, and
two texts with zero words in common land as maximally dissimilar even if
they're about the same thing. Retrieval quality is noticeably worse than the
default model - use KB_EMBEDDING_MODE=hashing only when you can't use the
default, not as a general substitute for it.

See rag/knowledge_base.py's `_embedding_function()` for how this is selected.
"""
from __future__ import annotations

import hashlib
import math
import re
from typing import Any

import chromadb

_TOKEN_RE = re.compile(r"[a-z0-9]+")
DIMENSIONS = 256


def _tokenize(text: str) -> list[str]:
    return _TOKEN_RE.findall((text or "").lower())


def _embed_one(text: str, dims: int = DIMENSIONS) -> list[float]:
    vec = [0.0] * dims
    for token in _tokenize(text):
        digest = hashlib.md5(token.encode("utf-8"), usedforsecurity=False).hexdigest()
        h = int(digest, 16)
        idx = h % dims
        sign = 1.0 if (h // dims) % 2 == 0 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


class HashingEmbeddingFunction(chromadb.EmbeddingFunction):
    """Chroma-compatible EmbeddingFunction (a callable taking a list of
    strings, returning a list of equal-length float vectors) - deterministic,
    offline, no download, no ML model. See module docstring for the tradeoff.

    Subclasses chromadb.EmbeddingFunction (rather than just duck-typing
    __call__) so it inherits embed_query()/embed_documents(), which newer
    Chroma versions call directly rather than always going through
    __call__ - without this, collection.query() raises AttributeError."""

    def __init__(self) -> None:
        pass  # no state, no model to load - overrides the base class's
        # warning-on-unimplemented-__init__ deprecation notice

    def __call__(self, input: Any) -> list[list[float]]:
        return [_embed_one(t) for t in input]

    @staticmethod
    def name() -> str:
        return "hashing-fallback-v1"


def _register() -> None:
    """Make this embedding function reconstructable by name when a
    collection created with it is reopened in a later process (a fresh
    KnowledgeBase() call with no explicit embedding_function - chromadb
    looks the persisted function's name up in its own registry rather than
    keeping a live reference across process restarts). Best-effort: older
    chromadb versions that don't expose this registry still work fine for
    a single long-lived process, they just can't be reopened cleanly by
    name in a new one - not worth hard-failing the whole module over.
    """
    try:
        from chromadb.api.collection_configuration import known_embedding_functions
        known_embedding_functions[HashingEmbeddingFunction.name()] = HashingEmbeddingFunction
    except Exception:  # noqa: BLE001 - registry internals are not a public,
        # version-stable API; failing to register just means "single-process
        # only" for this fallback, not a fatal error.
        pass


_register()
