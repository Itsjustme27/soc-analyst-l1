"""
Ingest wazuh_docs/*.md into the 'wazuh_docs' RAG collection the AI SOC
engineer's retrieve_wazuh_docs tool searches. Re-running is safe - upsert by
filename (doc_id = stem), so edited docs are refreshed, not duplicated.

Usage: python scripts_ingest_wazuh_docs.py
"""

from pathlib import Path

from rag.knowledge_base import COLLECTIONS, KnowledgeBase

DOC_DIR = Path(__file__).parent / "wazuh_docs"
KIND_BY_NAME = {
    "wazuh-rules.md": "rule-authoring",
    "wazuh-logtest.md": "rule-verification",
    "wazuh-api.md": "manager-api",
    "wazuh-indexer.md": "indexer-queries",
    "mitre-attack-mapping.md": "mitre-mapping",
}


def main() -> None:
    kb = KnowledgeBase()
    assert "wazuh_docs" in COLLECTIONS
    for path in sorted(DOC_DIR.glob("*.md")):
        text = path.read_text()
        kb.add(
            "wazuh_docs",
            text,
            {"source": path.name, "kind": KIND_BY_NAME.get(path.name, "reference")},
            doc_id=path.stem,
        )
        print(f"ingested wazuh_docs: {path.name}")
    print("\ncollection counts:", kb.counts())


if __name__ == "__main__":
    main()
