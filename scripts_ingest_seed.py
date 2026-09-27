"""
One-time (or re-run anytime) ingestion of seed_data/playbooks into the
'playbooks' RAG collection. Re-running is safe - upsert by filename.

Usage: python scripts_ingest_seed.py
"""

from pathlib import Path

from rag.knowledge_base import KnowledgeBase

PLAYBOOK_DIR = Path(__file__).parent / "seed_data" / "playbooks"


def main():
    kb = KnowledgeBase()
    for path in sorted(PLAYBOOK_DIR.glob("*.md")):
        text = path.read_text()
        kb.add("playbooks", text, {"source": path.name}, doc_id=path.stem)
        print(f"ingested playbook: {path.name}")
    print("\ncollection counts:", kb.counts())


if __name__ == "__main__":
    main()
