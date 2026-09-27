"""
Snapshot Wazuh manager rules into the LOCAL RAG knowledge base (wazuh_docs
collection, kind=wazuh-rule) so the AI SOC engineer can recall them offline
via retrieve_wazuh_docs. Re-running is safe - upsert by rule id - and stale
snapshots for the selected scope are pruned by default.

This is READ-only against the manager: it never modifies Wazuh configuration.

Usage:
    python scripts_ingest_wazuh_rules.py                     # custom rules (local_rules.xml)
    python scripts_ingest_wazuh_rules.py --all               # full ruleset
    python scripts_ingest_wazuh_rules.py --group web --max-rules 500
    python scripts_ingest_wazuh_rules.py --no-prune          # keep stale snapshots
"""

from __future__ import annotations

import argparse
import json

from config import cfg
from rag.knowledge_base import KnowledgeBase
from rag.rules_ingest import ingest_wazuh_rules
from tools.api_client import WazuhManagerAPI


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--all", action="store_true", help="snapshot the full ruleset instead of local_rules.xml"
    )
    ap.add_argument(
        "--filename", default=None, help="ruleset file to snapshot (e.g. local_rules.xml)"
    )
    ap.add_argument("--group", default=None, help="only rules in this group")
    ap.add_argument("--search", default=None, help="only rules matching this search term")
    ap.add_argument("--max-rules", type=int, default=2000, help="cap on rules stored per run")
    ap.add_argument(
        "--no-prune", action="store_true", help="keep stale snapshots (default: prune missing)"
    )
    ap.add_argument("--db", default=None, help="override CHROMA_DB_PATH (default: config)")
    args = ap.parse_args()

    api = WazuhManagerAPI(
        url=cfg.WAZUH_API_URL,
        username=cfg.WAZUH_API_USERNAME,
        password=cfg.WAZUH_API_PASSWORD,
        verify=cfg.WAZUH_API_VERIFY_SSL,
    )
    kb = KnowledgeBase(path=args.db)
    summary = ingest_wazuh_rules(
        api,
        kb,
        filename=args.filename,
        group=args.group,
        search=args.search,
        all_rules=args.all,
        max_rules=args.max_rules,
        delete_missing=not args.no_prune,
    )
    summary["manager"] = cfg.WAZUH_API_URL
    print(json.dumps(summary, indent=2))
    print("\ncollection counts:", kb.counts())


if __name__ == "__main__":
    main()
