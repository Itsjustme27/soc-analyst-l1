"""
Shared logic for snapshotting Wazuh manager rules into the LOCAL RAG store.

Used by:
  - tools/rag/ingest.py   (the AI SOC engineer's `ingest_wazuh_rules` tool)
  - scripts_ingest_wazuh_rules.py (ops CLI for re-syncing the corpus)

Rules are pulled READ-only from the manager's /rules endpoint and upserted
into the existing `wazuh_docs` collection with kind="wazuh-rule" and a stable
doc_id of `wazuh_rule_<id>`, so re-running refreshes in place instead of
duplicating. `delete_missing` prunes previously-synced snapshots that are no
longer present for the selected scope (per-ruleset-file), keeping the corpus
honest as rules are added/removed.

The manager is NEVER modified by anything in this module - it only reads.
Retrieval of these snapshots happens through the ordinary retrieve_wazuh_docs
tool; the returned text is data, never instructions.
"""

from __future__ import annotations

from typing import Any

COLLECTION = "wazuh_docs"
_PAGE = 500  # wazuh manager API caps list endpoints at 500 per page

RULE_KIND = "wazuh-rule"
RULE_SOURCE = "wazuh_rules"


def _fmt_mitre(mitre: Any) -> str:
    """MITRE items vary across API builds: list of {id,name} / {technique},
    {id,technique_name} or plain strings. Render a compact, searchable form."""
    if not mitre:
        return ""
    parts: list[str] = []
    for m in mitre:
        if isinstance(m, dict):
            mid = m.get("id") or m.get("technique")
            name = m.get("name") or m.get("technique_name")
            if mid and name:
                parts.append(f"{mid} ({name})")
            elif mid:
                parts.append(str(mid))
            elif name:
                parts.append(str(name))
        elif isinstance(m, str) and m.strip():
            parts.append(m.strip())
    return ", ".join(dict.fromkeys(parts))  # dedupe, keep order


def build_rule_doc(rule: dict[str, Any]) -> str:
    """Render one manager rule as a compact, retrieval-friendly text blob."""
    lines: list[str] = []
    rid = rule.get("id")
    lvl = rule.get("level")
    lines.append(f"Wazuh rule {rid} (level {lvl}) - {rule.get('status') or 'enabled'}")
    filename = rule.get("filename")
    if filename:
        lines.append(f"File: {filename}")
    groups = rule.get("groups") or []
    if groups:
        lines.append(f"Groups: {', '.join(map(str, groups))}")
    mitre = _fmt_mitre(rule.get("mitre"))
    if mitre:
        lines.append(f"MITRE: {mitre}")
    desc = str(rule.get("description") or "").strip()
    if desc:
        lines.append(f"Description: {desc}")
    details = rule.get("details") or {}
    if details:
        d = "; ".join(f"{k}={v}" for k, v in sorted(details.items()))
        lines.append(f"Details: {d}")
    return "\n".join(lines)


def _synced_ids(kb, filename_filter: str | None) -> set[str]:
    """All existing wazuh-rule doc ids in the collection, optionally scoped to
    one ruleset file."""
    where: dict[str, Any] = {"kind": RULE_KIND}
    if filename_filter:
        # chroma requires an explicit $and for multi-key metadata filters
        where = {"$and": [{"kind": RULE_KIND}, {"filename": filename_filter}]}
    return {r["id"] for r in kb.get(COLLECTION, where=where)}


def ingest_wazuh_rules(
    api: Any,
    kb: Any,
    *,
    filename: str | None = None,
    group: str | None = None,
    search: str | None = None,
    all_rules: bool = False,
    max_rules: int = 2000,
    delete_missing: bool = True,
) -> dict[str, Any]:
    """Pull rules from the manager and upsert them into the RAG.

    `filename` names the ruleset file to snapshot; when neither `filename` nor
    `all_rules` is given, the default is local_rules.xml (the custom rules an
    analyst owns - the "correlation rules"). `all_rules=True` snapshots the
    full ruleset regardless of file.

    Returns a summary dict; the manager is only ever read.
    """
    filename_filter = None if all_rules else (filename or "local_rules.xml")

    # ---- pull (READ only) -------------------------------------------------
    pulled: list[dict[str, Any]] = []
    offset = 0
    total_seen = 0
    while len(pulled) < max_rules:
        want = min(_PAGE, max_rules - len(pulled))
        resp = api.get_rules(
            limit=want,
            offset=offset,
            search=search,
            group=group,
            filename=filename_filter,
        )
        data = (resp or {}).get("data", {}) or {}
        batch = data.get("affected_items", []) or []
        total_seen = int(data.get("total_affected_items") or 0)
        if not batch:
            break
        pulled.extend(batch)
        offset += len(batch)
        if len(pulled) >= max_rules or len(pulled) >= total_seen:
            break
    truncated = total_seen > len(pulled)

    # ---- upsert (doc_id = wazuh_rule_<id>, stable across runs) ------------
    stored = 0
    for rule in pulled:
        rid = rule.get("id")
        if rid is None:
            continue
        meta = {
            "source": RULE_SOURCE,
            "kind": RULE_KIND,
            "rule_id": str(rid),
            "level": int(rule.get("level") or 0),
            "filename": rule.get("filename") or (filename_filter or ""),
            "status": rule.get("status") or "enabled",
            "groups": ", ".join(map(str, rule.get("groups") or [])),
        }
        kb.add(COLLECTION, build_rule_doc(rule), meta, doc_id=f"wazuh_rule_{rid}")
        stored += 1

    # ---- prune stale snapshots for the selected scope ----------------------
    pruned = 0
    if delete_missing and stored:
        current = {f"wazuh_rule_{r['id']}" for r in pulled if r.get("id") is not None}
        stale = sorted(_synced_ids(kb, filename_filter) - current)
        if stale:
            kb.delete(COLLECTION, stale)
            pruned = len(stale)

    note = (
        "Rules snapshotted into the LOCAL RAG 'wazuh_docs' collection "
        "(kind=wazuh-rule). The manager was not modified. Query them via "
        "retrieve_wazuh_docs; re-running refreshes by rule id."
    )
    if filename_filter == "local_rules.xml" and not pulled:
        note += (
            " local_rules.xml currently holds no rules of its own (or none "
            "match this selection) - the bundled rules live in other files; "
            "use all_rules=true to snapshot the full ruleset."
        )

    return {
        "collection": COLLECTION,
        "selected": {
            "filename": filename_filter,
            "group": group,
            "search": search,
            "all_rules": all_rules,
        },
        "rules_pulled": len(pulled),
        "rules_stored": stored,
        "rules_pruned": pruned,
        "truncated": truncated,
        "note": note,
    }


__all__ = [
    "COLLECTION",
    "RULE_KIND",
    "RULE_SOURCE",
    "build_rule_doc",
    "ingest_wazuh_rules",
]
