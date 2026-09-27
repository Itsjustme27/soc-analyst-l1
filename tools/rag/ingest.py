"""
`ingest_wazuh_rules` - pull Wazuh manager rules into the LOCAL RAG knowledge
base so the engineer can recall them offline via retrieve_wazuh_docs.

This is a READ tool: it only ever reads the manager (/rules) and writes to the
on-disk Chroma store (the same memory mechanism as capture_feedback, which
also runs live without approval). It never modifies Wazuh configuration, so it
needs no proposal. Re-runs are idempotent - upsert by rule id - and
delete_missing keeps the corpus in sync as rules come and go on the manager.
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError

MAX_RULES_LIMIT = 5000


class IngestWazuhRules(BaseWazuhTool):
    name = "ingest_wazuh_rules"
    description = (
        "Pull detection rules from the Wazuh manager and keep a snapshot in "
        "the LOCAL RAG knowledge base (wazuh_docs collection, kind=wazuh-rule) "
        "so future rule work can recall them via retrieve_wazuh_docs even "
        "offline. READ-only against the manager - it never modifies Wazuh. "
        "Defaults to the custom local_rules.xml (correlation rules you own); "
        "set all_rules=true (or filename=all) to snapshot the full ruleset. "
        "Re-running refreshes by rule id and prunes rules no longer present."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "filename": {
                "type": "string",
                "description": "Ruleset file to snapshot, e.g. 'local_rules.xml' "
                "(default). Use 'all' / 'all-rules' to snapshot "
                "the entire ruleset.",
            },
            "all_rules": {
                "type": "boolean",
                "description": "Snapshot the ENTIRE ruleset from the manager "
                "(equivalent to filename='all'). Default false = "
                "only the custom local_rules.xml.",
            },
            "group": {
                "type": "string",
                "description": "Only snapshot rules in this group (e.g. 'syslog').",
            },
            "search": {
                "type": "string",
                "description": "Only snapshot rules matching this search term "
                "(rule id or description substring).",
            },
            "max_rules": {
                "type": "integer",
                "description": f"Cap on how many rules to store per call "
                f"(default 2000, max {MAX_RULES_LIMIT}).",
            },
            "delete_missing": {
                "type": "boolean",
                "description": "Prune previously-synced snapshots that no "
                "longer exist for this selection (default true).",
            },
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        filename = (p.get("filename") or "").strip() or None
        all_rules = bool(p.get("all_rules")) or bool(
            filename and filename.lower() in ("all", "all-rules")
        )
        if all_rules:
            filename = None
        max_rules = int(p.get("max_rules") or 2000)
        max_rules = max(1, min(max_rules, MAX_RULES_LIMIT))
        delete_missing = True if p.get("delete_missing") is None else bool(p["delete_missing"])

        # Imported lazily so listing/importing the tool never touches disk or
        # chroma (same pattern as retrieve_wazuh_docs).
        from rag.knowledge_base import KnowledgeBase
        from rag.rules_ingest import ingest_wazuh_rules as _ingest

        kb = KnowledgeBase()
        try:
            summary = _ingest(
                ctx.wazuh,
                kb,
                filename=filename,
                group=(p.get("group") or "").strip() or None,
                search=(p.get("search") or "").strip() or None,
                all_rules=all_rules,
                max_rules=max_rules,
                delete_missing=delete_missing,
            )
        except ToolError:
            raise
        except Exception as e:  # noqa: BLE001 - surfaced, not swallowed
            raise ToolError(f"Failed to snapshot rules into the local knowledge base: {e}") from e
        summary["manager"] = getattr(ctx.wazuh, "base_url", "")
        summary["note"] = (
            f"{summary.get('note', '')} Snapshot is local-only; the manager was not modified."
        )
        return summary


__all__ = ["TOOLS", "IngestWazuhRules"]

TOOLS = [IngestWazuhRules]
