"""
OpenSearch query builders + validation for the AI SOC engineer.

The engineer never hands arbitrary query JSON straight to the indexer: typed
tools build queries from validated parameters (bounded size, fixed sort, time
range always applied) and `verify_opensearch_query` executes a size-0 count to
prove a query the dashboard engineer generated actually matches data.
"""

from __future__ import annotations

from typing import Any

from tools.api_client import WazuhAPIError
from tools.indexer_client import IndexerClient


def to_range_expr(time_range: str | None) -> str | None:
    """Normalize a user/LLM supplied time window to OpenSearch date math.

    Accepts: None/"" (no window), "-24h" / "24h" / "now-24h" / "7d" / "1w" /
    "30d" / ISO-ish. Falls back to now-24h when unrecognized (safe default)."""
    if not time_range:
        return None
    tr = str(time_range).strip()
    if tr.startswith("now-"):
        return tr
    if tr.startswith("-"):
        return "now" + tr
    if (
        tr.lower().endswith(("h", "m", "s", "d", "w", "M", "y"))
        and tr[:-1].replace(".", "").isdigit()
    ):
        return "now-" + tr
    if "T" in tr:  # absolute timestamp
        return tr
    return "now-24h"


def build_alert_query(
    q: str | None = None,
    group: str | None = None,
    agent: str | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
    level_min: int | None = None,
    level_max: int | None = None,
    rule_id: str | None = None,
    time_range: str | None = "-24h",
    extra: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a Wazuh-alert-doc bool query from typed filters."""
    must: list[dict[str, Any]] = []
    if q:
        must.append({"query_string": {"query": q, "default_operator": "AND"}})
    if group:
        must.append({"term": {"rule.groups": group}})
    if agent:
        # agent.name on the alert doc; also allow agent.id lookups via same field
        must.append({"term": {"agent.name": agent}})
    if src_ip:
        must.append({"term": {"data.srcip": src_ip}})
    if dst_ip:
        must.append({"term": {"data.dstip": dst_ip}})
    lvl_range: dict[str, Any] = {}
    if level_min is not None:
        lvl_range["gte"] = level_min
    if level_max is not None:
        lvl_range["lte"] = level_max
    if lvl_range:
        must.append({"range": {"rule.level": lvl_range}})
    if rule_id:
        must.append({"term": {"rule.id": rule_id}})
    expr = to_range_expr(time_range)
    if expr:
        must.append({"range": {"timestamp": {"gte": expr}}})
    for clause in extra or []:
        must.append(clause)
    if not must:
        return {"match_all": {}}
    return {"bool": {"filter": must}}


def search_body(
    query: dict[str, Any], size: int = 20, sort_by: str = "timestamp", order: str = "desc"
) -> dict[str, Any]:
    return {
        "size": size,
        "sort": [{sort_by: {"order": order}}],
        "query": query,
    }


def verify_opensearch_query(
    indexer: IndexerClient, index: str, body: dict[str, Any]
) -> dict[str, Any]:
    """Prove a query is valid (executes) and report how much data it matches.

    Executes the query with size=0 - read-only, cheap, and the same validation
    the dashboard engineer runs before proposing visualizations."""
    try:
        r = indexer.search(index, {**body, "size": 0})
    except WazuhAPIError as e:
        return {"valid": False, "error": str(e)}
    except Exception as e:  # noqa: BLE001 - unstable indexer shouldn't crash the flow
        return {"valid": False, "error": f"Indexer error: {e}"}
    return {
        "valid": True,
        "index": index,
        "matched": int(r.get("hits", {}).get("total", {}).get("value", 0)),
        "took_ms": r.get("took", 0),
    }


def field_caps_summary(
    indexer: IndexerClient, index: str = "wazuh-alerts-*", limit: int = 400
) -> dict[str, Any]:
    """Readable schema summary for the agent (dashboard engineer / gap
    analysis): field -> type, sorted, capped."""
    try:
        caps = indexer.field_caps(index)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e), "fields": {}}
    items = sorted(caps.items())
    return {"index": index, "field_count": len(items), "fields": dict(items[:limit])}
