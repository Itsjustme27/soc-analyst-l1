"""
Indexer search / schema tools - all READ (execute immediately).

These query the OpenSearch indexer where Wazuh stores alerts (wazuh-alerts-*)
and raw events (wazuh-archives-*). Results are summarized (not full blobs),
size-capped, and marked as untrusted data before they go to the LLM - see
guard.py.
"""

from __future__ import annotations

from typing import Any

from config import cfg
from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.indexer.queries import (
    build_alert_query,
    field_caps_summary,
    search_body,
    to_range_expr,
)


def _summarize_alert(doc: dict[str, Any], index: str) -> dict[str, Any]:
    """Key fields only - keeps tool output small and shrinks the injection
    surface (raw full_log is kept but size-capped)."""
    rule = doc.get("rule") or {}
    agent = doc.get("agent") or {}
    data = doc.get("data") or {}
    full_log = str(doc.get("full_log") or "")[:400]
    return {
        "id": doc.get("id") or doc.get("_id", ""),
        "index": index,
        "timestamp": doc.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups") or [],
        "mitre": rule.get("mitre") or {},
        "agent": agent.get("name"),
        "agent_id": agent.get("id"),
        "src_ip": data.get("srcip") or data.get("src_ip"),
        "src_port": data.get("srcport"),
        "dst_ip": data.get("dstip") or data.get("dst_ip"),
        "dst_port": data.get("dstport"),
        "user": data.get("user")
        or data.get("srcuser")
        or data.get("winuser")
        or data.get("linuxuser"),
        "full_log": full_log,
    }


class SearchWazuhAlerts(BaseWazuhTool):
    name = "search_wazuh_alerts"
    description = (
        "Search Wazuh alerts (wazuh-alerts-* index). Use for: 'show me alerts', "
        "'top attacking IPs', 'alerts for IP X', 'all brute-force alerts'. Supports a "
        "free-text query, rule group/level/rule-id filters, agent and IP filters, and a "
        "time window (e.g. -24h, 7d). Returns summarized alerts."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "free-text OpenSearch query (matches rule/groups/full_log)",
            },
            "group": {
                "type": "string",
                "description": "rule group filter, e.g. 'web', 'authentication_failures', 'attack'",
            },
            "agent": {"type": "string", "description": "agent name filter"},
            "src_ip": {"type": "string", "description": "source IP filter (data.srcip)"},
            "level_min": {
                "type": "integer",
                "description": "minimum rule level (0-15) - e.g. 9 for high+",
            },
            "level_max": {"type": "integer", "description": "maximum rule level"},
            "rule_id": {"type": "string", "description": "specific Wazuh rule id"},
            "time_range": {
                "type": "string",
                "description": "time window, e.g. -24h, 7d, 30d. Default -24h",
            },
            "size": {"type": "integer", "description": "max alerts to return (capped)"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        size = min(int(p.get("size", 20) or 20), cfg.TOOL_QUERY_SIZE_LIMIT)
        query = build_alert_query(
            q=p.get("query"),
            group=p.get("group"),
            agent=p.get("agent"),
            src_ip=p.get("src_ip"),
            level_min=p.get("level_min"),
            level_max=p.get("level_max"),
            rule_id=p.get("rule_id"),
            time_range=p.get("time_range", "-24h"),
        )
        body = search_body(query, size=size)
        docs = ctx.indexer.hits("wazuh-alerts-*", body)
        alerts = [_summarize_alert(d, "wazuh-alerts-*") for d in docs]
        return {"count": len(alerts), "alerts": alerts}


class SearchWazuhEvents(BaseWazuhTool):
    name = "search_wazuh_events"
    description = (
        "Search raw Wazuh events (wazuh-archives-* index) - the pre-rule log stream. "
        "Use when alerts are too coarse: see actual log lines, decoder output, "
        "authentication attempts that never reached a rule. Same filters as "
        "search_wazuh_alerts."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "description": "free-text query across the raw event"},
            "agent": {"type": "string"},
            "src_ip": {"type": "string"},
            "type": {
                "type": "string",
                "description": "event type filter e.g. 'authentication', 'web'",
            },
            "time_range": {"type": "string", "description": "default -24h"},
            "size": {"type": "integer"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        size = min(int(p.get("size", 20) or 20), cfg.TOOL_QUERY_SIZE_LIMIT)
        must: list[dict[str, Any]] = []
        if p.get("query"):
            must.append({"query_string": {"query": p["query"], "default_operator": "AND"}})
        if p.get("agent"):
            must.append({"term": {"agent.name": p["agent"]}})
        if p.get("src_ip"):
            must.append({"term": {"data.srcip": p["src_ip"]}})
        if p.get("type"):
            must.append({"term": {"data.type": p["type"]}})
        expr = to_range_expr(p.get("time_range", "-24h"))
        if expr:
            must.append({"range": {"timestamp": {"gte": expr}}})
        query: dict[str, Any] = {"bool": {"filter": must}} if must else {"match_all": {}}
        docs = ctx.indexer.hits("wazuh-archives-*", search_body(query, size=size))
        events = [_summarize_alert(d, "wazuh-archives-*") for d in docs]
        return {"count": len(events), "events": events}


class GetWazuhAlert(BaseWazuhTool):
    name = "get_wazuh_alert"
    description = (
        "Get one Wazuh alert by its id (e.g. 1790164005.1981881) with full detail "
        "including all raw fields - use for 'why did this alert trigger'."
    )
    input_schema = {
        "type": "object",
        "properties": {"alert_id": {"type": "string"}},
        "required": ["alert_id"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        query = {"bool": {"filter": [{"term": {"id": p["alert_id"]}}]}}
        docs = ctx.indexer.hits("wazuh-alerts-*", search_body(query, size=5, sort_by="_score"))
        for d in docs:
            if str(d.get("id")) == str(p["alert_id"]):
                return {"alert": d}
        # fall back to _id match
        docs2 = ctx.indexer.hits(
            "wazuh-alerts-*", {"size": 5, "query": {"ids": {"values": [p["alert_id"]]}}}
        )
        if docs2:
            return {"alert": docs2[0]}
        raise ToolError(f"Alert {p['alert_id']} not found in wazuh-alerts-*.")


class SearchWazuhIndex(BaseWazuhTool):
    name = "search_wazuh_index"
    description = (
        "Run a raw OpenSearch query body against a Wazuh index (default wazuh-alerts-*). "
        "For advanced/custom queries (aggregations, nested filters) the other tools "
        "can't express. The query body must be valid OpenSearch JSON with a 'query' key."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "index": {"type": "string", "description": "index or pattern, default wazuh-alerts-*"},
            "query_body": {
                "type": "object",
                "description": "OpenSearch search body (must include 'query' + optional 'size', 'aggs', 'sort')",
            },
            "summarize": {
                "type": "boolean",
                "description": "summarize alerts (default true); set false to get raw docs",
            },
        },
        "required": ["query_body"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        body = p.get("query_body")
        if not isinstance(body, dict) or "query" not in body:
            raise ToolError("query_body must be a JSON object containing an OpenSearch 'query'.")
        index = p.get("index") or "wazuh-alerts-*"
        body = dict(body)
        size = int(body.get("size", 20) or 20)
        body["size"] = min(size, cfg.TOOL_QUERY_SIZE_LIMIT)
        resp = ctx.indexer.search(index, body)
        hits = resp.get("hits", {}).get("hits", [])
        out = []
        for h in hits:
            src = h.get("_source") or {}
            out.append(
                _summarize_alert({**src, "_id": h.get("_id", "")}, index)
                if p.get("summarize", True)
                else src
            )
        return {
            "count": len(out),
            "total_matched": resp.get("hits", {}).get("total", {}).get("value", 0),
            "aggregations": resp.get("aggregations"),
            "hits": out,
        }


class GetIndexSchema(BaseWazuhTool):
    name = "get_index_schema"
    description = (
        "Inspect the Wazuh indexer schema (field name -> type via _field_caps) for an "
        "index. Use before building dashboards or detection-gap analysis to see which "
        "fields actually exist (never assume a field exists)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "index": {"type": "string", "description": "index or pattern, default wazuh-alerts-*"},
            "limit": {"type": "integer", "description": "max fields returned"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        return field_caps_summary(
            ctx.indexer, p.get("index") or "wazuh-alerts-*", limit=int(p.get("limit", 400) or 400)
        )


class VerifyOpenSearchQuery(BaseWazuhTool):
    name = "verify_opensearch_query"
    description = (
        "Validate an OpenSearch query body against the indexer (size-0 execution) and "
        "report how many documents it matches. Use before proposing dashboard "
        "visualizations to prove the query is valid and has data."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "index": {"type": "string", "description": "default wazuh-alerts-*"},
            "query_body": {"type": "object", "description": "OpenSearch search body with 'query'"},
        },
        "required": ["query_body"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        body = p.get("query_body")
        if not isinstance(body, dict) or "query" not in body:
            raise ToolError("query_body must be a JSON object containing an OpenSearch 'query'.")
        from tools.indexer.queries import verify_opensearch_query as _verify

        return _verify(ctx.indexer, p.get("index") or "wazuh-alerts-*", body)
