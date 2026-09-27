"""
Deterministic investigation workflows for the AI SOC engineer.

These are the plumbing behind the example end-to-end requests:

    "Investigate the top attacking IPs against my web servers in the last 24h"
        -> top_attacking_ips(service/group, time_range)
    "Investigate this IP" / "tell me about 203.0.113.7"
        -> investigate_ip(ip, time_range)
    "Explique por qué se disparó esta alerta / why did this alert trigger"
        -> why_did_alert_trigger(alert_id)

Everything is data-driven from the indexer (wazuh-alerts-* / wazuh-archives-*)
via typed OpenSearch aggregations - no LLM guessing about counts. The agent
calls these as tools and narrates the evidence it actually got back.
"""

from __future__ import annotations

import time
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.indexer.queries import to_range_expr


def _range_clause(time_range: str | None) -> dict[str, Any]:
    expr = to_range_expr(time_range)
    return {"range": {"timestamp": {"gte": expr}}} if expr else {"match_all": {}}


# --------------------------------------------------------------------------- #
def top_attacking_ips(
    indexer: Any,
    *,
    group: str = "web",
    time_range: str = "-24h",
    size: int = 10,
    fallback_groups: tuple[str, ...] = ("web", "attack"),
) -> dict[str, Any]:
    """Rank source IPs by alert volume, optionally restricted to a rule group
    (e.g. 'web' / 'attack'). Returns per-IP: alert count, rule groups, top
    rules, max level, first/last seen, affected agents."""

    def run_for(g: str) -> dict[str, Any]:
        body = {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        _range_clause(time_range),
                        {"term": {"rule.groups": g}},
                    ]
                }
            },
            "aggs": {
                "top_src": {
                    "terms": {"field": "data.srcip", "size": size},
                    "aggs": {
                        "groups": {"terms": {"field": "rule.groups", "size": 6}},
                        "rules": {"terms": {"field": "rule.id", "size": 6}},
                        "max_level": {"max": {"field": "rule.level"}},
                        "first_seen": {"min": {"field": "timestamp"}},
                        "last_seen": {"max": {"field": "timestamp"}},
                        "agents": {"terms": {"field": "agent.name", "size": 6}},
                    },
                },
            },
        }
        resp = indexer.search("wazuh-alerts-*", body)
        buckets = (resp.get("aggregations") or {}).get("top_src", {}).get("buckets", [])
        return [
            {
                "src_ip": b.get("key"),
                "alert_count": b.get("doc_count", 0),
                "max_level": (b.get("max_level") or {}).get("value"),
                "first_seen": (b.get("first_seen") or {}).get("value_as_string"),
                "last_seen": (b.get("last_seen") or {}).get("value_as_string"),
                "rule_groups": [x.get("key") for x in (b.get("groups") or {}).get("buckets", [])],
                "top_rules": [
                    {
                        "id": x.get("key"),
                        "hits": x.get("doc_count", 0),
                    }
                    for x in (b.get("rules") or {}).get("buckets", [])
                ],
                "agents": [x.get("key") for x in (b.get("agents") or {}).get("buckets", [])],
            }
            for b in buckets
        ]

    rows = run_for(group)
    if not rows and fallback_groups:
        for g in fallback_groups:
            rows = run_for(g)
            if rows:
                break
    return {"group": group, "time_range": time_range, "count": len(rows), "ips": rows}


# --------------------------------------------------------------------------- #
def investigate_ip(indexer: Any, *, ip: str, time_range: str = "-24h") -> dict[str, Any]:
    """Deep-dive on one source IP: aggregate alerts + raw events, build a
    timeline, enumerate targets/rules/agents/ports and MITRE techniques."""
    must: list[dict[str, Any]] = [_range_clause(time_range)]
    must.append({"term": {"data.srcip": ip}})
    alert_body = {
        "size": 0,
        "query": {"bool": {"filter": must}},
        "aggs": {
            "rule_groups": {"terms": {"field": "rule.groups", "size": 10}},
            "rules": {"terms": {"field": "rule.id", "size": 10}},
            "agents": {"terms": {"field": "agent.name", "size": 10}},
            "dst_ips": {"terms": {"field": "data.dstip", "size": 10}},
            "dst_ports": {"terms": {"field": "data.dstport", "size": 10}},
            "max_level": {"max": {"field": "rule.level"}},
            "first_seen": {"min": {"field": "timestamp"}},
            "last_seen": {"max": {"field": "timestamp"}},
            "timeline": {
                "date_histogram": {"field": "timestamp", "fixed_interval": "3h"},
                "aggs": {"max_level": {"max": {"field": "rule.level"}}},
            },
            "mitre": {"terms": {"field": "rule.mitre.id", "size": 10}},
        },
    }
    resp = indexer.search("wazuh-alerts-*", alert_body)
    aggs = resp.get("aggregations") or {}
    total = resp.get("hits", {}).get("total", {}).get("value", 0)

    # sample raw events from the archive for context (what actually happened)
    events = []
    try:
        ev = indexer.search(
            "wazuh-archives-*",
            {
                "size": 10,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "filter": [
                            _range_clause(time_range),
                            {"term": {"data.srcip": ip}},
                        ]
                    }
                },
            },
        )
        for h in ev.get("hits", {}).get("hits", []):
            src = h.get("_source") or {}
            events.append(
                {
                    "timestamp": src.get("timestamp"),
                    "location": src.get("location"),
                    "full_log": str(src.get("full_log") or "")[:400],
                    "decoder": (src.get("decoder") or {}).get("name"),
                }
            )
    except Exception:  # noqa: BLE001 - archives may be empty/disabled
        pass

    return {
        "ip": ip,
        "time_range": time_range,
        "total_alerts": total,
        "max_level": (aggs.get("max_level") or {}).get("value"),
        "first_seen": (aggs.get("first_seen") or {}).get("value_as_string"),
        "last_seen": (aggs.get("last_seen") or {}).get("value_as_string"),
        "rule_groups": [
            (b.get("key"), b.get("doc_count"))
            for b in (aggs.get("rule_groups") or {}).get("buckets", [])
        ],
        "top_rules": [
            {
                "id": b.get("key"),
                "hits": b.get("doc_count", 0),
                "level": next(
                    (x.get("key") for x in (b.get("levels") or {}).get("buckets", [])), None
                ),
            }
            for b in (aggs.get("rules") or {}).get("buckets", [])
        ],
        "agents_hit": [b.get("key") for b in (aggs.get("agents") or {}).get("buckets", [])],
        "targets": [b.get("key") for b in (aggs.get("dst_ips") or {}).get("buckets", [])],
        "dst_ports": [b.get("key") for b in (aggs.get("dst_ports") or {}).get("buckets", [])],
        "mitre_techniques": [b.get("key") for b in (aggs.get("mitre") or {}).get("buckets", [])],
        "timeline": [
            {
                "at": b.get("key_as_string"),
                "alerts": b.get("doc_count", 0),
                "max_level": (b.get("max_level") or {}).get("value"),
            }
            for b in (aggs.get("timeline") or {}).get("buckets", [])
        ],
        "sample_events": events,
    }


# --------------------------------------------------------------------------- #
def why_did_alert_trigger(indexer: Any, *, alert_id: str) -> dict[str, Any]:
    """Pull one alert + explain it: matched rule, MITRE, and surrounding raw
    events from the same source around the same time."""
    alert = None
    resp = indexer.search(
        "wazuh-alerts-*",
        {
            "size": 5,
            "query": {"bool": {"filter": [{"term": {"id": alert_id}}]}},
            "sort": [{"timestamp": {"order": "desc"}}],
        },
    )
    for h in resp.get("hits", {}).get("hits", []):
        src = h.get("_source") or {}
        if str(src.get("id")) == str(alert_id):
            alert = src
            break
    if alert is None:
        raise ToolError(f"Alert {alert_id} not found in wazuh-alerts-* (id field match).")
    rule = alert.get("rule") or {}

    # surrounding raw events from the archive (same srcip/agent, +-10min)
    related: list[dict[str, Any]] = []
    src_ip = (alert.get("data") or {}).get("srcip")
    agent = (alert.get("agent") or {}).get("name")
    ts = alert.get("timestamp")
    if ts:
        try:
            start = int(time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))) - 600
            end = int(time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))) + 600
            must = [{"range": {"timestamp": {"gte": f"{start}s", "lte": f"{end}s"}}}]
            if src_ip:
                must.append({"term": {"data.srcip": src_ip}})
            elif agent:
                must.append({"term": {"agent.name": agent}})
            r = indexer.search(
                "wazuh-archives-*",
                {
                    "size": 20,
                    "sort": [{"timestamp": {"order": "desc"}}],
                    "query": {"bool": {"filter": must}},
                },
            )
            related = [
                {
                    "timestamp": (h.get("_source") or {}).get("timestamp"),
                    "location": (h.get("_source") or {}).get("location"),
                    "full_log": str((h.get("_source") or {}).get("full_log") or "")[:300],
                }
                for h in r.get("hits", {}).get("hits", [])
            ]
        except Exception:  # noqa: BLE001
            pass

    return {
        "alert_id": alert_id,
        "timestamp": alert.get("timestamp"),
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups") or [],
        "mitre": rule.get("mitre") or {},
        "agent": (alert.get("agent") or {}).get("name"),
        "full_log": str(alert.get("full_log") or "")[:600],
        "data": alert.get("data") or {},
        "related_events": related[:10],
    }


# --------------------------------------------------------------------------- #
# tools exposing the workflows to the LLM
# --------------------------------------------------------------------------- #
class InvestigateIP(BaseWazuhTool):
    name = "investigate_ip"
    permission = Permission.READ
    description = (
        "Deep investigation of one source IP across Wazuh alerts and raw events: "
        "alert volume, rule groups/rules fired, max level, targets, ports, MITRE "
        "techniques, a timeline, and sample raw events. Use for 'investigate this IP' "
        "or 'tell me about 203.0.113.7'."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "ip": {"type": "string", "description": "the source IP to investigate"},
            "time_range": {"type": "string", "description": "default -24h, e.g. 7d"},
        },
        "required": ["ip"],
    }

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        return investigate_ip(ctx.indexer, ip=p["ip"], time_range=p.get("time_range", "-24h"))


class TopAttackingIPs(BaseWazuhTool):
    name = "top_attacking_ips"
    permission = Permission.READ
    description = (
        "Rank source IPs by alert volume over a time window, restricted to a rule "
        "group when given (default 'web' = web server attacks; also tries 'attack'). "
        "Returns per-IP counts, rule groups, top rules, max level, first/last seen. "
        "Use for 'top attacking IPs against my web servers in the last 24h'."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "group": {
                "type": "string",
                "description": "rule group to restrict to, e.g. web, attack, authentication_failures",
            },
            "time_range": {"type": "string", "description": "default -24h"},
            "size": {"type": "integer", "description": "how many IPs (default 10)"},
        },
        "required": [],
    }

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        size = min(int(p.get("size", 10) or 10), 50)
        return top_attacking_ips(
            ctx.indexer,
            group=p.get("group") or "web",
            time_range=p.get("time_range", "-24h"),
            size=size,
        )


class WhyDidAlertTrigger(BaseWazuhTool):
    name = "why_did_alert_trigger"
    permission = Permission.READ
    description = (
        "Explain one alert: matched rule + level + groups + MITRE, the raw log, and "
        "surrounding events from the same source. Use for 'why did this alert fire' "
        "or 'explain alert <id>'."
    )
    input_schema = {
        "type": "object",
        "properties": {"alert_id": {"type": "string"}},
        "required": ["alert_id"],
    }

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        return why_did_alert_trigger(ctx.indexer, alert_id=p["alert_id"])


TOOLS = [InvestigateIP, TopAttackingIPs, WhyDidAlertTrigger]
