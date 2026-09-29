"""
Turn a free-text dashboard intent into a concrete, verifiable panel plan.

WHY THIS EXISTS
`DesignDetectionDashboard` used to take `focus` as a closed enum
(web | ssh | network | general) and ignore everything else. Asking for
"ssh failed login from private to private ip" produced the same seven
generic panels as asking for anything else, with the request text parked in
the proposal's `reason` field - the dashboard looked identical no matter what
you typed. A dashboard that cannot express what you actually asked for is
worse than no dashboard.

THE DIVISION OF LABOUR
The model is NOT allowed to emit OpenSearch DSL or visState. It chooses:

  * a title,
  * zero or more filter clauses, expressed against a CLOSED vocabulary of
    semantic field keys (see PLAN_FIELDS) and a closed set of operators,
  * a list of panels, each drawn from a small vocabulary (count / trend /
    breakdown / unique) over those same keys.

This module then maps keys to real index fields, drops anything the live
indexer schema does not actually have, and renders deterministic agg payloads.
That split is the point: the model contributes judgement (what did the user
actually mean), the code contributes correctness (only fields that exist,
only query shapes the indexer can run). Every resulting panel query is then
still verified against the real indexer by the caller, so an LLM plan can
never smuggle in an unverified panel.

If the model returns nothing usable the caller falls back to the legacy
`_panel_plan(focus, ...)` template, so this can only improve specificity -
it can never make the builder fail.
"""

from __future__ import annotations

import json
import re
from typing import Any

# Semantic key -> real Wazuh alert-document field. The model picks the KEY, so
# it can never invent a field name; `plan()` drops any key whose real field is
# missing from the live field_caps schema.
PLAN_FIELDS: dict[str, str] = {
    # network
    "src_ip": "data.srcip",
    "dst_ip": "data.dstip",
    "src_port": "data.srcport",
    "dst_port": "data.dstport",
    "protocol": "data.protocol",
    "country": "GeoLocation.country_name",
    "city": "GeoLocation.city_name",
    # identity
    "user": "data.user",
    "src_user": "data.srcuser",
    "dst_user": "data.dstuser",
    # rule / detection
    "rule_id": "rule.id",
    "rule_level": "rule.level",
    "rule_group": "rule.groups",
    "rule_description": "rule.description",
    "mitre_technique": "rule.mitre.technique",
    "mitre_tactic": "rule.mitre.tactic",
    "mitre_id": "rule.mitre.id",
    # source of the event
    "agent": "agent.name",
    "agent_ip": "agent.ip",
    "location": "location",
    "decoder": "decoder.name",
    "data_source": "data_source",
    # web
    "url": "data.url",
    "http_status": "data.id",
    # windows
    "win_event_id": "data.win.system.eventID",
    "win_process": "data.win.eventdata.image",
    "win_target_user": "data.win.eventdata.targetUserName",
    # file integrity (syscheck)
    "fim_path": "syscheck.path",
    "fim_event": "syscheck.event",
    # vulnerability detector
    "cve": "data.vulnerability.cve",
    "vuln_severity": "data.vulnerability.severity",
    "package": "data.vulnerability.package.name",
}

# Natural names a model reaches for -> the canonical key. Resolved before the
# schema check, so "status" or "mitre" works instead of being dropped.
FIELD_ALIASES: dict[str, str] = {
    "source_ip": "src_ip",
    "srcip": "src_ip",
    "source": "src_ip",
    "attacker_ip": "src_ip",
    "destination_ip": "dst_ip",
    "dstip": "dst_ip",
    "target_ip": "dst_ip",
    "source_port": "src_port",
    "destination_port": "dst_port",
    "port": "dst_port",
    "geo": "country",
    "source_country": "country",
    "country_name": "country",
    "username": "user",
    "account": "user",
    "target_user": "dst_user",
    "status": "http_status",
    "status_code": "http_status",
    "http_code": "http_status",
    "uri": "url",
    "path": "url",
    "request": "url",
    "mitre": "mitre_technique",
    "technique": "mitre_technique",
    "attack_technique": "mitre_technique",
    "tactic": "mitre_tactic",
    "technique_id": "mitre_id",
    "mitre_technique_id": "mitre_id",
    "rule": "rule_description",
    "description": "rule_description",
    "level": "rule_level",
    "severity": "rule_level",
    "group": "rule_group",
    "groups": "rule_group",
    "category": "rule_group",
    "host": "agent",
    "hostname": "agent",
    "agent_name": "agent",
    "endpoint": "agent",
    "event_id": "win_event_id",
    "eventid": "win_event_id",
    "windows_event_id": "win_event_id",
    "process": "win_process",
    "image": "win_process",
    "file": "fim_path",
    "file_path": "fim_path",
    "fim": "fim_event",
    "change_type": "fim_event",
    "vulnerability": "cve",
    "cve_id": "cve",
    "vulnerability_severity": "vuln_severity",
}

# Operators a filter clause may use. `cidr` exists for the "private to private"
# case: range-on-ip against a private CIDR, OR-ed together.
PLAN_OPS: tuple[str, ...] = ("term", "terms", "match_phrase", "cidr")

# Fields where `cidr` is meaningful (typed `ip` by the indexer).
_IP_FIELDS: frozenset[str] = frozenset({"src_ip", "dst_ip"})

_MAX_PANELS = 8
_MAX_VALUES = 6
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)

_SYSTEM = """You plan Wazuh security dashboards. You do NOT write OpenSearch DSL \
or visualization JSON - you choose intent, and a rendering layer builds the queries.

You are given a user's request and the alert fields that actually exist on the
index. Reply with ONE JSON object and nothing else.

Schema:
{
  "title": "<short dashboard title, Title Case>",
  "filters": [
    {"field": "<key>", "op": "term"|"terms"|"match_phrase"|"cidr",
     "values": ["<value>", ...]}
  ],
  "panels": [
    {"kind": "count"},
    {"kind": "trend"},
    {"kind": "breakdown", "field": "<key>", "vis": "bar"|"pie"},
    {"kind": "unique", "field": "<key>"}
  ],
  "notes": "<one sentence: what the dashboard shows and any assumption you made>"
}

Available field keys (use ONLY these): {fields}

Rules:
- A `count` and a `trend` panel are always worth having; include them.
- Then add breakdowns/uniques that match what the user actually asked about.
- Use `cidr` op only with src_ip/dst_ip keys. "private source to private
  destination" is TWO clauses: one on src_ip and one on dst_ip, each with the
  RFC1918 ranges ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"].
- Use `match_phrase` for free-text-ish matches (rule_group, rule_description),
  `term` for exact values you are confident about.
- Never invent a field key, an operator, or a panel kind outside this schema.
- Prefer FEWER panels that are specific over many generic ones. Never exceed 8.
- Reply with the JSON object only - no prose, no markdown fence."""


# --------------------------------------------------------------------------- #
def _parse_json_object(text: str) -> dict[str, Any] | None:
    """Pull a JSON object out of a model reply, tolerating fences/prose.

    Returns None on anything unusable so callers can fall back rather than
    raise - a bad plan must never break the builder."""
    if not text:
        return None
    candidate = _FENCE.sub("", str(text)).strip()
    # Trim any leading/trailing prose around the object.
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end <= start:
        return None
    for blob in (candidate[start : end + 1], candidate):
        try:
            parsed = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _clean_field(key: Any) -> str | None:
    if not isinstance(key, str):
        return None
    k = key.strip().lower().replace("-", "_").replace(" ", "_")
    k = FIELD_ALIASES.get(k, k)
    return k if k in PLAN_FIELDS else None


def plan_filters(raw: Any, schema: dict[str, str]) -> tuple[list[dict[str, Any]], list[str]]:
    """Validate + sanitize the model's filter clauses into a bool filter list.

    Drops any clause naming an unknown field key, an unknown operator, or a
    field absent from the live schema, and records why. A hallucinated filter
    is dropped, never passed through to the indexer."""
    filters: list[dict[str, Any]] = []
    dropped: list[str] = []
    for clause in raw if isinstance(raw, list) else []:
        if not isinstance(clause, dict):
            dropped.append("ignored a non-object filter clause")
            continue
        key = _clean_field(clause.get("field"))
        if key is None:
            dropped.append(f"unknown filter field {clause.get('field')!r} - clause dropped")
            continue
        if PLAN_FIELDS[key] not in schema:
            dropped.append(f"field {PLAN_FIELDS[key]!r} is not in the index schema - dropped")
            continue
        op = str(clause.get("op") or "term").strip().lower()
        if op not in PLAN_OPS:
            dropped.append(f"unknown filter op {op!r} - clause dropped")
            continue
        values = clause.get("values")
        if not isinstance(values, list) or not values:
            values = [clause.get("value")]
        values = [str(v).strip() for v in values if v not in (None, "")][:_MAX_VALUES]
        if not values:
            dropped.append(f"filter on {key!r} had no usable values - dropped")
            continue
        if op == "cidr":
            if key not in _IP_FIELDS:
                dropped.append(f"cidr op is only valid on src_ip/dst_ip, not {key!r} - dropped")
                continue
            clauses = [{"range": {PLAN_FIELDS[key]: v}} for v in values]
            # Multiple CIDRs are OR-ed: an alert is in-scope if ANY of them hits.
            filters.append({"bool": {"should": clauses, "minimum_should_match": 1}})
            continue
        if op == "terms":
            filters.append({"terms": {PLAN_FIELDS[key]: values}})
        elif op == "match_phrase":
            filters.append({"match_phrase": {PLAN_FIELDS[key]: values[0]}})
        else:  # term
            filters.append({"term": {PLAN_FIELDS[key]: values[0]}})
    return filters, dropped


def plan_panels(
    raw: Any,
    schema: dict[str, str],
    focus: str,
    time_range_expr: str | None,
    filters: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Turn the model's panel picks into concrete, renderable panel specs.

    Every panel carries the same base query: the time window PLUS the intent
    filters, so a dashboard about "private-to-private SSH failures" only ever
    counts those alerts. Always leads with `alert_count` + `alert_trend` so
    every dashboard has a volume and a shape; the model's picks are appended
    (deduped, capped)."""
    base_filter: list[dict[str, Any]] = []
    if time_range_expr:
        base_filter.append({"range": {"timestamp": {"gte": time_range_expr}}})
    for clause in filters or []:
        base_filter.append(clause)

    def q() -> dict[str, Any]:
        return {"bool": {"filter": list(base_filter)}}

    dropped: list[str] = []
    picked: list[dict[str, Any]] = [
        {
            "slug": "alert_count",
            # Not "- general": this panel is already scoped by the intent filters.
            "title": "Matching alerts" if filters else "Alert volume",
            "vis_type": "metric",
            "aggs": [_count_agg()],
            "query": q(),
        },
        {
            "slug": "alert_trend",
            "title": "Alert trend",
            "vis_type": "line",
            "aggs": [_count_agg(), _date_hist_agg()],
            "query": q(),
        },
    ]
    seen = {"alert_count", "alert_trend"}

    for spec in raw if isinstance(raw, list) else []:
        if len(picked) >= _MAX_PANELS:
            break
        if not isinstance(spec, dict):
            continue
        kind = str(spec.get("kind") or "").strip().lower()
        key = _clean_field(spec.get("field"))
        field = PLAN_FIELDS.get(key) if key else None
        if kind in ("count", "trend"):
            continue  # already the first two panels
        if kind in ("breakdown", "unique") and not key:
            dropped.append(f"{kind} panel had no usable field - dropped")
            continue
        if kind in ("breakdown", "unique") and field not in schema:
            dropped.append(f"panel field {field!r} is not in the index schema - dropped")
            continue
        if kind == "breakdown":
            vis = str(spec.get("vis") or "bar").strip().lower()
            slug = f"{kind}_{key}"
            if slug in seen:
                continue
            seen.add(slug)
            picked.append(
                {
                    "slug": slug,
                    "title": f"{_humanize(key)} ({'pie' if vis == 'pie' else 'bar'})",
                    "vis_type": "pie" if vis == "pie" else "bar",
                    "aggs": [_count_agg(), _terms_agg(field)],
                    "query": q(),
                }
            )
        elif kind == "unique":
            slug = f"unique_{key}"
            if slug in seen:
                continue
            seen.add(slug)
            picked.append(
                {
                    "slug": slug,
                    "title": f"Unique {_noun(key)}",
                    "vis_type": "metric",
                    "aggs": [_count_agg(), _cardinality_agg(field)],
                    "query": q(),
                }
            )
        else:
            dropped.append(f"unknown panel kind {kind!r} - dropped")

    if len(picked) < 3:
        # The model gave us nothing usable: fall back to the generic shape so
        # the dashboard is still coherent rather than two empty panels.
        for extra in _fallback_panels(schema, base_filter, seen):
            if len(picked) >= _MAX_PANELS:
                break
            picked.append(extra)
    return picked, dropped


def _fallback_panels(
    schema: dict[str, str], base_filter: list[dict[str, Any]], seen: set[str]
) -> list[dict[str, Any]]:
    """The generic extras used when the model's picks were unusable."""

    def q() -> dict[str, Any]:
        return {"bool": {"filter": list(base_filter)}}

    out: list[dict[str, Any]] = []
    for key, slug, vis, aggs in (
        ("rule_level", "level_dist", "bar", lambda f: [_count_agg(), _terms_agg(f, size=15)]),
        ("rule_group", "top_groups", "bar", lambda f: [_count_agg(), _terms_agg(f, size=6)]),
        ("src_ip", "top_src_ips", "pie", lambda f: [_count_agg(), _terms_agg(f, size=8)]),
    ):
        field = PLAN_FIELDS[key]
        if field not in schema or slug in seen:
            continue
        seen.add(slug)
        out.append(
            {
                "slug": slug,
                "title": _humanize(key),
                "vis_type": vis,
                "aggs": aggs(field),
                "query": q(),
            }
        )
    return out


# --------------------------------------------------------------------------- #
def _count_agg() -> dict[str, Any]:
    return {
        "id": "1",
        "enabled": True,
        "type": "count",
        "schema": "metric",
        "params": {"customLabel": "alerts"},
    }


def _terms_agg(field: str, size: int = 8) -> dict[str, Any]:
    return {
        "id": "2",
        "enabled": True,
        "type": "terms",
        "schema": "segment",
        "params": {
            "field": field,
            "size": size,
            "order": "desc",
            "orderBy": "1",
            "customLabel": field.split(".")[-1],
        },
    }


def _cardinality_agg(field: str) -> dict[str, Any]:
    return {
        "id": "2",
        "enabled": True,
        "type": "cardinality",
        "schema": "metric",
        "params": {"field": field, "customLabel": f"unique {field.split('.')[-1]}"},
    }


def _date_hist_agg() -> dict[str, Any]:
    return {
        "id": "2",
        "enabled": True,
        "type": "date_histogram",
        "schema": "segment",
        "params": {
            "field": "timestamp",
            "interval": "auto",
            "includeEmptyRows": True,
            "customLabel": "time",
        },
    }


_NOUNS: dict[str, str] = {
    "src_ip": "source IPs",
    "dst_ip": "destination IPs",
    "src_port": "source ports",
    "dst_port": "destination ports",
    "protocol": "protocols / methods",
    "country": "source countries",
    "city": "cities",
    "user": "users",
    "src_user": "source users",
    "dst_user": "target users",
    "rule_id": "rules",
    "rule_level": "alert levels",
    "rule_group": "rule groups",
    "rule_description": "rule descriptions",
    "mitre_technique": "MITRE techniques",
    "mitre_tactic": "MITRE tactics",
    "mitre_id": "MITRE technique IDs",
    "agent": "agents",
    "agent_ip": "agent IPs",
    "location": "log locations",
    "decoder": "decoders",
    "data_source": "data sources",
    "url": "URLs",
    "http_status": "HTTP status codes",
    "win_event_id": "Windows event IDs",
    "win_process": "processes",
    "win_target_user": "target accounts",
    "fim_path": "changed files",
    "fim_event": "file change types",
    "cve": "CVEs",
    "vuln_severity": "vulnerability severities",
    "package": "vulnerable packages",
}


def _noun(key: str) -> str:
    return _NOUNS.get(key, key.replace("_", " "))


def _humanize(key: str) -> str:
    """Breakdown title for a key."""
    if key == "rule_level":
        return "Alert level distribution"
    return "Top " + _noun(key)


# --------------------------------------------------------------------------- #
def plan_dashboard(
    ctx: Any, intent: str, schema: dict[str, str], *, time_range_expr: str | None, focus: str
) -> dict[str, Any]:
    """Ask the model to plan the dashboard, then sanitize the result.

    Returns {"ok": bool, "title"?, "filters", "panels", "notes",
    "dropped", "error"?}. Never raises: a provider outage or unusable reply
    comes back as ok=False so the caller can fall back to the template."""
    intent = (intent or "").strip()
    if not intent:
        return {"ok": False, "error": "empty intent", "filters": [], "panels": [], "dropped": []}

    # Only offer the model keys whose real field actually exists on this index,
    # so it is never tempted to plan a panel the schema can't support.
    usable_keys = {k: PLAN_FIELDS[k] for k in sorted(PLAN_FIELDS) if PLAN_FIELDS[k] in schema}
    schema_hints = (
        ", ".join(f"{k} -> {f} ({schema[f]})" for k, f in usable_keys.items())
        or "none of the known fields are present on this index"
    )
    user_msg = f"Field keys available on this index: {schema_hints}\n\nUser request: {intent}"
    try:
        # .replace(), not .format(): the prompt embeds a literal JSON schema, so
        # str.format would try to interpret every brace in it as a field.
        system = _SYSTEM.replace("{fields}", ", ".join(usable_keys) or "(none)")
        reply = ctx.get_llm().chat_text(
            system=system,
            messages=[{"role": "user", "content": user_msg}],
            max_tokens=2000,
        )
    except Exception as e:  # noqa: BLE001 - a planner outage must not break the builder
        return {
            "ok": False,
            "error": f"LLM planner failed: {e}",
            "filters": [],
            "panels": [],
            "dropped": [],
        }

    obj = _parse_json_object(reply)
    if obj is None:
        return {
            "ok": False,
            "error": "the planner did not return a JSON object",
            "raw": str(reply)[:500],
            "filters": [],
            "panels": [],
            "dropped": [],
        }

    filters, dropped = plan_filters(obj.get("filters"), schema)
    # A plan that lost every filter the model asked for is not worth trusting -
    # the user would get a generic dashboard that silently ignores their words.
    asked_for_filters = isinstance(obj.get("filters"), list) and bool(obj.get("filters"))
    if asked_for_filters and not filters:
        return {
            "ok": False,
            "error": "every filter the planner proposed was unusable",
            "dropped": dropped,
            "filters": [],
            "panels": [],
        }
    panels, panel_dropped = plan_panels(obj.get("panels"), schema, focus, time_range_expr, filters)
    title = str(obj.get("title") or "").strip()[:120]
    return {
        "ok": True,
        "title": title,
        "filters": filters,
        "panels": panels,
        "notes": str(obj.get("notes") or "")[:400],
        "dropped": dropped + panel_dropped,
    }
