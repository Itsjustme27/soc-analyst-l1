"""
Dashboard engineering workflow for the AI SOC engineer.

Turns a request like "create a dashboard for web server attacks" into an
evidence-backed, human-approvable dashboard proposal:

  1. Inspect the indexer schema (field_caps) and verify each panel's OpenSearch
     query actually matches data (size-0 count) - the evidence for the panel.
  2. Compose deterministic visualization payloads (agg-based visState) +
     dashboard panelsJSON from validated fields only.
  3. Propose the bundle through the Approval Center. After approval, execution
     creates each visualization then the dashboard via the OpenSearch
     Dashboards saved-objects API and reports the server-confirmed ids.

Best-effort by design: the Wazuh dashboard (port 443, admin/admin in the
bundled stack) may be unreachable or configured differently - the engine never
claims a dashboard was created unless the dashboards server returned the saved
object. Dashboard creation is PROPOSE; deletion is EXECUTE.
"""

from __future__ import annotations

import json
import re
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.dashboard import osd_objects as osd
from tools.dashboard.client import dashboards_request
from tools.indexer.queries import search_body, verify_opensearch_query

_INDEX = "wazuh-alerts-*"
_PANEL_LIMIT = 8
# Index families that contain no alert documents: none of the panel fields
# (rule.*, data.srcip, agent.name, timestamp) exist there, so a dashboard
# bound to them renders empty or errors. Never selected for alert panels.
_NON_ALERT_PATTERN_HINTS = ("statistics", "archives", "monitoring", "sample-data")


# --------------------------------------------------------------------------- #
def _find_index_pattern() -> str | None:
    """Discover the Wazuh *alerts* index pattern id from the dashboards server.

    Only an alerts-capable pattern is acceptable for alert panels: statistics /
    archives / monitoring indices carry none of the alert fields the panels use.
    Those families are rejected even when the API lists them first (which is how
    a proposal could previously end up bound to 'wazuh-statistics-*'). Returns
    None when unreachable or no alerts pattern is found - the caller falls back
    to the conventional 'wazuh-alerts-*' id."""
    try:
        resp = dashboards_request(
            "GET",
            "/api/saved_objects/_find",
            params={"type": "index-pattern", "per_page": 50},
        )
    except Exception:  # noqa: BLE001 - best-effort discovery
        return None
    items = resp.get("saved_objects") or resp.get("objects") or []

    def text(item: dict[str, Any]) -> str:
        attrs = item.get("attributes") or {}
        return f"{item.get('id') or ''} {attrs.get('title') or ''}".lower()

    # 1) a pattern that is clearly the alerts pattern (id and/or title).
    for item in items:
        t = text(item)
        if "alerts" in t or "wazuh-alerts" in t:
            return item.get("id")
    # 2) best-effort: any wazuh-ish pattern, never a non-alert family.
    fallback: str | None = None
    for item in items:
        t = text(item)
        if any(h in t for h in _NON_ALERT_PATTERN_HINTS):
            continue
        if "wazuh" in t or "filebeat" in t or "index-pattern" in t:
            fallback = fallback or item.get("id")
    return fallback


def _index_pattern_object(index_pattern_id: str | None) -> dict[str, Any] | None:
    """Fetch the index-pattern saved object itself, so panel fields can be
    checked against what the pattern actually knows about (its cached
    `fields` list) before anything is created.

    Best-effort like `_find_index_pattern`: any failure (unreachable server,
    404, malformed payload) returns None rather than raising, so the *design*
    step degrades gracefully. The *execute* step (below) treats a None result
    here as fatal, since writing panels against an index pattern that does
    not exist on the target dashboards server would create an unresolvable
    dashboard.
    """
    if not index_pattern_id:
        return None
    try:
        obj = dashboards_request("GET", f"/api/saved_objects/index-pattern/{index_pattern_id}")
    except Exception:  # noqa: BLE001 - best-effort discovery
        return None
    if not isinstance(obj, dict) or obj.get("error") or (obj.get("statusCode") or 200) >= 400:
        return None
    return obj


def _agg_fields(vis_attrs: dict[str, Any]) -> set[str]:
    """The set of field names a visualization's aggs actually query, pulled
    back out of its visState - used to check those fields exist on the
    target index pattern before execution."""
    try:
        vs = json.loads(vis_attrs["visState"])
    except (KeyError, TypeError, ValueError):
        return set()
    return {
        field for agg in vs.get("aggs") or [] if (field := (agg.get("params") or {}).get("field"))
    }


# --------------------------------------------------------------------------- #
def _panel_plan(focus: str, schema: dict[str, str]) -> list[dict[str, Any]]:
    """Deterministic panel list for a focus. Each panel: slug, title, vis_type,
    aggs (agg-based visState), query (OpenSearch body used to verify)."""
    has_ip = "data.srcip" in schema
    has_agent = "agent.name" in schema
    filter_term: dict[str, Any] | None = None
    if focus == "web":
        filter_term = {"term": {"rule.groups": "web"}}
    elif focus == "ssh":
        filter_term = {"term": {"rule.groups": "authentication_failures"}}
    elif focus == "network":
        filter_term = {"term": {"rule.groups": "attack"}}

    base_query: dict[str, Any] = {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-7d"}}}]}}
    if filter_term:
        base_query["bool"]["filter"].append(filter_term)

    def q() -> dict[str, Any]:
        return json.loads(json.dumps(base_query))

    metric_aggs = [
        {
            "id": "1",
            "enabled": True,
            "type": "count",
            "schema": "metric",
            "params": {"customLabel": "alerts (7d)"},
        },
    ]
    panels: list[dict[str, Any]] = [
        {
            "slug": "alert_count",
            "title": f"Alert volume - {focus or 'all'}",
            "vis_type": "metric",
            "aggs": metric_aggs,
            "query": {"bool": {"filter": [base_query["bool"]["filter"][0]]}},
        },
        {
            "slug": "alert_trend",
            "title": "Alert trend (7d)",
            "vis_type": "line",
            "aggs": [
                {
                    "id": "1",
                    "enabled": True,
                    "type": "count",
                    "schema": "metric",
                    "params": {"customLabel": "alerts"},
                },
                {
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
                },
            ],
            "query": base_query,
        },
    ]
    if has_ip:
        panels.append(
            {
                "slug": "top_src_ips",
                "title": "Top source IPs",
                "vis_type": "pie",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {"customLabel": "alerts"},
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "data.srcip",
                            "size": 8,
                            "order": "desc",
                            "orderBy": "1",
                            "customLabel": "source IP",
                        },
                    },
                ],
                "query": q(),
            }
        )
    panels.extend(
        [
            {
                "slug": "top_groups",
                "title": "Top rule groups",
                "vis_type": "bar",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {"customLabel": "alerts"},
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "rule.groups",
                            "size": 6,
                            "order": "desc",
                            "orderBy": "1",
                            "customLabel": "group",
                        },
                    },
                ],
                "query": q(),
            },
            {
                "slug": "top_rules",
                "title": "Top rules",
                "vis_type": "bar",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {"customLabel": "alerts"},
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "rule.id",
                            "size": 8,
                            "order": "desc",
                            "orderBy": "1",
                            "customLabel": "rule id",
                        },
                    },
                ],
                "query": q(),
            },
            {
                "slug": "level_dist",
                "title": "Alert level distribution",
                "vis_type": "bar",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {"customLabel": "alerts"},
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "rule.level",
                            "size": 15,
                            "order": "desc",
                            "orderBy": "1",
                            "customLabel": "level",
                        },
                    },
                ],
                "query": q(),
            },
        ]
    )
    if has_agent:
        panels.append(
            {
                "slug": "top_agents",
                "title": "Top agents",
                "vis_type": "bar",
                "aggs": [
                    {
                        "id": "1",
                        "enabled": True,
                        "type": "count",
                        "schema": "metric",
                        "params": {"customLabel": "alerts"},
                    },
                    {
                        "id": "2",
                        "enabled": True,
                        "type": "terms",
                        "schema": "segment",
                        "params": {
                            "field": "agent.name",
                            "size": 6,
                            "order": "desc",
                            "orderBy": "1",
                            "customLabel": "agent",
                        },
                    },
                ],
                "query": q(),
            }
        )
    return panels[:_PANEL_LIMIT]


# --------------------------------------------------------------------------- #
class DesignDetectionDashboard(BaseWazuhTool):
    name = "design_detection_dashboard"
    description = (
        "Dashboard engineering workflow: build a Wazuh-dashboard proposal (alert volume, "
        "trend, top source IPs, rule groups, rules, levels, agents) from the real indexer "
        "schema, verifying each panel's query actually matches data. Focus: web | ssh | "
        "network | general. WRITE on execute: creates the visualizations + dashboard on the "
        "Wazuh dashboard server (best-effort; requires human approval)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "dashboard title, e.g. 'Web Server Attacks'",
            },
            "focus": {"type": "string", "description": "web | ssh | network | general"},
            "description": {"type": "string"},
            "time_range": {"type": "string", "description": "verification window (default -7d)"},
            "reason": {"type": "string", "description": "why this dashboard is needed"},
        },
        "required": ["title", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        focus = (p.get("focus") or "general").lower()
        if focus not in ("web", "ssh", "network", "general"):
            raise ToolError("focus must be one of: web | ssh | network | general")

        # 1) schema + panel plan
        try:
            schema = ctx.indexer.field_caps(_INDEX)
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Cannot read indexer schema - dashboard design aborted: {e}") from e
        panels = _panel_plan(focus, schema)

        # 2) verify each panel's query matches data (evidence)
        verified: list[dict[str, Any]] = []
        degraded: list[str] = []
        for panel in panels:
            check = verify_opensearch_query(
                ctx.indexer, _INDEX, search_body(panel["query"], size=0)
            )
            if not check.get("valid"):
                degraded.append(panel["slug"])
                check = {"valid": False, "error": check.get("error")}
            verified.append(
                {
                    "slug": panel["slug"],
                    "title": panel["title"],
                    "matched": check.get("matched", 0),
                    "note": check.get("error", "panel query verified"),
                }
            )

        # 3) index pattern (best-effort discovery + best-effort metadata for
        #    field validation - a missing/unreachable dashboards server here
        #    just means field checks are skipped at design time; execution
        #    below re-checks and blocks if the pattern truly can't be found).
        index_pattern = _find_index_pattern() or "wazuh-alerts-*"
        design_known_fields = osd.index_pattern_fields(_index_pattern_object(index_pattern) or {})

        # 4) build the full bundle (visualizations + dashboard panels) using
        # the validated osd_objects builders - correct vis types, complete
        # params, reference-form searchSourceJSON, and a dashboard whose
        # panels carry gridData/panelIndex/panelRefName + optionsJSON. See
        # tools/dashboard/osd_objects.py for why each of those matters.
        visualizations: list[dict[str, Any]] = []
        vis_issues: list[str] = []
        for panel in panels:
            attrs, refs = osd.build_visualization_attributes(
                panel["title"],
                panel["vis_type"],
                panel["aggs"],
                index_pattern,
                query=panel["query"],
                description="Generated by the AI SOC engineer (verified against wazuh-alerts-*)",
            )
            vis_obj = {
                "id": f"vis-{panel['slug']}",
                "type": "visualization",
                "version": 1,
                "attributes": attrs,
                "references": refs,
            }
            vis_issues.extend(osd.validate_visualization(vis_obj, design_known_fields))
            visualizations.append(
                {
                    "slug": panel["slug"],
                    "id": vis_obj["id"],
                    "title": panel["title"],
                    "vis_type": panel["vis_type"],
                    "obj": vis_obj,
                }
            )

        panels_json, panel_refs = osd.build_panels([v["id"] for v in visualizations])
        dashboard_id = "dashboard-" + re.sub(r"[^a-z0-9]+", "-", p["title"].lower()).strip("-")
        dash_obj = {
            "id": dashboard_id,
            "type": "dashboard",
            "version": 1,
            "attributes": osd.build_dashboard_attributes(
                p["title"],
                p.get("description") or f"Wazuh {focus} alert dashboard over {index_pattern}",
                panels_json,
            ),
            "references": panel_refs,
        }
        dash_issues = osd.validate_dashboard(dash_obj)
        saved_objects: list[dict[str, Any]] = [v["obj"] for v in visualizations] + [dash_obj]

        proposed = {
            # Re-running this same workflow with an approved context executes
            # deterministically: it re-verifies each panel query against the
            # indexer, creates the visualizations and the dashboard, and reports
            # only the server-confirmed ids. The payload is the tool's own input.
            "action": "design_detection_dashboard",
            "reason": p.get("reason", ""),
            "payload": {
                k: p[k] for k in ("title", "focus", "description", "time_range", "reason") if k in p
            },
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {
            "title": p["title"],
            "focus": focus,
            "index_pattern": index_pattern,
            "visualizations": [
                {"slug": v["slug"], "title": v["title"], "vis_type": v["vis_type"]}
                for v in visualizations
            ],
            "panelsJSON": panels_json,
            # the importable, self-contained saved-object bundle (ids are the
            # vis-<slug> placeholders; execution remaps them to server ids).
            "saved_objects": saved_objects,
        }
        errors = (
            [
                f"panel '{d}' query failed: {next((v['note'] for v in verified if v['slug'] == d), '')}"
                for d in degraded
            ]
            + vis_issues
            + dash_issues
        )
        validated = not errors
        proposed["validation"] = {
            "valid": validated,
            "errors": errors or None,
            "note": (
                "Queries verified against the real indexer; creation is best-effort on the "
                "dashboards server and will report the server-confirmed ids."
            ),
            "evidence": {
                "focus": focus,
                "index": _INDEX,
                "index_pattern": index_pattern,
                "panels": verified,
            },
            "next_steps": [
                "approve -> create visualizations + dashboard on the dashboards server",
                "open the dashboard in the Wazuh UI to confirm rendering",
            ],
        }
        ctx.approve_or_raise(proposed)

        # --- execution ---------------------------------------------------- #
        # The index pattern must actually exist on *this* dashboards server -
        # a design-time discovery miss silently falls back to the
        # conventional id, but execution is not allowed to guess: writing
        # panels against a pattern that isn't there produces a dashboard
        # that can never resolve its own data source.
        idx_obj = _index_pattern_object(index_pattern)
        if idx_obj is None:
            raise ToolError(
                f"Could not locate that index-pattern ('{index_pattern}') on the dashboards "
                "server - create it (or re-check WAZUH_DASHBOARD_URL) before retrying."
            )
        known_fields = osd.index_pattern_fields(idx_obj)
        if known_fields is not None:
            missing = sorted(
                {
                    field
                    for v in visualizations
                    for field in _agg_fields(v["obj"]["attributes"])
                    if field not in known_fields
                }
            )
            if missing:
                raise ToolError(
                    f"Index pattern '{index_pattern}' does not know about field(s) {missing} used "
                    "by these panels - refresh the index pattern fields in the Wazuh dashboard "
                    "and try again."
                )

        # create visualizations, then the dashboard, then read it back
        created_vis: list[dict[str, Any]] = []
        try:
            for v in visualizations:
                resp = dashboards_request(
                    "POST",
                    "/api/saved_objects/visualization",
                    body={
                        "attributes": v["obj"]["attributes"],
                        "references": v["obj"]["references"],
                    },
                )
                obj = resp.get("saved_object") or resp.get("object") or resp
                vid = obj.get("id") or resp.get("id")
                created_vis.append({"slug": v["slug"], "id": vid, "title": v["title"]})
        except ToolError as e:
            raise ToolError(f"Visualization step failed (dashboard not created): {e}") from e

        real_panels_json, real_refs = osd.build_panels([v["id"] for v in created_vis])
        try:
            dash = dashboards_request(
                "POST",
                "/api/saved_objects/dashboard",
                body={
                    "attributes": osd.build_dashboard_attributes(
                        p["title"], p.get("description", ""), real_panels_json
                    ),
                    # panel references mirror the dashboard's own panelRefName
                    # entries so the panel ids resolve on import/export.
                    "references": real_refs,
                },
            )
        except ToolError as e:
            raise ToolError(
                f"Dashboard create failed after {len(created_vis)} visualizations: {e}"
            ) from e
        dobj = dash.get("saved_object") or dash.get("object") or dash
        did = dobj.get("id") or dash.get("id")

        # Read the dashboard back and validate what the server actually
        # stored - a bad read-back is reported, never silently claimed as
        # success (see docs/architecture.md: "evidence before claims").
        render_issues: list[str]
        try:
            fetched = dashboards_request("GET", f"/api/saved_objects/dashboard/{did}")
            render_issues = osd.validate_dashboard(fetched)
        except ToolError as e:
            render_issues = [f"could not read the dashboard back after creating it: {e}"]

        return {
            "status": "executed" if not render_issues else "executed_with_issues",
            "dashboard_id": did,
            "title": p["title"],
            "visualizations": created_vis,
            "panels_created": len(created_vis),
            "verified_panels": [{"slug": v["slug"], "matched": v["matched"]} for v in verified],
            "render_check": {"ok": not render_issues, "issues": render_issues},
            "open_url_path": f"/app/dashboards#/view/{did}",
            "detail": dash.get("message"),
        }


TOOLS = [DesignDetectionDashboard]
