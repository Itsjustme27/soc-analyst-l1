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
from tools.dashboard import planner, preview, threatintel
from tools.dashboard.client import dashboards_request
from tools.indexer.queries import search_body, to_range_expr, verify_opensearch_query

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
        "Dashboard engineering workflow: turn a request into a Wazuh-dashboard proposal "
        "whose panels actually match the data, verifying every panel query against the real "
        "indexer. Pass `intent` as free text (e.g. 'ssh failed logins from private IPs to "
        "private IPs') to get a plan specific to that request; omit it to fall back to the "
        "fixed `focus` template (web | ssh | network | general). WRITE on execute: creates "
        "the visualizations + dashboard on the Wazuh dashboard server (best-effort; requires "
        "human approval)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "dashboard title, e.g. 'Web Server Attacks'",
            },
            "intent": {
                "type": "string",
                "description": (
                    "free-text description of what the dashboard should show, e.g. "
                    "'ssh failed login from private to private ip'. Planned against the "
                    "live index schema, then every panel query is verified. Optional; "
                    "without it the `focus` template is used."
                ),
            },
            "focus": {
                "type": "string",
                "description": "fallback template: web | ssh | network | general (used when no intent)",
            },
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

        # 0a) title has to be a name, not the request text. Rejected while
        # proposing, derived while replaying an approval - see resolve_title.
        title, problem = preview.resolve_title(ctx, p["title"])
        if problem:
            raise ToolError(problem)
        p["title"] = title

        # 0) duplicate guard - before any saved objects are built, because this
        #    tool's whole failure mode was re-creating the same dashboard on
        #    every request. Propose-time only; see preview.duplicate_veto for why
        #    a create-time guard would strand already-approved proposals.
        veto = preview.duplicate_veto(ctx, p["title"])
        if veto:
            raise ToolError(veto)

        # 1) schema + panel plan
        try:
            schema = ctx.indexer.field_caps(_INDEX)
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Cannot read indexer schema - dashboard design aborted: {e}") from e

        # 1a) free-text intent -> a plan specific to what was actually asked.
        # Falls back to the fixed template whenever the planner is unavailable
        # or returns something unusable, so this can only add specificity.
        intent = str(p.get("intent") or "").strip()
        plan_info: dict[str, Any] = {}
        panels: list[dict[str, Any]] | None = None
        if intent:
            planned = planner.plan_dashboard(
                ctx,
                intent,
                schema,
                time_range_expr=to_range_expr(p.get("time_range") or "-7d"),
                focus=focus,
            )
            if planned.get("ok"):
                panels = planned["panels"]
                plan_info = {
                    "planned_from_intent": intent,
                    "intent_notes": planned.get("notes", ""),
                    "intent_filter": planned.get("filters", []),
                    "planner_dropped": planned.get("dropped", []),
                }
            else:
                plan_info = {
                    "planned_from_intent": intent,
                    "planner_fallback": planned.get("error", "planner unusable"),
                    "planner_dropped": planned.get("dropped", []),
                }
        if panels is None:
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

        # 2a) an intent filter that matches nothing produces a dashboard of
        # zeroes. Say so loudly instead of proposing seven empty panels - the
        # approver should learn the request didn't match, not approve a blank
        # screen. Only meaningful when a filter was actually applied.
        empty_panels = [v["slug"] for v in verified if not v["matched"]]
        if plan_info.get("intent_filter") and empty_panels:
            plan_info["intent_filter_matched_nothing"] = True
            plan_info["intent_filter_panels_empty"] = empty_panels

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
                p.get("description")
                or plan_info.get("intent_notes")
                or f"Wazuh {focus} alert dashboard over {index_pattern}",
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
            # only the server-confirmed ids. The payload is the tool's own input
            # (intent included, so execution replans the same way).
            "action": "design_detection_dashboard",
            "reason": p.get("reason", ""),
            "payload": {
                k: p[k]
                for k in ("title", "intent", "focus", "description", "time_range", "reason")
                if k in p
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
        if plan_info.get("intent_filter_matched_nothing"):
            errors.insert(
                0,
                "the intent filter matched 0 alerts in the window, so every panel is "
                "empty: "
                + json.dumps(plan_info.get("intent_filter"))
                + " - reword the request or widen the time range",
            )
        errors.extend(f"planner dropped: {d}" for d in plan_info.get("planner_dropped") or [])
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
                **plan_info,
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


def _unresolved_data_refs(visualizations: list[dict[str, Any]]) -> list[str]:
    """Index-pattern references that do not resolve on the dashboards server.

    Reads each created visualization back and resolves its data reference. A
    dangling one is silent - the object is created, passes every schema
    validation, and renders a dashboard of empty panels - so it is worth a round
    trip per visualization to prove the panels can actually see data.

    This is a diagnostic that runs AFTER the dashboard exists, so it catches
    broadly and only ever returns strings. Letting a transport error escape here
    would turn a successful create into a failed one, which is strictly worse
    than the broken reference it was checking for.
    """
    issues: list[str] = []
    for v in visualizations:
        slug = v.get("slug")
        vid = v.get("id")
        if not vid:
            issues.append(f"panel {slug!r} was created without a server id")
            continue
        try:
            obj = dashboards_request("GET", f"/api/saved_objects/visualization/{vid}")
        except Exception as e:  # noqa: BLE001 - diagnostic, must not fail the create
            issues.append(f"panel {slug!r} could not be read back: {type(e).__name__}: {e}")
            continue
        refs = [
            r for r in ((obj or {}).get("references") or []) if r.get("type") == "index-pattern"
        ]
        if not refs:
            issues.append(f"panel {slug!r} has no index-pattern reference")
            continue
        for r in refs:
            try:
                dashboards_request("GET", f"/api/saved_objects/index-pattern/{r['id']}")
            except Exception:  # noqa: BLE001 - a failed resolve IS the finding
                issues.append(
                    f"panel {slug!r} references index-pattern "
                    f"{r['id']!r}, which does not exist on the dashboards server - "
                    "its panels will render empty"
                )
    return issues


class DesignThreatIntelDashboard(BaseWazuhTool):
    """Threat-intelligence dashboard over Wazuh's OWN vulnerability + MITRE data.

    The engineer kept being asked for a dashboard that aggregates CVEs, CVSS
    scores, severity trends and attacker behaviour, and kept producing an
    alert-volume dashboard instead - because DesignDetectionDashboard only reads
    wazuh-alerts-*, and Wazuh indexes the threat data separately. This tool
    queries where the data actually is.

    Two things it does that the alert dashboard cannot, both forced by what the
    indexer really holds (see tools/dashboard/threatintel.py for the full
    measurements):

    * It REPORTS what it cannot build. There is no geo data and no IOC data on
      this deployment, so those panels do not exist; `unsupported` says so in the
      proposal instead of shipping two permanently blank charts. An operator who
      approved a geo panel and got an empty box could not otherwise tell "no
      attacks from anywhere" from "never collected".
    * It judges a panel healthy only if its AGGREGATION produced buckets, not if
      its query matched documents. A panel can match 9000 alerts and still draw
      an empty chart when its field is unmapped.
    """

    name = "design_threat_intel_dashboard"
    description = (
        "Threat-intelligence dashboard from Wazuh's Vulnerability Detector "
        "(CVE, CVSS base score, severity, affected packages, scoring source, "
        "publication timeline) joined with MITRE ATT&CK tactics/techniques from "
        "the alert stream. Reads "
        f"{threatintel.THREAT_INDEX} and reports which requested capabilities "
        "(geo-origin, IOC feeds) have no data behind them. WRITE on execute: "
        "creates the visualizations + dashboard on the Wazuh dashboard server "
        "(requires human approval)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "title": {
                "type": "string",
                "description": "dashboard title, e.g. 'Threat Intelligence - Vulnerabilities & ATT&CK'",
            },
            "description": {"type": "string"},
            "reason": {"type": "string", "description": "why this dashboard is needed"},
        },
        "required": ["title", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        panels = threatintel.panel_plan()

        title, problem = preview.resolve_title(ctx, p["title"])
        if problem:
            raise ToolError(problem)
        p["title"] = title

        veto = preview.duplicate_veto(ctx, p["title"])
        if veto:
            raise ToolError(veto)

        # 1) verify the declared schema against the live indexer. _field_caps
        #    returns nothing for wazuh-states-vulnerabilities-*, so the field
        #    list is declared and re-probed with real aggregations instead.
        fields = threatintel.verify_fields(ctx.indexer)

        # 2) run every panel's real aggregation and judge it on buckets.
        verified = [threatintel.verify_panel(ctx.indexer, panel) for panel in panels]
        degraded = [v["slug"] for v in verified if not v["healthy"]]

        # 3) the combined data view must exist before any saved object can
        #    resolve it. Idempotent get-or-create.
        pattern = threatintel.ensure_index_pattern()
        if not pattern.get("found"):
            raise ToolError(
                "Could not resolve or create the combined index pattern "
                f"{threatintel.THREAT_INDEX!r} on the dashboards server: "
                f"{pattern.get('error') or 'not found'}. Create it in the Wazuh "
                "UI (Management > Index Patterns) and retry - the dashboard's "
                "panels will not resolve their data source without it."
            )
        # The pattern's TITLE is what a human sees and what the preview reports;
        # its server ID is what a saved object's reference must point at. For
        # Wazuh's built-in data views the two are identical (their ids ARE the
        # pattern, e.g. id "wazuh-alerts-*"), which is why the alert tool can
        # pass one value for both. A pattern created through the API gets a
        # uuid instead, so pointing a reference at the title leaves the
        # dashboard unable to resolve its own data source - the panels render
        # empty with no error anywhere. Use each where it belongs.
        index_pattern = pattern["title"]
        index_pattern_id = pattern["id"] or index_pattern

        # 4) build the bundle with the same validated builders the alert
        #    dashboard uses, so vis types, params, searchSourceJSON references
        #    and gridData geometry are identical.
        visualizations: list[dict[str, Any]] = []
        vis_issues: list[str] = []
        for panel in panels:
            attrs, refs = osd.build_visualization_attributes(
                panel["title"],
                panel["vis_type"],
                panel["aggs"],
                index_pattern_id,
                query=panel["query"],
                description=threatintel.summary(),
            )
            obj = {
                "id": f"vis-{panel['slug']}",
                "type": "visualization",
                "version": 1,
                "attributes": attrs,
                "references": refs,
            }
            vis_issues.extend(osd.validate_visualization(obj))
            visualizations.append(
                {
                    "slug": panel["slug"],
                    "id": obj["id"],
                    "title": panel["title"],
                    "vis_type": panel["vis_type"],
                    "obj": obj,
                }
            )

        panels_json, panel_refs = osd.build_panels([v["id"] for v in visualizations])
        dash_obj = {
            "id": "dashboard-threat-intel",
            "type": "dashboard",
            "version": 1,
            "attributes": osd.build_dashboard_attributes(
                p["title"],
                p.get("description") or threatintel.summary(),
                panels_json,
            ),
            "references": panel_refs,
        }
        dash_issues = osd.validate_dashboard(dash_obj)
        saved_objects = [v["obj"] for v in visualizations] + [dash_obj]

        proposed = {
            "action": "design_threat_intel_dashboard",
            "reason": p.get("reason", ""),
            "payload": {k: p[k] for k in ("title", "description", "reason") if k in p},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {
            "title": p["title"],
            "index_pattern": index_pattern,
            "visualizations": [
                {"slug": v["slug"], "title": v["title"], "vis_type": v["vis_type"]}
                for v in visualizations
            ],
            "panelsJSON": panels_json,
            "saved_objects": saved_objects,
            "unsupported": threatintel.UNSUPPORTED,
        }
        errors = [
            f"panel '{d}' produced no data: "
            f"{next((v['note'] for v in verified if v['slug'] == d), '')}"
            for d in degraded
        ] + ([f"declared field(s) not found: {fields['missing']}"] if fields["missing"] else [])
        errors += vis_issues + dash_issues
        proposed["validation"] = {
            "valid": not errors,
            "errors": errors or None,
            "note": (
                "Every panel's aggregation was executed against the real indexer. "
                "Panels are reported healthy only when the aggregation produced "
                "buckets, not merely when the query matched documents."
            ),
            "evidence": {
                "index": threatintel.THREAT_INDEX,
                "index_pattern_id": pattern.get("id"),
                "panels": verified,
                "fields_present": len(fields["present"]),
            },
            "unsupported": threatintel.UNSUPPORTED,
            "next_steps": [
                "approve -> create visualizations + dashboard on the dashboards server",
                "preview the charts in the engineer's Dashboard Preview tab before approving",
                "open the dashboard in the Wazuh UI to confirm rendering",
            ],
        }
        ctx.approve_or_raise(proposed)

        # --- execution ---------------------------------------------------- #
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
                created_vis.append(
                    {"slug": v["slug"], "id": obj.get("id") or resp.get("id"), "title": v["title"]}
                )
        except ToolError as e:
            raise ToolError(f"Visualization step failed (dashboard not created): {e}") from e

        real_panels_json, real_refs = osd.build_panels([v["id"] for v in created_vis])
        try:
            dash = dashboards_request(
                "POST",
                "/api/saved_objects/dashboard",
                body={
                    "attributes": osd.build_dashboard_attributes(
                        p["title"], p.get("description") or threatintel.summary(), real_panels_json
                    ),
                    "references": real_refs,
                },
            )
        except ToolError as e:
            raise ToolError(
                f"Dashboard create failed after {len(created_vis)} visualizations: {e}"
            ) from e
        dobj = dash.get("saved_object") or dash.get("object") or dash
        did = dobj.get("id") or dash.get("id")

        try:
            fetched = dashboards_request("GET", f"/api/saved_objects/dashboard/{did}")
            render_issues = osd.validate_dashboard(fetched)
        except ToolError as e:
            render_issues = [f"could not read the dashboard back after creating it: {e}"]

        # A saved object can be created, be schema-valid, and still be dead: an
        # index-pattern reference that does not resolve leaves every panel
        # showing an empty chart and no error anywhere. This shipped once - the
        # reference pointed at the pattern's TITLE while the pattern itself had
        # a uuid id - so it is checked explicitly rather than left for the UI to
        # reveal.
        render_issues += _unresolved_data_refs(created_vis)

        return {
            "status": "executed" if not render_issues else "executed_with_issues",
            "dashboard_id": did,
            "title": p["title"],
            "index_pattern": index_pattern,
            "visualizations": created_vis,
            "panels_created": len(created_vis),
            "verified_panels": [
                {"slug": v["slug"], "matched": v["matched"], "healthy": v["healthy"]}
                for v in verified
            ],
            "unsupported": threatintel.UNSUPPORTED,
            "render_check": {"ok": not render_issues, "issues": render_issues},
            "open_url_path": f"/app/dashboards#/view/{did}",
            "detail": dash.get("message"),
        }


TOOLS = [DesignDetectionDashboard, DesignThreatIntelDashboard]
