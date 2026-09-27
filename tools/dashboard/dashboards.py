"""
Saved-dashboard tools for the Wazuh dashboard (OpenSearch Dashboards
saved-objects API).

Create/Update write RENDERABLE objects: panels are gridData panels with
panelRefName -> references (osd_objects.build_panels), so the saved-objects
API's envelope checks AND the dashboard app's render checks pass. Verify reads
objects back and reports exactly what would break on render (registered vis
type, valid gridData, optionsJSON, resolvable index pattern).
"""

from __future__ import annotations

import json
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.dashboard import osd_objects as osd
from tools.dashboard import preview as preview_mod
from tools.dashboard.client import dashboards_request


# --------------------------------------------------------------------------- #
def _normalize_panel_ids(panels: Any) -> list[str]:
    """Accept [{id, x, y, w, h}, "v2", ...] and return the ordered vis ids."""
    if not isinstance(panels, list):
        raise ToolError("panels must be a list of {id, ...} objects or visualization id strings.")
    ids: list[str] = []
    for p in panels:
        if isinstance(p, str):
            ids.append(p)
        elif isinstance(p, dict) and p.get("id"):
            ids.append(str(p["id"]))
        else:
            raise ToolError(
                "panels must be a list of {id, ...} objects or visualization id strings."
            )
    if not ids:
        raise ToolError("panels is empty - nothing to place.")
    return ids


def _fetch_visualization(vid: str) -> dict[str, Any] | None:
    """Fetch one saved visualization; None when it doesn't exist."""
    try:
        resp = dashboards_request("GET", f"/api/saved_objects/visualization/{vid}")
    except ToolError:
        return None
    if (resp.get("statusCode") or 200) >= 400 or "attributes" not in resp:
        return None
    return resp


def _require_visualizations(ids: list[str]) -> None:
    missing = [vid for vid in ids if _fetch_visualization(vid) is None]
    if missing:
        raise ToolError(
            "Cannot build the dashboard: these visualization ids do not exist "
            f"on the dashboard server: {', '.join(missing)}. Create them first "
            "(or pass ids from get_wazuh_visualizations / get_wazuh_dashboards)."
        )


# --------------------------------------------------------------------------- #
class GetWazuhDashboards(BaseWazuhTool):
    name = "get_wazuh_dashboards"
    description = (
        "List saved dashboards on the Wazuh dashboard (saved-objects API) - to see "
        "what exists before creating another."
    )
    input_schema = {
        "type": "object",
        "properties": {"limit": {"type": "integer", "description": "max results (default 20)"}},
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        limit = min(int(p.get("limit", 20) or 20), 100)
        try:
            resp = dashboards_request(
                "GET",
                "/api/saved_objects/_find",
                params={"type": "dashboard", "per_page": limit},
            )
        except ToolError:
            raise
        items = resp.get("saved_objects") or resp.get("objects") or []
        out = []
        for i in items:
            attrs = i.get("attributes") or {}
            try:
                panels = len(json.loads(attrs.get("panelsJSON") or "[]") or [])
            except json.JSONDecodeError:
                panels = 0
            out.append({"id": i.get("id"), "title": attrs.get("title"), "panels": panels})
        return {"count": len(out), "dashboards": out, "dashboard_ok": True}


class UpdateWazuhDashboard(BaseWazuhTool):
    name = "update_wazuh_dashboard"
    description = (
        "Update an existing saved dashboard (replace its panels with renderable "
        "gridData panels + references). WRITE - proposes and requires approval."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "dashboard_id": {"type": "string"},
            "title": {"type": "string"},
            "panels": {"type": "array", "description": "list of {id, x, y, w, h} or id strings"},
            "reason": {"type": "string"},
        },
        "required": ["dashboard_id", "panels", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        vis_ids = _normalize_panel_ids(p.get("panels"))
        try:
            existing = dashboards_request(
                "GET", f"/api/saved_objects/dashboard/{p['dashboard_id']}"
            )
        except ToolError:
            raise ToolError(
                f"Dashboard '{p['dashboard_id']}' does not exist - nothing to update."
            ) from None
        _require_visualizations(vis_ids)

        panels_json, refs = osd.build_panels(vis_ids)
        attrs = dict(existing.get("attributes") or {})
        attrs["title"] = p.get("title") or attrs.get("title") or p["dashboard_id"]
        attrs["panelsJSON"] = panels_json
        attrs["optionsJSON"] = json.dumps({"hidePanelTitles": False, "useMargins": True})
        attrs["version"] = int(attrs.get("version") or 1)
        attrs["hits"] = attrs.get("hits", 0)

        proposed = {
            "action": "update_wazuh_dashboard",
            "reason": p.get("reason", ""),
            "payload": {
                "dashboard_id": p["dashboard_id"],
                "title": attrs["title"],
                "panels": vis_ids,
                "reason": p.get("reason", ""),
            },
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {"title": attrs["title"], "panelsJSON": panels_json}
        proposed["validation"] = {"valid": True, "note": "Panels are renderable gridData panels."}
        ctx.approve_or_raise(proposed)
        try:
            resp = dashboards_request(
                "PUT",
                f"/api/saved_objects/dashboard/{p['dashboard_id']}",
                body={"attributes": attrs, "references": refs},
            )
        except ToolError:
            raise
        return {
            "status": "executed",
            "dashboard_id": p["dashboard_id"],
            "title": attrs["title"],
            "panels": len(vis_ids),
            "detail": resp.get("message"),
        }


class CreateWazuhDashboard(BaseWazuhTool):
    name = "create_wazuh_dashboard"
    description = (
        "Create a saved dashboard on the Wazuh dashboard from panels referencing "
        "visualization ids. WRITE - proposes and requires human approval."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "description": {"type": "string"},
            "panels": {"type": "array", "description": "list of {id, x, y, w, h} or id strings"},
            "reason": {"type": "string"},
        },
        "required": ["title", "panels", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)

        # Title has to be a name, not the request text. See preview.resolve_title.
        title, problem = preview_mod.resolve_title(ctx, p["title"])
        if problem:
            raise ToolError(problem)
        p["title"] = title

        # Refuse to create a second dashboard with a title that already exists.
        # Without this the engineer re-creates the same dashboard on every
        # request: the saved-objects API happily accepts a duplicate id, so the
        # operator ends up with N copies and no error to explain why.
        #
        # Checked FIRST, before the visualization ids are resolved. A repeat is
        # the common case here, and making the operator wait on per-panel saved
        # object lookups only to be told the title already exists would be both
        # slower and more confusing than saying so immediately.
        #
        # Propose-time only - preview.duplicate_veto stands down when an
        # approved proposal is being replayed, so this cannot strand a
        # proposal the operator already approved.
        veto = preview_mod.duplicate_veto(ctx, p["title"])
        if veto:
            raise ToolError(veto)

        vis_ids = _normalize_panel_ids(p.get("panels"))
        _require_visualizations(vis_ids)

        panels_json, refs = osd.build_panels(vis_ids)
        attrs = osd.build_dashboard_attributes(p["title"], p.get("description", ""), panels_json)

        proposed = {
            "action": "create_wazuh_dashboard",
            "reason": p.get("reason", ""),
            "payload": {
                "title": p["title"],
                "description": p.get("description", ""),
                "panels": vis_ids,
                "reason": p.get("reason", ""),
            },
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {
            "title": p["title"],
            "description": p.get("description", ""),
            "panelsJSON": panels_json,
        }
        proposed["validation"] = {"valid": True, "note": "Panels are renderable gridData panels."}
        ctx.approve_or_raise(proposed)
        try:
            resp = dashboards_request(
                "POST",
                "/api/saved_objects/dashboard",
                body={"attributes": attrs, "references": refs},
            )
        except ToolError:
            raise
        resp_obj = resp.get("saved_object") or resp.get("object") or {}
        obj_id = resp_obj.get("id") or resp.get("id")
        return {
            "status": "executed",
            "dashboard_id": obj_id,
            "title": p["title"],
            "panels": len(vis_ids),
            "detail": resp.get("message"),
        }


class VerifyWazuhDashboard(BaseWazuhTool):
    name = "verify_wazuh_dashboard"
    description = (
        "READ-ONLY check that saved dashboards actually RENDER: registered vis types, "
        "valid gridData/panelIndex panels, optionsJSON, references that match the "
        "panels, and an index pattern that resolves. Reports issues per dashboard - "
        "an empty issues list means it should open in OSD. Use before/after creating "
        "or editing dashboards, or to audit old ones."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "dashboard_id": {"type": "string", "description": "check only this dashboard id"},
            "title_contains": {
                "type": "string",
                "description": "check only dashboards whose title contains this",
            },
            "limit": {"type": "integer", "description": "max dashboards to check (default 20)"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        limit = min(int(p.get("limit", 20) or 20), 100)
        dashboard_id = p.get("dashboard_id")
        title_contains = (p.get("title_contains") or "").lower() or None

        try:
            resp = dashboards_request(
                "GET",
                "/api/saved_objects/_find",
                params={"type": "dashboard", "per_page": limit},
            )
        except ToolError:
            raise
        dashboards = [
            i
            for i in (resp.get("saved_objects") or resp.get("objects") or [])
            if isinstance(i, dict) and "attributes" in i
        ]
        if dashboard_id:
            dashboards = [d for d in dashboards if d.get("id") == dashboard_id]
        if title_contains:
            dashboards = [
                d
                for d in dashboards
                if title_contains in ((d.get("attributes") or {}).get("title") or "").lower()
            ]

        out: list[dict[str, Any]] = []
        for dash in dashboards:
            d_id = dash.get("id")
            issues = list(osd.validate_dashboard(dash))
            refs = dash.get("references") or []
            vis_ids = [r.get("id") for r in refs if r.get("type") == "visualization"]
            panels = (dash.get("attributes") or {}).get("panelsJSON")
            try:
                panels = json.loads(panels) if isinstance(panels, str) else panels or []
            except json.JSONDecodeError:
                panels = []
            vis_ids += [p.get("id") for p in panels if isinstance(p, dict) and p.get("id")]
            for vid in dict.fromkeys(v for v in vis_ids if v):
                vis = _fetch_visualization(vid)
                if vis is None:
                    issues.append(
                        f"{d_id}: dashboard references visualization '{vid}' which could not be found."
                    )
                    continue
                issues.extend(osd.validate_visualization(vis))
                issues.extend(self._check_index_pattern(vis, d_id))
            renders = not issues
            out.append(
                {
                    "dashboard_id": d_id,
                    "title": (dash.get("attributes") or {}).get("title"),
                    "renders": renders,
                    "issues": issues,
                    "panel_count": len([p for p in panels if isinstance(p, dict)]),
                }
            )
        return {
            "checked": len(out),
            "broken": sum(1 for d in out if not d["renders"]),
            "dashboards": out,
            "dashboard_ok": all(d["renders"] for d in out),
        }

    @staticmethod
    def _check_index_pattern(vis: dict[str, Any], owner: str) -> list[str]:
        """Verify the index pattern(s) a visualization references actually
        exist on the server - a dangling indexRefName breaks render."""
        issues: list[str] = []
        refs = vis.get("references") or []
        index_ids = [r.get("id") for r in refs if r.get("type") == "index-pattern"]
        meta = (vis.get("attributes") or {}).get("kibanaSavedObjectMeta") or {}
        try:
            ss = json.loads(meta.get("searchSourceJSON", "{}"))
        except (TypeError, ValueError):
            ss = {}
        if isinstance(ss, dict) and ss.get("index"):
            index_ids.append(ss["index"])
        for idx_id in dict.fromkeys(i for i in index_ids if i):
            try:
                resp = dashboards_request("GET", f"/api/saved_objects/index-pattern/{idx_id}")
            except ToolError:
                resp = None
            if resp is None or (resp.get("statusCode") or 200) >= 400:
                issues.append(
                    f"{owner}: Could not locate that index-pattern ('{idx_id}') "
                    "referenced by the dashboard. Re-point the saved object at an "
                    "existing index pattern and try again."
                )
        return issues


class DeleteWazuhDashboard(BaseWazuhTool):
    name = "delete_wazuh_dashboard"
    description = (
        "Delete a saved dashboard by id. HIGH RISK (EXECUTE): requires approval AND "
        "explicit confirmation."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "dashboard_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["dashboard_id", "reason"],
    }
    permission = Permission.EXECUTE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        proposed = {
            "action": "delete_wazuh_dashboard",
            "reason": p.get("reason", ""),
            "payload": {"dashboard_id": p["dashboard_id"], "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["validation"] = {
            "valid": True,
            "note": "Deletion requires approval + confirmation.",
        }
        ctx.approve_or_raise(proposed)
        try:
            resp = dashboards_request("DELETE", f"/api/saved_objects/dashboard/{p['dashboard_id']}")
        except ToolError:
            raise
        return {
            "status": "executed",
            "dashboard_id": p["dashboard_id"],
            "detail": resp.get("message"),
        }
