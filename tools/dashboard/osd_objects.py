"""
OpenSearch Dashboards (Wazuh dashboard) saved-object builders + validators.

Why this exists: the dashboard engine used to create objects that the
saved-objects API ACCEPTED (it only checks the envelope) but that the
dashboard app could not RENDER. Opening them failed because of:

  1. vis type "bar" - not a registered visualization type. Vertical bars
     are "histogram" (or "horizontal_bar").
  2. panelsJSON entries shaped {id, x, y, w, h, type} - not the dashboard
     format. Each panel needs gridData {x, y, w, h, i}, panelIndex,
     embeddableConfig, version and a panelRefName that names a reference.
  3. partial vis params - visState.params is merged with the type defaults
     SHALLOWLY, so a categoryAxes/valueAxes array without `labels`/`title`,
     a pie without `labels`, or a metric without `metric.style` replaces the
     defaults wholesale and the chart throws on first render.
  4. searchSourceJSON carrying a raw `aggs` array (aggs belong to visState;
     search source expects AggConfigs) and a raw `index` instead of the
     reference form `indexRefName` + references entry.
  5. no optionsJSON on the dashboard.

build_* functions produce the correct shapes; validate_* functions check an
object (as stored or as fetched back from the server) and return a list of
human-readable problems - empty means it should render. The engine runs the
validators before creating anything AND after creation (reading the objects
back), so a malformed dashboard is reported instead of claimed as success.
"""

from __future__ import annotations

import copy
import json
from typing import Any

PANEL_VERSION = "7.10.2"  # OSD 1.x/2.x dashboard panel schema (Kibana 7.10 lineage)
INDEX_REF_NAME = "kibanaSavedObjectMeta.searchSourceJSON.index"

VALID_VIS_TYPES = ("histogram", "horizontal_bar", "line", "area", "pie", "metric", "table")
_VIS_TYPE_ALIASES = {
    "bar": "histogram",
    "vertical_bar": "histogram",
    "column": "histogram",
    "donut": "pie",
    "count": "metric",
}
_XY_TYPES = ("histogram", "horizontal_bar", "line", "area")


def normalize_vis_type(vis_type: str) -> str:
    t = _VIS_TYPE_ALIASES.get((vis_type or "").lower(), (vis_type or "").lower())
    if t not in VALID_VIS_TYPES:
        raise ValueError(
            f"Unsupported visualization type '{vis_type}'. Use one of {VALID_VIS_TYPES}."
        )
    return t


# --------------------------------------------------------------------------- #
# visState
# --------------------------------------------------------------------------- #
def _axis_label(filter_: bool, rotate: int = 0) -> dict[str, Any]:
    return {"show": True, "filter": filter_, "truncate": 100, "rotate": rotate}


def vis_params(vis_type: str, metric_label: str = "Count") -> dict[str, Any]:
    """COMPLETE params per type (see module docstring, point 3)."""
    t = normalize_vis_type(vis_type)
    if t == "metric":
        return {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": "Green to Red",
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 10000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": "",
                    "fontSize": 60,
                },
            },
        }
    if t == "table":
        return {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
            "sort": {"columnIndex": None, "direction": None},
        }
    if t == "pie":
        return {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
        }
    horizontal = t == "horizontal_bar"
    series_type = "histogram" if t in ("histogram", "horizontal_bar") else t
    return {
        "type": t,
        "grid": {"categoryLines": False},
        "categoryAxes": [
            {
                "id": "CategoryAxis-1",
                "type": "category",
                "position": "left" if horizontal else "bottom",
                "show": True,
                "style": {},
                "scale": {"type": "linear"},
                "labels": _axis_label(True, 0),
                "title": {},
            }
        ],
        "valueAxes": [
            {
                "id": "ValueAxis-1",
                "name": "LeftAxis-1",
                "type": "value",
                "position": "bottom" if horizontal else "left",
                "show": True,
                "style": {},
                "scale": {"type": "linear", "mode": "normal"},
                "labels": _axis_label(False, 0),
                "title": {"text": metric_label},
            }
        ],
        "seriesParams": [
            {
                "show": True,
                "type": series_type,
                "mode": "stacked" if series_type == "histogram" else "normal",
                "data": {"label": metric_label, "id": "1"},
                "valueAxis": "ValueAxis-1",
                "drawLinesBetweenPoints": True,
                "lineWidth": 2,
                "showCircles": True,
                "interpolate": "linear",
            }
        ],
        "addTooltip": True,
        "addLegend": True,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": False,
        "labels": {"show": False},
        "thresholdLine": {
            "show": False,
            "value": 10,
            "width": 1,
            "style": "full",
            "color": "#E7664C",
        },
    }


def normalize_aggs(aggs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Fill the params the agg editor/renderer expects.

    Guarantees each agg has a unique string 'id' and required 'schema'.
    - If 'id' is missing/None, generate a stable unique id from position + type.
    - If 'schema' is missing, infer from type (metric -> 'metric', terms/date_histogram -> 'segment').
    """
    out = []
    for idx, a in enumerate(copy.deepcopy(aggs)):
        # Unique, stable id - never "None"
        raw_id = a.get("id")
        if raw_id is None or raw_id == "":
            a["id"] = f"{a.get('type', 'agg')}_{idx}"
        else:
            a["id"] = str(raw_id)

        # Required schema - infer from type if missing
        if "schema" not in a:
            t = a.get("type", "")
            if t in ("count", "avg", "sum", "min", "max", "cardinality", "std_dev"):
                a["schema"] = "metric"
            else:
                a["schema"] = "segment"

        a.setdefault("enabled", True)
        a.setdefault("params", {})
        if a.get("type") == "date_histogram":
            p = a["params"]
            p.setdefault("interval", "auto")
            p.setdefault("min_doc_count", 1)
            p.setdefault("extended_bounds", {})
            p.setdefault("drop_partials", False)
            p.setdefault("scaleMetricValues", False)
            p.setdefault("useNormalizedOpenSearchInterval", True)
            p.pop("includeEmptyRows", None)
        if a.get("type") == "terms":
            p = a["params"]
            p.setdefault("otherBucket", False)
            p.setdefault("otherBucketLabel", "Other")
            p.setdefault("missingBucket", False)
            p.setdefault("missingBucketLabel", "Missing")
        out.append(a)
    return out


def build_vis_state(
    title: str,
    vis_type: str,
    aggs: list[dict[str, Any]],
    extra_params: dict[str, Any] | None = None,
) -> str:
    """Complete params for the type; caller-supplied params are applied only
    for keys the defaults don't define, so a partial axis/label block can
    never replace a complete default (the shallow-merge crash)."""
    t = normalize_vis_type(vis_type)
    norm = normalize_aggs(aggs)
    metric = next((a for a in norm if a.get("schema") == "metric"), {})
    label = (metric.get("params") or {}).get("customLabel") or "Count"
    params = vis_params(t, label)
    for k, v in (extra_params or {}).items():
        params.setdefault(k, v)
    return json.dumps({"title": title, "type": t, "aggs": norm, "params": params})


# --------------------------------------------------------------------------- #
# search source + references
# --------------------------------------------------------------------------- #
def _filters(query: dict[str, Any] | None, index_pattern_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for clause in ((query or {}).get("bool") or {}).get("filter") or []:
        if "term" in clause:
            field = next(iter(clause["term"]))
            out.append(
                {
                    "meta": {
                        "index": index_pattern_id,
                        "type": "phrase",
                        "key": field,
                        "params": {"query": clause["term"][field]},
                        "negate": False,
                        "disabled": False,
                        "alias": None,
                    },
                    "query": {"match_phrase": {field: clause["term"][field]}},
                    "$state": {"store": "appState"},
                }
            )
        elif "range" in clause:
            field = next(iter(clause["range"]))
            out.append(
                {
                    "meta": {
                        "index": index_pattern_id,
                        "type": "range",
                        "key": field,
                        "params": clause["range"][field],
                        "negate": False,
                        "disabled": False,
                        "alias": None,
                    },
                    "range": clause["range"],
                    "$state": {"store": "appState"},
                }
            )
    return out


def build_search_source(
    index_pattern_id: str, query: dict[str, Any] | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """(searchSourceJSON, references) in the reference form: indexRefName +
    a references entry - never a raw `aggs` array."""
    ss = {
        "query": {"query": "", "language": "kuery"},
        "filter": _filters(query, index_pattern_id),
        "indexRefName": INDEX_REF_NAME,
    }
    refs = [{"name": INDEX_REF_NAME, "type": "index-pattern", "id": index_pattern_id}]
    return json.dumps(ss), refs


def build_visualization_attributes(
    title: str,
    vis_type: str,
    aggs: list[dict[str, Any]],
    index_pattern_id: str,
    query: dict[str, Any] | None = None,
    description: str = "",
    extra_params: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    ss, refs = build_search_source(index_pattern_id, query)
    attrs = {
        "title": title,
        "visState": build_vis_state(title, vis_type, aggs, extra_params),
        "uiStateJSON": "{}",
        "description": description,
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": ss},
    }
    return attrs, refs


# --------------------------------------------------------------------------- #
# dashboard
# --------------------------------------------------------------------------- #
def build_panels(
    vis_ids: list[str], width: int = 24, height: int = 15
) -> tuple[str, list[dict[str, Any]]]:
    """(panelsJSON, references) - 2-column grid, panelRefName -> reference."""
    panels, refs = [], []
    for i, vid in enumerate(vis_ids):
        idx = str(i + 1)
        panels.append(
            {
                "version": PANEL_VERSION,
                "gridData": {
                    "x": (i % 2) * width,
                    "y": (i // 2) * height,
                    "w": width,
                    "h": height,
                    "i": idx,
                },
                "panelIndex": idx,
                "embeddableConfig": {},
                "panelRefName": f"panel_{i}",
            }
        )
        refs.append({"name": f"panel_{i}", "type": "visualization", "id": vid})
    return json.dumps(panels), refs


def build_dashboard_attributes(
    title: str, description: str, panels_json: str, time_from: str = "now-7d", time_to: str = "now"
) -> dict[str, Any]:
    return {
        "title": title,
        "description": description,
        "hits": 0,
        "panelsJSON": panels_json,
        "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
        "version": 1,
        "timeRestore": True,
        "timeFrom": time_from,
        "timeTo": time_to,
        "refreshInterval": {"pause": True, "value": 0},
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps(
                {"query": {"query": "", "language": "kuery"}, "filter": []}
            )
        },
    }


# --------------------------------------------------------------------------- #
# validators - return a list of problems; empty list == should render
# --------------------------------------------------------------------------- #
def _loads(text: Any, what: str, issues: list[str]) -> Any:
    if isinstance(text, (dict, list)):
        return text
    try:
        return json.loads(text)
    except (TypeError, ValueError) as e:
        issues.append(f"{what} is not valid JSON ({e})")
        return None


def validate_visualization(
    obj: dict[str, Any], known_fields: dict[str, bool] | None = None
) -> list[str]:
    """`obj` is a saved object ({id?, attributes, references}). `known_fields`
    (name -> aggregatable) from the index pattern, when available, catches
    'Saved field parameter is now invalid'."""
    issues: list[str] = []
    name = obj.get("id") or (obj.get("attributes") or {}).get("title") or "visualization"
    attrs = obj.get("attributes") or {}
    refs = {r.get("name"): r for r in obj.get("references") or []}
    vs = _loads(attrs.get("visState"), f"{name}: visState", issues)
    if isinstance(vs, dict):
        t = vs.get("type")
        if t not in VALID_VIS_TYPES:
            issues.append(
                f"{name}: visualization type '{t}' is not registered in OSD "
                f"(valid: {', '.join(VALID_VIS_TYPES)})"
            )
        params = vs.get("params") or {}
        xy_like = (
            t in _XY_TYPES or _VIS_TYPE_ALIASES.get(t) in _XY_TYPES or "categoryAxes" in params
        )
        if xy_like:
            for key in ("categoryAxes", "valueAxes", "seriesParams"):
                if not params.get(key):
                    issues.append(f"{name}: params.{key} missing")
            for key in ("categoryAxes", "valueAxes"):
                for ax in params.get(key) or []:
                    if "labels" not in ax:
                        issues.append(
                            f"{name}: params.{key}[{ax.get('id')}] has no 'labels' (chart throws on render)"
                        )
        elif t == "pie" and "labels" not in params:
            issues.append(f"{name}: pie params.labels missing")
        elif t == "metric" and "style" not in (params.get("metric") or {}):
            issues.append(f"{name}: metric params.metric.style missing")
        ids = set()
        for a in vs.get("aggs") or []:
            for key in ("id", "type", "schema"):
                if key not in a:
                    issues.append(f"{name}: agg missing '{key}': {a}")
            if a.get("id") in ids:
                issues.append(f"{name}: duplicate agg id {a.get('id')}")
            ids.add(a.get("id"))
            field = (a.get("params") or {}).get("field")
            if field and known_fields is not None:
                if field not in known_fields:
                    issues.append(
                        f"{name}: field '{field}' is not in the index pattern's field list "
                        "(refresh the index pattern fields)"
                    )
                elif not known_fields[field]:
                    issues.append(
                        f"{name}: field '{field}' is not aggregatable in the index pattern"
                    )
    meta = attrs.get("kibanaSavedObjectMeta") or {}
    ss = _loads(meta.get("searchSourceJSON", "{}"), f"{name}: searchSourceJSON", issues)
    if isinstance(ss, dict):
        if "aggs" in ss:
            issues.append(f"{name}: searchSourceJSON contains 'aggs' (aggs belong in visState)")
        ref_name = ss.get("indexRefName")
        if ref_name:
            if ref_name not in refs:
                issues.append(f"{name}: indexRefName '{ref_name}' has no matching reference")
        elif not ss.get("index"):
            issues.append(f"{name}: searchSourceJSON has no index pattern (indexRefName/index)")
    return issues


def validate_dashboard(obj: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    name = obj.get("id") or (obj.get("attributes") or {}).get("title") or "dashboard"
    attrs = obj.get("attributes") or {}
    refs = {r.get("name"): r for r in obj.get("references") or []}
    panels = _loads(attrs.get("panelsJSON"), f"{name}: panelsJSON", issues)
    if isinstance(panels, list):
        if not panels:
            issues.append(f"{name}: dashboard has no panels")
        seen = set()
        for i, p in enumerate(panels):
            gd = p.get("gridData")
            if not isinstance(gd, dict) or not all(k in gd for k in ("x", "y", "w", "h", "i")):
                issues.append(
                    f"{name}: panel {i} has no valid gridData {{x,y,w,h,i}} (legacy/invalid panel shape)"
                )
            if "panelIndex" not in p:
                issues.append(f"{name}: panel {i} has no panelIndex")
            elif p["panelIndex"] in seen:
                issues.append(f"{name}: duplicate panelIndex {p['panelIndex']}")
            seen.add(p.get("panelIndex"))
            ref_name = p.get("panelRefName")
            if not ref_name and not (p.get("id") and p.get("type")):
                issues.append(f"{name}: panel {i} has neither panelRefName nor id/type")
            if ref_name and ref_name not in refs:
                issues.append(
                    f"{name}: panel {i} panelRefName '{ref_name}' has no matching reference"
                )
    elif panels is not None:
        issues.append(f"{name}: panelsJSON must be a list")
    if "optionsJSON" in attrs:
        _loads(attrs["optionsJSON"], f"{name}: optionsJSON", issues)
    else:
        issues.append(f"{name}: optionsJSON missing")
    return issues


def index_pattern_fields(index_pattern_obj: dict[str, Any]) -> dict[str, bool] | None:
    """name -> aggregatable from an index-pattern saved object, or None when
    the pattern carries no cached field list (then field checks are skipped)."""
    raw = (index_pattern_obj.get("attributes") or {}).get("fields")
    if not raw:
        return None
    try:
        fields = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return None
    if not fields:
        return None
    return {f.get("name"): bool(f.get("aggregatable")) for f in fields if f.get("name")}
