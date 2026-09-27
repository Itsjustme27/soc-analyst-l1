"""Server-side preview renderer for proposed Wazuh dashboards.

WHY
`create_wazuh_dashboard` proposes a blob of `panelsJSON` - a list of references
to saved-object visualization ids. That is a poor thing to approve: the operator
sees structure, not the chart, and cannot tell an empty panel from a broken one.
This module renders the *actual* panel queries against the *actual* indexer and
draws them in the *actual* gridData geometry the dashboard will use, so approval
is a decision about a chart rather than about JSON.

CORRELATION WITH WAZUH
Nothing here re-implements the panel definition. A panel is exactly what
`tools/dashboard/engine.py::_panel_plan` already produces -

    {"slug", "title", "vis_type", "aggs", "query"}

where `aggs` is a visState agg list (the thing that gets saved into the
visualization's visState) and `query` is the OpenSearch body the dashboards
server will run. This module executes those same aggs through the same
`_search` endpoint the panels will hit, and lays the results out using the
same geometry as `osd_objects.build_panels()` (2 columns, 24x15 per panel). So
the PNG is a faithful preview of the Wazuh dashboard, not a mock-up: if a panel
is empty here it will be empty there.

AGG TRANSLATION
visState aggs are not OpenSearch aggs, so `_agg_to_osd` maps them:
  count        -> {"filter": {"match_all": {}}}          (value = doc_count)
  avg/sum/...  -> {"avg": {"field": f}}                  (value = value)
  std_dev      -> {"extended_stats": {"field": f}}       (value = std_deviation)
  cardinality  -> {"cardinality": {"field": f}}
  terms        -> {"terms": {"field": f, "size": n}}
  date_histogram -> {"date_histogram": {...}}
`interval: "auto"` MUST be resolved to a concrete interval: the live indexer
returns HTTP 400 for a date_histogram with no interval, so a naive passthrough
produces a panel that errors in Wazuh for a reason that has nothing to do with
the data. `_auto_interval` picks one from the query's own time range.

matplotlib is imported lazily and only inside `render_dashboard_preview`, so
importing this module (or the tool registry) never requires it, and a
deployment without it gets one clear error instead of an ImportError trace.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.dashboard import osd_objects as osd

# Grid geometry - must match osd_objects.build_panels() defaults so the preview
# has the same shape as the dashboard it previews.
PANEL_W = 24
PANEL_H = 15
PANEL_COLS = 2

# Palette matches the SOC console (templates/index.html) so the preview sits in
# the page without a glaring white block.
C_BG = "#14130f"  # --panel
C_PANEL = "#211e18"  # --raised
C_TEXT = "#ece9e2"
C_MUTED = "#9a938a"
C_FAINT = "#6e685f"
C_ACCENT = "#58ae80"
# matplotlib rejects CSS rgba() strings - it needs hex or a tuple. #EBE7DE1A is
# rgba(235,231,222,.10): the console's hairline colour at 10% alpha.
C_GRID = "#EBE7DE1A"
SERIES = ("#58ae80", "#d8a15b", "#d97968", "#7fa8c9", "#b39ddb", "#c2b280")

MAX_BUCKETS = 20  # terms buckets drawn; a 500-bucket bar chart is unreadable
_TARGET_BUCKETS = 60  # date_histogram aims for roughly this many bars

_METRIC_AGGS = {
    "avg": "avg",
    "sum": "sum",
    "min": "min",
    "max": "max",
    "value_count": "value_count",
}
# Agg types whose result is a single scalar (not buckets). Kept separate from
# _METRIC_AGGS because std_dev/cardinality need a different OpenSearch body.
_METRIC_TYPES = frozenset(
    {"count", "avg", "sum", "min", "max", "value_count", "cardinality", "std_dev"}
)


class PreviewError(RuntimeError):
    """Preview could not be produced (bad spec, or matplotlib unavailable)."""


# --------------------------------------------------------------------------- #
# time range -> interval
# --------------------------------------------------------------------------- #
_REL = re.compile(r"^now\s*-\s*(\d+)\s*([smhdw])$", re.I)
_UNIT_MS = {"s": 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000, "w": 604_800_000}
# (kind, value) - calendar intervals for d/w, fixed below that. Both are
# accepted by the live indexer (verified).
_LADDER = (
    ("fixed_interval", "1m"),
    ("fixed_interval", "5m"),
    ("fixed_interval", "10m"),
    ("fixed_interval", "30m"),
    ("fixed_interval", "1h"),
    ("fixed_interval", "3h"),
    ("calendar_interval", "1d"),
    ("calendar_interval", "1w"),
)


def _parse_gte(query: dict[str, Any] | None) -> datetime | None:
    """Best-effort lower bound of a query's time range, as an aware datetime."""
    for clause in ((query or {}).get("bool") or {}).get("filter") or []:
        rng = (clause or {}).get("range") or {}
        for field, spec in rng.items():
            if field != "timestamp" or not isinstance(spec, dict):
                continue
            gte = spec.get("gte")
            if not isinstance(gte, str):
                continue
            m = _REL.match(gte.strip())
            if m:
                n, unit = int(m.group(1)), m.group(2).lower()
                return datetime.now(timezone.utc).replace(tzinfo=timezone.utc) - _timedelta_ms(
                    n * _UNIT_MS[unit]
                )
            try:
                return datetime.fromisoformat(gte.replace("Z", "+00:00"))
            except ValueError:
                continue
    return None


def _timedelta_ms(ms: int):
    from datetime import timedelta

    return timedelta(milliseconds=ms)


def _auto_interval(query: dict[str, Any] | None) -> tuple[str, str]:
    """Concrete (kind, value) for a date_histogram whose interval is "auto".

    Defaults to 1h when the range is unknown, which is a sane middle ground for
    a SOC dashboard and always valid.
    """
    gte = _parse_gte(query)
    if gte is None:
        return ("fixed_interval", "1h")
    span_ms = max((datetime.now(timezone.utc) - gte).total_seconds() * 1000, 60_000)
    for kind, value in _LADDER:
        step_ms = _UNIT_MS[value[-1]] * int(value[:-1]) if value[-1].isalpha() else 60_000
        if span_ms / step_ms <= _TARGET_BUCKETS:
            return (kind, value)
    return ("calendar_interval", "1w")


# --------------------------------------------------------------------------- #
# visState aggs -> OpenSearch aggs
# --------------------------------------------------------------------------- #
def _agg_to_osd(agg: dict[str, Any], query: dict[str, Any] | None) -> dict[str, Any]:
    """One visState agg -> one OpenSearch agg body (no id key)."""
    a_type = (agg.get("type") or "").strip()
    params = agg.get("params") or {}
    field = params.get("field") or agg.get("field")

    if a_type == "count":
        return {"filter": {"match_all": {}}}

    if a_type == "std_dev":
        if not field:
            raise PreviewError("std_dev agg needs params.field")
        return {"extended_stats": {"field": field}}

    if a_type == "cardinality":
        if not field:
            raise PreviewError("cardinality agg needs params.field")
        return {"cardinality": {"field": field, "precision_threshold": 1000}}

    if a_type in _METRIC_AGGS:
        # A metric over no field is a document count in Wazuh's UI.
        if not field:
            return {"filter": {"match_all": {}}}
        return {_METRIC_AGGS[a_type]: {"field": field}}

    if a_type == "terms":
        if not field:
            raise PreviewError("terms agg needs params.field")
        size = int(params.get("size") or 10)
        return {"terms": {"field": field, "size": max(1, min(size, MAX_BUCKETS * 5))}}

    if a_type in ("date_histogram", "auto_date_histogram"):
        if not field:
            raise PreviewError(f"{a_type} agg needs params.field")
        raw = str(params.get("interval") or params.get("fixed_interval") or "auto")
        if raw == "auto":
            kind, value = _auto_interval(query)
        elif _REL.match(raw) or raw in ("auto", ""):
            kind, value = _auto_interval(query)
        elif re.fullmatch(r"\d+[smhdw]", raw):
            unit = raw[-1]
            kind = "calendar_interval" if unit in "dw" else "fixed_interval"
            value = raw
        else:
            kind, value = "fixed_interval", raw
        return {
            "date_histogram": {
                "field": field,
                kind: value,
                "min_doc_count": int(params.get("min_doc_count", 0) or 0),
            }
        }

    if a_type == "histogram":
        # NUMERIC histogram. This is not a date histogram, and treating it as
        # one is worse than an empty panel: `interval` here is a number of
        # field units, and sending it to date_histogram makes the indexer try to
        # parse it as a date interval and answer 400. A CVSS score distribution
        # is the case that exposed this - a `histogram` over
        # vulnerability.score.base was translated to
        # {"date_histogram": {"fixed_interval": "1"}}, which is a parse error
        # against a float field.
        if not field:
            raise PreviewError("histogram agg needs params.field")
        raw = params.get("interval", params.get("fixed_interval", 1))
        try:
            interval = float(raw)
        except (TypeError, ValueError):
            raise PreviewError(
                f"histogram interval must be a number of field units, got {raw!r}"
            ) from None
        if interval <= 0:
            raise PreviewError(f"histogram interval must be > 0, got {raw!r}")
        return {
            "histogram": {
                "field": field,
                "interval": interval,
                "min_doc_count": int(params.get("min_doc_count", 0) or 0),
            }
        }

    raise PreviewError(f"unsupported agg type {a_type!r} in preview")


def vis_aggs_to_osd(
    aggs: list[dict[str, Any]], query: dict[str, Any] | None = None
) -> dict[str, Any]:
    """visState agg list -> {"<id>": <opensearch agg>, ...}.

    Ids come from the visState agg when present so nested bucket metrics keep
    their parent/child relationship.
    """
    out: dict[str, Any] = {}
    for i, agg in enumerate(aggs or []):
        if agg.get("enabled") is False:
            continue
        key = str(agg.get("id") or f"{agg.get('type', 'agg')}_{i}")
        out[key] = _agg_to_osd(agg, query)
    return out


# --------------------------------------------------------------------------- #
# run one panel
# --------------------------------------------------------------------------- #
def _is_metric(agg: dict[str, Any]) -> bool:
    """Whether a visState agg is a scalar series rather than a bucket series.

    `schema` is authoritative when it says one of the two things Wazuh actually
    uses, but it is not trusted blindly. A visState with `schema` set to the
    aggregation type instead of the metric/segment split is accepted by the
    saved-objects API and then renders as a blank panel, and the preview
    faithfully reported it as `empty` - which is honest about the data and
    useless about the cause. Inferring from the agg type when `schema` says
    neither lets the preview diagnose a real dashboard bug instead of just
    reporting a symptom.
    """
    schema = (agg.get("schema") or "").strip().lower()
    if schema in ("metric", "segment"):
        return schema == "metric"
    return (agg.get("type") or "").strip() in _METRIC_TYPES


def _bucket_rows(buckets: list[dict[str, Any]], child_key: str | None) -> list[dict[str, Any]]:
    rows = []
    for b in buckets:
        label = b.get("key_as_string") or b.get("key")
        value = b.get("doc_count")
        if child_key and isinstance(b.get(child_key), dict):
            cv = b[child_key]
            value = cv.get("value", cv.get("doc_count", value))
        rows.append({"label": label, "value": value})
    return rows


def _scalar_value(agg_body: dict[str, Any], result: dict[str, Any]) -> Any:
    if "doc_count" in result:
        return result["doc_count"]
    if "value" in result:
        return result["value"]
    if "std_deviation" in result:
        return result["std_deviation"]
    for k in ("avg", "sum", "min", "max"):
        if k in result:
            return result[k]
    return None


def run_panel(
    indexer: Any,
    index: str,
    panel: dict[str, Any],
    timeout: float | None = None,
) -> dict[str, Any]:
    """Execute one panel's aggs against the live indexer.

    Never raises for data problems - returns {"status": "error"|"empty"|"ok"}
    so one broken panel cannot blank the whole preview. A preview that silently
    drops a failing panel would be worse than useless: the operator would
    approve a dashboard with a hole in it.
    """
    title = panel.get("title") or "(untitled)"
    raw_type = (panel.get("vis_type") or "metric").strip()
    # Normalize the same way the saved visualization will be, so the preview
    # draws the chart Wazuh draws: the engine emits "bar", which Wazuh stores
    # as a "histogram". Rendering from the raw string would draw a different
    # chart than the operator is approving. An unknown type is reported as-is
    # rather than raising - a preview must not die on a bad label.
    try:
        vis_type = osd.normalize_vis_type(raw_type)
    except ValueError:
        vis_type = raw_type.lower()
    aggs = panel.get("aggs") or []
    query = panel.get("query") or {"bool": {"filter": []}}

    out: dict[str, Any] = {
        "title": title,
        "slug": panel.get("slug"),
        "vis_type": vis_type,
        "status": "error",
        "rows": [],
        "total": 0,
        "note": "",
    }

    if not aggs:
        out.update(status="empty", note="panel has no aggregations")
        return out

    try:
        osd_aggs = vis_aggs_to_osd(aggs, query)
        body = {"size": 0, "query": query, "aggs": osd_aggs}
        resp = indexer.search(index, body)
    except PreviewError as e:
        out.update(status="error", note=str(e))
        return out
    except Exception as e:  # indexer/network/400 - surface, do not crash
        out.update(status="error", note=f"{type(e).__name__}: {str(e)[:200]}")
        return out

    aggs_out = resp.get("aggregations") or {}
    total = ((resp.get("hits") or {}).get("total") or {}).get("value")
    out["total"] = total

    # Split metrics from segments the way the visState does.
    metrics: list[tuple[str, str, dict[str, Any]]] = []
    segments: list[tuple[str, dict[str, Any]]] = []
    for i, agg in enumerate(aggs):
        key = str(agg.get("id") or f"{agg.get('type', 'agg')}_{i}")
        res = aggs_out.get(key)
        if res is None:
            continue
        if _is_metric(agg):
            metrics.append(
                (key, (agg.get("params") or {}).get("customLabel") or agg.get("type", "count"), res)
            )
        else:
            segments.append((key, res))

    if segments:
        key, res = segments[0]
        child = next((m[0] for m in metrics if m[0] != key), None)
        rows = _bucket_rows(res.get("buckets") or [], child)
        out["rows"] = rows
        if not rows:
            out.update(
                status="empty",
                note=f"no buckets for {segments and _seg_field(aggs, key) or 'the field'}",
            )
        else:
            out["status"] = "ok"
        return out

    if metrics:
        key, label, res = metrics[0]
        value = _scalar_value(aggs_out.get(key) or res, res)
        out["rows"] = [{"label": label, "value": value}]
        out["status"] = "ok" if value is not None else "empty"
        if value is None:
            out["note"] = "aggregation returned no value"
        return out

    out.update(status="empty", note="aggregation produced neither buckets nor a value")
    return out


def _seg_field(aggs: list[dict[str, Any]], key: str) -> str:
    for i, a in enumerate(aggs):
        if str(a.get("id") or f"{a.get('type', 'agg')}_{i}") == key:
            return (a.get("params") or {}).get("field") or "field"
    return "field"


# --------------------------------------------------------------------------- #
# rendering
# --------------------------------------------------------------------------- #
def _fmt_num(v: Any) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        if v != v or v in (math.inf, -math.inf):
            return "-"
        if v == int(v) and abs(v) < 1e15:
            return f"{int(v):,}"
        return f"{v:,.2f}"
    if isinstance(v, int):
        return f"{v:,}"
    return str(v)


def _label(v: Any, width: int = 22) -> str:
    s = "" if v is None else str(v)
    return s if len(s) <= width else s[: width - 1] + "\u2026"


def render_dashboard_preview(
    panels: list[dict[str, Any]],
    indexer: Any,
    out_path: str | Path,
    *,
    index: str = "wazuh-alerts-*",
    title: str = "",
    subtitle: str = "",
) -> dict[str, Any]:
    """Render panels to a PNG laid out like the Wazuh dashboard.

    Returns {"path", "panels", "grid", "empty", "error"} - "panels" carries the
    per-panel status so the UI can list which panels are empty, and "error" is
    set only when the whole render failed.
    """
    try:
        import matplotlib

        matplotlib.use("Agg", force=True)
        import matplotlib.pyplot as plt
        from matplotlib.figure import Figure
    except Exception as e:  # pragma: no cover - depends on optional dep
        raise PreviewError(
            f"matplotlib is required to render dashboard previews ({e}). "
            "Install it with: pip install matplotlib"
        ) from e

    panels = panels or []
    if not panels:
        raise PreviewError("no panels to preview")

    results = [run_panel(indexer, index, p) for p in panels]

    # Named n_grid_rows, not rows: each result dict also carries a "rows" key
    # holding that panel's data buckets, and the two are unrelated.
    n_grid_rows = max(1, math.ceil(len(panels) / PANEL_COLS))
    # Keep the dashboard's 24:15 per-panel aspect so the preview is a true
    # scale model of what the operator will approve.
    fig_w = 13.0
    fig_h = fig_w * (PANEL_H * n_grid_rows) / (PANEL_W * PANEL_COLS)

    fig = Figure(figsize=(fig_w, fig_h), dpi=110, facecolor=C_BG)
    gs = fig.add_gridspec(
        n_grid_rows,
        PANEL_COLS,
        left=0.035,
        right=0.985,
        top=0.90 if (title or subtitle) else 0.97,
        bottom=0.035,
        hspace=0.30,
        wspace=0.16,
    )

    if title:
        fig.suptitle(
            title, color=C_TEXT, fontsize=13, fontweight="bold", x=0.035, ha="left", y=0.975
        )
    if subtitle:
        fig.text(0.035, 0.935, subtitle, color=C_MUTED, fontsize=8.5, ha="left")

    for i, res in enumerate(results):
        ax = fig.add_subplot(gs[i // PANEL_COLS, i % PANEL_COLS])
        ax.set_facecolor(C_PANEL)
        for spine in ax.spines.values():
            spine.set_color(C_GRID)
        ax.tick_params(colors=C_MUTED, labelsize=7.5, length=2)
        _draw_panel(ax, res)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out_path, facecolor=C_BG, bbox_inches=None)
    plt.close(fig)

    return {
        "path": str(out_path),
        "panels": results,
        "grid": {"cols": PANEL_COLS, "rows": n_grid_rows, "panel_w": PANEL_W, "panel_h": PANEL_H},
        "empty": [r["title"] for r in results if r["status"] == "empty"],
        "errors": [r["title"] for r in results if r["status"] == "error"],
    }


def _draw_panel(ax: Any, res: dict[str, Any]) -> None:
    """Draw one panel's result. Any failure degrades to a readable note."""
    title = res.get("title") or "(untitled)"
    status = res.get("status")
    vis_type = res.get("vis_type") or "metric"

    ax.set_title(_label(title, 34), color=C_TEXT, fontsize=9, fontweight="bold", loc="left", pad=6)

    if status != "ok":
        msg = {
            "empty": "no data",
            "error": "query failed",
        }.get(status, "no data")
        detail = res.get("note") or ""
        ax.text(
            0.5,
            0.54,
            msg.upper(),
            color=C_FAINT if status == "empty" else C_ACCENT,
            fontsize=11,
            fontweight="bold",
            ha="center",
            va="center",
        )
        if detail:
            ax.text(
                0.5, 0.36, _label(detail, 46), color=C_FAINT, fontsize=6.5, ha="center", va="center"
            )
        ax.set_xticks([])
        ax.set_yticks([])
        return

    rows = res.get("rows") or []
    try:
        if vis_type == "metric":
            value = rows[0]["value"] if rows else None
            ax.text(
                0.5,
                0.5,
                _fmt_num(value),
                color=C_TEXT,
                fontsize=30,
                fontweight="bold",
                ha="center",
                va="center",
            )
            ax.set_xticks([])
            ax.set_yticks([])
            if rows and rows[0].get("label"):
                ax.text(
                    0.5,
                    0.22,
                    _label(rows[0]["label"], 28),
                    color=C_MUTED,
                    fontsize=8,
                    ha="center",
                    va="center",
                )
            return

        if vis_type == "table":
            _draw_table(ax, rows)
            return

        if vis_type == "pie":
            _draw_pie(ax, rows)
            return

        _draw_bars(ax, rows, vis_type)
    except Exception as e:  # never let one panel break the figure
        ax.clear()
        ax.set_facecolor(C_PANEL)
        ax.text(0.5, 0.5, "render error", color=C_FAINT, fontsize=10, ha="center", va="center")
        ax.set_title(_label(title, 34), color=C_TEXT, fontsize=9, loc="left", pad=6)
        ax.text(
            0.5,
            0.34,
            _label(f"{type(e).__name__}", 40),
            color=C_FAINT,
            fontsize=6.5,
            ha="center",
            va="center",
        )


def _draw_bars(ax: Any, rows: list[dict[str, Any]], vis_type: str) -> None:
    """Buckets as a chart, oriented to match what Wazuh will actually draw.

    `vis_type` here is already normalized (osd.normalize_vis_type), so the
    engine's "bar" arrives as "histogram" - and a Wazuh histogram is VERTICAL,
    including over a date_histogram. Orientation therefore follows the vis type
    alone; it must not be guessed from the label shape, or the preview ends up
    showing a horizontal chart for a panel that will render vertically.
    """
    top = rows[:MAX_BUCKETS]
    values = [r.get("value") or 0 for r in top]
    labels = [_label(r.get("label"), 16) for r in top]
    horizontal = vis_type == "horizontal_bar"

    if horizontal:
        ypos = list(range(len(top)))
        ax.barh(ypos, values, color=C_ACCENT, height=0.68, zorder=3)
        ax.set_yticks(ypos)
        ax.set_yticklabels(labels, fontsize=6.5)
        ax.invert_yaxis()
        ax.xaxis.grid(True, color=C_GRID, zorder=0)
        ax.set_axisbelow(True)
    elif vis_type in ("line", "area"):
        xpos = list(range(len(top)))
        ax.plot(xpos, values, color=C_ACCENT, linewidth=1.6, zorder=3)
        if vis_type == "area":
            ax.fill_between(xpos, values, color=C_ACCENT, alpha=0.18, zorder=2)
        ax.scatter(xpos, values, color=C_ACCENT, s=6, zorder=4)
        _tick_every(ax, xpos, labels, top)
        ax.yaxis.grid(True, color=C_GRID, zorder=0)
        ax.set_axisbelow(True)
    else:  # histogram and anything else bucket-shaped
        xpos = list(range(len(top)))
        ax.bar(xpos, values, color=C_ACCENT, width=0.78, zorder=3)
        _tick_every(ax, xpos, labels, top)
        ax.yaxis.grid(True, color=C_GRID, zorder=0)
        ax.set_axisbelow(True)

    ax.grid(True, axis="x" if horizontal else "y", color=C_GRID, zorder=0)
    if values and max(values) > 0:
        ax.set_ylim(0, max(values) * 1.14) if not horizontal else ax.set_xlim(0, max(values) * 1.14)


def _tick_every(ax: Any, xpos: list[int], labels: list[str], top: list[dict[str, Any]]) -> None:
    """Thin x tick labels so they never overlap into an unreadable smear."""
    step = max(1, len(top) // 6)
    ax.set_xticks(xpos[::step])
    ax.set_xticklabels(
        [labels[i] for i in range(0, len(top), step)], fontsize=6, rotation=30, ha="right"
    )


def _draw_pie(ax: Any, rows: list[dict[str, Any]]) -> None:
    top = rows[:MAX_BUCKETS]
    values = [max(0.0, float(r.get("value") or 0)) for r in top]
    labels = [_label(r.get("label"), 14) for r in top]
    if not any(values):
        ax.text(0.5, 0.5, "no data", color=C_FAINT, fontsize=10, ha="center", va="center")
        ax.set_xticks([])
        ax.set_yticks([])
        return
    ax.pie(
        values,
        labels=labels,
        autopct=lambda p: f"{p:.0f}%" if p >= 5 else "",
        textprops={"color": C_MUTED, "fontsize": 6.5},
        colors=list(SERIES) * ((len(values) // len(SERIES)) + 1),
        wedgeprops={"edgecolor": C_PANEL, "linewidth": 1},
    )
    ax.axis("equal")


def _draw_table(ax: Any, rows: list[dict[str, Any]]) -> None:
    top = rows[:12]
    if not top:
        ax.text(0.5, 0.5, "no rows", color=C_FAINT, fontsize=10, ha="center", va="center")
        ax.set_xticks([])
        ax.set_yticks([])
        return
    cell_labels = [[_label(r.get("label"), 20), _fmt_num(r.get("value"))] for r in top]
    tbl = ax.table(
        cellText=cell_labels,
        colLabels=["key", "count"],
        cellLoc="left",
        colLoc="left",
        loc="upper left",
    )
    tbl.auto_set_font_size(False)
    tbl.set_fontsize(6.8)
    tbl.scale(1, 1.32)
    for (r, _c), cell in tbl.get_celld().items():
        cell.set_edgecolor(C_GRID)
        cell.set_facecolor(C_PANEL)
        cell.get_text().set_color(C_MUTED)
        if r == 0:
            cell.get_text().set_color(C_ACCENT)
            cell.get_text().set_fontweight("bold")
    ax.axis("off")


# --------------------------------------------------------------------------- #
# duplicate detection
# --------------------------------------------------------------------------- #
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize_title(title: str) -> str:
    """Loose title key so 'Web Attacks', 'web attacks' and 'web-attacks' match."""
    return _NON_ALNUM.sub(" ", (title or "").strip().lower()).strip()


# A dashboard title is a NAME, not a request. The engineer is an LLM, and when
# it misreads the field it tends to copy the operator's whole sentence across.
# That shipped once as a 213-character title ending in "...drill-down views."
# with the surrounding JSON quotes still attached, which is unreadable in the
# dashboard list and made duplicate detection useless (two requests that
# differed by a word were two different dashboards).
_TITLE_MAX = 80
_TITLE_MAX_WORDS = 12


def clean_title(raw: str) -> str:
    """Normalize a raw title without changing its meaning.

    Strips the JSON quoting the model sometimes carries over ("Foo"), collapses
    runs of whitespace, and drops interior double quotes - none of which are
    meaningful in a dashboard name but all of which are visible in the list UI.
    """
    s = "" if raw is None else str(raw).strip()
    # Only strip a *balanced* surrounding pair, so a title that genuinely starts
    # and ends with a quote is not mangled into nothing.
    if len(s) >= 2 and s[0] == s[-1] == '"':
        s = s[1:-1].strip()
    s = " ".join(s.split())
    return s.replace('"', "").strip()


def check_title(raw: str) -> tuple[str, str | None]:
    """(cleaned_title, problem_message). `problem` is None when the title is
    usable; otherwise it is a message explaining what to do instead.

    Rejects rather than silently truncates. A wrong dashboard name is a
    decision the operator has to be able to see and correct, and a truncated
    sentence is not reviewable - the operator cannot tell what was dropped. The
    message is written for the model that will read it, since the engineer
    retries on ToolError.
    """
    title = clean_title(raw)
    if not title:
        return title, (
            "title is empty. Give the dashboard a short name such as "
            "'Web Server Attacks' - do not paste the request text."
        )
    words = title.split()
    if len(title) > _TITLE_MAX or len(words) > _TITLE_MAX_WORDS:
        return title, (
            f"title is {len(title)} characters / {len(words)} words, which is a "
            "request, not a name. Use a short dashboard name of at most "
            f"{_TITLE_MAX} characters (e.g. 'Web Server Attacks') and put the "
            "full requirement in `description` or `reason`."
        )
    return title, None


# Clause boundaries, earliest match wins. A request sentence states its subject
# first and then qualifies it ("Build a threat dashboard THAT aggregates CVEs
# and IOCs"), so the first clause is the name and the rest is the spec.
_CLAUSE_END = (" that ", " which ", " with ", ", ", "; ", ": ", " and ", " - ", " -- ")

# Imperative lead-ins the model copies from the request. "Build a real-time
# threat dashboard" is a name; "Build" is the verb, not part of it.
_LEAD_VERB = re.compile(
    r"^(?:please\s+)?(?:can you\s+|i\s+(?:want|need|would like)\s+(?:a|an|to)\s+)?"
    r"(?:build|create|make|design|generate|add|show|give me|set up|produce)\s+"
    r"(?:me\s+)?(?:a|an|the|some)\s+",
    re.IGNORECASE,
)


def derive_title(raw: str, limit: int = _TITLE_MAX) -> str:
    """Best-effort short name from a sentence-shaped title.

    Used ONLY when replaying an approved proposal, where hard-failing would
    strand a proposal the operator already approved. The propose path rejects
    instead (see check_title) so the model learns to send a name; by the time a
    proposal is approved it is too late to be picky, and an imperfect-but-sane
    name the operator can rename beats a dashboard that never gets created.
    """
    s = clean_title(raw).rstrip(" .")
    if not s:
        # Deliberately NOT "": a replay must never come back empty-handed, and
        # an empty title is the one input that would be rejected downstream too,
        # so returning it would strand the approval exactly as before.
        return "Untitled dashboard"
    s = _LEAD_VERB.sub("", s, count=1).strip() or s

    cut = len(s)
    for sep in _CLAUSE_END:
        i = s.lower().find(sep)
        if i != -1:
            cut = min(cut, i)
    s = s[:cut].strip().rstrip(" ,;:-")

    # Still too long: take whole words up to the budget, never mid-word.
    words = s.split()
    if len(s) > limit or len(words) > _TITLE_MAX_WORDS:
        keep = 1
        used = 0
        for w in words:
            if used and (used + len(w) + 1 > limit or keep >= _TITLE_MAX_WORDS):
                break
            used += len(w) + 1
            keep += 1
        s = " ".join(words[:keep])

    # Guard the degenerate cases. A title with no letters or digits left ("!!!",
    # "---", "...") is worse than the original request: it is unsearchable in
    # the dashboard list and every such dashboard collides with every other.
    if not _NON_ALNUM.sub("", s).replace(" ", ""):
        return "Untitled dashboard"
    return s.strip()


def resolve_title(ctx: Any, raw: str) -> tuple[str, str | None]:
    """(title_to_use, problem_message). `problem` is None when usable.

    The propose/execute split here is the same one as duplicate_veto, and for
    the same reason. While PROPOSING, a sentence title is rejected so the model
    retries with a real name - that is where the mistake is still cheap to fix.
    While REPLAYING an approved proposal it is not: the operator already
    approved this dashboard, and refusing over punctuation strands a decision
    they made. So the title is derived instead, and the result reports the
    change so the rename is visible rather than silent.
    """
    title, problem = check_title(raw)
    if problem is None:
        return title, None
    if not getattr(ctx, "approval", None):
        return title, problem
    derived = derive_title(raw)
    if derived:
        return derived, None
    return title, problem


def find_duplicate(
    title: str, limit: int = 100, fetch: Callable[..., Any] | None = None
) -> dict[str, Any] | None:
    """Existing saved dashboard whose title matches `title`, else None.

    `fetch` is injectable so this is testable without a Wazuh dashboard.
    """
    if fetch is None:
        from tools.dashboard.client import dashboards_request

        def fetch(method: str, path: str, **kw: Any) -> dict[str, Any]:
            return dashboards_request(method, path, **kw)

    try:
        resp = fetch(
            "GET", "/api/saved_objects/_find", params={"type": "dashboard", "per_page": limit}
        )
    except Exception:
        # Never block a create because the listing failed - the create will
        # still be validated by Wazuh itself.
        return None

    want = normalize_title(title)
    if not want:
        return None
    for item in resp.get("saved_objects") or resp.get("objects") or []:
        attrs = item.get("attributes") or {}
        if normalize_title(attrs.get("title") or "") != want:
            continue
        try:
            panels = len(json.loads(attrs.get("panelsJSON") or "[]") or [])
        except (json.JSONDecodeError, TypeError):
            panels = None
        return {
            "id": item.get("id"),
            "title": attrs.get("title"),
            "description": attrs.get("description") or "",
            "panels": panels,
            "updated_at": attrs.get("updatedAt") or item.get("updated_at"),
        }
    return None


def duplicate_veto(ctx: Any, title: str) -> str | None:
    """Refuse to PROPOSE a dashboard that already exists. Returns the error
    message, or None when the create may proceed.

    This is deliberately a PROPOSE-time guard, not a create-time one, and the
    distinction is load-bearing. The failure it exists to stop is the engineer
    re-proposing the same dashboard on every request. But a human approving a
    proposal is a decision to create that dashboard, and execution of an
    approved proposal is a separate run of this same tool - so a create-time
    guard would veto it. Worse, the veto is self-fulfilling: once an earlier
    execution really did create the dashboard, the guard would refuse the
    replay *forever*, stranding a proposal that had already been approved. That
    is exactly how this shipped and it locked approved proposals out of
    execution.

    So: when ctx.approval is set, approval_executor is replaying an approved
    proposal (the single-use claim already happened - see
    approval_executor.claim_for_execution) and the guard stands down. It still
    runs on a plain propose, which is where the loop lived.
    """
    if getattr(ctx, "approval", None):
        return None  # replaying an approved proposal - a human already decided
    duplicate = find_duplicate(title)
    if not duplicate:
        return None
    return (
        f"Dashboard {duplicate.get('title')!r} already exists "
        f"(id={duplicate.get('id')}, {duplicate.get('panels')} panels, "
        f"updated {duplicate.get('updated_at')}). Refusing to propose a "
        "duplicate - use get_wazuh_dashboards to see it, or "
        "update_wazuh_dashboard to change it. Preview it in the engineer's "
        "Dashboard Preview tab first."
    )
