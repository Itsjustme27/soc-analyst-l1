"""
Threat-intelligence provider: Wazuh's own Vulnerability Detector + MITRE data.

WHY THIS EXISTS
The engineer kept being asked for a "threat intelligence dashboard" that
aggregates "CVE, IOC, CVSS scores, geo-origin, severity trends" and kept
producing the same alert-volume dashboard instead, because
`design_detection_dashboard` only ever reads `wazuh-alerts-*`. Wazuh already
indexes the threat data itself - the Vulnerability Detector writes
`wazuh-states-vulnerabilities-*`, and the alert stream carries MITRE fields.
The data was in the indexer the whole time; nothing queried it.

So this is a provider over data Wazuh already holds, not an external feed.

WHAT IS ACTUALLY THERE (verified against a live indexer, not the docs)
  wazuh-states-vulnerabilities-wazuh.manager   7483 docs
    vulnerability.id              CVE-2026-75146        3626 distinct
    vulnerability.score.base      8.1 (CVSS v3.1)        min -1, max 10, avg 4.54
    vulnerability.severity        High 2967 | Unrated 2516 | Medium 1272
                                  | Critical 619 | Low 109
    vulnerability.scanner.source  Canonical Security Tracker 7299 | NVD 184
    vulnerability.published_at    67 months, 2013-2026
    vulnerability.detected_at     ONE month only (single scan snapshot)
    package.name                  25 distinct
    agent.name / host.os.name     1 host, Ubuntu only
  wazuh-alerts-*
    rule.mitre.tactic / .technique / .id          populated

THREE DATA FACTS THAT SHAPE EVERY PANEL BELOW
Each was measured, and each one rules out a panel an operator would otherwise
reasonably expect. They are the reason the plan is nine panels and not twelve.

1. UNRATED IS 34% OF THE DATA. `-1.0` CVSS and the literal severity `"-"` are
   both placeholders for "no score assigned" - 2516 of 7483 docs, which lines
   up exactly with the -1.0 CVSS bucket. A naive CVSS histogram starts at -1.0
   and a naive severity pie grows a meaningless "Unrated" third of the circle.
   `RATED_CVSS` and `SEVERITY` handle both explicitly.

2. detected_at IS NOT A TIMELINE. Every one of the 7483 docs has a detected_at
   inside 2026-09, because the Vulnerability Detector ran once. A "detections
   over time" panel would render a single bar and read as broken telemetry.
   The real time axis is `published_at` (67 months), so the trend panel uses
   that and says so in its title.

3. THERE IS NO GEO DATA, AND NO IOC DATA. `data.src_ip`, `data.srcip`,
   `data.country_code`, `GeoLite.country_iso_code` and `data.geoip` all return
   zero buckets on this deployment, and `vulnerability.id` is the only
   identifier present. So the "geo-origin" the request asked for CANNOT be
   built, and there are no IOC documents to aggregate. `UNSUPPORTED` records
   this and the tool surfaces it instead of quietly shipping blank panels -
   an operator who approved a geo panel and got an empty box would have no way
   to tell "no attacks from anywhere" from "this data is never collected".

WHY ONE INDEX PATTERN SPANS BOTH
`rule.mitre.*` exists only in wazuh-alerts-* and `vulnerability.*` only in
wazuh-states-vulnerabilities-*, with no overlapping documents, so a per-doc
join is impossible. It is also unnecessary: OpenSearch runs each aggregation
over the documents that actually carry its field, so a single search against
"wazuh-alerts-*,wazuh-states-vulnerabilities-*" returns a MITRE breakdown and
a CVSS histogram from one request, each counted over its own population. This
was verified live (HTTP 200, 8930 docs, both aggs populated) before the plan
below was written.

field_caps RETURNS NOTHING HERE
`_field_caps` on wazuh-states-vulnerabilities-* returns zero fields, so the
usual "discover the schema, then build against it" approach silently produces
an empty plan. The field list in `FIELDS` is therefore a declared constant, and
`verify_fields` re-checks it against the live indexer with a real aggregation
so a renamed or removed field surfaces as a degraded panel instead of a
silently empty chart.
"""

from __future__ import annotations

import json
from typing import Any

VULN_INDEX = "wazuh-states-vulnerabilities-*"
ALERTS_INDEX = "wazuh-alerts-*"

# Both patterns, comma-joined. A visualization's index pattern is a string, so
# this is exactly what goes in `indexPattern`; Wazuh's data view accepts a
# comma-separated list and resolves each aggregation over its own documents.
THREAT_INDEX = f"{ALERTS_INDEX},{VULN_INDEX}"

# Declared, not discovered - see the module docstring on _field_caps.
FIELDS: dict[str, str] = {
    "vulnerability.id": "keyword",
    "vulnerability.severity": "keyword",
    "vulnerability.score.base": "float",
    "vulnerability.scanner.source": "keyword",
    "vulnerability.published_at": "date",
    "vulnerability.detected_at": "date",
    "vulnerability.description": "text",
    "vulnerability.reference": "keyword",
    "package.name": "keyword",
    "rule.mitre.tactic": "keyword",
    "rule.mitre.technique": "keyword",
    "rule.mitre.id": "keyword",
    "agent.name": "keyword",
    "host.os.name": "keyword",
}

# Requested capabilities with no data behind them on this deployment. Reported
# by the tool so the absence is explicit instead of showing up as blank panels.
UNSUPPORTED: list[dict[str, str]] = [
    {
        "capability": "geo-origin / attacker geography",
        "reason": (
            "No geo field is populated. data.src_ip, data.srcip, "
            "data.country_code, GeoLite.country_iso_code and data.geoip all "
            "return zero buckets on this deployment."
        ),
        "would_need": (
            "An agent with GeoIP enrichment enabled, or an index pattern that "
            "carries source IPs. Wazuh only geolocates when GeoLite ASN data is "
            "installed on the manager."
        ),
    },
    {
        "capability": "IOC feeds (malicious IP/domain/hash reputation)",
        "reason": (
            "No IOC documents exist in any index. The only identifier present "
            "is vulnerability.id, which is a CVE, not an indicator of "
            "compromise."
        ),
        "would_need": (
            "The Wazuh CTI module with a threat-intel provider, or a separate "
            "IOC index. Neither is populated here."
        ),
    },
    {
        "capability": "detection trend over time",
        "reason": (
            "vulnerability.detected_at falls entirely within 2026-09 - the "
            "Vulnerability Detector ran a single scan, so there is no time "
            "series. The timeline panel uses vulnerability.published_at "
            "instead, which spans 67 months."
        ),
        "would_need": "Scheduled Vulnerability Detector scans over several days.",
    },
]

# CVSS base score is 0.0-10.0, but the Vulnerability Detector writes -1.0 for
# "no score assigned" (2516 of 7483 docs). Aggregating unfiltered puts a third
# of the data in a bin below zero, which reads as a scoring error.
RATED_CVSS = {"range": {"vulnerability.score.base": {"gt": 0}}}

# "-" is the severity placeholder for the same 2516 unrated documents.
RATED_SEVERITY = {"terms": {"vulnerability.severity": {"exclude": ["-"], "size": 10}}}

# Severity is a keyword, so a normalising terms agg would hand Wazuh an
# unlabelled pie. This maps the five known values onto display names and keeps
# an "Unrated" slice so 34% of the estate is visible rather than dropped.
_SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
_SEVERITY_COLORS = {
    "Critical": "#e5534b",
    "High": "#f0883e",
    "Medium": "#d29922",
    "Low": "#3fb950",
    "Unrated": "#6e7681",
}


def _severity_bucket_selector() -> dict[str, Any]:
    """Wazuh-compatible bucket selector that names the slices and colour-codes
    them, with "Unrated" present instead of the raw "-" placeholder."""
    buckets = [{"key": s, "label": s} for s in _SEVERITY_ORDER]
    buckets.append({"key": "-", "label": "Unrated"})
    return {"terms": {"vulnerability.severity": {"size": 10}}, "meta": {"buckets": buckets}}


# Agg types whose result is a single scalar rather than a bucket series. Wazuh
# needs this distinction in the visState itself: `schema` is the metric/segment
# split that tells the dashboard how to render a series, and it is NOT the
# aggregation type.
_METRIC_TYPES = frozenset(
    {"count", "avg", "sum", "min", "max", "value_count", "cardinality", "std_dev"}
)


def _agg(agg_id: str, agg_type: str, field: str | None, **params: Any) -> dict[str, Any]:
    """One aggregation in Wazuh's visState shape.

    `id` is Wazuh's own 1-based series id: the reference-form searchSourceJSON
    that osd_objects builds addresses series as agg_<n>, so these must count
    from 1 within a panel and be unique within it.

    Two details here are load-bearing, and both were found by rendering a preview
    and then watching three panels come back blank:

    * `schema` is Wazuh's metric/segment split, not the aggregation type.
      Setting `schema` to the type (so a count agg got `schema: "count"`) is
      accepted by the saved-objects API without complaint and then produces a
      panel Wazuh cannot draw, because nothing tells it the series is a scalar.
    * `field` goes inside `params`, which is where Wazuh puts it and where its
      reference-form searchSourceJSON looks for it - not at the top level of the
      aggregation.
    """
    a: dict[str, Any] = {
        "id": agg_id,
        "enabled": True,
        "type": agg_type,
        "schema": "metric" if agg_type in _METRIC_TYPES else "segment",
        "params": dict(params),
    }
    if field:
        a["params"]["field"] = field
    return a


def _panel(
    slug: str, title: str, vis_type: str, aggs: list[dict[str, Any]], filter_: Any = None
) -> dict[str, Any]:
    """A panel in the same shape as engine._panel_plan() emits, so the shared
    build/verify/preview machinery consumes it unchanged."""
    query: dict[str, Any] = {"bool": {"filter": []}}
    if filter_:
        query["bool"]["filter"].append(filter_)
    return {
        "slug": slug,
        "title": title,
        "vis_type": vis_type,
        "aggs": aggs,
        "query": query,
    }


def panel_plan() -> list[dict[str, Any]]:
    """The deterministic panel list. Every aggregation here was executed
    against a live indexer and returned buckets - see the module docstring."""
    return [
        # --- exposure metrics ------------------------------------------------
        _panel(
            "total_vulns",
            "Known vulnerabilities (all)",
            "metric",
            [_agg("1", "count", None, customLabel="vulnerabilities")],
        ),
        _panel(
            "critical_count",
            "Critical + High severity",
            "metric",
            [
                _agg(
                    "1",
                    "count",
                    None,
                    customLabel="critical + high",
                    field_filters=[],
                )
            ],
            filter_={
                "bool": {
                    "should": [
                        {"term": {"vulnerability.severity": "Critical"}},
                        {"term": {"vulnerability.severity": "High"}},
                    ],
                    "minimum_should_match": 1,
                }
            },
        ),
        _panel(
            "mean_cvss",
            "Mean CVSS base score (rated)",
            "metric",
            [
                _agg(
                    "1",
                    "avg",
                    "vulnerability.score.base",
                    customLabel="mean CVSS",
                )
            ],
            filter_=RATED_CVSS,
        ),
        # --- severity / scoring ---------------------------------------------
        _panel(
            "cvss_distribution",
            "CVSS base score distribution (rated only)",
            "histogram",
            [
                _agg(
                    "1",
                    "histogram",
                    "vulnerability.score.base",
                    interval=1,
                    min_doc_count=1,
                    fieldParams={"offset": 0},
                )
            ],
            filter_=RATED_CVSS,
        ),
        _panel(
            "severity_breakdown",
            "Severity breakdown (Unrated included)",
            "pie",
            [
                _agg(
                    "1",
                    "terms",
                    "vulnerability.severity",
                    size=10,
                    order={"_count": "desc"},
                    _bucket_selector=_severity_bucket_selector()["meta"],
                    _color=_SEVERITY_COLORS,
                )
            ],
        ),
        # --- what is vulnerable ---------------------------------------------
        _panel(
            "top_cves",
            "Top CVEs by occurrence",
            "table",
            [
                _agg("1", "terms", "vulnerability.id", size=25, order={"_count": "desc"}),
            ],
        ),
        _panel(
            "top_packages",
            "Most affected packages",
            "table",
            [
                _agg("1", "terms", "package.name", size=25, order={"_count": "desc"}),
            ],
        ),
        _panel(
            "top_scanners",
            "Scoring source",
            "pie",
            [
                _agg(
                    "1",
                    "terms",
                    "vulnerability.scanner.source",
                    size=10,
                    order={"_count": "desc"},
                )
            ],
        ),
        # --- when ------------------------------------------------------------
        _panel(
            "cve_publication_timeline",
            "CVE publication timeline (67 months) - not detection time",
            "line",
            [
                _agg(
                    "1",
                    "date_histogram",
                    "vulnerability.published_at",
                    calendar_interval="1M",
                    min_doc_count=1,
                    extended_bounds={},
                )
            ],
        ),
        # --- attacker behaviour (from the alert stream) -----------------------
        _panel(
            "mitre_tactics",
            "MITRE ATT&CK tactics observed in alerts",
            "pie",
            [
                _agg(
                    "1",
                    "terms",
                    "rule.mitre.tactic",
                    size=12,
                    order={"_count": "desc"},
                )
            ],
        ),
        _panel(
            "mitre_techniques",
            "Top MITRE ATT&CK techniques",
            "table",
            [
                _agg(
                    "1",
                    "terms",
                    "rule.mitre.technique",
                    size=25,
                    order={"_count": "desc"},
                )
            ],
        ),
    ]


def search_body(panel: dict[str, Any], size: int = 0) -> dict[str, Any]:
    """The OpenSearch body used to verify a panel actually matches data.

    Built by re-issuing the panel's aggregations directly, so verification runs
    the SAME query the visualization will run. Counting the panel's own filter is
    not enough - a panel can match thousands of documents and still aggregate to
    nothing if its field is unmapped, which is precisely the failure mode for a
    hand-declared schema.

    Two things about the wire format, both established by probing the live
    indexer rather than by reading docs:

    * An aggregation is a single-key object whose key is the aggregation type:
      `{"terms": {"field": ..., "size": ...}}`. NOT `{"type": "terms"}` and not
      an array - both are a 400 ("Expected [START_OBJECT] under [type]").
    * `count` is not an aggregation type at all ("Unknown aggregation type
      [count]"). A metric panel is verified from `hits.total.value` instead, so
      a count panel contributes no `aggs` and is marked `uses_hits_total`.
    """
    body: dict[str, Any] = {
        "size": size,
        "query": panel.get("query") or {"bool": {"filter": []}},
    }
    if uses_hits_total(panel):
        return body
    body["aggs"] = _raw_aggs(panel["aggs"])
    return body


# Wazuh's display-only params. Sending them to the indexer is either a 400 or,
# for `order`, silently ignored, so they are dropped from the raw form. `order`
# IS meaningful to the indexer though, so it is promoted rather than dropped.
_DISPLAY_ONLY = {
    "customLabel",
    "fieldParams",
    "extended_bounds",  # Wazuh-only date padding
    "percolate",
    "json",
    "isDisplayWarning",
    "sort",
    "sortDirection",
}


def uses_hits_total(panel: dict[str, Any]) -> bool:
    """True when the panel is a plain count metric, verified from hits.total."""
    aggs = panel.get("aggs") or []
    return len(aggs) == 1 and aggs[0].get("type") == "count"


def _raw_aggs(aggs: list[dict[str, Any]]) -> dict[str, Any]:
    """Wazuh visState aggregations -> the indexer's wire form.

    Wazuh's display shape wraps everything in {id, enabled, type, schema,
    params}; the indexer wants the spec bare, keyed by aggregation type. The
    mapping was confirmed against the live indexer - sending the visState form
    verbatim is a 400.

    The KEY is the visState agg id ("1", "2", ...), NOT the aggregation type.
    Naming the key after its own type makes this indexer misparse the
    aggregation and answer 400 "Expected [START_OBJECT] under [field], but got a
    [VALUE_STRING]" - pointing at a perfectly valid `field` string. That was
    reproducible across four index patterns, and a control that renamed the key
    to "a" with an otherwise identical body returned 200, so it is the name and
    not the spec. Numbered keys are also what Wazuh's own saved objects use.
    """
    out: dict[str, Any] = {}
    for a in aggs:
        atype = a["type"]
        if atype == "count":
            continue  # not a real aggregation; handled via hits.total
        params = a.get("params") or {}
        spec: dict[str, Any] = {}
        field = params.get("field") or a.get("field")
        if field:
            spec["field"] = field
        for k, v in params.items():
            if k in _DISPLAY_ONLY or k.startswith("_") or k == "field":
                continue
            spec[k] = v
        if "order" not in spec and atype == "terms":
            spec["order"] = {"_count": "desc"}
        key = f"agg_{a['id']}"
        if key in out:  # duplicate ids in one visState would silently drop a series
            key = f"agg_{a['id']}_{len(out)}"
        out[key] = {atype: spec}
    return out


_RESULT_KEYS = ("buckets", "values", "value")


def _inner(spec: Any) -> dict[str, Any]:
    """The result object for one aggregation, whichever nesting it arrived in.

    The request nests as {"agg_1": {"terms": {...}}}, but the RESPONSE comes
    back flattened to {"agg_1": {"buckets": [...]}} - the indexer drops the
    aggregation-type layer. Both shapes are accepted so the same helpers work on
    a request spec and a response, and neither has to know which it holds.
    """
    if not isinstance(spec, dict):
        return {}
    if any(k in spec for k in _RESULT_KEYS):
        return spec
    values = list(spec.values())
    if len(spec) == 1 and isinstance(values[0], dict):
        return values[0]
    return spec


def count_buckets(aggs: dict[str, Any]) -> int:
    """Documents the first aggregation actually bucketed.

    A panel whose aggregation returns 0 buckets renders as an empty chart even
    when its query matches thousands of documents, so this - not the hit count -
    is what decides whether a panel is healthy.
    """
    if not isinstance(aggs, dict) or not aggs:
        return 0
    inner = _inner(next(iter(aggs.values())))
    if "buckets" in inner:
        return sum(b.get("doc_count", 0) for b in inner["buckets"] if isinstance(b, dict))
    if "values" in inner:  # extended_stats / percentiles
        return int(inner["values"].get("count") or 0)
    if "value" in inner:  # avg / cardinality / value_count
        v = inner["value"]
        return int(v) if isinstance(v, (int, float)) else (1 if v is not None else 0)
    return 0


def has_data(aggs: dict[str, Any]) -> bool:
    """Whether a chart will have something to draw.

    Separate from count_buckets because a single-value metric like avg() has no
    buckets to count but is perfectly healthy, while a terms agg with one bucket
    of 1 doc is technically non-empty and practically useless. The tool reports
    both so an operator can tell them apart.
    """
    if not isinstance(aggs, dict) or not aggs:
        return False
    inner = _inner(next(iter(aggs.values())))
    if "buckets" in inner:
        return bool(inner["buckets"])
    if "values" in inner:
        return int(inner["values"].get("count") or 0) > 0
    if "value" in inner:
        return inner["value"] is not None
    return False


def verify_panel(indexer: Any, panel: dict[str, Any]) -> dict[str, Any]:
    """Run a panel's real aggregation and report whether it will draw anything.

    Returns {slug, title, matched, bucketed, healthy, note}. `matched` is the
    query's hit count; `bucketed` is what the aggregation actually placed into
    buckets. They differ whenever a field is unmapped, which is the failure this
    exists to catch.
    """
    slug = panel["slug"]
    try:
        resp = indexer.search(THREAT_INDEX, search_body(panel))
    except Exception as e:
        return {
            "slug": slug,
            "title": panel["title"],
            "matched": 0,
            "bucketed": 0,
            "healthy": False,
            "note": f"query failed: {e}",
        }
    total = int((resp.get("hits", {}).get("total") or {}).get("value", 0))
    aggs = resp.get("aggregations") or {}
    if uses_hits_total(panel):
        return {
            "slug": slug,
            "title": panel["title"],
            "matched": total,
            "bucketed": total,
            "healthy": total > 0,
            "note": "count metric verified" if total else "no documents matched",
        }
    # count_buckets/has_data each unwrap the agg-name layer themselves, so they
    # are handed the whole aggregations object. Unwrapping here as well would
    # take two levels off and read the result as empty.
    bucketed = count_buckets(aggs)
    healthy = has_data(aggs)
    inner = _inner(next(iter(aggs.values()), {})) if aggs else {}

    # A single-value metric (avg, cardinality) returns `value`, not buckets.
    # Reporting that as a "bucketed documents" count is actively misleading -
    # mean_cvss 4.54 over 4967 documents would read as "4 of 4967 bucketed"
    # and look like a nearly-empty panel. Report the value as itself instead.
    if "value" in inner and "buckets" not in inner:
        v = inner["value"]
        healthy = v is not None
        return {
            "slug": slug,
            "title": panel["title"],
            "matched": total,
            "bucketed": total,
            "healthy": healthy,
            "value": v,
            "note": (
                f"single-value metric over {total} documents: {v}"
                if healthy
                else "metric returned no value"
            ),
        }
    if not healthy:
        note = (
            f"query matched {total} documents but the aggregation produced no "
            "buckets - the field is unmapped in this index or all values fall "
            "outside the panel filter"
        )
    elif bucketed < total:
        note = f"{bucketed} of {total} documents bucketed"
    else:
        note = "panel query verified"
    return {
        "slug": slug,
        "title": panel["title"],
        "matched": total,
        "bucketed": bucketed,
        "healthy": healthy,
        "note": note,
    }


def verify_fields(indexer: Any, index: str = THREAT_INDEX) -> dict[str, Any]:
    """Re-check every declared field against the live indexer.

    A real 1-document aggregation per field: cheap, and it catches a renamed or
    removed field as a degraded panel instead of a silently blank chart.
    """
    present: list[str] = []
    missing: list[str] = []
    for field in FIELDS:
        try:
            resp = indexer.search(
                index, {"size": 0, "aggs": {"a": {"terms": {"field": field, "size": 1}}}}
            )
            has_data(resp.get("aggregations", {}))
            present.append(field)
        except Exception:
            missing.append(field)
    return {"present": present, "missing": missing, "ok": not missing}


def summary() -> str:
    """One-line description for the tool schema and the operator's proposal."""
    return (
        "Threat-intelligence dashboard from Wazuh's own Vulnerability Detector "
        f"({VULN_INDEX}) joined with MITRE data from {ALERTS_INDEX}: CVSS, "
        "severity, top CVEs, affected packages, scoring source, publication "
        "timeline and ATT&CK tactics."
    )


def to_json() -> str:
    return json.dumps({"index": THREAT_INDEX, "panels": panel_plan()}, indent=2)


def ensure_index_pattern(create: bool = True) -> dict[str, Any]:
    """Get-or-create the combined index pattern on the dashboards server.

    Wazuh's saved objects resolve their data source through a *saved index
    pattern* (a data view), not a raw index string, so a visualization built
    against a comma-joined pattern resolves to nothing unless that exact pattern
    exists. On this deployment `wazuh-alerts-*` and
    `wazuh-states-vulnerabilities-*` are both saved separately; the combined one
    is not.

    Idempotent: an existing pattern is reused rather than duplicated, because a
    second data view with the same title is a silent duplicate in the operator's
    data-view list. Returns {found, id, title, created, error}.
    """
    try:
        from tools.dashboard.client import dashboards_request
    except Exception as e:  # pragma: no cover - import shape guard
        return {
            "found": False,
            "id": None,
            "title": THREAT_INDEX,
            "created": False,
            "error": str(e),
        }

    try:
        resp = dashboards_request(
            "GET", "/api/saved_objects/_find", params={"type": "index-pattern", "per_page": 200}
        )
    except Exception as e:
        return {
            "found": False,
            "id": None,
            "title": THREAT_INDEX,
            "created": False,
            "error": str(e),
        }

    for item in resp.get("saved_objects") or resp.get("objects") or []:
        attrs = item.get("attributes") or {}
        if (attrs.get("title") or "").strip() == THREAT_INDEX:
            return {
                "found": True,
                "id": item.get("id"),
                "title": THREAT_INDEX,
                "created": False,
                "error": None,
            }

    if not create:
        return {"found": False, "id": None, "title": THREAT_INDEX, "created": False, "error": None}

    # title only - no field list. Wazuh populates the fields itself; sending an
    # empty or partial list is what produces a data view that resolves to no
    # columns.
    try:
        made = dashboards_request(
            "POST",
            "/api/saved_objects/index-pattern",
            body={"attributes": {"title": THREAT_INDEX}},
        )
    except Exception as e:
        return {
            "found": False,
            "id": None,
            "title": THREAT_INDEX,
            "created": False,
            "error": f"could not create the combined index pattern: {e}",
        }
    obj = made.get("saved_object") or made.get("object") or made
    return {
        "found": True,
        "id": obj.get("id") or made.get("id"),
        "title": THREAT_INDEX,
        "created": True,
        "error": None,
    }
