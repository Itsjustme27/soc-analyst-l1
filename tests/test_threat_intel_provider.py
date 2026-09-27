"""Tests for the threat-intelligence provider and the preview bugs it exposed.

Every assertion here corresponds to a failure that actually happened while
building this against a live Wazuh, and each is one that a schema-shape test
would not have caught:

* A visState agg whose `schema` is the aggregation type instead of Wazuh's
  metric/segment split saves without complaint and then renders blank.
* An index-pattern reference pointing at the pattern's TITLE rather than its
  server id makes every panel empty with no error logged anywhere.
* Routing a numeric `histogram` to `date_histogram` is a 400, not an empty
  panel - `interval` means field units, not a date span.
* Naming an indexer aggregation key after its own aggregation type makes this
  indexer 400 with a misleading "Expected [START_OBJECT] under [field]".
"""

from __future__ import annotations

import json
import unittest

from tools.dashboard import engine as dash_engine
from tools.dashboard import preview, threatintel


class FakeIndexer:
    """Minimal indexer that replays canned responses and records what it saw."""

    def __init__(self, responses=None):
        self.responses = responses or {}
        self.requests = []

    def search(self, index, body):
        self.requests.append((index, body))
        key = json.dumps(body.get("aggs"), sort_keys=True)
        for needle, resp in self.responses.items():
            if needle in key:
                return resp
        return {"hits": {"total": {"value": 0}}, "aggregations": {}}


def _hits(total=0, **aggs):
    return {"hits": {"total": {"value": total}}, "aggregations": aggs}


class TestVisStateShape(unittest.TestCase):
    """Wazuh's visState contract, which the saved-objects API does not enforce."""

    def test_schema_is_the_metric_segment_split_not_the_agg_type(self):
        """A `schema` of "count" is accepted on save and renders blank.

        Wazuh reads `schema` to decide whether a series is a scalar or a bucket
        list. Anything that is not "metric" or "segment" leaves it guessing,
        which it does by drawing nothing.
        """
        a = threatintel._agg("1", "count", None, customLabel="n")
        self.assertEqual(a["schema"], "metric")
        self.assertNotEqual(a["schema"], a["type"])

    def test_every_bucket_agg_is_declared_a_segment(self):
        for agg_type in ("terms", "histogram", "date_histogram"):
            with self.subTest(agg_type):
                self.assertEqual(threatintel._agg("1", agg_type, "f").get("schema"), "segment")

    def test_every_scalar_agg_is_declared_a_metric(self):
        for agg_type in (
            "count",
            "avg",
            "sum",
            "min",
            "max",
            "value_count",
            "cardinality",
            "std_dev",
        ):
            with self.subTest(agg_type):
                self.assertEqual(threatintel._agg("1", agg_type, "f").get("schema"), "metric")

    def test_field_lives_inside_params(self):
        """Where Wazuh puts it, and where its reference searchSourceJSON looks."""
        a = threatintel._agg("1", "terms", "vulnerability.severity", size=10)
        self.assertEqual(a["params"]["field"], "vulnerability.severity")
        self.assertNotIn("field", a)


class TestPanelPlan(unittest.TestCase):
    def test_plan_is_deterministic(self):
        self.assertEqual(
            [p["slug"] for p in threatintel.panel_plan()],
            [p["slug"] for p in threatintel.panel_plan()],
        )

    def test_slugs_are_unique(self):
        slugs = [p["slug"] for p in threatintel.panel_plan()]
        self.assertEqual(len(slugs), len(set(slugs)))

    def test_every_panel_has_the_fields_the_shared_machinery_needs(self):
        """preview.run_panel and osd.build_visualization_attributes both read these."""
        for p in threatintel.panel_plan():
            with self.subTest(p["slug"]):
                for key in ("slug", "title", "vis_type", "aggs", "query"):
                    self.assertIn(key, p)
                self.assertTrue(p["aggs"], "panel with no aggregations")
                self.assertIn("filter", p["query"]["bool"])

    def test_vis_types_are_ones_wazuh_stores(self):
        self.assertTrue(
            set(p["vis_type"] for p in threatintel.panel_plan())
            <= {"metric", "pie", "table", "line", "histogram", "bar", "area"},
        )

    def test_cvss_panels_exclude_the_unrated_placeholder(self):
        """-1.0 means "no score assigned" and is 34% of this data.

        Aggregated unfiltered it puts a third of the estate in a bin below zero,
        which reads as a scoring error rather than as missing data.
        """
        rated = threatintel.RATED_CVSS
        self.assertEqual(rated["range"]["vulnerability.score.base"]["gt"], 0)
        for slug in ("cvss_distribution", "mean_cvss"):
            with self.subTest(slug):
                panel = next(p for p in threatintel.panel_plan() if p["slug"] == slug)
                self.assertIn(rated, panel["query"]["bool"]["filter"])

    def test_severity_panel_keeps_unrated_visible_rather_than_dropping_it(self):
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "severity_breakdown")
        buckets = panel["aggs"][0]["params"]["_bucket_selector"]["buckets"]
        labels = [b["label"] for b in buckets]
        self.assertIn("Unrated", labels)
        self.assertNotIn("-", labels)

    def test_timeline_uses_published_at_not_detected_at(self):
        """detected_at is a single month here - the detector ran once.

        A "detections over time" panel on it renders one bar and looks broken.
        """
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "cve_publication_timeline")
        self.assertEqual(panel["aggs"][0]["params"]["field"], "vulnerability.published_at")
        self.assertIn("publication", panel["title"].lower())


class TestRawAggTranslation(unittest.TestCase):
    """visState aggs -> the indexer's wire form."""

    def _one(self, agg):
        return threatintel._raw_aggs([agg])["agg_1"]

    def test_spec_is_keyed_by_agg_type_not_flattened(self):
        """This indexer wants {"agg_1": {"terms": {...}}}.

        {"agg_1": {"type": "terms", ...}} is 400, and so is an array.
        """
        out = self._one(threatintel._agg("1", "terms", "vulnerability.severity", size=5))
        self.assertEqual(list(out), ["terms"])
        self.assertEqual(out["terms"]["field"], "vulnerability.severity")

    def test_key_is_the_agg_id_not_the_agg_type(self):
        """Naming the key after its own type makes this indexer misparse it.

        It answers 400 "Expected [START_OBJECT] under [field], but got a
        [VALUE_STRING]" - pointing at a field string that is perfectly valid.
        Reproduced across four index patterns; renaming the key to "a" with an
        otherwise identical body returned 200.
        """
        out = threatintel._raw_aggs([threatintel._agg("1", "terms", "rule.level", size=3)])
        self.assertEqual(list(out), ["agg_1"])
        self.assertNotIn("terms", out)

    def test_count_agg_contributes_no_aggregation(self):
        """`count` is not an aggregation type ("Unknown aggregation type [count]")."""
        self.assertEqual(threatintel._raw_aggs([threatintel._agg("1", "count", None)]), {})

    def test_display_only_params_are_not_sent_to_the_indexer(self):
        out = self._one(
            threatintel._agg("1", "terms", "vulnerability.severity", size=5, customLabel="sev")
        )
        self.assertNotIn("customLabel", out["terms"])
        # `field` is in the wire spec because the indexer needs it there - it is
        # hoisted out of params once, not carried twice.
        self.assertEqual(out["terms"]["field"], "vulnerability.severity")

    def test_display_only_underscore_params_are_dropped(self):
        out = self._one(
            threatintel._agg("1", "terms", "vulnerability.severity", _color={"High": "#f00"})
        )
        self.assertNotIn("_color", out["terms"])

    def test_terms_gets_a_count_order_by_default(self):
        out = self._one(threatintel._agg("1", "terms", "package.name", size=5))
        self.assertEqual(out["terms"]["order"], {"_count": "desc"})

    def test_duplicate_agg_ids_do_not_silently_drop_a_series(self):
        out = threatintel._raw_aggs(
            [threatintel._agg("1", "terms", "a"), threatintel._agg("1", "terms", "b")]
        )
        self.assertEqual(len(out), 2)


class TestSearchBody(unittest.TestCase):
    def test_count_panel_sends_no_aggs_and_uses_hits_total(self):
        panel = {"query": {"bool": {"filter": []}}, "aggs": [threatintel._agg("1", "count", None)]}
        self.assertTrue(threatintel.uses_hits_total(panel))
        self.assertNotIn("aggs", threatintel.search_body(panel))

    def test_agg_panel_sends_its_aggregation(self):
        panel = {
            "query": {"bool": {"filter": []}},
            "aggs": [threatintel._agg("1", "terms", "vulnerability.severity", size=5)],
        }
        self.assertFalse(threatintel.uses_hits_total(panel))
        self.assertIn("aggs", threatintel.search_body(panel))

    def test_panel_query_is_preserved(self):
        panel = {
            "query": {"bool": {"filter": [{"range": {"vulnerability.score.base": {"gt": 0}}}]}},
            "aggs": [threatintel._agg("1", "terms", "package.name", size=5)],
        }
        self.assertEqual(threatintel.search_body(panel)["query"], panel["query"])

    def test_index_pattern_spans_both_indices(self):
        """MITRE only exists in wazuh-alerts-*, vulnerability.* only in the
        vulnerabilities index, so one panel set needs both."""
        self.assertIn(threatintel.ALERTS_INDEX, threatintel.THREAT_INDEX)
        self.assertIn(threatintel.VULN_INDEX, threatintel.THREAT_INDEX)


class TestResultUnwrapping(unittest.TestCase):
    """The request nests the agg type; the response drops it."""

    def test_count_buckets_reads_a_flattened_response(self):
        resp = {
            "agg_1": {"doc_count_error_upper_bound": 0, "buckets": [{"key": "a", "doc_count": 3}]}
        }
        self.assertEqual(threatintel.count_buckets(resp), 3)

    def test_count_buckets_reads_a_nested_request_shape(self):
        req = {"agg_1": {"terms": {"buckets": [{"key": "a", "doc_count": 5}]}}}
        self.assertEqual(threatintel.count_buckets(req), 5)

    def test_count_buckets_reads_extended_stats(self):
        self.assertEqual(threatintel.count_buckets({"a": {"values": {"count": 42}}}), 42)

    def test_has_data_true_for_one_bucket(self):
        self.assertTrue(
            threatintel.has_data({"agg_1": {"buckets": [{"key": "a", "doc_count": 1}]}})
        )

    def test_has_data_false_for_zero_buckets(self):
        self.assertFalse(threatintel.has_data({"agg_1": {"buckets": []}}))

    def test_has_data_true_for_a_scalar_metric(self):
        """avg() has no buckets but is a perfectly healthy panel."""
        self.assertTrue(threatintel.has_data({"agg_1": {"value": 7.3}}))

    def test_has_data_false_for_a_null_metric(self):
        self.assertFalse(threatintel.has_data({"agg_1": {"value": None}}))

    def test_junk_never_raises(self):
        for junk in ({}, {"a": None}, {"a": "x"}, None, [], 5):
            with self.subTest(repr(junk)):
                self.assertEqual(threatintel.count_buckets(junk), 0)
                self.assertFalse(threatintel.has_data(junk))


class TestVerifyPanel(unittest.TestCase):
    def test_healthy_requires_buckets_not_just_matched_documents(self):
        """A panel can match 9000 documents and still draw an empty chart."""
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "top_cves")
        ix = FakeIndexer({"vulnerability.id": _hits(9000, agg_1={"buckets": []})})
        out = threatintel.verify_panel(ix, panel)
        self.assertEqual(out["matched"], 9000)
        self.assertEqual(out["bucketed"], 0)
        self.assertFalse(out["healthy"])
        self.assertIn("no buckets", out["note"])

    def test_healthy_when_buckets_come_back(self):
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "top_cves")
        ix = FakeIndexer(
            {"vulnerability.id": _hits(9000, agg_1={"buckets": [{"key": "CVE-1", "doc_count": 7}]})}
        )
        out = threatintel.verify_panel(ix, panel)
        self.assertTrue(out["healthy"])
        self.assertEqual(out["bucketed"], 7)

    def test_scalar_metric_reports_its_value_not_a_bogus_bucketed_count(self):
        """mean_cvss 7.3 over 4967 docs must not read as "7 of 4967 bucketed"."""
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "mean_cvss")
        ix = FakeIndexer({"score.base": _hits(4967, agg_1={"value": 7.345})})
        out = threatintel.verify_panel(ix, panel)
        self.assertTrue(out["healthy"])
        self.assertAlmostEqual(out["value"], 7.345, places=3)
        self.assertEqual(out["bucketed"], 4967)
        self.assertIn("single-value", out["note"])

    def test_count_panel_reads_hits_total(self):
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "total_vulns")
        ix = FakeIndexer()
        out = threatintel.verify_panel(ix, panel)
        self.assertEqual(out["matched"], 0)
        self.assertFalse(out["healthy"])
        self.assertEqual(ix.requests[0][1].get("aggs"), None, "must not send an aggs block")

    def test_a_query_failure_degrades_the_panel_without_raising(self):
        panel = threatintel.panel_plan()[0]

        class Boom:
            def search(self, *a, **kw):
                raise RuntimeError("indexer down")

        out = threatintel.verify_panel(Boom(), panel)
        self.assertFalse(out["healthy"])
        self.assertIn("indexer down", out["note"])


class TestVerifyFields(unittest.TestCase):
    def test_missing_field_is_reported_not_raised(self):
        class Partial:
            def search(self, index, body):
                field = (body["aggs"]["a"]["terms"]["field"],)
                if field[0] == "vulnerability.severity":
                    raise RuntimeError("no mapping")
                return _hits(1, a={"buckets": [{"key": "x", "doc_count": 1}]})

        out = threatintel.verify_fields(Partial())
        self.assertIn("vulnerability.severity", out["missing"])
        self.assertFalse(out["ok"])

    def test_all_present_is_ok(self):
        ix = FakeIndexer({"": _hits(1, a={"buckets": [{"key": "x", "doc_count": 1}]})})
        out = threatintel.verify_fields(ix)
        self.assertTrue(out["ok"])
        self.assertEqual(out["missing"], [])
        self.assertEqual(len(out["present"]), len(threatintel.FIELDS))

    def test_it_probes_the_combined_pattern(self):
        ix = FakeIndexer({"": _hits(1, a={"buckets": [{"key": "x", "doc_count": 1}]})})
        threatintel.verify_fields(ix)
        self.assertEqual(ix.requests[0][0], threatintel.THREAT_INDEX)


class TestEnsureIndexPattern(unittest.TestCase):
    def _patch(self, listing, created=None):
        import tools.dashboard.client as client

        real = client.dashboards_request
        calls = []

        def fake(method, path, **kw):
            calls.append((method, path, kw))
            if method == "GET":
                return listing
            return created or {"saved_object": {"id": "new-uuid"}}

        client.dashboards_request = fake
        self.addCleanup(lambda: setattr(client, "dashboards_request", real))
        return calls

    def test_existing_pattern_is_reused_not_duplicated(self):
        listing = {
            "saved_objects": [
                {"id": "abc", "attributes": {"title": threatintel.THREAT_INDEX}},
            ]
        }
        calls = self._patch(listing)
        out = threatintel.ensure_index_pattern()
        self.assertTrue(out["found"])
        self.assertFalse(out["created"])
        self.assertEqual(out["id"], "abc")
        self.assertEqual([c[0] for c in calls], ["GET"], "must not create when one exists")

    def test_creates_when_absent(self):
        calls = self._patch({"saved_objects": []})
        out = threatintel.ensure_index_pattern()
        self.assertTrue(out["created"])
        self.assertEqual(out["id"], "new-uuid")
        self.assertEqual(calls[-1][0], "POST")
        self.assertEqual(calls[-1][1], "/api/saved_objects/index-pattern")

    def test_create_sends_only_a_title(self):
        """An empty or partial field list is what yields a data view that
        resolves to no columns."""
        calls = self._patch({"saved_objects": []})
        threatintel.ensure_index_pattern()
        body = calls[-1][2].get("body") or {}
        self.assertEqual(list(body.get("attributes") or {}), ["title"])

    def test_create_false_does_not_create(self):
        calls = self._patch({"saved_objects": []})
        out = threatintel.ensure_index_pattern(create=False)
        self.assertFalse(out["found"])
        self.assertFalse(out["created"])
        self.assertEqual([c[0] for c in calls], ["GET"])

    def test_a_listing_failure_is_reported_not_raised(self):
        import tools.dashboard.client as client

        real = client.dashboards_request

        def boom(*a, **kw):
            raise RuntimeError("dashboards server down")

        client.dashboards_request = boom
        self.addCleanup(lambda: setattr(client, "dashboards_request", real))
        out = threatintel.ensure_index_pattern()
        self.assertFalse(out["found"])
        self.assertIn("dashboards server down", out["error"])


class TestUnsupportedIsHonest(unittest.TestCase):
    def test_geo_and_iocs_are_declared_unbuildable(self):
        caps = " ".join(u["capability"].lower() for u in threatintel.UNSUPPORTED)
        self.assertIn("geo", caps)
        self.assertIn("ioc", caps)

    def test_every_unsupported_entry_explains_what_would_be_needed(self):
        """An operator who cannot get geo must be told what to install."""
        for u in threatintel.UNSUPPORTED:
            with self.subTest(u["capability"]):
                self.assertTrue(u["reason"].strip())
                self.assertTrue(u["would_need"].strip())

    def test_no_panel_claims_to_need_geo_or_ioc_data(self):
        """Otherwise the dashboard ships blank panels for them."""
        banned = ("country_code", "geoip", "src_ip", "srcip", "asn")
        for p in threatintel.panel_plan():
            blob = json.dumps(p).lower()
            for term in banned:
                with self.subTest(f"{p['slug']}/{term}"):
                    self.assertNotIn(term, blob)


class TestPreviewNumericHistogram(unittest.TestCase):
    """A histogram is numeric. Routing it to date_histogram is a 400."""

    def _body(self, agg):
        return preview.vis_aggs_to_osd([agg], {"bool": {"filter": []}})["1"]

    def test_histogram_stays_a_numeric_histogram(self):
        out = self._body(threatintel._agg("1", "histogram", "vulnerability.score.base", interval=1))
        self.assertEqual(list(out), ["histogram"])
        self.assertEqual(out["histogram"]["interval"], 1.0)

    def test_histogram_interval_is_numeric_even_when_written_as_text(self):
        out = self._body(threatintel._agg("1", "histogram", "f", interval="2"))
        self.assertEqual(out["histogram"]["interval"], 2.0)

    def test_a_date_interval_on_a_histogram_is_refused(self):
        """`interval: "1d"` on a numeric histogram is a unit error, not a nudge."""
        with self.assertRaises(preview.PreviewError) as cm:
            self._body(threatintel._agg("1", "histogram", "f", interval="1d"))
        self.assertIn("field units", str(cm.exception))

    def test_a_zero_interval_is_refused(self):
        with self.assertRaises(preview.PreviewError):
            self._body(threatintel._agg("1", "histogram", "f", interval=0))

    def test_a_missing_field_is_refused(self):
        with self.assertRaises(preview.PreviewError):
            self._body(threatintel._agg("1", "histogram", None))

    def test_date_histogram_is_still_routed_to_date_histogram(self):
        out = self._body(
            threatintel._agg(
                "1", "date_histogram", "vulnerability.published_at", calendar_interval="1M"
            )
        )
        self.assertEqual(list(out), ["date_histogram"])


class TestPreviewMetricInference(unittest.TestCase):
    def test_a_recognised_schema_is_authoritative(self):
        self.assertTrue(preview._is_metric({"type": "terms", "schema": "metric"}))
        self.assertFalse(preview._is_metric({"type": "count", "schema": "segment"}))

    def test_an_unrecognised_schema_falls_back_to_the_agg_type(self):
        """schema: "count" is what a bad visState really carries.

        Trusting it left the preview reporting `empty`, which is honest about the
        data and useless about the cause.
        """
        self.assertTrue(preview._is_metric({"type": "count", "schema": "count"}))
        self.assertFalse(preview._is_metric({"type": "terms", "schema": "terms"}))

    def test_a_missing_schema_falls_back_to_the_agg_type(self):
        self.assertTrue(preview._is_metric({"type": "avg"}))
        self.assertFalse(preview._is_metric({"type": "date_histogram"}))

    def test_a_count_panel_renders_a_value_not_an_empty_panel(self):
        # preview keys its aggregations by the visState agg id, so the response
        # key is "1" - unlike threatintel._raw_aggs, which keys by "agg_1".
        ix = FakeIndexer({'"match_all"': _hits(9379, **{"1": {"doc_count": 9379}})})
        out = preview.run_panel(ix, "idx", threatintel.panel_plan()[0])
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["rows"][0]["value"], 9379)

    def test_a_cvss_histogram_panel_renders_buckets(self):
        panel = next(p for p in threatintel.panel_plan() if p["slug"] == "cvss_distribution")
        ix = FakeIndexer(
            {
                '"histogram"': _hits(
                    4967,
                    **{
                        "1": {
                            "buckets": [{"key": 0.0, "doc_count": 9}, {"key": 1.0, "doc_count": 36}]
                        }
                    },
                )
            }
        )
        out = preview.run_panel(ix, "idx", panel)
        self.assertEqual(out["status"], "ok")
        self.assertEqual(len(out["rows"]), 2)


class TestUnresolvedDataRefs(unittest.TestCase):
    """A saved object can be valid and still be dead."""

    def _patch(self, handler):
        import tools.dashboard.engine as mod

        real = mod.dashboards_request
        mod.dashboards_request = handler
        self.addCleanup(lambda: setattr(mod, "dashboards_request", real))

    def test_a_resolving_reference_reports_nothing(self):
        def ok(method, path, **kw):
            return {"references": [{"type": "index-pattern", "id": "pat-1"}]}

        self._patch(ok)
        self.assertEqual(dash_engine._unresolved_data_refs([{"slug": "a", "id": "v1"}]), [])

    def test_a_dangling_reference_is_reported(self):
        def dangling(method, path, **kw):
            if "index-pattern" in path:
                raise RuntimeError("404 not found")
            return {"references": [{"type": "index-pattern", "id": "wazuh-alerts-*,wazuh-x-*"}]}

        self._patch(dangling)
        issues = dash_engine._unresolved_data_refs([{"slug": "top_cves", "id": "v1"}])
        self.assertEqual(len(issues), 1)
        self.assertIn("wazuh-alerts-*,wazuh-x-*", issues[0])
        self.assertIn("empty", issues[0])

    def test_a_missing_reference_is_reported(self):
        self._patch(lambda *a, **kw: {"references": []})
        issues = dash_engine._unresolved_data_refs([{"slug": "top_cves", "id": "v1"}])
        self.assertEqual(len(issues), 1)
        self.assertIn("no index-pattern reference", issues[0])

    def test_a_visualization_without_a_server_id_is_reported(self):
        self._patch(lambda *a, **kw: {})
        issues = dash_engine._unresolved_data_refs([{"slug": "top_cves", "id": None}])
        self.assertEqual(len(issues), 1)
        self.assertIn("without a server id", issues[0])

    def test_an_unreadable_visualization_is_reported(self):
        def boom(method, path, **kw):
            raise RuntimeError("500")

        self._patch(boom)
        issues = dash_engine._unresolved_data_refs([{"slug": "top_cves", "id": "v1"}])
        self.assertEqual(len(issues), 1)
        self.assertIn("could not be read back", issues[0])

    def test_it_checks_every_panel(self):
        self._patch(lambda *a, **kw: {"references": []})
        issues = dash_engine._unresolved_data_refs(
            [{"slug": f"p{i}", "id": f"v{i}"} for i in range(3)]
        )
        self.assertEqual(len(issues), 3)


class TestToolPassesThePatternId(unittest.TestCase):
    """The bug this exists for: a saved object that is valid and still dead.

    `build_visualization_attributes` takes a parameter named
    `index_pattern_id`, and for Wazuh's built-in data views the id and the title
    are the same string, so passing the title works there by coincidence. A
    pattern created through the API gets a uuid, and a reference pointing at its
    title resolves to nothing: the dashboard is created, passes every schema
    validation, and renders eleven empty panels with no error logged anywhere.

    This drives the whole tool, because the fault was in the call site - not in
    the helper the other tests check.
    """

    def _run(self, pattern_id, pattern_title):
        import tools.dashboard.engine as mod

        class AnyBuckets(FakeIndexer):
            def search(self, index, body):
                self.requests.append((index, body))
                aggs = body.get("aggs")
                if not aggs:
                    return _hits(3)
                key = next(iter(aggs))
                spec = aggs[key]
                if isinstance(spec, dict) and len(spec) == 1:
                    inner = next(iter(spec.values()))
                    if isinstance(inner, dict) and "buckets" not in inner and "value" not in inner:
                        return _hits(3, **{key: {"buckets": [{"key": "x", "doc_count": 3}]}})
                return _hits(3, **{key: {"buckets": [{"key": "x", "doc_count": 3}]}})

        real_ensure = mod.threatintel.ensure_index_pattern
        real_request = mod.dashboards_request
        mod.threatintel.ensure_index_pattern = lambda *a, **kw: {
            "found": True,
            "id": pattern_id,
            "title": pattern_title,
            "created": True,
            "error": None,
        }
        self.addCleanup(lambda: setattr(mod.threatintel, "ensure_index_pattern", real_ensure))

        posted = []
        dash_body = {}

        def fake_request(method, path, **kw):
            if method == "POST" and "visualization" in path:
                vid = f"vis-{len(posted)}"
                posted.append((vid, kw.get("body") or {}))
                return {"saved_object": {"id": vid}}
            if method == "POST":
                dash_body.update(kw.get("body") or {})
                return {"saved_object": {"id": "dash-1"}, "message": "created"}
            if "index-pattern" in path:
                if path.rsplit("/", 1)[-1] == pattern_id:
                    return {"id": pattern_id, "attributes": {"title": pattern_title}}
                raise RuntimeError(f"404 not found: {path}")
            if "visualization/" in path:
                vid = path.rsplit("/", 1)[-1]
                body = next((b for i, b in posted if i == vid), {})
                return {"id": vid, "references": body.get("references") or []}
            # Read the dashboard back exactly as it was posted, so
            # validate_dashboard sees a real object rather than a stub.
            return {
                "id": "dash-1",
                "attributes": dash_body.get("attributes") or {},
                "references": dash_body.get("references") or [],
            }

        mod.dashboards_request = fake_request
        self.addCleanup(lambda: setattr(mod, "dashboards_request", real_request))

        from tools.base import ToolContext

        ctx = ToolContext(
            wazuh=None, indexer=AnyBuckets(), user="approver", agent="approval_executor"
        )
        ctx.approval = {
            "id": "appr-1",
            "status": "executing",
            "action": "design_threat_intel_dashboard",
        }
        out = mod.DesignThreatIntelDashboard().run(
            ctx, title="Threat Intelligence - Vulnerabilities & ATT&CK", reason="r"
        )
        return out, posted

    def test_saved_references_point_at_the_pattern_id_not_its_title(self):
        out, posted = self._run("uuid-1234", "wazuh-alerts-*,wazuh-states-vulnerabilities-*")
        self.assertEqual(out["status"], "executed", out["render_check"])
        self.assertTrue(posted, "no visualizations were created")
        for vid, body in posted:
            refs = [r for r in (body.get("references") or []) if r["type"] == "index-pattern"]
            with self.subTest(vid):
                self.assertEqual(len(refs), 1)
                self.assertEqual(refs[0]["id"], "uuid-1234")

    def test_the_title_is_still_reported_for_the_operator(self):
        out, _ = self._run("uuid-1234", "wazuh-alerts-*,wazuh-states-vulnerabilities-*")
        self.assertEqual(out["index_pattern"], "wazuh-alerts-*,wazuh-states-vulnerabilities-*")

    def test_a_dangling_reference_surfaces_as_executed_with_issues(self):
        """And the check that would have caught it actually runs."""
        out, _ = self._run("uuid-1234", "wazuh-alerts-*,wazuh-states-vulnerabilities-*")
        self.assertEqual(out["render_check"]["ok"], True)

    def test_it_falls_back_to_the_title_when_there_is_no_id(self):
        """Wazuh's built-in patterns have id == title, so the fallback is right."""
        out, posted = self._run("wazuh-alerts-*", "wazuh-alerts-*")
        self.assertEqual(out["status"], "executed")


class TestToolWiring(unittest.TestCase):
    def test_the_tool_is_registered(self):
        from tools.dashboard import TOOLS

        names = [t.name for t in TOOLS]
        self.assertIn("design_threat_intel_dashboard", names)
        self.assertIn("design_detection_dashboard", names)

    def test_it_is_a_propose_permission_tool(self):
        from tools.base import Permission
        from tools.dashboard import TOOLS

        tool = next(t for t in TOOLS if t.name == "design_threat_intel_dashboard")
        self.assertEqual(tool.permission, Permission.PROPOSE)

    def test_its_description_states_the_unsupported_gap(self):
        """The model has to know geo/IOC is unavailable before it promises it."""
        from tools.dashboard import TOOLS

        tool = next(t for t in TOOLS if t.name == "design_threat_intel_dashboard")
        blob = (tool.description + json.dumps(tool.input_schema)).lower()
        self.assertIn("geo", blob)
        self.assertIn("ioc", blob)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
