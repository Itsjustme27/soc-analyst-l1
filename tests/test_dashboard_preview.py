"""
Offline tests for the dashboard preview renderer and the duplicate-dashboard
guard. Runs with MOCK_MODE only — no API keys, no network, no Wazuh dashboard.

What is covered:
  * visState agg -> OpenSearch agg translation (incl. the interval: "auto"
    trap that the live indexer rejects with HTTP 400).
  * run_panel never raises for a bad panel/query, and reports per-panel status
    instead of silently dropping the panel.
  * render_dashboard_preview produces a real PNG in the Wazuh grid geometry and
    degrades to a clear error when matplotlib is missing.
  * find_duplicate / normalize_title, and that both create paths refuse a
    repeated title.
  * The two Flask routes, including the path-traversal rejection.

Run: cd soc-agent && MOCK_MODE=true ./venv/bin/python -m unittest tests.test_dashboard_preview -v
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)

from tools.dashboard import osd_objects as osd  # noqa: E402
from tools.dashboard import preview  # noqa: E402


# --------------------------------------------------------------------------- #
# A stand-in for the live indexer: records the body it was given and answers with
# only the agg ids that body actually asked for - which is what a real
# aggregation response does, and what makes the fake faithful. Returning one
# shared block regardless would hide id collisions between panels.
# --------------------------------------------------------------------------- #
class FakeIndexer:
    def __init__(self, aggregations=None, hits=42, raises=None):
        self.aggregations = aggregations or {}
        self.hits = hits
        self.raises = raises
        self.calls = []

    def search(self, index, body):
        self.calls.append((index, body))
        if self.raises:
            raise self.raises
        asked = body.get("aggs") or {}
        return {
            "aggregations": {k: self.aggregations[k] for k in asked if k in self.aggregations},
            "hits": {"total": {"value": self.hits}},
        }


def metric_agg(idx="1", label="alerts"):
    return {
        "id": idx,
        "enabled": True,
        "type": "count",
        "schema": "metric",
        "params": {"customLabel": label},
    }


def terms_agg(field, idx="1", size=5):
    return {
        "id": idx,
        "enabled": True,
        "type": "terms",
        "schema": "segment",
        "params": {"field": field, "size": size},
    }


def date_agg(field="timestamp", interval="auto", idx="1"):
    return {
        "id": idx,
        "enabled": True,
        "type": "date_histogram",
        "schema": "segment",
        "params": {"field": field, "interval": interval, "min_doc_count": 1},
    }


class TestAggTranslation(unittest.TestCase):
    """visState aggs are not OpenSearch aggs; this is the bridge."""

    def test_count_becomes_filter_match_all(self):
        out = preview.vis_aggs_to_osd([metric_agg()])
        self.assertEqual(out, {"1": {"filter": {"match_all": {}}}})

    def test_metric_field_maps_to_opensearch_agg(self):
        agg = {"id": "1", "type": "avg", "params": {"field": "rule.level"}}
        out = preview.vis_aggs_to_osd([agg])
        self.assertEqual(out, {"1": {"avg": {"field": "rule.level"}}})

    def test_std_dev_uses_extended_stats(self):
        agg = {"id": "1", "type": "std_dev", "params": {"field": "rule.level"}}
        self.assertEqual(
            preview.vis_aggs_to_osd([agg]), {"1": {"extended_stats": {"field": "rule.level"}}}
        )

    def test_terms_carries_size(self):
        out = preview.vis_aggs_to_osd([terms_agg("rule.groups", size=7)])
        self.assertEqual(out["1"]["terms"], {"field": "rule.groups", "size": 7})

    def test_auto_interval_is_resolved_to_a_concrete_interval(self):
        """interval:"auto" is invalid on the wire - the indexer returns 400.

        So the preview MUST substitute a real interval, otherwise the preview
        errors for a reason that has nothing to do with the data.
        """
        out = preview.vis_aggs_to_osd([date_agg(interval="auto")])
        dh = out["1"]["date_histogram"]
        self.assertEqual(dh["field"], "timestamp")
        self.assertIn("fixed_interval", dh)
        self.assertNotEqual(dh["fixed_interval"], "auto")

    def test_explicit_d_or_w_uses_calendar_interval(self):
        out = preview.vis_aggs_to_osd([date_agg(interval="1d")])
        self.assertEqual(out["1"]["date_histogram"]["calendar_interval"], "1d")

    def test_explicit_sub_day_uses_fixed_interval(self):
        out = preview.vis_aggs_to_osd([date_agg(interval="30m")])
        self.assertEqual(out["1"]["date_histogram"]["fixed_interval"], "30m")

    def test_wider_range_gets_a_wider_interval(self):
        """auto must scale with the range, or a 7d range floods one panel."""
        q_short = {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-1h"}}}]}}
        q_long = {"bool": {"filter": [{"range": {"timestamp": {"gte": "now-90d"}}}]}}
        short = preview._auto_interval(q_short)
        long_ = preview._auto_interval(q_long)
        self.assertNotEqual(short, long_)

    def test_missing_field_on_bucket_agg_raises(self):
        for agg in (terms_agg(None), date_agg(field=None)):
            with self.assertRaises(preview.PreviewError):
                preview.vis_aggs_to_osd([agg])

    def test_disabled_agg_is_skipped(self):
        agg = terms_agg("rule.groups")
        agg["enabled"] = False
        self.assertEqual(preview.vis_aggs_to_osd([agg]), {})

    def test_unsupported_agg_type_raises(self):
        with self.assertRaises(preview.PreviewError):
            preview.vis_aggs_to_osd(
                [{"id": "1", "type": "significant_terms", "params": {"field": "x"}}]
            )


class TestRunPanel(unittest.TestCase):
    def test_metric_panel_reads_doc_count(self):
        idx = FakeIndexer({"1": {"doc_count": 1290}})
        r = preview.run_panel(
            idx, "wazuh-alerts-*", {"title": "Volume", "vis_type": "metric", "aggs": [metric_agg()]}
        )
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["rows"][0]["value"], 1290)

    def test_buckets_become_rows(self):
        idx = FakeIndexer({"1": {"buckets": [{"key": "syslog", "doc_count": 805}]}})
        panel = {"title": "Groups", "vis_type": "bar", "aggs": [terms_agg("rule.groups")]}
        r = preview.run_panel(idx, "i", panel)
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["rows"], [{"label": "syslog", "value": 805}])

    def test_unmapped_field_is_empty_not_an_error(self):
        """A terms agg on a field that isn't mapped returns 0 buckets.

        That is a real, common case (this host has no data.srcip) and must read
        as "empty" - not as a crash and not as a silently missing panel.
        """
        idx = FakeIndexer({"1": {"buckets": []}})
        r = preview.run_panel(
            idx, "i", {"title": "IPs", "vis_type": "pie", "aggs": [terms_agg("data.srcip")]}
        )
        self.assertEqual(r["status"], "empty")
        self.assertIn("data.srcip", r["note"])

    def test_indexer_exception_is_reported_not_raised(self):
        idx = FakeIndexer(raises=RuntimeError("HTTP 400 Bad Request"))
        r = preview.run_panel(idx, "i", {"title": "X", "aggs": [terms_agg("rule.groups")]})
        self.assertEqual(r["status"], "error")
        self.assertIn("400", r["note"])

    def test_panel_with_no_aggs_is_empty(self):
        r = preview.run_panel(FakeIndexer(), "i", {"title": "X", "aggs": []})
        self.assertEqual(r["status"], "empty")

    def test_total_hits_reported(self):
        idx = FakeIndexer({"1": {"doc_count": 5}}, hits=1287)
        r = preview.run_panel(idx, "i", {"title": "X", "aggs": [metric_agg()]})
        self.assertEqual(r["total"], 1287)

    def test_index_and_query_are_passed_through(self):
        """Correlation: the preview must run the panel's OWN query."""
        idx = FakeIndexer({"1": {"doc_count": 1}})
        q = {"bool": {"filter": [{"term": {"rule.groups": "web"}}]}}
        preview.run_panel(idx, "custom-index", {"title": "X", "aggs": [metric_agg()], "query": q})
        index, body = idx.calls[0]
        self.assertEqual(index, "custom-index")
        self.assertEqual(body["query"], q)
        self.assertEqual(body["size"], 0)


class TestRenderPreview(unittest.TestCase):
    def setUp(self):
        try:
            import matplotlib  # noqa: F401
        except ImportError:
            self.skipTest("matplotlib not installed")

    def _panels(self):
        return [
            {
                "slug": "count",
                "title": "Alert volume",
                "vis_type": "metric",
                "aggs": [metric_agg()],
            },
            {
                "slug": "groups",
                "title": "Top groups",
                "vis_type": "bar",
                "aggs": [terms_agg("rule.groups")],
            },
        ]

    def test_renders_a_png_and_reports_per_panel_status(self):
        import tempfile

        idx = FakeIndexer(
            {
                "1": {"doc_count": 1290},
                "1 ": {
                    "buckets": [
                        {"key": "syslog", "doc_count": 805},
                        {"key": "sshd", "doc_count": 12},
                    ]
                },
            }
        )
        # Both panels request agg id "1" - each is a separate search, so the
        # fake answers per call. Distinguish them by the agg body.
        inner = idx.search

        def search(index, body):
            if (body.get("aggs") or {}).get("1", {}).get("terms"):
                return {
                    "aggregations": {
                        "1": {
                            "buckets": [
                                {"key": "syslog", "doc_count": 805},
                                {"key": "sshd", "doc_count": 12},
                            ]
                        }
                    },
                    "hits": {"total": {"value": 1287}},
                }
            return inner(index, body)

        idx.search = search
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "p.png"
            r = preview.render_dashboard_preview(self._panels(), idx, out, title="T", subtitle="s")
            self.assertTrue(out.is_file())
            self.assertGreater(out.stat().st_size, 1000)
            self.assertEqual(out.read_bytes()[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual([p["status"] for p in r["panels"]], ["ok", "ok"])
            self.assertEqual(r["errors"], [])

    def test_grid_geometry_matches_the_dashboard(self):
        """2 columns and 24x15 panels - the preview must be a scale model."""
        import tempfile

        idx = FakeIndexer({"1": {"doc_count": 1}, "2": {"buckets": [{"key": "a", "doc_count": 1}]}})
        with tempfile.TemporaryDirectory() as d:
            r = preview.render_dashboard_preview(self._panels(), idx, Path(d) / "p.png")
        self.assertEqual(r["grid"]["cols"], preview.PANEL_COLS)
        self.assertEqual(r["grid"]["panel_w"], 24)
        self.assertEqual(r["grid"]["panel_h"], 15)
        # Same geometry osd_objects.build_panels assigns to a real dashboard.
        panels_json, _refs = osd.build_panels(["v0", "v1"])
        import json

        grid = [p["gridData"] for p in json.loads(panels_json)]
        self.assertEqual(
            [(g["x"], g["y"], g["w"], g["h"]) for g in grid], [(0, 0, 24, 15), (24, 0, 24, 15)]
        )

    def test_empty_panel_listing_is_returned(self):
        import tempfile

        class EmptyGroups(FakeIndexer):
            def search(self, index, body):
                if (body.get("aggs") or {}).get("1", {}).get("terms"):
                    return {"aggregations": {"1": {"buckets": []}}, "hits": {"total": {"value": 3}}}
                return {
                    "aggregations": {"1": {"doc_count": 1290}},
                    "hits": {"total": {"value": 1290}},
                }

        with tempfile.TemporaryDirectory() as d:
            r = preview.render_dashboard_preview(self._panels(), EmptyGroups({}), Path(d) / "p.png")
        self.assertEqual(r["empty"], ["Top groups"])

    def test_one_failing_panel_does_not_lose_the_others(self):
        """A panel that errors must stay visible - a silently dropped panel
        would let an operator approve a dashboard with a hole in it."""
        import tempfile

        class HalfBroken(FakeIndexer):
            def search(self, index, body):
                if (body.get("aggs") or {}).get("1", {}).get("terms"):
                    raise RuntimeError("400 bad request")
                return {
                    "aggregations": {"1": {"doc_count": 1290}},
                    "hits": {"total": {"value": 1290}},
                }

        with tempfile.TemporaryDirectory() as d:
            r = preview.render_dashboard_preview(self._panels(), HalfBroken({}), Path(d) / "p.png")
        self.assertEqual([p["status"] for p in r["panels"]], ["ok", "error"])
        self.assertEqual(r["errors"], ["Top groups"])
        self.assertEqual(r["empty"], [])

    def test_no_panels_raises(self):
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(preview.PreviewError):
                preview.render_dashboard_preview([], FakeIndexer(), Path(d) / "p.png")

    def test_missing_matplotlib_gives_one_clear_error(self):
        """The module must import fine without matplotlib; only rendering
        needs it, and then the error must name the fix."""
        import sys

        if "matplotlib" not in sys.modules:
            try:
                import matplotlib  # noqa: F401
            except ImportError:
                self.skipTest("matplotlib not installed")
        import tempfile

        real_import = (
            __builtins__["__import__"]
            if isinstance(__builtins__, dict)
            else __builtins__.__import__
        )

        def fake_import(name, *a, **kw):
            if name.startswith("matplotlib"):
                raise ImportError("no matplotlib")
            return real_import(name, *a, **kw)

        with tempfile.TemporaryDirectory() as d:
            try:
                import builtins

                builtins.__import__ = fake_import
                try:
                    with self.assertRaises(preview.PreviewError) as cm:
                        preview.render_dashboard_preview(
                            self._panels(), FakeIndexer(), Path(d) / "p.png"
                        )
                    self.assertIn("pip install matplotlib", str(cm.exception))
                finally:
                    builtins.__import__ = real_import
            except ImportError:
                self.skipTest("cannot patch __import__")


class TestDuplicateGuard(unittest.TestCase):
    """The engineer kept re-creating the same dashboard; these stop it."""

    def setUp(self):
        # Bind the real function once. Patching the module attribute and then
        # calling `preview.find_duplicate` inside the replacement would resolve
        # to the patched attribute again and recurse forever.
        self._real_find = preview.find_duplicate
        self.addCleanup(self._restore)

    def _restore(self):
        import tools.dashboard.dashboards as mod
        import tools.dashboard.engine as eng

        mod.preview_mod.find_duplicate = self._real_find
        eng.preview.find_duplicate = self._real_find

    def _patch_to(self, objects):
        """Point both create paths at a fake dashboards-server listing."""
        import tools.dashboard.dashboards as mod
        import tools.dashboard.engine as eng

        def fetch(method, path, **kw):
            return {"saved_objects": objects}

        real = self._real_find

        def fake(title, **kw):
            return real(title, fetch=fetch)

        mod.preview_mod.find_duplicate = fake
        eng.preview.find_duplicate = fake
        return fake

    def test_normalize_title_is_loose(self):
        for a in ("Web Attacks", "  web attacks ", "Web-Attacks", "WEB_ATTACKS"):
            self.assertEqual(preview.normalize_title(a), "web attacks")

    def _fetch_with(self, objects):
        def fetch(method, path, **kw):
            return {"saved_objects": objects}

        return fetch

    def test_finds_a_duplicate_regardless_of_casing_and_punctuation(self):
        objects = [
            {
                "id": "dashboard-web",
                "attributes": {"title": "Web-Server Attacks", "panelsJSON": "[]"},
            }
        ]
        dup = preview.find_duplicate("web server attacks", fetch=self._fetch_with(objects))
        self.assertIsNotNone(dup)
        self.assertEqual(dup["id"], "dashboard-web")

    def test_no_duplicate_for_a_different_title(self):
        objects = [{"id": "d1", "attributes": {"title": "SSH Failures"}}]
        self.assertIsNone(preview.find_duplicate("Web Attacks", fetch=self._fetch_with(objects)))

    def test_malformed_panelsjson_does_not_crash(self):
        objects = [{"id": "d1", "attributes": {"title": "A B", "panelsJSON": "{not json"}}]
        dup = preview.find_duplicate("a b", fetch=self._fetch_with(objects))
        self.assertEqual(dup["panels"], None)

    def test_listing_failure_never_blocks_a_create(self):
        """A duplicate check that hard-fails would make the dashboard tool
        unusable whenever the listing endpoint hiccups."""

        def boom(method, path, **kw):
            raise RuntimeError("dashboards server down")

        self.assertIsNone(preview.find_duplicate("Anything", fetch=boom))

    def test_empty_title_never_matches(self):
        objects = [{"id": "d1", "attributes": {"title": "anything"}}]
        self.assertIsNone(preview.find_duplicate("   ", fetch=self._fetch_with(objects)))

    def test_create_tool_refuses_a_duplicate_title(self):
        """create_wazuh_dashboard must stop, not silently make copy #2."""
        from tools.base import ToolContext, ToolError
        from tools.dashboard.dashboards import CreateWazuhDashboard

        self._patch_to(
            [{"id": "dashboard-web", "attributes": {"title": "Web Attacks", "panelsJSON": "[]"}}]
        )
        ctx = ToolContext(wazuh=None, indexer=None, user="u", agent="t")
        with self.assertRaises(ToolError) as cm:
            CreateWazuhDashboard().run(ctx, title="web attacks", panels=["vis-a"], reason="because")
        self.assertIn("already exists", str(cm.exception))
        self.assertIn("update_wazuh_dashboard", str(cm.exception))

    def test_duplicate_is_reported_before_panel_validation(self):
        """A repeat is the common case; the operator must not first be sent
        through per-panel saved-object lookups to be told the title exists."""
        from tools.base import ToolContext, ToolError
        from tools.dashboard.dashboards import CreateWazuhDashboard

        self._patch_to([{"id": "d1", "attributes": {"title": "Web Attacks"}}])
        # vis-a does not exist on the server, so a validation-first
        # implementation would raise about the visualization instead.
        with self.assertRaises(ToolError) as cm:
            CreateWazuhDashboard().run(
                ToolContext(wazuh=None, indexer=None, user="u", agent="t"),
                title="Web Attacks",
                panels=["vis-a"],
                reason="r",
            )
        self.assertNotIn("do not exist", str(cm.exception))

    def test_engine_tool_refuses_a_duplicate_title(self):
        from tools.base import ToolContext, ToolError
        from tools.dashboard.engine import DesignDetectionDashboard

        self._patch_to(
            [{"id": "dashboard-web", "attributes": {"title": "Web Attacks", "panelsJSON": "[]"}}]
        )
        ctx = ToolContext(wazuh=None, indexer=None, user="u", agent="t")
        with self.assertRaises(ToolError) as cm:
            DesignDetectionDashboard().run(ctx, title="WEB ATTACKS", reason="because")
        self.assertIn("already exists", str(cm.exception))

    def test_guard_runs_before_the_indexer_is_touched(self):
        """Cheap rejection: a duplicate must not cost a field_caps round trip."""
        from tools.base import ToolContext, ToolError
        from tools.dashboard.engine import DesignDetectionDashboard

        class Exploding:
            def field_caps(self, *a, **kw):
                raise AssertionError("indexer was queried despite a duplicate title")

        self._patch_to([{"id": "d1", "attributes": {"title": "Web Attacks"}}])
        with self.assertRaises(ToolError):
            DesignDetectionDashboard().run(
                ToolContext(wazuh=None, indexer=Exploding(), user="u", agent="t"),
                title="Web Attacks",
                reason="r",
            )


class TestApprovedReplayIsNeverVetoed(unittest.TestCase):
    """REGRESSION. The duplicate guard shipped as a create-time check, which
    locked approved proposals out of execution permanently: the dashboard an
    approval described already existed (an earlier execution had made it), so
    the guard refused the replay, and since the proposal stayed 'approved' it
    could never succeed. The operator approved four proposals and none could be
    executed.

    The guard belongs to the PROPOSE path. Replaying an approval must not
    consult it. These tests fail if the ctx.approval check is removed.
    """

    def setUp(self):
        self._real_find = preview.find_duplicate
        self.addCleanup(self._restore)

    def _restore(self):
        import tools.dashboard.dashboards as mod
        import tools.dashboard.engine as eng

        mod.preview_mod.find_duplicate = self._real_find
        eng.preview.find_duplicate = self._real_find

    def _every_listing_reports_a_duplicate(self):
        """Every listing says the title already exists."""
        import tools.dashboard.dashboards as mod
        import tools.dashboard.engine as eng

        objects = [
            {
                "id": "0f21c260-1111",
                "attributes": {"title": "Web Attacks", "panelsJSON": "[]"},
            }
        ]

        def fetch(method, path, **kw):
            return {"saved_objects": objects}

        real = self._real_find

        def fake(title, **kw):
            return real(title, fetch=fetch)

        mod.preview_mod.find_duplicate = fake
        eng.preview.find_duplicate = fake
        return fake

    def _claimed_ctx(self):
        """A ctx carrying a claimed approval - what approval_executor builds."""
        from tools.base import ToolContext

        ctx = ToolContext(wazuh=None, indexer=None, user="approver", agent="approval_executor")
        ctx.approval = {
            "id": "appr-1",
            "action": "design_detection_dashboard",
            "status": "executing",
        }
        return ctx

    def test_veto_is_silent_when_an_approval_is_being_replayed(self):
        self._every_listing_reports_a_duplicate()
        self.assertIsNone(preview.duplicate_veto(self._claimed_ctx(), "Web Attacks"))

    def test_veto_still_fires_on_a_plain_propose(self):
        """The guard must not be disabled outright - that was the whole point."""
        self._every_listing_reports_a_duplicate()
        from tools.base import ToolContext

        self.assertIsNotNone(
            preview.duplicate_veto(
                ToolContext(wazuh=None, indexer=None, user="u", agent="t"), "Web Attacks"
            )
        )

    def test_any_truthy_approval_stands_the_guard_down(self):
        """Guard on `is not None`, not on a status string: approval_executor
        hands the tool the claimed record, and a future caller could pass a
        differently-shaped dict. Keying on status would silently re-break this."""
        self._every_listing_reports_a_duplicate()
        from tools.base import ToolContext

        for approval in ({"id": "x"}, {"status": "approved"}, {"anything": True}):
            ctx = ToolContext(wazuh=None, indexer=None, user="u", agent="t")
            ctx.approval = approval
            self.assertIsNone(preview.duplicate_veto(ctx, "Web Attacks"), approval)

    def test_engine_replay_gets_past_the_guard(self):
        """End-to-end through the tool: an approved duplicate must reach the
        panel plan, not stop at the veto."""
        self._every_listing_reports_a_duplicate()
        from tools.dashboard.engine import DesignDetectionDashboard

        class FakeIndexer:
            def field_caps(self, index, *a, **kw):
                return {"fields": {}}

            def search(self, body, *a, **kw):
                return {"hits": {"total": {"value": 7}, "hits": []}}

        tool = DesignDetectionDashboard()
        # It gets past the guard: the failure, if any, is downstream of it.
        with self.assertRaises(Exception) as cm:
            tool.run(
                self._claimed_ctx(),
                title="Web Attacks",
                reason="approved earlier",
                focus="web",
            )
        self.assertNotIn("already exists", str(cm.exception))

    def test_execute_route_succeeds_when_a_duplicate_exists(self):
        """The real regression, through the real HTTP route.

        A previously-approved proposal is executed while the dashboards server
        reports the same title already present. In production this returned
        ok=false / "already exists" and the proposal could never be retried.

        approval_executor is stubbed because the subject under test is whether
        the guard blocks the replay, not whether a live Wazuh answers. The stub
        mirrors the real executor's one relevant act - handing the tool the
        claimed approval - so this cannot pass by accident if ctx.approval is
        ever left unset, and it records whether the veto spoke.
        """
        import json as _json
        import os
        import sys
        import tempfile

        import config
        import dashboard

        self._every_listing_reports_a_duplicate()

        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        self.addCleanup(lambda: os.unlink(tmp.name))
        with open(tmp.name, "w", encoding="utf-8") as fh:
            _json.dump(
                [
                    {
                        "id": "appr-replay",
                        "action": "design_detection_dashboard",
                        "status": "approved",
                        "payload": {"title": "Web Attacks", "focus": "web", "reason": "r"},
                        "created_at": "2026-01-01T00:00:00",
                    }
                ],
                fh,
            )
        old_path = config.cfg.APPROVALS_PATH
        config.cfg.APPROVALS_PATH = tmp.name
        self.addCleanup(setattr, config.cfg, "APPROVALS_PATH", old_path)

        seen = {}

        def fake_execute(proposal_id, **kw):
            ctx = dashboard._engineer_context(user="approver", agent="approval_executor")
            ctx.approval = {"id": proposal_id, "status": "executing"}
            seen["approval_present"] = bool(ctx.approval)
            seen["veto"] = preview.duplicate_veto(ctx, "Web Attacks")
            return {"ok": True, "http_status": 200, "result": {"dashboard_id": "made-it"}}

        stub = type(sys)("approval_executor")
        stub.execute_proposal = fake_execute
        sys.modules["approval_executor"] = stub
        self.addCleanup(sys.modules.pop, "approval_executor", None)

        dashboard.app.config["TESTING"] = True
        c = dashboard.app.test_client()
        r = c.post("/api/proposals/appr-replay/execute", json={"confirm": False})
        body = r.get_json()

        self.assertEqual(r.status_code, 200)
        self.assertTrue(seen.get("approval_present"), "stub did not receive an approval ctx")
        self.assertIsNone(seen.get("veto"), "the duplicate veto spoke during a replay")
        self.assertNotIn("already exists", str(body))


class TestTitleDiscipline(unittest.TestCase):
    """A dashboard title is a name. The engineer once shipped an entire request
    sentence as the title - 216 characters, 28 words, JSON quotes attached."""

    SENTENCE = (
        '"Build a real-time general threat dashboard that aggregates, normalizes, '
        "and visualizes security threat feeds (CVEs, IOCs, CVSS scores, geo-origin, "
        'severity trends) with live filtering, alerting, and drill-down views."'
    )

    def test_clean_strips_json_quotes_and_collapses_space(self):
        self.assertEqual(preview.clean_title('"Web  Attacks"'), "Web Attacks")
        self.assertEqual(preview.clean_title('  "Web   Attacks"  '), "Web Attacks")

    def test_clean_does_not_eat_an_unbalanced_quote(self):
        self.assertEqual(preview.clean_title('"Web Attacks'), '"Web Attacks'.replace('"', ""))

    def test_clean_drops_interior_quotes(self):
        self.assertEqual(preview.clean_title('The "Real" Threat Board'), "The Real Threat Board")

    def test_clean_keeps_a_genuine_balanced_quoted_name(self):
        self.assertEqual(preview.clean_title('"Attack" Surface Map'), "Attack Surface Map")

    def test_a_real_name_passes(self):
        for name in ("Web Server Attacks", "SSH Failures", "General Threat Intelligence"):
            title, problem = preview.check_title(name)
            self.assertIsNone(problem, name)
            self.assertEqual(title, name)

    def test_a_sentence_is_rejected_with_an_actionable_message(self):
        title, problem = preview.check_title(self.SENTENCE)
        self.assertIsNotNone(problem)
        self.assertIn("description", problem)
        self.assertIn("80", problem)

    def test_empty_is_rejected(self):
        for bad in ("", "   ", '""'):
            _, problem = preview.check_title(bad)
            self.assertIsNotNone(problem, bad)

    def test_derive_cuts_at_the_first_clause(self):
        got = preview.derive_title(self.SENTENCE)
        self.assertLessEqual(len(got), 80)
        self.assertEqual(got, "real-time general threat dashboard")

    def test_derive_strips_the_imperative_verb(self):
        self.assertEqual(
            preview.derive_title("Create a Network Traffic Overview"), "Network Traffic Overview"
        )
        self.assertEqual(preview.derive_title("Please build me an SSH Overview"), "SSH Overview")

    def test_derive_leaves_a_good_title_alone(self):
        self.assertEqual(
            preview.derive_title("General Threat Intelligence Dashboard"),
            "General Threat Intelligence Dashboard",
        )

    def test_derive_never_returns_empty_for_non_empty_input(self):
        """An empty derived title would be worse than the original."""
        for bad in (self.SENTENCE, '"x"', "!!!", "a", "---"):
            self.assertTrue(preview.derive_title(bad), bad)

    def test_resolve_rejects_while_proposing(self):
        """Proposing is where the mistake is cheap to fix, so the model is told."""
        from tools.base import ToolContext

        ctx = ToolContext(wazuh=None, indexer=None, user="u", agent="t")
        _, problem = preview.resolve_title(ctx, self.SENTENCE)
        self.assertIsNotNone(problem)

    def test_resolve_derives_while_replaying_an_approval(self):
        """Replaying: the operator already approved this. Refusing over
        punctuation would strand a decision they made."""
        from tools.base import ToolContext

        ctx = ToolContext(wazuh=None, indexer=None, user="u", agent="t")
        ctx.approval = {"id": "a", "status": "executing"}
        title, problem = preview.resolve_title(ctx, self.SENTENCE)
        self.assertIsNone(problem)
        self.assertEqual(title, "real-time general threat dashboard")

    def test_resolve_never_rejects_an_empty_title_on_replay(self):
        """Even degenerate, a replay proceeds - derive_title supplies a
        placeholder rather than deadlocking the approval."""
        from tools.base import ToolContext

        ctx = ToolContext(wazuh=None, indexer=None, user="u", agent="t")
        ctx.approval = {"id": "a", "status": "executing"}
        title, problem = preview.resolve_title(ctx, '""')
        self.assertIsNone(problem)
        self.assertTrue(title)

    def test_the_engine_rejects_a_sentence_while_proposing(self):
        from tools.base import ToolContext, ToolError
        from tools.dashboard.engine import DesignDetectionDashboard

        class Exploding:
            def field_caps(self, *a, **kw):
                raise AssertionError("indexer was queried despite a bad title")

        with self.assertRaises(ToolError) as cm:
            DesignDetectionDashboard().run(
                ToolContext(wazuh=None, indexer=Exploding(), user="u", agent="t"),
                title=self.SENTENCE,
                reason="r",
            )
        self.assertIn("not a name", str(cm.exception))


class TestPreviewRoutes(unittest.TestCase):
    def setUp(self):
        import tempfile

        self.tmp = tempfile.TemporaryDirectory()
        import config

        self._old_dir = config.cfg.PREVIEW_DIR
        config.cfg.PREVIEW_DIR = self.tmp.name
        import dashboard

        dashboard.app.config["TESTING"] = True
        self.client = dashboard.app.test_client()

    def tearDown(self):
        import config

        config.cfg.PREVIEW_DIR = self._old_dir
        self.tmp.cleanup()

    def test_missing_title_is_a_400(self):
        r = self.client.post("/api/engineer/dashboard/preview", json={"focus": "general"})
        self.assertEqual(r.status_code, 400)

    def test_empty_panel_list_is_a_400(self):
        r = self.client.post("/api/engineer/dashboard/preview", json={"title": "X", "panels": []})
        self.assertEqual(r.status_code, 400)

    def test_png_route_rejects_a_non_token_name(self):
        """The name becomes a filesystem path, so anything that is not a
        generated token must be refused. Werkzeug normalises an encoded slash
        before routing (404) and the regex catches the rest (400) - either is
        a refusal; what must never happen is a 200 with someone else's bytes.
        """
        for bad in (
            "zzz.png",
            "..%2F..%2Fconfig.py.png",
            "abc123.png",
            "0" * 31 + ".png",
            "0" * 33 + ".png",
            "%2e%2e%2fconfig.py.png",
        ):
            r = self.client.get(f"/api/engineer/dashboard/preview/{bad}")
            self.assertIn(r.status_code, (400, 404), f"{bad} should be refused")
            self.assertNotIn(b"ANTHROPIC", r.data)
            self.assertNotIn(b"DASHBOARD", r.data)

    def test_unknown_token_is_a_404(self):
        r = self.client.get("/api/engineer/dashboard/preview/" + "0" * 32 + ".png")
        self.assertEqual(r.status_code, 404)

    def test_png_name_without_the_suffix_is_still_token_checked(self):
        r = self.client.get("/api/engineer/dashboard/preview/nope.png.png")
        self.assertIn(r.status_code, (400, 404))

    def test_only_token_named_files_are_servable(self):
        """The token check is the authorisation boundary for this directory.

        Asserting "nonexistent name -> 404" cannot tell a working check from a
        missing one, because both end in 404. So plant a REAL file whose name is
        not a token: a working check must refuse it, a removed one serves it.
        """
        secret = b"\x89PNG\r\n\x1a\nPLANTED"
        planted = Path(self.tmp.name) / "notatoken.png"
        planted.write_bytes(secret)

        r = self.client.get("/api/engineer/dashboard/preview/notatoken.png")
        self.assertEqual(r.status_code, 400)
        self.assertNotIn(secret, r.data)

        # And the same for a name that merely looks hex-ish but is too long.
        short = Path(self.tmp.name) / ("a" * 31 + ".png")
        short.write_bytes(secret)
        self.assertEqual(
            self.client.get(f"/api/engineer/dashboard/preview/{'a' * 31}.png").status_code, 400
        )

    def test_render_reports_the_duplicate_in_the_response(self):
        """The preview must carry the duplicate warning to the UI, so the
        operator learns about a repeat before the create is ever proposed."""
        import dashboard
        from tools.dashboard import preview as pv

        class Ctx:
            indexer = FakeIndexer({"1": {"doc_count": 7}})

        real_ctx = dashboard._engineer_context
        real_find = pv.find_duplicate
        dashboard._engineer_context = lambda **kw: Ctx()
        pv.find_duplicate = lambda title, **kw: {"id": "dashboard-web", "title": title, "panels": 7}
        try:
            r = self.client.post(
                "/api/engineer/dashboard/preview",
                json={
                    "title": "Web Attacks",
                    "panels": [{"title": "Volume", "vis_type": "metric", "aggs": [metric_agg()]}],
                },
            )
        finally:
            dashboard._engineer_context = real_ctx
            pv.find_duplicate = real_find

        self.assertEqual(r.status_code, 200)
        dup = r.get_json()["duplicate"]
        self.assertIsNotNone(dup, "response must include the duplicate check result")
        self.assertEqual(dup["id"], "dashboard-web")

    def test_render_response_shape_is_what_the_ui_reads(self):
        """Field names are a contract with renderDashboardPreview() in
        templates/index.html - renaming one silently blanks the panel."""
        import dashboard

        class Ctx:
            indexer = FakeIndexer({"1": {"doc_count": 7}})

        real_ctx = dashboard._engineer_context
        dashboard._engineer_context = lambda **kw: Ctx()
        try:
            r = self.client.post(
                "/api/engineer/dashboard/preview",
                json={
                    "title": "T",
                    "panels": [{"title": "Volume", "vis_type": "metric", "aggs": [metric_agg()]}],
                },
            )
        finally:
            dashboard._engineer_context = real_ctx

        d = r.get_json()
        for key in ("png_url", "title", "index", "grid", "panels", "empty", "errors", "duplicate"):
            self.assertIn(key, d, f"{key} missing - the UI reads it")
        self.assertEqual(d["grid"]["cols"], 2)
        p = d["panels"][0]
        for key in ("title", "vis_type", "status", "rows", "total", "note"):
            self.assertIn(key, p)
        self.assertTrue(d["png_url"].endswith(d["token"] + ".png"))

    def test_works_without_a_dashboards_server(self):
        """A live host has no Wazuh dashboard at all; the preview is built from
        the indexer and must still render, reporting duplicate=None."""
        import dashboard

        class Ctx:
            indexer = FakeIndexer({"1": {"doc_count": 7}})

        real_ctx = dashboard._engineer_context
        dashboard._engineer_context = lambda **kw: Ctx()
        try:
            r = self.client.post(
                "/api/engineer/dashboard/preview",
                json={
                    "title": "T",
                    "panels": [{"title": "Volume", "vis_type": "metric", "aggs": [metric_agg()]}],
                },
            )
        finally:
            dashboard._engineer_context = real_ctx
        self.assertEqual(r.status_code, 200)
        self.assertIsNone(r.get_json()["duplicate"])

    def test_prune_keeps_the_directory_bounded(self):
        import dashboard

        d = Path(self.tmp.name)
        for i in range(dashboard._PREVIEW_KEEP + 7):
            f = d / f"{i:032x}.png"
            f.write_bytes(b"x")
            os.utime(f, (1000 + i, 1000 + i))
        dashboard._prune_previews(keep=5)
        self.assertEqual(len(list(d.glob("*.png"))), 5)

    def test_prune_never_raises_on_a_missing_dir(self):
        import config
        import dashboard

        old = config.cfg.PREVIEW_DIR
        config.cfg.PREVIEW_DIR = str(Path(old) / "does-not-exist")
        try:
            dashboard._prune_previews()  # must not raise
        finally:
            config.cfg.PREVIEW_DIR = old


class TestEngineerPreviewTab(unittest.TestCase):
    """The preview needs a tab of its own in the engineer view, or the
    operator never sees it."""

    @classmethod
    def setUpClass(cls):
        cls.html = (BASE / "templates" / "index.html").read_text(encoding="utf-8")

    def test_engineer_view_has_subtabs(self):
        self.assertIn('id="engineer-subtabs"', self.html)
        self.assertIn('data-sub="preview"', self.html)

    def test_both_panes_exist(self):
        self.assertIn('id="engineer-pane-chat"', self.html)
        self.assertIn('id="engineer-pane-preview"', self.html)

    def test_chat_pane_still_contains_the_thread(self):
        """The sub-tab must wrap the existing engineer UI, not replace it."""
        self.assertIn('id="engineer-input"', self.html)
        self.assertIn('id="engineer-wrap"', self.html)
        self.assertIn("sendEngineer()", self.html)

    def test_render_function_calls_the_preview_route(self):
        self.assertIn("function renderDashboardPreview()", self.html)
        self.assertIn("/api/engineer/dashboard/preview", self.html)

    def test_token_is_not_put_in_the_image_url(self):
        """The PNG is auth-gated and an <img src> cannot send a header, so it
        is blob-fetched. Leaking the bearer token into a query string would put
        it in access logs and browser history."""
        fn = self.html.split("async function renderDashboardPreview()")[1].split("\nfunction ")[0]
        self.assertIn("URL.createObjectURL", fn)
        self.assertIn("Authorization", fn)
        self.assertNotIn("encodeURIComponent(DASHBOARD_TOKEN)", fn)

    def test_duplicate_warning_is_rendered(self):
        fn = self.html.split("async function renderDashboardPreview()")[1].split("\nfunction ")[0]
        self.assertIn("r.duplicate", fn)
        self.assertIn("already exists", fn)


class TestVisTypeFidelity(unittest.TestCase):
    """The preview must draw the chart Wazuh will draw.

    The engine emits vis_type "bar"; Wazuh stores that as a "histogram", which
    renders as VERTICAL bars. If the preview used the raw string it would fall
    back to a horizontal chart, and the operator would be approving a picture
    that does not match the dashboard they get.
    """

    def _run(self, vis_type):
        idx = FakeIndexer({"1": {"buckets": [{"key": "a", "doc_count": 1}]}})
        return preview.run_panel(
            idx, "i", {"title": "X", "vis_type": vis_type, "aggs": [terms_agg("rule.groups")]}
        )

    def test_bar_is_reported_as_histogram(self):
        self.assertEqual(self._run("bar")["vis_type"], "histogram")

    def test_donut_is_reported_as_pie(self):
        self.assertEqual(self._run("donut")["vis_type"], "pie")

    def test_matches_normalize_vis_type_for_every_plan_type(self):
        for t in (
            "bar",
            "column",
            "donut",
            "count",
            "vertical_bar",
            "histogram",
            "line",
            "area",
            "table",
            "metric",
            "horizontal_bar",
            "pie",
        ):
            self.assertEqual(self._run(t)["vis_type"], osd.normalize_vis_type(t), t)

    def test_unknown_type_does_not_raise(self):
        r = self._run("some-future-type")
        self.assertEqual(r["vis_type"], "some-future-type")

    def test_only_horizontal_bar_is_drawn_horizontally(self):
        """Orientation follows the normalized type alone - never the labels."""
        import inspect

        src = inspect.getsource(preview._draw_bars)
        self.assertIn('horizontal = vis_type == "horizontal_bar"', src)
        self.assertNotIn("_looks_temporal", inspect.getsource(preview))


class TestPanelPlanIsReusable(unittest.TestCase):
    """The preview must consume the engine's own panel plan, not a lookalike.

    If these drift, the preview stops being a preview of what gets created.
    """

    def test_plan_panels_carry_what_run_panel_needs(self):
        from tools.dashboard.engine import _panel_plan

        schema = {
            "rule.id": "integer",
            "rule.level": "integer",
            "rule.groups": "keyword",
            "data.srcip": "ip",
            "agent.name": "keyword",
            "timestamp": "date",
        }
        plan = _panel_plan("general", schema)
        self.assertTrue(plan)
        for p in plan:
            self.assertIn("title", p)
            self.assertIn("vis_type", p)
            self.assertIn("aggs", p)
            self.assertIn("query", p)
            # And the type must be one the renderer actually understands.
            osd.normalize_vis_type(p["vis_type"])

    def test_every_plan_vis_type_normalizes(self):
        from tools.dashboard.engine import _panel_plan

        for focus in ("web", "ssh", "network", "general"):
            for p in _panel_plan(focus, {"timestamp": "date"}):
                t = osd.normalize_vis_type(p["vis_type"])
                # run_panel must not reject it: the agg list has to translate.
                preview.vis_aggs_to_osd(osd.normalize_aggs(p["aggs"]), p["query"])
                self.assertIn(
                    t, ("histogram", "horizontal_bar", "line", "area", "pie", "metric", "table")
                )


if __name__ == "__main__":
    unittest.main()
