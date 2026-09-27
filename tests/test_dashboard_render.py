"""
Dashboards must RENDER, not just save. Covers the manual create/update/
visualization tools and the read-only verify_wazuh_dashboard tool against a
fake OSD server that stores what's POSTed/PUT and returns it on GET.

Run: python -m unittest tests.test_dashboard_render -v
"""

from __future__ import annotations

import copy
import json
import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

from tools.base import ToolContext, ToolError  # noqa: E402
from tools.dashboard import osd_objects as osd  # noqa: E402


class FakeOSD:
    def __init__(self, pattern_exists=True):
        self.store: dict[tuple[str, str], dict] = {}
        self.calls: list[tuple[str, str, dict | None]] = []
        self.pattern_exists = pattern_exists
        self.n = 0

    def seed(self, otype, oid, attributes, references):
        self.store[(otype, oid)] = {
            "id": oid,
            "type": otype,
            "attributes": attributes,
            "references": references,
        }

    def __call__(self, method, path, body=None, params=None, **kw):
        self.calls.append((method, path, body))
        parts = path.strip("/").split("/")
        if parts[2] == "_find":
            return {
                "saved_objects": [
                    copy.deepcopy(v) for (t, _), v in self.store.items() if t == params["type"]
                ]
            }
        otype = parts[2]
        if otype == "index-pattern" and method == "GET":
            if not self.pattern_exists:
                return {"statusCode": 404, "error": "Not Found"}
            return {
                "id": parts[3],
                "type": "index-pattern",
                "attributes": {"title": "wazuh-alerts-*"},
            }
        if method == "POST":
            self.n += 1
            oid = f"{otype}-{self.n}"
            self.store[(otype, oid)] = {"id": oid, "type": otype, **copy.deepcopy(body)}
            return {"id": oid, "type": otype}
        if method == "PUT":
            obj = self.store[(otype, parts[3])]
            obj["attributes"].update(copy.deepcopy(body["attributes"]))
            obj["references"] = copy.deepcopy(body["references"])
            return {"id": parts[3]}
        if method == "GET":
            if (otype, parts[3]) not in self.store:
                return {"statusCode": 404, "error": "Not Found"}
            return copy.deepcopy(self.store[(otype, parts[3])])
        raise AssertionError(path)


def approved(action):
    return ToolContext(
        wazuh=mock.MagicMock(),
        indexer=mock.MagicMock(),
        approval={"id": "a", "action": action, "status": "approved"},
    )


def good_vis(fake, oid):
    attrs, refs = osd.build_visualization_attributes(
        "t", "histogram", [{"id": "1", "type": "count", "schema": "metric", "params": {}}], "idx"
    )
    fake.seed("visualization", oid, attrs, refs)


class TestManualDashboardTools(unittest.TestCase):
    def test_create_dashboard_writes_renderable_panels_and_references(self):
        from tools.dashboard.dashboards import CreateWazuhDashboard

        fake = FakeOSD()
        good_vis(fake, "v1")
        good_vis(fake, "v2")
        with mock.patch("tools.dashboard.dashboards.dashboards_request", side_effect=fake):
            out = CreateWazuhDashboard().run(
                approved("create_wazuh_dashboard"),
                title="T",
                panels=[{"id": "v1", "x": 0}, "v2"],
                reason="r",
            )
        dash = fake.store[("dashboard", out["dashboard_id"])]
        self.assertEqual(osd.validate_dashboard(dash), [])
        self.assertEqual([r["id"] for r in dash["references"]], ["v1", "v2"])

    def test_create_dashboard_refuses_missing_visualizations(self):
        from tools.dashboard.dashboards import CreateWazuhDashboard

        fake = FakeOSD()
        with mock.patch("tools.dashboard.dashboards.dashboards_request", side_effect=fake):
            with self.assertRaises(ToolError):
                CreateWazuhDashboard().run(
                    approved("create_wazuh_dashboard"), title="T", panels=["ghost"], reason="r"
                )
        self.assertFalse(any(m == "POST" for m, _, _ in fake.calls))

    def test_update_dashboard_sends_references_with_panels(self):
        from tools.dashboard.dashboards import UpdateWazuhDashboard

        fake = FakeOSD()
        good_vis(fake, "v1")
        panels, refs = osd.build_panels(["v1"])
        fake.seed("dashboard", "d1", osd.build_dashboard_attributes("D", "", panels), refs)
        good_vis(fake, "v9")
        with mock.patch("tools.dashboard.dashboards.dashboards_request", side_effect=fake):
            UpdateWazuhDashboard().run(
                approved("update_wazuh_dashboard"), dashboard_id="d1", panels=["v9"], reason="r"
            )
        dash = fake.store[("dashboard", "d1")]
        self.assertEqual(osd.validate_dashboard(dash), [])
        self.assertEqual([r["id"] for r in dash["references"]], ["v9"])

    def test_create_visualization_binds_index_pattern_and_fixes_bar(self):
        from tools.dashboard.visualizations import CreateWazuhVisualization

        fake = FakeOSD()
        state = json.dumps(
            {
                "type": "bar",
                "aggs": [{"id": "1", "type": "count", "schema": "metric", "params": {}}],
                "params": {"categoryAxes": [{"id": "CategoryAxis-1"}]},
            }
        )
        with (
            mock.patch("tools.dashboard.visualizations.dashboards_request", side_effect=fake),
            mock.patch("tools.dashboard.engine.dashboards_request", side_effect=fake),
            mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx"),
        ):
            out = CreateWazuhVisualization().run(
                approved("create_wazuh_visualization"),
                title="t",
                vis_type="bar",
                vis_state=state,
                reason="r",
            )
        vis = fake.store[("visualization", out["visualization_id"])]
        self.assertEqual(osd.validate_visualization(vis), [])
        self.assertEqual(json.loads(vis["attributes"]["visState"])["type"], "histogram")
        self.assertEqual(vis["references"][0]["id"], "idx")

    def test_create_visualization_refuses_missing_index_pattern(self):
        from tools.dashboard.visualizations import CreateWazuhVisualization

        fake = FakeOSD(pattern_exists=False)
        state = json.dumps(
            {"aggs": [{"id": "1", "type": "count", "schema": "metric", "params": {}}]}
        )
        with (
            mock.patch("tools.dashboard.visualizations.dashboards_request", side_effect=fake),
            mock.patch("tools.dashboard.engine.dashboards_request", side_effect=fake),
            mock.patch("tools.dashboard.engine._find_index_pattern", return_value="gone"),
        ):
            with self.assertRaises(ToolError):
                CreateWazuhVisualization().run(
                    approved("create_wazuh_visualization"),
                    title="t",
                    vis_type="metric",
                    vis_state=state,
                    reason="r",
                )
        self.assertFalse(any(m == "POST" for m, _, _ in fake.calls))


class TestVerifyTool(unittest.TestCase):
    def _fake_with_old_and_new(self):
        fake = FakeOSD()
        # the exact shape the old engine produced
        fake.seed(
            "visualization",
            "old-v",
            {
                "title": "old",
                "visState": json.dumps(
                    {
                        "title": "old",
                        "type": "bar",
                        "aggs": [{"id": "1", "type": "count", "schema": "metric", "params": {}}],
                        "params": {
                            "type": "histogram",
                            "categoryAxes": [{"id": "CategoryAxis-1"}],
                            "valueAxes": [{"id": "ValueAxis-1"}],
                            "seriesParams": [{}],
                        },
                    }
                ),
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"index": "idx", "filter": [], "aggs": []})
                },
            },
            [{"name": osd.INDEX_REF_NAME, "type": "index-pattern", "id": "idx"}],
        )
        fake.seed(
            "dashboard",
            "old-d",
            {
                "title": "Old AI dashboard",
                "panelsJSON": json.dumps(
                    [{"id": "old-v", "x": 0, "y": 0, "w": 24, "h": 15, "type": "visualization"}]
                ),
            },
            [{"name": "panel_old-v", "type": "visualization", "id": "old-v"}],
        )
        good_vis(fake, "new-v")
        panels, refs = osd.build_panels(["new-v"])
        fake.seed(
            "dashboard",
            "new-d",
            osd.build_dashboard_attributes("New AI dashboard", "", panels),
            refs,
        )
        return fake

    def test_spots_broken_and_passes_good(self):
        from tools.dashboard.dashboards import VerifyWazuhDashboard

        fake = self._fake_with_old_and_new()
        with mock.patch("tools.dashboard.dashboards.dashboards_request", side_effect=fake):
            out = VerifyWazuhDashboard().run(approved("x"))
        by_id = {d["dashboard_id"]: d for d in out["dashboards"]}
        self.assertEqual(out["checked"], 2)
        self.assertEqual(out["broken"], 1)
        self.assertFalse(by_id["old-d"]["renders"])
        self.assertTrue(by_id["new-d"]["renders"], by_id["new-d"]["issues"])
        text = " ".join(by_id["old-d"]["issues"])
        for needle in ("gridData", "'bar' is not registered", "optionsJSON"):
            self.assertIn(needle, text)

    def test_single_dashboard_and_title_filter(self):
        from tools.dashboard.dashboards import VerifyWazuhDashboard

        fake = self._fake_with_old_and_new()
        with mock.patch("tools.dashboard.dashboards.dashboards_request", side_effect=fake):
            one = VerifyWazuhDashboard().run(approved("x"), dashboard_id="new-d")
            filt = VerifyWazuhDashboard().run(approved("x"), title_contains="old")
        self.assertEqual(one["checked"], 1)
        self.assertEqual(filt["checked"], 1)
        self.assertEqual(filt["dashboards"][0]["dashboard_id"], "old-d")

    def test_missing_index_pattern_is_reported(self):
        from tools.dashboard.dashboards import VerifyWazuhDashboard

        fake = self._fake_with_old_and_new()
        fake.pattern_exists = False
        with mock.patch("tools.dashboard.dashboards.dashboards_request", side_effect=fake):
            out = VerifyWazuhDashboard().run(approved("x"), dashboard_id="new-d")
        self.assertIn(
            "Could not locate that index-pattern", " ".join(out["dashboards"][0]["issues"])
        )

    def test_verify_is_read_only_and_registered(self):
        from tools.base import Permission
        from tools.registry import get_tool

        self.assertIs(get_tool("verify_wazuh_dashboard").permission, Permission.READ)


if __name__ == "__main__":
    unittest.main()
