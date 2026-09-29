"""
Intent-driven builders: the dashboard planner and the rule drafter.

THE BUG CLASS THESE EXIST TO KILL
Both builder UIs were template machines. `design_detection_dashboard` took
`focus` as a closed enum (web|ssh|network|general) and ignored free text
entirely, so "ssh failed login from private to private ip" produced the same
seven generic panels as any other request, with the request itself parked in
the proposal's `reason`. `develop_wazuh_rule` demanded hand-written XML plus
samples, leaving "Starter rule" - one hardcoded SSH template - as the only way
in. Ask for something else and you got that same template.

The invariants pinned here:
  * a free-text intent produces a plan that is SPECIFIC to the intent, and the
    difference is observable in the panel set and the queries, not just prose;
  * the model never gets to name a field or an operator - it picks from a
    closed vocabulary, and anything outside it (or absent from the live
    schema) is dropped rather than passed to the indexer;
  * every panel carries the intent's filter, so the dashboard counts what was
    actually asked about;
  * a planner outage or an unusable plan degrades to the old template instead
    of breaking the builder, and says so in the evidence;
  * drafting is READ and proposes nothing - the human reads the XML first.

Everything is offline: mocked indexer/wazuh and a stub LLM provider, so the
assertions are about OUR code's behaviour, not a model's.

Run: cd soc-agent && MOCK_MODE=true ./venv/bin/python -m unittest tests.test_builder_intent -v
"""

from __future__ import annotations

import json
import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

from tools.base import ApprovalRequired, Permission, ToolContext, ToolError
from tools.dashboard import planner
from tools.dashboard.engine import DesignDetectionDashboard
from tools.detection.drafter import DraftWazuhRule

# A realistic wazuh-alerts field_caps result.
SCHEMA = {
    "data.srcip": "ip",
    "data.dstip": "ip",
    "data.user": "keyword",
    "rule.id": "keyword",
    "rule.level": "long",
    "rule.groups": "keyword",
    "rule.description": "text",
    "agent.name": "keyword",
    "timestamp": "date",
}


class StubLLM:
    """Records the prompts it was given and replies with a canned object."""

    name = "stub"

    def __init__(self, reply):
        self.reply = reply
        self.calls: list[dict] = []

    def chat_text(self, *, system, messages, max_tokens):
        self.calls.append({"system": system, "messages": messages, "max_tokens": max_tokens})
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)


def make_ctx(llm=None, *, matched=42, schema=None):
    indexer = mock.MagicMock()
    indexer.field_caps.return_value = dict(schema or SCHEMA)
    indexer.search.return_value = {"hits": {"total": {"value": matched}}, "took": 1}
    return ToolContext(wazuh=mock.MagicMock(), indexer=indexer, llm=llm or StubLLM({}))


PRIVATE_TO_PRIVATE_PLAN = {
    "title": "Private SSH Failures",
    "filters": [
        {"field": "rule_group", "op": "match_phrase", "values": ["ssh"]},
        {"field": "src_ip", "op": "cidr", "values": ["10.0.0.0/8", "192.168.0.0/16"]},
        {"field": "dst_ip", "op": "cidr", "values": ["10.0.0.0/8"]},
    ],
    "panels": [
        {"kind": "count"},
        {"kind": "trend"},
        {"kind": "breakdown", "field": "src_ip", "vis": "pie"},
        {"kind": "breakdown", "field": "user", "vis": "bar"},
    ],
    "notes": "Failed SSH logins whose source and destination are both RFC1918.",
}


# --------------------------------------------------------------------------- #
class TestFilterSanitizing(unittest.TestCase):
    """The model picks from a closed vocabulary; it cannot name a field."""

    def test_cidr_becomes_an_or_of_range_clauses(self):
        filters, dropped = planner.plan_filters(
            [{"field": "src_ip", "op": "cidr", "values": ["10.0.0.0/8", "192.168.0.0/16"]}],
            SCHEMA,
        )
        self.assertEqual(dropped, [])
        # Multiple CIDRs must be OR-ed (should), not AND-ed - an alert is
        # in-scope if ANY private range hits.
        self.assertEqual(
            filters,
            [
                {
                    "bool": {
                        "should": [
                            {"range": {"data.srcip": "10.0.0.0/8"}},
                            {"range": {"data.srcip": "192.168.0.0/16"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }
            ],
        )

    def test_a_hallucinated_field_key_is_dropped_not_forwarded(self):
        filters, dropped = planner.plan_filters(
            [{"field": "data.not_a_field", "op": "term", "values": ["x"]}], SCHEMA
        )
        self.assertEqual(filters, [])
        self.assertTrue(dropped)
        self.assertIn("data.not_a_field", dropped[0])

    def test_a_known_key_absent_from_the_live_schema_is_dropped(self):
        schema = {"rule.groups": "keyword"}  # no data.srcip on this index
        filters, dropped = planner.plan_filters(
            [{"field": "src_ip", "op": "term", "values": ["1.2.3.4"]}], schema
        )
        self.assertEqual(filters, [])
        self.assertIn("not in the index schema", dropped[0])

    def test_an_unknown_operator_is_dropped(self):
        filters, dropped = planner.plan_filters(
            [{"field": "rule_group", "op": "regex_evil", "values": ["x"]}], SCHEMA
        )
        self.assertEqual(filters, [])
        self.assertIn("unknown filter op", dropped[0])

    def test_cidr_on_a_non_ip_field_is_dropped(self):
        filters, dropped = planner.plan_filters(
            [{"field": "rule_group", "op": "cidr", "values": ["10.0.0.0/8"]}], SCHEMA
        )
        self.assertEqual(filters, [])
        self.assertIn("only valid on src_ip/dst_ip", dropped[0])

    def test_term_and_match_phrase_map_to_real_fields(self):
        filters, _ = planner.plan_filters(
            [
                {"field": "rule_group", "op": "term", "values": ["ssh"]},
                {"field": "rule_description", "op": "match_phrase", "values": ["failed login"]},
            ],
            SCHEMA,
        )
        self.assertEqual(
            filters,
            [
                {"term": {"rule.groups": "ssh"}},
                {"match_phrase": {"rule.description": "failed login"}},
            ],
        )

    def test_a_clause_with_no_usable_values_is_dropped(self):
        filters, dropped = planner.plan_filters(
            [{"field": "rule_group", "op": "term", "values": []}], SCHEMA
        )
        self.assertEqual(filters, [])
        self.assertTrue(dropped)


# --------------------------------------------------------------------------- #
class TestPanelPlanning(unittest.TestCase):
    def test_every_panel_carries_the_time_window_and_the_intent_filter(self):
        panels, _ = planner.plan_panels(
            [{"kind": "breakdown", "field": "src_ip"}],
            SCHEMA,
            "general",
            "now-7d",
            [{"term": {"rule.groups": "ssh"}}],
        )
        self.assertTrue(panels)
        for panel in panels:
            filters = panel["query"]["bool"]["filter"]
            self.assertIn({"range": {"timestamp": {"gte": "now-7d"}}}, filters)
            self.assertIn({"term": {"rule.groups": "ssh"}}, filters)

    def test_a_breakdown_renders_a_terms_agg_on_the_real_field(self):
        panels, _ = planner.plan_panels(
            [{"kind": "breakdown", "field": "user", "vis": "pie"}], SCHEMA, "general", None, []
        )
        breakdown = next(p for p in panels if p["slug"] == "breakdown_user")
        self.assertEqual(breakdown["vis_type"], "pie")
        terms = [a for a in breakdown["aggs"] if a["type"] == "terms"]
        self.assertEqual(terms[0]["params"]["field"], "data.user")

    def test_a_breakdown_on_an_absent_field_is_dropped(self):
        panels, dropped = planner.plan_panels(
            [{"kind": "breakdown", "field": "decoder"}],
            {"rule.groups": "keyword"},
            "general",
            None,
            [],
        )
        self.assertNotIn("breakdown_decoder", [p["slug"] for p in panels])
        self.assertTrue(any("not in the index schema" in d for d in dropped))
        # with the planned panel gone the shape is padded back out to something
        # coherent rather than left as two lone panels
        self.assertGreaterEqual(len(panels), 3)

    def test_unique_renders_a_cardinality_agg(self):
        panels, _ = planner.plan_panels(
            [{"kind": "unique", "field": "src_ip"}], SCHEMA, "general", None, []
        )
        uniq = next(p for p in panels if p["slug"] == "unique_src_ip")
        card = [a for a in uniq["aggs"] if a["type"] == "cardinality"]
        self.assertEqual(card[0]["params"]["field"], "data.srcip")

    def test_panel_count_is_capped(self):
        many = [{"kind": "breakdown", "field": k} for k in list(planner.PLAN_FIELDS) * 3]
        panels, _ = planner.plan_panels(many, SCHEMA, "general", None, [])
        self.assertLessEqual(len(panels), 8)

    def test_duplicate_picks_are_collapsed(self):
        panels, _ = planner.plan_panels(
            [{"kind": "breakdown", "field": "src_ip"}, {"kind": "breakdown", "field": "src_ip"}],
            SCHEMA,
            "general",
            None,
            [],
        )
        self.assertEqual([p["slug"] for p in panels].count("breakdown_src_ip"), 1)


# --------------------------------------------------------------------------- #
class TestPlanDashboard(unittest.TestCase):
    def test_the_users_own_request_yields_a_specific_plan(self):
        ctx = make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN))
        plan = planner.plan_dashboard(
            ctx,
            "ssh failed login from private to private ip",
            SCHEMA,
            time_range_expr="now-7d",
            focus="general",
        )
        self.assertTrue(plan["ok"])
        self.assertEqual(plan["title"], "Private SSH Failures")
        # private-to-private means BOTH ends are filtered
        blob = json.dumps(plan["filters"])
        self.assertIn("data.srcip", blob)
        self.assertIn("data.dstip", blob)
        self.assertIn("rule.groups", blob)
        self.assertEqual(plan["dropped"], [])

    def test_the_prompt_only_offers_fields_that_exist_on_the_index(self):
        ctx = make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN), schema={"rule.groups": "keyword"})
        planner.plan_dashboard(
            ctx, "anything", {"rule.groups": "keyword"}, time_range_expr=None, focus="general"
        )
        sent = ctx.llm.calls[0]["messages"][0]["content"]
        self.assertIn("rule_group", sent)
        # src_ip's real field is absent, so the key must not be offered
        self.assertNotIn("src_ip ->", sent)

    def test_the_system_prompt_keeps_its_json_schema_intact(self):
        """A literal `{` in the prompt must not be eaten by str.format - the
        planner uses .replace() precisely because the prompt embeds JSON."""
        ctx = make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN))
        planner.plan_dashboard(ctx, "ssh", SCHEMA, time_range_expr="now-7d", focus="general")
        system = ctx.llm.calls[0]["system"]
        self.assertIn('"title":', system)
        self.assertIn('"panels":', system)
        self.assertNotIn("{fields}", system)

    def test_every_filter_being_unusable_fails_the_plan_instead_of_lying(self):
        """Silently dropping the filter would hand back a generic dashboard
        that ignores what the user asked - worse than saying it failed."""
        plan_bad = {
            "title": "t",
            "filters": [{"field": "nope", "op": "term", "values": ["x"]}],
            "panels": [],
        }
        plan = planner.plan_dashboard(
            make_ctx(StubLLM(plan_bad)), "x", SCHEMA, time_range_expr=None, focus="general"
        )
        self.assertFalse(plan["ok"])
        self.assertIn("unusable", plan["error"])

    def test_an_llm_outage_is_reported_not_raised(self):
        class Boom:
            def chat_text(self, **kw):
                raise RuntimeError("gateway 503")

        plan = planner.plan_dashboard(
            make_ctx(Boom()), "x", SCHEMA, time_range_expr=None, focus="general"
        )
        self.assertFalse(plan["ok"])
        self.assertIn("gateway 503", plan["error"])

    def test_a_non_json_reply_fails_cleanly(self):
        plan = planner.plan_dashboard(
            make_ctx(StubLLM("I'm sorry, I can't help with that.")),
            "x",
            SCHEMA,
            time_range_expr=None,
            focus="general",
        )
        self.assertFalse(plan["ok"])
        self.assertIn("JSON", plan["error"])

    def test_a_fenced_reply_still_parses(self):
        fenced = "```json\n" + json.dumps(PRIVATE_TO_PRIVATE_PLAN) + "\n```"
        plan = planner.plan_dashboard(
            make_ctx(StubLLM(fenced)), "x", SCHEMA, time_range_expr=None, focus="general"
        )
        self.assertTrue(plan["ok"])

    def test_empty_intent_is_rejected_without_calling_the_model(self):
        ctx = make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN))
        plan = planner.plan_dashboard(ctx, "  ", SCHEMA, time_range_expr=None, focus="general")
        self.assertFalse(plan["ok"])
        self.assertEqual(ctx.llm.calls, [])


# --------------------------------------------------------------------------- #
class TestDesignDetectionDashboardWithIntent(unittest.TestCase):
    def _run(self, ctx, **kw):
        params = {"title": "T", "reason": "r", "time_range": "-7d", **kw}
        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-1"):
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(ctx, **params)
        return cm.exception.proposed_action

    def test_intent_changes_the_panels_not_just_the_prose(self):
        """THE regression: the same request used to yield the generic set."""
        proposed = self._run(
            make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN)),
            intent="ssh failed login private to private ip",
        )
        slugs = [v["slug"] for v in proposed["generated_config"]["visualizations"]]
        self.assertIn("breakdown_src_ip", slugs)
        self.assertIn("breakdown_user", slugs)
        self.assertNotIn("top_groups", slugs)  # generic preset panel, not planned

    def test_the_planned_filter_reaches_every_saved_visualization(self):
        proposed = self._run(
            make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN)), intent="ssh private to private"
        )
        blob = json.dumps(proposed["generated_config"]["saved_objects"])
        self.assertIn("data.srcip", blob)
        self.assertIn("10.0.0.0/8", blob)

    def test_the_intent_is_in_the_payload_so_execution_replans_identically(self):
        proposed = self._run(make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN)), intent="ssh private")
        self.assertEqual(proposed["payload"]["intent"], "ssh private")
        # and the original title is preserved in the payload (generated_config
        # carries the planner's better title)
        self.assertEqual(proposed["payload"]["title"], "T")

    def test_the_filter_survives_into_the_saved_visualization(self):
        """THE bug that made the whole feature cosmetic.

        The filter reached the size-0 verification query, so the evidence panel
        showed real per-panel counts - but `_filters()` only understood `term`
        and `range`, so `match_phrase` and the CIDR `bool.should` were silently
        dropped from the saved object. The created dashboard would have
        rendered every alert in the index while claiming to be filtered."""
        proposed = self._run(
            make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN)), intent="ssh private to private"
        )
        for obj in proposed["generated_config"]["saved_objects"]:
            if obj["type"] != "visualization":
                continue
            ss = obj["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"]
            entries = json.loads(ss)["filter"]
            self.assertTrue(entries, f"{obj['id']} has no filters at all")
            blob = json.dumps(entries)
            # the SSH group filter AND both private-range ORs are present
            self.assertIn("rule.groups", blob, obj["id"])
            self.assertIn("10.0.0.0/8", blob, obj["id"])
            self.assertIn("minimum_should_match", blob, obj["id"])

    def test_no_filter_clause_is_ever_silently_dropped(self):
        from tools.dashboard.osd_objects import _filters

        clauses = [
            {"term": {"rule.groups": "ssh"}},
            {"terms": {"rule.id": ["5716", "5760"]}},
            {"match_phrase": {"rule.description": "failed login"}},
            {"range": {"timestamp": {"gte": "now-7d"}}},
            {
                "bool": {
                    "should": [{"range": {"data.srcip": "10.0.0.0/8"}}],
                    "minimum_should_match": 1,
                }
            },
            {"exists": {"field": "data.user"}},  # not specially handled
        ]
        rendered = _filters({"bool": {"filter": clauses}}, "idx-1")
        self.assertEqual(len(rendered), len(clauses))
        for entry in rendered:
            self.assertIn("meta", entry)
            # a range filter uses `range`; everything else carries `query`
            self.assertTrue("query" in entry or "range" in entry, entry)

    def test_evidence_records_the_intent_and_the_filter(self):
        proposed = self._run(make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN)), intent="ssh private")
        ev = proposed["validation"]["evidence"]
        self.assertEqual(ev["planned_from_intent"], "ssh private")
        self.assertTrue(ev["intent_filter"])

    def test_an_intent_filter_matching_nothing_is_a_validation_error(self):
        """Seven empty panels must not be proposed as if they were fine."""
        proposed = self._run(
            make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN), matched=0), intent="ssh private"
        )
        self.assertFalse(proposed["validation"]["valid"])
        self.assertTrue(
            any("matched 0 alerts" in (e or "") for e in proposed["validation"]["errors"])
        )
        self.assertTrue(proposed["validation"]["evidence"]["intent_filter_matched_nothing"])

    def test_a_planner_outage_fails_loudly_instead_of_proposing_the_template(self):
        """A request the planner couldn't handle must not come back as the generic
        preset dressed up as success - that was the "it always makes the same
        default dashboard" report."""

        class Boom:
            def chat_text(self, **kw):
                raise RuntimeError("no model")

        with self.assertRaises(ToolError) as cm:
            self._run(make_ctx(Boom()), intent="ssh private", focus="ssh")
        msg = str(cm.exception)
        self.assertIn("Couldn't plan a dashboard for 'ssh private'", msg)
        self.assertIn("no model", msg)
        self.assertIn("Nothing was proposed", msg)

    def test_intent_is_taken_from_reason_when_the_agent_omits_it(self):
        request = "ssh failed logins private to private"
        proposed = self._run(make_ctx(StubLLM(PRIVATE_TO_PRIVATE_PLAN)), reason=request)
        ev = proposed["validation"]["evidence"]
        self.assertEqual(ev["planned_from_intent"], request)
        self.assertEqual(ev["intent_source"], "reason")
        self.assertTrue(ev["intent_filter"])

    def test_a_one_word_reason_is_not_treated_as_a_request(self):
        class NeverCalled:
            def chat_text(self, **kw):
                raise AssertionError("planner must not run for a trivial reason")

        proposed = self._run(make_ctx(NeverCalled()), reason="needed", focus="ssh")
        self.assertNotIn("planned_from_intent", proposed["validation"]["evidence"])

    def test_the_ui_preset_reason_still_gets_the_preset(self):
        class NeverCalled:
            def chat_text(self, **kw):
                raise AssertionError("planner must not run for the preset path")

        proposed = self._run(make_ctx(NeverCalled()), reason="Dashboard builder (ssh)", focus="ssh")
        self.assertNotIn("planned_from_intent", proposed["validation"]["evidence"])

    def test_no_intent_still_uses_the_preset_unchanged(self):
        """Back-compat: the old enum path must behave exactly as before."""
        proposed = self._run(make_ctx(StubLLM("unused")), focus="web")
        slugs = [v["slug"] for v in proposed["generated_config"]["visualizations"]]
        self.assertIn("top_src_ips", slugs)
        self.assertNotIn("intent", proposed["payload"])

    def test_an_invalid_focus_is_still_rejected(self):
        with self.assertRaises(ToolError):
            DesignDetectionDashboard().run(
                make_ctx(StubLLM({})), title="t", focus="windows", reason="r"
            )


# --------------------------------------------------------------------------- #
VALID_DRAFT = {
    "rule_xml": (
        '<rule id="100300" level="10">\n'
        '  <match type="pcre2">Failed password for invalid user</match>\n'
        "  <description>Repeated failed SSH logins from one internal source</description>\n"
        "  <group>authentication_failures,</group>\n"
        "</rule>"
    ),
    "positive_samples": [
        "Nov 21 09:41:01 db01 sshd[2710]: Failed password for invalid user root from 10.10.4.22 port 1 ssh2",
        "Nov 21 09:41:04 db01 sshd[2710]: Failed password for invalid user admin from 10.10.4.22 port 2 ssh2",
    ],
    "negative_samples": [],
    "log_format": "syslog",
    "notes": "Self-contained rule on the sshd failure line.",
}


class TestDraftWazuhRule(unittest.TestCase):
    def test_an_intent_becomes_a_reviewable_draft(self):
        ctx = make_ctx(StubLLM(VALID_DRAFT))
        out = DraftWazuhRule().run(ctx, intent="ssh failed login from private to private ip")
        self.assertEqual(out["status"], "draft")
        self.assertIn("<rule", out["rule_xml"])
        self.assertEqual(len(out["positive_samples"]), 2)
        self.assertTrue(out["static_validation"]["valid"])
        self.assertEqual(out["static_validation"]["rule_id"], 100300)

    def test_negatives_are_optional_and_absent_is_not_an_error(self):
        out = DraftWazuhRule().run(make_ctx(StubLLM(VALID_DRAFT)), intent="ssh")
        self.assertEqual(out["negative_samples"], [])
        self.assertTrue(out["negatives_optional"])

    def test_negatives_are_returned_when_the_model_has_a_real_near_miss(self):
        draft = dict(
            VALID_DRAFT,
            negative_samples=["Nov 21 09:41:09 db01 sshd[2710]: Accepted password for admin"],
        )
        out = DraftWazuhRule().run(make_ctx(StubLLM(draft)), intent="ssh failures")
        self.assertEqual(len(out["negative_samples"]), 1)

    def test_a_draft_with_no_positive_samples_is_refused_not_proposed(self):
        draft = dict(VALID_DRAFT, positive_samples=[])
        with self.assertRaises(ToolError) as cm:
            DraftWazuhRule().run(make_ctx(StubLLM(draft)), intent="ssh")
        self.assertIn("positive sample", str(cm.exception))

    def test_a_draft_with_no_rule_xml_is_refused(self):
        with self.assertRaises(ToolError) as cm:
            DraftWazuhRule().run(make_ctx(StubLLM({"positive_samples": ["x"]})), intent="ssh")
        self.assertIn("no <rule> XML", str(cm.exception))

    def test_an_invalid_draft_is_flagged_rather_than_hidden(self):
        bad = dict(
            VALID_DRAFT, rule_xml='<rule id="100300" level="99"><description>d</description></rule>'
        )
        out = DraftWazuhRule().run(make_ctx(StubLLM(bad)), intent="ssh")
        self.assertFalse(out["static_validation"]["valid"])
        self.assertTrue(out["static_validation"]["errors"])

    def test_the_drafter_never_proposes_anything(self):
        """READ permission + no approve_or_raise: a hallucinated rule must not
        be able to create a pending approval on its own."""
        self.assertEqual(DraftWazuhRule.permission, Permission.READ)
        ctx = make_ctx(StubLLM(VALID_DRAFT))
        with mock.patch("approvals.create_proposal") as create:
            DraftWazuhRule().run(ctx, intent="ssh")
        create.assert_not_called()

    def test_a_multiline_sample_is_flattened_to_one_log_line(self):
        draft = dict(VALID_DRAFT, positive_samples=["line one\nline two", "line one line two"])
        out = DraftWazuhRule().run(make_ctx(StubLLM(draft)), intent="ssh")
        # collapsed to a single line, and the duplicate removed
        self.assertEqual(out["positive_samples"], ["line one line two"])

    def test_the_log_format_reaches_the_model(self):
        ctx = make_ctx(StubLLM(VALID_DRAFT))
        DraftWazuhRule().run(ctx, intent="ssh", log_format="json")
        self.assertIn("json", ctx.llm.calls[0]["messages"][0]["content"])

    def test_an_llm_outage_surfaces_as_a_clean_tool_error(self):
        class Boom:
            def chat_text(self, **kw):
                raise RuntimeError("gateway down")

        with self.assertRaises(ToolError) as cm:
            DraftWazuhRule().run(make_ctx(Boom()), intent="ssh")
        self.assertIn("gateway down", str(cm.exception))

    def test_xml_wrapped_in_prose_is_still_extracted(self):
        draft = dict(
            VALID_DRAFT, rule_xml="Here you go:\n" + VALID_DRAFT["rule_xml"] + "\nHope that helps!"
        )
        out = DraftWazuhRule().run(make_ctx(StubLLM(draft)), intent="ssh")
        self.assertTrue(out["rule_xml"].startswith("<rule"))
        self.assertTrue(out["rule_xml"].endswith("</rule>"))


# --------------------------------------------------------------------------- #
class TestRegistrySurfacesValidationErrors(unittest.TestCase):
    """The "Internal server error." on the Rule builder.

    registry.execute() runs PROPOSE tools in a dry-run to collect their
    proposal. Their own validation (static check, "id already exists", "needs a
    positive sample") raises ToolError from INSIDE that dry-run, and only
    ApprovalRequired/PermissionDenied were caught - so the ToolError escaped
    execute() and surfaced as an opaque HTTP 500."""

    def test_a_tool_error_in_the_dry_run_is_returned_not_raised(self):
        from tools import registry

        class Boom(registry.BaseWazuhTool if hasattr(registry, "BaseWazuhTool") else object):
            pass

        tool = mock.MagicMock()
        tool.name = "boom_tool"
        tool.permission = Permission.PROPOSE
        tool.validate.return_value = {"a": 1}
        tool.redact.return_value = {"a": 1}
        tool.run.side_effect = ToolError("Rule failed static validation:\n- id must be >= 100000")
        with mock.patch.dict(registry._TOOL_INSTANCES, {"boom_tool": tool}):
            with mock.patch.object(registry.audit, "audit_log"):
                out = registry.execute(
                    ToolContext(wazuh=mock.MagicMock(), indexer=mock.MagicMock()),
                    "boom_tool",
                    {},
                )
        self.assertEqual(out["status"], "error")
        self.assertIn("id must be >= 100000", out["error"])

    def test_approval_required_still_produces_a_proposal(self):
        """Regression guard for the new except clause - ApprovalRequired is a
        ToolError subclass and must keep its own meaning."""
        from tools import registry

        proposed = {"action": "do_thing", "reason": "r", "payload": {}, "permission": "propose"}
        tool = mock.MagicMock()
        tool.name = "propose_tool"
        tool.permission = Permission.PROPOSE
        tool.validate.return_value = {}
        tool.redact.return_value = {}
        tool.run.side_effect = ApprovalRequired(proposed)
        with mock.patch.dict(registry._TOOL_INSTANCES, {"propose_tool": tool}):
            with mock.patch.object(registry, "_store_proposal", return_value={"id": "appr-1"}):
                with mock.patch.object(registry.audit, "audit_log"):
                    out = registry.execute(
                        ToolContext(wazuh=mock.MagicMock(), indexer=mock.MagicMock()),
                        "propose_tool",
                        {},
                    )
        self.assertEqual(out["status"], "approval_required")
        self.assertEqual(out["proposal"]["id"], "appr-1")

    def test_permission_denied_still_propagates(self):
        """PermissionDenied is also a ToolError subclass; it must NOT be
        downgraded into a plain error string."""
        from tools import registry
        from tools.base import PermissionDenied

        tool = mock.MagicMock()
        tool.name = "denied_tool"
        tool.permission = Permission.PROPOSE
        tool.validate.return_value = {}
        tool.redact.return_value = {}
        tool.run.side_effect = PermissionDenied("nope")
        with mock.patch.dict(registry._TOOL_INSTANCES, {"denied_tool": tool}):
            with self.assertRaises(PermissionDenied):
                registry.execute(
                    ToolContext(wazuh=mock.MagicMock(), indexer=mock.MagicMock()),
                    "denied_tool",
                    {},
                )


class TestEngineerToolRoute(unittest.TestCase):
    """Over HTTP, as the builder UIs actually call it."""

    def setUp(self):
        from config import cfg
        from dashboard import app

        app.config["TESTING"] = True
        self.client = app.test_client()
        self._orig = (
            cfg.DASHBOARD_TOKEN,
            cfg.DASHBOARD_USERS,
            cfg.APPROVALS_PATH,
            cfg.AUDIT_LOG_PATH,
        )
        cfg.DASHBOARD_TOKEN = ""
        cfg.DASHBOARD_USERS = "alice:tokA:admin"
        # keep this off the developer's real data/ files
        import tempfile

        self._tmp = tempfile.mkdtemp(prefix="builder-intent-")
        cfg.APPROVALS_PATH = f"{self._tmp}/approvals.json"
        cfg.AUDIT_LOG_PATH = f"{self._tmp}/audit.jsonl"

    def tearDown(self):
        import shutil

        from config import cfg

        (cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS, cfg.APPROVALS_PATH, cfg.AUDIT_LOG_PATH) = (
            self._orig
        )
        shutil.rmtree(self._tmp, ignore_errors=True)

    def _post(self, tool, params):
        return self.client.post(
            "/api/engineer/tool",
            json={"tool": tool, "params": params},
            headers={"Authorization": "Bearer tokA"},
        )

    def test_a_validation_failure_is_a_readable_400_ish_not_an_internal_error(self):
        """The screenshot: "error: Internal server error." on the Rule builder.

        develop_wazuh_rule with a rule whose id is already taken raises
        ToolError from inside registry's dry-run. Over HTTP that used to
        escape as a 500 with the message replaced by a generic string."""
        with mock.patch("tools.detection.detection_engine._rule_exists", return_value=True):
            r = self._post(
                "develop_wazuh_rule",
                {
                    "rule_xml": '<rule id="100900" level="5"><description>d</description></rule>',
                    "positive_samples": ["Nov 21 09:41:01 h sshd[1]: Failed password"],
                    "reason": "r",
                },
            )
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertEqual(body["status"], "error")
        self.assertNotEqual(body["error"], "Internal server error.")
        self.assertIn("already exists", body["error"])

    def test_static_validation_failure_is_reported_verbatim(self):
        r = self._post(
            "develop_wazuh_rule",
            {
                "rule_xml": "<rule id='1' level='99'></rule>",
                "positive_samples": ["some log line"],
                "reason": "r",
            },
        )
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertEqual(body["status"], "error")
        self.assertIn("static validation", body["error"])

    def test_the_drafter_is_reachable_and_returns_a_draft(self):
        r = self._post(
            "draft_wazuh_rule", {"intent": "ssh failed login from private to private ip"}
        )
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertEqual(body["status"], "ok")
        self.assertIn("<rule", body["result"]["rule_xml"])
        self.assertTrue(body["result"]["positive_samples"])
        # READ tool: no proposal, nothing to approve
        self.assertNotIn("proposal", body)


# --------------------------------------------------------------------------- #
class TestTheBuildersAreWiredUp(unittest.TestCase):
    def test_the_drafter_is_registered_as_a_tool(self):
        from tools.registry import build_tools_meta

        names = {t["name"] for t in build_tools_meta()}
        self.assertIn("draft_wazuh_rule", names)
        self.assertIn("design_detection_dashboard", names)

    def test_the_drafter_metadata_is_llm_shaped(self):
        from tools.registry import get_tool

        meta = get_tool("draft_wazuh_rule").meta()
        self.assertEqual(meta["permission"], "read")
        self.assertIn("intent", meta["input_schema"]["properties"])
        self.assertEqual(meta["input_schema"]["required"], ["intent"])

    def test_the_dashboard_tool_advertises_intent(self):
        from tools.registry import get_tool

        schema = get_tool("design_detection_dashboard").meta()["input_schema"]
        self.assertIn("intent", schema["properties"])
        # intent must stay optional - the preset path is still valid
        self.assertNotIn("intent", schema["required"])


if __name__ == "__main__":
    unittest.main()


class TestPlannerVocabulary(unittest.TestCase):
    """Common requests must be expressible (audit 2026-09-28: URL / status /
    country / MITRE / Windows asks were silently dropped to generic panels)."""

    SCHEMA = {
        "timestamp": "date",
        "rule.groups": "keyword",
        "data.url": "keyword",
        "data.id": "keyword",
        "GeoLocation.country_name": "keyword",
        "rule.mitre.technique": "keyword",
        "rule.mitre.tactic": "keyword",
        "data.win.system.eventID": "keyword",
        "data.srcip": "ip",
    }

    def test_new_keys_and_aliases_resolve(self):
        from tools.dashboard import planner

        for raw, key in [
            ("url", "url"),
            ("Status", "http_status"),
            ("country", "country"),
            ("MITRE", "mitre_technique"),
            ("tactic", "mitre_tactic"),
            ("event id", "win_event_id"),
            ("source ip", "src_ip"),
        ]:
            self.assertEqual(planner._clean_field(raw), key, raw)

    def test_requested_breakdowns_survive(self):
        from tools.dashboard import planner

        raw = [
            {"kind": "breakdown", "field": f}
            for f in ("url", "status", "country", "mitre", "event_id")
        ]
        panels, dropped = planner.plan_panels(raw, self.SCHEMA, "general", "now-7d", [])
        titles = [p["title"] for p in panels]
        self.assertEqual(dropped, [])
        for t in (
            "Top URLs",
            "Top HTTP status codes",
            "Top source countries",
            "Top MITRE techniques",
            "Top Windows event IDs",
        ):
            self.assertTrue(any(x.startswith(t) for x in titles), (t, titles))

    def test_keys_whose_field_is_missing_are_still_dropped(self):
        from tools.dashboard import planner

        panels, dropped = planner.plan_panels(
            [{"kind": "breakdown", "field": "cve"}], self.SCHEMA, "general", "now-7d", []
        )
        self.assertTrue(dropped)
        self.assertFalse(any("CVE" in p["title"] for p in panels))

    def test_titles_do_not_claim_the_generic_preset(self):
        from tools.dashboard import planner

        f = [{"term": {"rule.groups": "web"}}]
        panels, _ = planner.plan_panels(
            [{"kind": "unique", "field": "src_ip"}], self.SCHEMA, "general", "now-7d", f
        )
        titles = [p["title"] for p in panels]
        self.assertEqual(titles[0], "Matching alerts")
        self.assertIn("Unique source IPs", titles)
        self.assertFalse(any("general" in t for t in titles))

    def test_the_engineer_is_pointed_at_the_designing_tool(self):
        from agent import prompt_profile
        from agent.soc_engineer import SYSTEM_PROMPT, SYSTEM_PROMPT_DEFAULT

        # The Wazuh tool-level routing (design_detection_dashboard / `intent` /
        # "ALREADY exist") is specific to the default engineer brief. The
        # "detailed" profile is a platform-level brief and deliberately does not
        # restate it, so this only applies to the prompt actually in use.
        if SYSTEM_PROMPT is not SYSTEM_PROMPT_DEFAULT:
            self.skipTest(
                f"Wazuh tool routing lives in the default brief only "
                f"(active profile: {prompt_profile.active_profile()})"
            )

        self.assertIn("design_detection_dashboard", SYSTEM_PROMPT)
        self.assertIn("`intent`", SYSTEM_PROMPT)
        self.assertIn("ALREADY exist", SYSTEM_PROMPT)
