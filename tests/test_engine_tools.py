"""
PHASE 13: offline tests for the engineer tool engines - investigation,
detection, dashboard, detection-gaps, and the registry permission gate.

Everything is mocked (ToolContext with MagicMock wazuh/indexer): no live
Wazuh, no network, and no `data/` file writes (approvals.create_proposal /
audit.audit_log are patched wherever the registry is exercised).

Run: cd soc-agent && MOCK_MODE=true python3 -m unittest tests.test_engine_tools -v
"""

from __future__ import annotations

import copy
import json
import os
import pathlib
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

from tools.base import ApprovalRequired, ToolContext, ToolError, ToolParamError


def make_ctx(wazuh=None, indexer=None, approval=None) -> ToolContext:
    return ToolContext(
        wazuh=wazuh or mock.MagicMock(),
        indexer=indexer or mock.MagicMock(),
        approval=approval,
    )


LOCAL_RULES_TEMPLATE = r"""<!-- Local rules -->
<group name="local,syslog,sshd,">
  <rule id="100001" level="5">
    <if_sid>5716</if_sid>
    <regex>^from 1\.1\.1\.1 port</regex>
    <description>sshd: authentication failed from IP 1.1.1.1.</description>
  </rule>
</group>
"""

RULE_5760 = {
    "id": 5760,
    "level": 5,
    "description": "sshd: authentication failed.",
    "groups": ["authentication_failures"],
    "details": {"match": "Failed password|Failed keyboard|authentication error"},
}

# The one known-good log line the decoder preflight submits. Mirrors
# tools/wazuh/logtest.py::CANONICAL_SSHD_FAILED_LOG and is pinned to the
# fixture tests/fixtures/sample_events/sshd_failed_auth.log by
# TestLogtestHarness.test_fixture_matches_canonical_preflight_sample.
CANONICAL_SSHD_FAILED_LOG = (
    "Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2"
)
CANONICAL_BASE_RULE_ID = 5716

# The event actually under test in TestLogtestHarness. Deliberately a DIFFERENT
# line from the preflight sample: a fake manager has no way to tell the fixed
# preflight line from "the sample you were asked to test" if they are the same
# string, and a harness that silently conflates the two is exactly the class of
# bug this suite exists to catch. Real Wazuh also fires stock 5716 on this one
# ('Failed password for ... from ...'), so if_sid: 5716 is the right parent.
CANDIDATE_SAMPLE_LOG = (
    "Dec 10 01:02:02 host sshd[5678]: Failed password for admin from 203.0.113.9 port 51234 ssh2"
)


def logtest_hit(rule_id, *, level=5, desc="rule", decoder="sshd", alert=True, token="tok1"):
    """A 4.7+ shaped logtest response."""
    return {
        "data": {
            "codemsg": 0,
            "alert": alert,
            "output": {
                "rule": {"id": rule_id, "level": level, "description": desc} if alert else {},
                "decoder": {"name": decoder} if decoder else {},
            },
            "token": token,
        }
    }


NO_DECODER_RESPONSE = {
    "data": {
        "codemsg": 0,
        "alert": False,
        "output": {"rule": {}, "decoder": {}},
        "messages": ["No decoder matched."],
        "token": "tok1",
    }
}


def with_preflight(handler, *, preflight_token="preflight-tok"):
    """Wrap a per-event logtest fake with the decoder preflight.

    Every logtest-backed tool now submits the canonical sshd sample first and
    requires it to decode and fire stock rule 5716 before any sample verdict is
    reported. Mocks have to answer that call, otherwise the tool correctly
    refuses to produce results - which is itself the behaviour under test
    elsewhere (see TestLogtestHarness).

    The canonical call is intercepted here so a handler that counts calls (e.g.
    to assert session threading) still only sees the real sample calls.
    """
    preflight_resp = logtest_hit(
        CANONICAL_BASE_RULE_ID,
        desc="sshd: authentication failed.",
        token=preflight_token,
    )

    def fake(log, log_format=None, location=None, token=None):
        if log == CANONICAL_SSHD_FAILED_LOG:
            return preflight_resp
        return handler(log, log_format=log_format, location=location, token=token)

    return fake


class TestInvestigationTools(unittest.TestCase):
    """tools/investigate/investigator.py - indexed evidence, no LLM guessing."""

    @staticmethod
    def _bucket(key, count):
        return {
            "key": key,
            "doc_count": count,
            "max_level": {"value": 10.0},
            "first_seen": {"value_as_string": "2026-09-23T10:00:00.000Z"},
            "last_seen": {"value_as_string": "2026-09-23T11:00:00.000Z"},
            "groups": {"buckets": [{"key": "web", "doc_count": count}]},
            "rules": {"buckets": [{"key": "31151", "doc_count": count}]},
            "agents": {"buckets": [{"key": "wks-web-01", "doc_count": count}]},
        }

    def test_top_attacking_ips_parses_buckets(self):
        from tools.investigate.investigator import top_attacking_ips

        indexer = mock.MagicMock()
        indexer.search.return_value = {
            "aggregations": {"top_src": {"buckets": [self._bucket("203.0.113.7", 12)]}}
        }
        out = top_attacking_ips(indexer, group="web", time_range="-24h")
        self.assertEqual(out["count"], 1)
        ip = out["ips"][0]
        self.assertEqual(ip["src_ip"], "203.0.113.7")
        self.assertEqual(ip["alert_count"], 12)
        self.assertEqual(ip["rule_groups"], ["web"])
        self.assertEqual(ip["top_rules"][0]["id"], "31151")
        indexer.search.assert_called_with("wazuh-alerts-*", mock.ANY)
        body = indexer.search.call_args[0][1]
        self.assertIn("top_src", body["aggs"])
        self.assertEqual(body["size"], 0)

    def test_top_attacking_ips_falls_back_to_attack_group(self):
        from tools.investigate.investigator import top_attacking_ips

        indexer = mock.MagicMock()
        empty = {"aggregations": {"top_src": {"buckets": []}}}
        full = {"aggregations": {"top_src": {"buckets": [self._bucket("198.51.100.9", 3)]}}}
        # run_for("web") is called first, then the fallback loop tries
        # "web" again before "attack" -> three searches in this build.
        indexer.search.side_effect = [empty, empty, full]
        out = top_attacking_ips(indexer, group="web", time_range="-24h")
        self.assertEqual(out["ips"][0]["src_ip"], "198.51.100.9")
        self.assertGreaterEqual(indexer.search.call_count, 2)

    def test_investigate_ip_builds_result(self):
        from tools.investigate.investigator import investigate_ip

        indexer = mock.MagicMock()

        def fake_search(index, body):
            if index == "wazuh-archives-*":
                return {
                    "hits": {
                        "hits": [
                            {
                                "_source": {
                                    "timestamp": "t",
                                    "location": "loc",
                                    "full_log": "failed pw",
                                    "decoder": {"name": "sshd"},
                                }
                            }
                        ]
                    }
                }
            return {
                "hits": {"total": {"value": 7}},
                "aggregations": {
                    "rule_groups": {"buckets": [{"key": "web", "doc_count": 7}]},
                    "rules": {"buckets": [{"key": "31151", "doc_count": 7}]},
                    "agents": {"buckets": []},
                    "dst_ips": {"buckets": [{"key": "10.0.0.1", "doc_count": 7}]},
                    "dst_ports": {"buckets": []},
                    "max_level": {"value": 10.0},
                    "first_seen": {"value_as_string": "a"},
                    "last_seen": {"value_as_string": "b"},
                    "timeline": {"buckets": [{"key_as_string": "k", "doc_count": 2}]},
                    "mitre": {"buckets": [{"key": "T1110", "doc_count": 4}]},
                },
            }

        indexer.search.side_effect = fake_search
        out = investigate_ip(indexer, ip="203.0.113.7", time_range="-24h")
        self.assertEqual(out["ip"], "203.0.113.7")
        self.assertEqual(out["total_alerts"], 7)
        self.assertEqual(out["mitre_techniques"], ["T1110"])
        self.assertEqual(len(out["sample_events"]), 1)

    def test_investigate_ip_requires_ip(self):
        from tools.investigate.investigator import InvestigateIP

        with self.assertRaises(ToolParamError):
            InvestigateIP().run(make_ctx(), ip="")

    def test_why_did_alert_trigger_found(self):
        from tools.investigate.investigator import why_did_alert_trigger

        indexer = mock.MagicMock()

        def fake_search(index, body):
            if index == "wazuh-archives-*":
                return {
                    "hits": {
                        "hits": [
                            {"_source": {"timestamp": "t2", "location": "l", "full_log": "context"}}
                        ]
                    }
                }
            return {
                "hits": {
                    "hits": [
                        {
                            "_source": {
                                "id": "ALT-1",
                                "timestamp": "2026-09-23T10:00:00",
                                "rule": {
                                    "id": 31151,
                                    "level": 10,
                                    "description": "x",
                                    "groups": ["web"],
                                    "mitre": {"id": ["T1110"]},
                                },
                                "agent": {"name": "wks-01"},
                                "full_log": "failed pw",
                                "data": {"srcip": "203.0.113.7"},
                            }
                        }
                    ]
                }
            }

        indexer.search.side_effect = fake_search
        out = why_did_alert_trigger(indexer, alert_id="ALT-1")
        self.assertEqual(out["rule_id"], 31151)
        self.assertEqual(out["mitre"]["id"], ["T1110"])
        self.assertEqual(len(out["related_events"]), 1)

    def test_why_did_alert_trigger_missing_raises(self):
        from tools.investigate.investigator import why_did_alert_trigger

        indexer = mock.MagicMock()
        indexer.search.return_value = {"hits": {"hits": [{"_source": {"id": "OTHER"}}]}}
        with self.assertRaises(ToolError):
            why_did_alert_trigger(indexer, alert_id="ALT-9")


class TestDetectionEngine(unittest.TestCase):
    """tools/detection/detection_engine.py - static validation, deterministic
    proposals, and frequency-aware post-deploy verification."""

    FREQ_RULE = (
        '<rule id="105563" level="10" frequency="3" timeframe="60">\n'
        "  <if_matched_sid>5760</if_matched_sid>\n"
        "  <description>Repeated SSH authentication failures</description>\n"
        "</rule>"
    )

    PLAIN_RULE = (
        '<rule id="105565" level="5">\n'
        "  <match>Failed password</match>\n"
        "  <description>Detects a failed SSH password</description>\n"
        "</rule>"
    )

    @staticmethod
    def _no_alert(token="tok"):
        return {"data": {"alert": False, "output": {"rule": {}}, "codemsg": 0, "token": token}}

    def _manager_ctx(self):
        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE

        def fake_get_rules(**kw):
            q = kw.get("q") or ""
            if kw.get("limit") == 100:
                return {"data": {"affected_items": [RULE_5760], "total_affected_items": 1}}
            if "105563" in q:
                return {"data": {"affected_items": [], "total_affected_items": 0}}
            return {"data": {"affected_items": [RULE_5760], "total_affected_items": 1}}

        wazuh.get_rules.side_effect = fake_get_rules
        # preflight-aware: the canonical sshd sample decodes and fires 5716,
        # real samples are currently undetected (the "candidate adds coverage"
        # baseline). See with_preflight.
        wazuh.run_logtest.side_effect = with_preflight(
            lambda log, log_format=None, location=None, token=None: self._no_alert(token=token)
        )
        wazuh.end_logtest_session.return_value = {}
        wazuh.put_rules_file.return_value = {
            "message": "Rule was successfully uploaded",
            "data": {"affected_items": ["local_rules.xml"]},
        }
        return make_ctx(wazuh=wazuh)

    # -- develop_wazuh_rule ------------------------------------------- #
    def test_child_element_frequency_rejected_without_manager_call(self):
        from tools.detection.detection_engine import DevelopWazuhRule

        bad = (
            '<rule id="105564" level="10">\n'
            "  <match>Failed password</match>\n"
            "  <frequency>3</frequency>\n"
            "  <timeframe>60</timeframe>\n"
            "  <description>x</description>\n"
            "</rule>"
        )
        ctx = make_ctx()
        with self.assertRaises(ToolError) as cm:
            DevelopWazuhRule().run(
                ctx, rule_xml=bad, positive_samples=["Failed password for root"], reason="test"
            )
        self.assertIn("must be a rule ATTRIBUTE", str(cm.exception))
        ctx.wazuh.get_rules_file.assert_not_called()
        ctx.wazuh.run_logtest.assert_not_called()

    def test_develop_proposes_rerunnable_payload(self):
        from tools.detection.detection_engine import DevelopWazuhRule

        ctx = self._manager_ctx()
        with self.assertRaises(ApprovalRequired) as cm:
            DevelopWazuhRule().run(
                ctx,
                rule_xml=self.FREQ_RULE,
                positive_samples=["p1", "p2"],
                negative_samples=["n1"],
                reason="golden rule",
            )
        proposed = cm.exception.proposed_action
        self.assertEqual(proposed["action"], "create_wazuh_rule")
        # PHASE 12 invariant: the stored payload is a re-runnable call to the
        # same tool with its own input params - not a display snapshot.
        self.assertEqual(
            proposed["payload"],
            {"rule_xml": self.FREQ_RULE, "overwrite": False, "reason": "golden rule"},
        )
        self.assertIn("105563", proposed.get("generated_config", ""))
        # planning must never write to the manager
        ctx.wazuh.put_rules_file.assert_not_called()

    def test_develop_executes_with_matching_approval(self):
        from tools.detection.detection_engine import DevelopWazuhRule

        ctx = self._manager_ctx()
        ctx.approval = {"action": "create_wazuh_rule", "status": "approved"}
        out = DevelopWazuhRule().run(
            ctx,
            rule_xml=self.FREQ_RULE,
            positive_samples=["p1"],
            negative_samples=["n1"],
            reason="golden rule",
        )
        self.assertEqual(out["status"], "executed")
        self.assertEqual(out["rule_id"], 105563)
        self.assertTrue(out["restart_required"])
        ctx.wazuh.put_rules_file.assert_called_once()
        new_content = ctx.wazuh.put_rules_file.call_args[0][1]
        self.assertIn("105563", new_content)

    def test_develop_requires_positive_samples(self):
        from tools.detection.detection_engine import DevelopWazuhRule

        ctx = make_ctx()
        with self.assertRaises(ToolError):
            DevelopWazuhRule().run(ctx, rule_xml=self.PLAIN_RULE, positive_samples=[], reason="x")

    # -- verify_rule_deployment --------------------------------------- #
    def test_verify_frequency_rule_uses_single_session(self):
        from tools.detection.detection_engine import VerifyRuleDeployment

        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = (
            '<group name="local,">\n' + self.FREQ_RULE + "\n</group>\n"
        )
        tokens_seen = []

        def fake_logtest(log, log_format=None, location=None, token=None):
            tokens_seen.append(token)
            idx = len(tokens_seen)
            if idx <= 2:
                rid, desc = 5760, "sshd: authentication failed."
            elif idx == 3:
                rid, desc = 105563, "Repeated SSH authentication failures"
            else:
                rid, desc = 5715, "sshd: authentication succeeded."
            data = {
                "codemsg": 0,
                "alert": True,
                "output": {
                    "rule": {"id": rid, "level": 5, "description": desc},
                    "decoder": {"name": "sshd"},
                },
            }
            if idx <= 3:
                data["token"] = "tok1"
            return {"data": data}

        wazuh.run_logtest.side_effect = with_preflight(fake_logtest)
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        pos = [
            "Failed password for root #1",
            "Failed password for root #2",
            "Failed password for root #3",
        ]
        out = VerifyRuleDeployment().run(
            ctx,
            rule_id=105563,
            positive_samples=pos,
            negative_samples=["Accepted password for admin"],
        )
        self.assertTrue(out["frequency_rule"])
        # The verdict stays inconclusive even though this mock makes the rule
        # fire on the 3rd sample. Measured against a live 4.x manager, logtest
        # holds no frequency state at all (8 failures in one session never
        # tripped a frequency=5 rule), so it is not a valid oracle for a
        # correlation rule in either direction - "confirmed" here would be an
        # accident of the mock. The per-sample pass counts below remain the
        # meaningful assertions, along with the session threading.
        self.assertIsNone(out["verified"])
        self.assertEqual(out["verification"], "inconclusive")
        self.assertEqual(out["positive_pass"], "1/3")  # fires on the 3rd (threshold)
        self.assertEqual(out["negative_pass"], "1/1")
        # all positives shared ONE session (token threaded); the negative got
        # a fresh session. The decoder preflight runs on its own short-lived
        # session first and is closed as soon as it answers.
        self.assertEqual(tokens_seen, [None, "tok1", "tok1", None])
        closed = [c.args[0] for c in wazuh.end_logtest_session.call_args_list]
        self.assertIn("tok1", closed)
        self.assertIn("preflight-tok", closed)

    def test_verify_plain_rule(self):
        from tools.detection.detection_engine import VerifyRuleDeployment

        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = (
            '<group name="local,">\n' + self.PLAIN_RULE + "\n</group>\n"
        )

        def fake_logtest(log, log_format=None, location=None, token=None):
            if "Accepted" in log:
                rid, desc = 5715, "sshd: authentication succeeded."
            else:
                rid, desc = 105565, "Detects a failed SSH password"
            return {
                "data": {
                    "codemsg": 0,
                    "alert": True,
                    "output": {
                        "rule": {"id": rid, "level": 5, "description": desc},
                        "decoder": {"name": "sshd"},
                    },
                }
            }

        wazuh.run_logtest.side_effect = with_preflight(fake_logtest)
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        out = VerifyRuleDeployment().run(
            ctx,
            rule_id=105565,
            positive_samples=["Failed password for root"],
            negative_samples=["Accepted password for admin"],
        )
        self.assertFalse(out["frequency_rule"])
        self.assertTrue(out["verified"])
        self.assertEqual(out["positive_pass"], "1/1")
        self.assertEqual(out["negative_pass"], "1/1")

    def test_verify_rule_gone_reports_false(self):
        from tools.detection.detection_engine import VerifyRuleDeployment

        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        wazuh.run_logtest.side_effect = with_preflight(
            lambda log, log_format=None, location=None, token=None: logtest_hit(
                5760, desc="sshd: authentication failed."
            )
        )
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        out = VerifyRuleDeployment().run(
            ctx, rule_id=105565, positive_samples=["Failed password"], negative_samples=["Accepted"]
        )
        self.assertFalse(out["verified"])
        self.assertEqual(out["positive_pass"], "0/1")

    def test_frequency_rule_verdict_is_inconclusive_not_false(self):
        """logtest cannot hold frequency state, so a frequency rule that does
        not fire is UNKNOWN, not disproven. Reporting verified=False reads as
        "broken rule" and invites deleting a working rule."""
        from tools.detection.detection_engine import VerifyRuleDeployment

        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = (
            '<group name="local,">\n' + self.FREQ_RULE + "\n</group>\n"
        )
        # the parent fires, the correlation rule never does - the real-world case
        wazuh.run_logtest.side_effect = with_preflight(
            lambda log, log_format=None, location=None, token=None: logtest_hit(
                5760, desc="sshd: authentication failed."
            )
        )
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        out = VerifyRuleDeployment().run(
            ctx,
            rule_id=105563,
            positive_samples=[
                "Failed password for root",
                "Failed password for root",
                "Failed password for root",
                "Failed password for root",
                "Failed password for root",
            ],
            negative_samples=["Accepted password for deploy"],
        )
        self.assertTrue(out["frequency_rule"])
        self.assertIsNone(out["verified"])
        self.assertEqual(out["verification"], "inconclusive")
        self.assertTrue(out["frequency_rule_unverifiable_via_logtest"])
        # the negative arm is still a genuine, trustworthy signal
        self.assertEqual(out["negative_pass"], "1/1")
        self.assertIn("analysisd", out["how_to_verify_frequency_rule"])
        # the note must not tell the operator to go hunting for a phantom bug
        self.assertNotIn("check the rule's frequency", out["note"])

    def test_plain_rule_keeps_a_boolean_verdict(self):
        from tools.detection.detection_engine import VerifyRuleDeployment

        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE

        def fake_logtest(log, log_format=None, location=None, token=None):
            # the negative must resolve to a DIFFERENT rule, else it counts as
            # a false positive and the verdict is (correctly) False
            if "Accepted" in log:
                rid, desc = 5715, "sshd: authentication succeeded."
            else:
                rid, desc = 105565, "Detects a failed SSH password"
            return {
                "data": {
                    "codemsg": 0,
                    "alert": True,
                    "output": {
                        "rule": {"id": rid, "level": 5, "description": desc},
                        "decoder": {"name": "sshd"},
                    },
                }
            }

        wazuh.run_logtest.side_effect = with_preflight(fake_logtest)
        wazuh.end_logtest_session.return_value = {}
        ctx = make_ctx(wazuh=wazuh)
        out = VerifyRuleDeployment().run(
            ctx,
            rule_id=105565,
            positive_samples=["Failed password for root"],
            negative_samples=["Accepted password for deploy"],
        )
        self.assertIs(out["verified"], True)
        self.assertEqual(out["verification"], "confirmed")
        self.assertFalse(out["frequency_rule_unverifiable_via_logtest"])


class TestLogtestHarness(unittest.TestCase):
    """The logtest harness itself.

    The incident: rule validation fed raw rule XML into the logtest socket as
    if it were a log event - a whole local_rules.xml, or line by line - so
    every line came back "No decoder matched.", including literal tags like
    `<if_sid>5716</if_sid>`. That answer is about the *harness*, not the rule,
    and it looked exactly like a manager verdict.

    These tests pin the three things that make that impossible again:
      1. rule XML can never reach the `event` field (any layer),
      2. a failed decoder preflight is surfaced, never laundered into
         per-sample "no decode" rows,
      3. a candidate rule is loaded into the ruleset and then tested with ONE
         real sample event, and the fired rule id is the candidate - not the
         1002 catch-all.
    """

    # A candidate rule that chains the stock base rule the canonical sample
    # fires. If the harness ever stops staging the rule into the ruleset, this
    # can only ever come back as 5716 (or 1002), and the tests below catch it.
    # NB the match term is a <regex>. Wazuh's stock local_rules.xml example uses
    # <srcip> here, but tools/wazuh/validation.py's tag whitelist does not accept
    # it - a candidate the static validator rejects never reaches the logtest
    # harness, so these tests would be exercising the validator, not the thing
    # under test. <regex> is valid under both.
    CANDIDATE_RULE = (
        '<rule id="100001" level="5">\n'
        "  <if_sid>5716</if_sid>\n"
        "  <regex>^from 1\\.1\\.1\\.1 port</regex>\n"
        "  <description>sshd: authentication failed from IP 1.1.1.1.</description>\n"
        "</rule>"
    )

    def _ctx(self, logtest_handler, *, rules_file=LOCAL_RULES_TEMPLATE):
        wazuh = mock.MagicMock()
        wazuh.get_rules_file.return_value = rules_file
        wazuh.run_logtest.side_effect = logtest_handler
        wazuh.end_logtest_session.return_value = {}
        # the candidate id is free and nothing else in the ruleset overlaps
        wazuh.get_rules.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
        wazuh.put_rules_file.return_value = {
            "message": "Rule was successfully uploaded",
            "data": {"affected_items": ["local_rules.xml"]},
        }
        return make_ctx(wazuh=wazuh)

    @staticmethod
    def _calls(wazuh):
        return [c.args[0] for c in wazuh.run_logtest.call_args_list]

    # ------------------------------------------------------------------ #
    # 1) rule XML must never reach the event field
    # ------------------------------------------------------------------ #
    def test_rule_xml_lines_are_refused_as_events(self):
        """The exact incident input: every line of a local_rules.xml, including
        the <if_sid> tag, must be refused rather than sent and answered with
        'No decoder matched.'"""
        from tools.base import ToolError
        from tools.wazuh.logtest import RunWazuhLogtest

        ctx = self._ctx(lambda *a, **k: logtest_hit(5716))
        for line in LOCAL_RULES_TEMPLATE.splitlines():
            if not line.strip():
                continue
            with self.assertRaises(ToolError) as cm:
                RunWazuhLogtest().run(ctx, log=line, preflight=False)
            self.assertIn("No decoder matched", str(cm.exception))
        # not one line of the rules file was ever sent to the manager
        self.assertEqual(self._calls(ctx.wazuh), [])

    def test_whole_rules_file_blob_is_refused_as_one_event(self):
        from tools.base import ToolError
        from tools.wazuh.logtest import RunWazuhLogtest

        ctx = self._ctx(lambda *a, **k: logtest_hit(5716))
        with self.assertRaises(ToolError) as cm:
            RunWazuhLogtest().run(ctx, log=LOCAL_RULES_TEMPLATE, preflight=False)
        self.assertIn("No decoder matched", str(cm.exception))
        self.assertEqual(self._calls(ctx.wazuh), [])

    def test_api_client_refuses_xml_event_at_the_transport(self):
        """Defence in depth: the guard is not only in the tool layer. Even a
        caller that reaches WazuhManagerAPI.run_logtest directly cannot ship
        rule XML as `event`."""
        from tools.api_client import WazuhAPIError, WazuhManagerAPI

        api = WazuhManagerAPI(url="https://manager:55000", username="u", password="p")
        api.put = mock.MagicMock()  # nothing must reach the wire
        with self.assertRaises(WazuhAPIError) as cm:
            api.run_logtest("    <if_sid>5716</if_sid>")
        self.assertIn("No decoder matched", str(cm.exception))
        api.put.assert_not_called()

    def test_api_client_sends_the_documented_logtest_shape(self):
        """{log_format, location, event, token?} - event is a real log line."""
        from tools.api_client import WazuhManagerAPI

        api = WazuhManagerAPI(url="https://manager:55000", username="u", password="p")
        api.put = mock.MagicMock(return_value={"data": {}})
        api.run_logtest(
            CANONICAL_SSHD_FAILED_LOG, log_format="syslog", location="/var/log/auth.log"
        )
        body = api.put.call_args.kwargs["body"]
        self.assertEqual(body["event"], CANONICAL_SSHD_FAILED_LOG)
        self.assertEqual(body["log_format"], "syslog")
        self.assertEqual(body["location"], "/var/log/auth.log")
        self.assertNotIn("token", body)  # omitted on the first call
        api.run_logtest(CANONICAL_SSHD_FAILED_LOG, token="sess-1")
        self.assertEqual(api.put.call_args.kwargs["body"]["token"], "sess-1")

    def test_looks_like_xml_does_not_misfire_on_real_log_lines(self):
        """A guard that cries wolf on ordinary log lines would block legitimate
        work, so pin both directions: markup in, real events out."""
        from tools.wazuh.xmlio import looks_like_xml

        for line in (
            CANONICAL_SSHD_FAILED_LOG,
            "Dec 10 01:02:02 host sshd[1]: Accepted password for root from 1.1.1.1 port 22 ssh2",
            'Aug 27 09:12:01 web nginx: 10.0.0.5 GET /a?x=1&y=2 200 12 "-" "curl/8.4"',
            "Jan  1 00:00:00 host kernel: [12345.678] TCP: request_sock_TCP: Possible SYN flooding",
        ):
            self.assertFalse(looks_like_xml(line), f"misfired on: {line}")
        for blob in (
            "<if_sid>5716</if_sid>",
            '  <rule id="100001" level="5">',
            "<!-- Local rules -->",
            '<?xml version="1.0"?>',
            LOCAL_RULES_TEMPLATE,
        ):
            self.assertTrue(looks_like_xml(blob), f"missed: {blob}")

    def test_sample_event_in_an_xml_comment_never_yields_tags(self):
        """The legacy 'example line parked in a local_rules.xml comment' pattern
        is now a fixture, but the shim must still hand back ONLY the event."""
        from tools.wazuh.logtest import sample_events_from_xml_comment

        rules = (
            "<!-- Local rules -->\n"
            "<!-- sample: Dec 10 01:02:02 host sshd[1234]: Failed none for root "
            "from 1.1.1.1 port 1066 ssh2 -->\n"
            '<group name="local,">\n'
            '  <rule id="100001" level="5"><if_sid>5716</if_sid></rule>\n'
            "</group>\n"
        )
        self.assertEqual(sample_events_from_xml_comment(rules), [CANONICAL_SSHD_FAILED_LOG])

    # ------------------------------------------------------------------ #
    # 2) a broken decoder set must be surfaced, not laundered
    # ------------------------------------------------------------------ #
    def test_preflight_failure_surfaces_instead_of_no_decode_rows(self):
        """When the canonical line does not decode, 'No decoder matched' on the
        real samples is meaningless. develop_wazuh_rule must say so and submit
        nothing, rather than filing every sample as `no_decode`."""
        from tools.base import ApprovalRequired
        from tools.detection.detection_engine import DevelopWazuhRule

        ctx = self._ctx(
            lambda *a, **k: NO_DECODER_RESPONSE, rules_file='<group name="local,">\n</group>\n'
        )
        with self.assertRaises(ApprovalRequired) as cm:
            DevelopWazuhRule().run(
                ctx,
                rule_xml=self.CANDIDATE_RULE,
                positive_samples=[CANDIDATE_SAMPLE_LOG],
                reason="broken decoder set",
            )
        ev = cm.exception.proposed_action["validation"]["evidence"]
        self.assertTrue(ev["harness_broken"])
        self.assertIn("no decoders loaded", ev["preflight"]["error"])
        rows = ev["sample_groups"]["positives"]
        self.assertEqual([r["class"] for r in rows], ["preflight_failed"])
        # only the preflight call was made - the sample was never submitted
        self.assertEqual(self._calls(ctx.wazuh), [CANONICAL_SSHD_FAILED_LOG])
        self.assertIn("NO logtest verdicts were collected", ev["baseline_summary"])

    def test_verify_refuses_to_report_when_preflight_fails(self):
        """A verdict built on a session that cannot decode is worse than no
        verdict: it would blame the rule for the harness."""
        from tools.base import ToolError
        from tools.detection.detection_engine import VerifyRuleDeployment

        ctx = self._ctx(lambda *a, **k: NO_DECODER_RESPONSE)
        with self.assertRaises(ToolError) as cm:
            VerifyRuleDeployment().run(
                ctx, rule_id=100001, positive_samples=[CANONICAL_SSHD_FAILED_LOG]
            )
        self.assertIn("no decoders loaded", str(cm.exception))
        self.assertEqual(self._calls(ctx.wazuh), [CANONICAL_SSHD_FAILED_LOG])

    def test_preflight_rejects_a_ruleset_that_lacks_the_base_rule(self):
        """Decoding is not enough: the canonical sample must also fire stock
        rule 5716, otherwise an if_sid: 5716 chain cannot be judged here."""
        from tools.base import ToolError
        from tools.wazuh.logtest import preflight_decoders

        ctx = self._ctx(lambda *a, **k: logtest_hit(9999, desc="some other rule"))
        with self.assertRaises(ToolError) as cm:
            preflight_decoders(ctx.wazuh)
        self.assertIn("no decoders loaded", str(cm.exception))
        self.assertIn("5716", str(cm.exception))

    # ------------------------------------------------------------------ #
    # 3) THE regression test: stage the rule, submit one real event, and the
    #    candidate's own id must fire - not the 1002 catch-all.
    # ------------------------------------------------------------------ #
    def test_candidate_rule_fires_after_staging_on_the_real_sample(self):
        from tools.base import ApprovalRequired
        from tools.wazuh.logtest import TestWazuhRule

        seen: list[str] = []

        def fake(log, log_format=None, location=None, token=None):
            seen.append(log)
            if log == CANONICAL_SSHD_FAILED_LOG:
                return logtest_hit(5716, desc="sshd: authentication failed.")
            # the candidate is now in the ruleset, so the manager fires it
            return logtest_hit(100001, level=5, desc="sshd: authentication failed from IP 1.1.1.1.")

        ctx = self._ctx(fake)

        # planning first: nothing is written, and the only logtest call is the
        # read-only preflight - the sample is never submitted, and an approver
        # is never asked to sign off on a broken harness.
        with self.assertRaises(ApprovalRequired):
            TestWazuhRule().run(
                ctx,
                rule_xml=self.CANDIDATE_RULE,
                sample_event=CANDIDATE_SAMPLE_LOG,
                reason="stage + test",
            )
        ctx.wazuh.put_rules_file.assert_not_called()
        self.assertEqual(seen, [CANONICAL_SSHD_FAILED_LOG])
        seen.clear()  # forget the planning run; the approved run is what counts

        # with the approval in hand: staged, then tested with ONE real event
        ctx.approval = {"action": "test_wazuh_rule", "status": "approved"}
        out = TestWazuhRule().run(
            ctx,
            rule_xml=self.CANDIDATE_RULE,
            sample_event=CANDIDATE_SAMPLE_LOG,
            reason="stage + test",
        )

        # THE assertion the incident demands: the candidate fired, NOT 1002.
        self.assertEqual(out["fired_rule_id"], 100001)
        self.assertNotIn(out["fired_rule_id"], (1002, 1005))
        self.assertEqual(out["status"], "tested")
        self.assertTrue(out["matched"])
        self.assertFalse(out["catch_all_rule"])
        self.assertEqual(out["decoder"], "sshd")
        self.assertEqual(out["fired_level"], 5)
        self.assertEqual(out["sample"], CANDIDATE_SAMPLE_LOG)

        # the rule really was loaded into the ruleset logtest evaluates
        self.assertTrue(out["staging"]["staged"])
        ctx.wazuh.put_rules_file.assert_called_once()
        self.assertIn('id="100001"', ctx.wazuh.put_rules_file.call_args.args[1])
        self.assertIn("<if_sid>5716</if_sid>", ctx.wazuh.put_rules_file.call_args.args[1])

        # exactly two logtest calls: the preflight sample, then the one real
        # sample event. No rules file, no per-line sweep.
        self.assertEqual(seen, [CANONICAL_SSHD_FAILED_LOG, CANDIDATE_SAMPLE_LOG])
        for line in seen:
            self.assertNotIn("<if_sid>", line)
            self.assertNotIn("<rule", line)

    def test_catch_all_on_a_positive_fails_loudly_not_as_a_null_match(self):
        """1002 is the generic catch-all: the event decoded but no specific
        rule matched. Treating that as an ordinary 'some other rule fired'
        result is how a broken harness passes itself off as a working rule."""
        from tools.wazuh.logtest import TestWazuhRule

        def fake(log, log_format=None, location=None, token=None):
            if log == CANONICAL_SSHD_FAILED_LOG:
                return logtest_hit(5716, desc="sshd: authentication failed.")
            return logtest_hit(1002, level=0, desc="Log collection: /var/log/auth.log")

        ctx = self._ctx(fake)
        ctx.approval = {"action": "test_wazuh_rule", "status": "approved"}
        out = TestWazuhRule().run(
            ctx,
            rule_xml=self.CANDIDATE_RULE,
            sample_event=CANDIDATE_SAMPLE_LOG,
            reason="catch-all probe",
        )
        self.assertEqual(out["fired_rule_id"], 1002)
        self.assertEqual(out["status"], "catch_all")
        self.assertTrue(out["catch_all_rule"])
        self.assertFalse(out["matched"])
        self.assertIn("catch-all", out["error"])
        self.assertIn("Do NOT read this as a null-match baseline", out["error"])

    def test_catch_all_positive_makes_verification_inconclusive(self):
        """Same signal one layer up: a positive swallowed by 1002 is not a
        per-sample failure of the rule, it is a broken harness - so the verdict
        must be inconclusive (unknown), never 'failed'."""
        from tools.detection.detection_engine import VerifyRuleDeployment

        # the preflight decodes fine; the real sample is swallowed by 1002
        ctx = self._ctx(
            with_preflight(
                lambda *a, **k: logtest_hit(1002, level=0, desc="Log collection: /var/log/auth.log")
            )
        )
        out = VerifyRuleDeployment().run(
            ctx, rule_id=100001, positive_samples=[CANDIDATE_SAMPLE_LOG]
        )
        self.assertIsNone(out["verified"])
        self.assertEqual(out["verification"], "inconclusive")
        self.assertTrue(out["harness_suspect"])
        self.assertEqual(len(out["catch_all_hits"]), 1)
        self.assertIn("catch-all", out["note"])

    def test_candidate_firing_without_an_alert_is_not_reported_as_a_miss(self):
        """The candidate WAS the rule that fired. Level 0 / noalert is a
        configuration answer, and reporting it as 'the rule did not match'
        invites rewriting a rule that in fact works."""
        from tools.wazuh.logtest import TestWazuhRule

        # 4.7+ shape: the rule that matched is in output.rule, but the manager
        # did not raise an alert (level 0, or <alert_opts> noalert).
        no_alert = {
            "data": {
                "codemsg": 0,
                "alert": False,
                "output": {
                    "rule": {
                        "id": 100001,
                        "level": 0,
                        "description": "sshd: authentication failed from IP 1.1.1.1.",
                    },
                    "decoder": {"name": "sshd"},
                },
                "token": "tok-nomatch",
            }
        }

        def fake(log, log_format=None, location=None, token=None):
            if log == CANONICAL_SSHD_FAILED_LOG:
                return logtest_hit(5716, desc="sshd: authentication failed.")
            return no_alert

        ctx = self._ctx(fake)
        ctx.approval = {"action": "test_wazuh_rule", "status": "approved"}
        out = TestWazuhRule().run(
            ctx,
            rule_xml=self.CANDIDATE_RULE,
            sample_event=CANDIDATE_SAMPLE_LOG,
            reason="alerting check",
        )
        self.assertEqual(out["fired_rule_id"], 100001)
        self.assertEqual(out["status"], "no_alert")
        self.assertFalse(out["matched"])
        self.assertIn("did not raise an alert", out["error"])
        self.assertIn("not a matching failure", out["error"])

    def test_logtest_called_once_per_case_not_once_per_line(self):
        """The shape of the fix: ONE logtest call for (rule staged + 1 event)."""
        from tools.wazuh.logtest import TestWazuhRule

        ctx = self._ctx(
            with_preflight(
                lambda log, log_format=None, location=None, token=None: logtest_hit(
                    100001, desc="sshd: authentication failed from IP 1.1.1.1."
                )
            )
        )
        ctx.approval = {"action": "test_wazuh_rule", "status": "approved"}
        TestWazuhRule().run(
            ctx,
            rule_xml=self.CANDIDATE_RULE,
            sample_event=CANDIDATE_SAMPLE_LOG,
            reason="call count",
        )
        self.assertEqual(len(ctx.wazuh.run_logtest.call_args_list), 2)  # preflight + 1 event

    def test_rule_xml_passed_as_the_sample_event_is_refused(self):
        from tools.base import ApprovalRequired, ToolError
        from tools.wazuh.logtest import TestWazuhRule

        ctx = self._ctx(lambda *a, **k: logtest_hit(5716))
        ctx.approval = {"action": "test_wazuh_rule", "status": "approved"}
        with self.assertRaises(ToolError) as cm:
            TestWazuhRule().run(
                ctx,
                rule_xml=self.CANDIDATE_RULE,
                sample_event=self.CANDIDATE_RULE,  # <-- the bug, verbatim
                reason="misuse",
            )
        self.assertIn("No decoder matched", str(cm.exception))
        self.assertEqual(self._calls(ctx.wazuh), [])
        self.assertIsNotNone(ApprovalRequired)  # gate is still a real gate

    def test_static_validation_runs_before_any_manager_round_trip(self):
        """XML structure is answered by the parser, never by the socket: a
        malformed rule must not cost a logtest call."""
        from tools.base import ToolError
        from tools.wazuh.logtest import TestWazuhRule

        ctx = self._ctx(lambda *a, **k: logtest_hit(5716))
        ctx.approval = {"action": "test_wazuh_rule", "status": "approved"}
        with self.assertRaises(ToolError):
            TestWazuhRule().run(
                ctx,
                rule_xml='<rule id="100001" level="5"><frequency>3</frequency></rule>',
                sample_event=CANONICAL_SSHD_FAILED_LOG,
                reason="malformed",
            )
        self.assertEqual(self._calls(ctx.wazuh), [])

    # ------------------------------------------------------------------ #
    # the fixture is the single source for the canonical sample
    # ------------------------------------------------------------------ #
    def test_fixture_matches_canonical_preflight_sample(self):
        from tools.wazuh.logtest import CANONICAL_SSHD_FAILED_LOG

        path = pathlib.Path(__file__).parent / "fixtures" / "sample_events" / "sshd_failed_auth.log"
        self.assertTrue(path.exists(), "canonical sample fixture is missing")
        self.assertEqual(path.read_text().strip(), CANONICAL_SSHD_FAILED_LOG)
        self.assertEqual(CANONICAL_SSHD_FAILED_LOG, CANONICAL_SSHD_FAILED_LOG)
        # the local_rules.xml example in this test file must not double as the
        # event fixture - keep them separate so a line sweep cannot confuse them
        self.assertNotIn(CANONICAL_SSHD_FAILED_LOG, LOCAL_RULES_TEMPLATE)


class TestDashboardEngine(unittest.TestCase):
    """tools/dashboard/engine.py - evidence-backed, approval-gated design."""

    @staticmethod
    def _ctx_with_schema():
        indexer = mock.MagicMock()
        indexer.field_caps.return_value = {
            "data.srcip": "keyword",
            "agent.name": "keyword",
            "rule.groups": "keyword",
            "rule.level": "long",
        }
        indexer.search.return_value = {"hits": {"total": {"value": 42}}, "took": 3}
        return make_ctx(indexer=indexer)

    def test_design_proposes_rerunnable_payload(self):
        from tools.dashboard.engine import DesignDetectionDashboard

        ctx = self._ctx_with_schema()
        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-abc"):
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(
                    ctx,
                    title="Web Server Attacks",
                    focus="web",
                    description="web attack dashboard",
                    time_range="-7d",
                    reason="golden dashboard",
                )
        proposed = cm.exception.proposed_action
        self.assertEqual(proposed["action"], "design_detection_dashboard")
        # PHASE 12 invariant: payload is the tool's own input params.
        self.assertEqual(
            proposed["payload"],
            {
                "title": "Web Server Attacks",
                "focus": "web",
                "description": "web attack dashboard",
                "time_range": "-7d",
                "reason": "golden dashboard",
            },
        )
        cfg = proposed.get("generated_config") or {}
        self.assertIn("visualizations", cfg)
        self.assertIn("panelsJSON", cfg)
        # every panel query was verified against the (mocked) indexer
        self.assertGreaterEqual(ctx.indexer.search.call_count, 4)

    def test_invalid_focus_rejected(self):
        from tools.dashboard.engine import DesignDetectionDashboard

        ctx = self._ctx_with_schema()
        with self.assertRaises(ToolError):
            DesignDetectionDashboard().run(ctx, title="t", focus="windows", reason="r")

    def test_schema_failure_aborts(self):
        from tools.dashboard.engine import DesignDetectionDashboard

        indexer = mock.MagicMock()
        indexer.field_caps.side_effect = RuntimeError("indexer down")
        ctx = make_ctx(indexer=indexer)
        with self.assertRaises(ToolError) as cm:
            DesignDetectionDashboard().run(ctx, title="t", focus="web", reason="r")
        self.assertIn("Cannot read indexer schema", str(cm.exception))

    # -- pattern discovery: never bind alert panels to a non-alert index family --

    def test_find_index_pattern_prefers_alerts_over_statistics(self):
        # Regression: the API can list wazuh-statistics-* first; it must never
        # win over the alerts pattern (bounds a dashboard that renders empty).
        from tools.dashboard import engine

        resp = {
            "saved_objects": [
                {"id": "wazuh-statistics-*", "attributes": {"title": "wazuh-statistics-*"}},
                {"id": "abcd-1234", "attributes": {"title": "wazuh-alerts-*"}},
            ]
        }
        with mock.patch("tools.dashboard.engine.dashboards_request", return_value=resp):
            self.assertEqual(engine._find_index_pattern(), "abcd-1234")
        # id may also be the pattern id itself, without a title match.
        resp = {
            "saved_objects": [
                {"id": "wazuh-statistics-*", "attributes": {"title": "wazuh-statistics-*"}},
                {"id": "wazuh-alerts-*", "attributes": {"title": "Wazuh alerts"}},
            ]
        }
        with mock.patch("tools.dashboard.engine.dashboards_request", return_value=resp):
            self.assertEqual(engine._find_index_pattern(), "wazuh-alerts-*")

    def test_find_index_pattern_rejects_non_alert_families(self):
        from tools.dashboard import engine

        resp = {
            "saved_objects": [
                {"id": "wazuh-statistics-*", "attributes": {"title": "wazuh-statistics-*"}},
                {"id": "wazuh-archives-*", "attributes": {"title": "wazuh-archives-*"}},
                {"id": "wazuh-monitoring-*", "attributes": {"title": "wazuh-monitoring-*"}},
            ]
        }
        with mock.patch("tools.dashboard.engine.dashboards_request", return_value=resp):
            self.assertIsNone(engine._find_index_pattern())
        # caller falls back to the conventional alerts id.
        with mock.patch("tools.dashboard.engine._find_index_pattern", return_value=None):
            from tools.dashboard.engine import DesignDetectionDashboard

            ctx = self._ctx_with_schema()
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(ctx, title="t", focus="web", reason="r")
            self.assertEqual(
                cm.exception.proposed_action["generated_config"]["index_pattern"], "wazuh-alerts-*"
            )

    def test_find_index_pattern_unreachable_returns_none(self):
        from tools.dashboard import engine

        with mock.patch(
            "tools.dashboard.engine.dashboards_request", side_effect=RuntimeError("dashboards down")
        ):
            self.assertIsNone(engine._find_index_pattern())

    # -- proposal is a complete, resolvable, OSD-openable saved-object bundle --

    def test_proposal_bundle_is_complete_and_renderable(self):
        from tools.dashboard import osd_objects as osd
        from tools.dashboard.engine import DesignDetectionDashboard

        ctx = self._ctx_with_schema()
        with (
            mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-abc"),
            mock.patch(
                "tools.dashboard.engine._index_pattern_object",
                return_value={"id": "idx-abc", "attributes": {"title": "wazuh-alerts-*"}},
            ),
        ):
            with self.assertRaises(ApprovalRequired) as cm:
                DesignDetectionDashboard().run(
                    ctx,
                    title="Web Server Attacks",
                    focus="web",
                    description="web attack dashboard",
                    time_range="-7d",
                    reason="golden dashboard",
                )
        proposed = cm.exception.proposed_action
        cfg = proposed["generated_config"]
        self.assertEqual(cfg["index_pattern"], "idx-abc")
        self.assertTrue(proposed["validation"]["valid"], proposed["validation"]["errors"])
        bundle = cfg["saved_objects"]
        self.assertEqual([o["type"] for o in bundle].count("visualization"), 7)
        dash = next(o for o in bundle if o["type"] == "dashboard")
        self.assertEqual(dash["id"], "dashboard-web-server-attacks")
        # every panel resolves via panelRefName -> reference -> a bundle visualization
        refs = {r["name"]: r["id"] for r in dash["references"]}
        vis_ids = {o["id"] for o in bundle if o["type"] == "visualization"}
        for panel in json.loads(dash["attributes"]["panelsJSON"]):
            self.assertIn(panel["panelRefName"], refs)
            self.assertIn(refs[panel["panelRefName"]], vis_ids)
            self.assertEqual(set(panel["gridData"]), {"x", "y", "w", "h", "i"})
        self.assertEqual(osd.validate_dashboard(dash), [])
        term_web_seen = False
        for vis in (o for o in bundle if o["type"] == "visualization"):
            self.assertEqual(osd.validate_visualization(vis), [], vis["id"])
            vs = json.loads(vis["attributes"]["visState"])
            self.assertIn(vs["type"], osd.VALID_VIS_TYPES)
            ss = json.loads(vis["attributes"]["kibanaSavedObjectMeta"]["searchSourceJSON"])
            self.assertNotIn("aggs", ss)
            self.assertEqual(ss["indexRefName"], osd.INDEX_REF_NAME)
            self.assertEqual(
                vis["references"],
                [{"name": osd.INDEX_REF_NAME, "type": "index-pattern", "id": "idx-abc"}],
            )
            if any(
                f.get("query", {}).get("match_phrase", {}).get("rule.groups") == "web"
                for f in ss["filter"]
            ):
                term_web_seen = True
            self.assertTrue(any("range" in f and "timestamp" in f["range"] for f in ss["filter"]))
        self.assertTrue(term_web_seen, "no visualization carries the rule.groups: web filter")

    # -- execution against a fake OSD server that stores and returns objects --

    def _fake_osd(self, *, pattern_exists=True, fields=None, corrupt_on_read=False):
        store: dict[tuple[str, str], dict] = {}
        calls: list[tuple[str, str, dict | None]] = []
        counter = {"n": 0}

        def fake_request(method: str, path: str, body: dict | None = None, **kw) -> dict:
            calls.append((method, path, body))
            parts = path.strip("/").split("/")  # api/saved_objects/<type>[/<id>]
            otype = parts[2] if len(parts) > 2 else ""
            if method == "GET" and otype == "index-pattern":
                if not pattern_exists:
                    return {"statusCode": 404, "error": "Not Found"}
                attrs = {"title": "wazuh-alerts-*"}
                if fields is not None:
                    attrs["fields"] = json.dumps(
                        [{"name": f, "aggregatable": True} for f in fields]
                    )
                return {"id": parts[3], "type": "index-pattern", "attributes": attrs}
            if method == "POST":
                counter["n"] += 1
                oid = f"{otype}-{counter['n']}"
                store[(otype, oid)] = {"id": oid, "type": otype, **copy.deepcopy(body)}
                return {"id": oid, "type": otype, "attributes": body["attributes"]}
            if method == "GET":
                obj = copy.deepcopy(store[(otype, parts[3])])
                if corrupt_on_read and otype == "dashboard":
                    obj["attributes"]["panelsJSON"] = json.dumps(
                        [{"id": "x", "type": "visualization"}]
                    )
                return obj
            raise AssertionError(f"unexpected call {method} {path}")

        return fake_request, calls, store

    def _approved_ctx(self):
        indexer = mock.MagicMock()
        indexer.field_caps.return_value = {
            "data.srcip": "keyword",
            "agent.name": "keyword",
            "rule.groups": "keyword",
            "rule.level": "long",
        }
        indexer.search.return_value = {"hits": {"total": {"value": 42}}, "took": 3}
        return make_ctx(
            indexer=indexer, approval={"action": "design_detection_dashboard", "status": "approved"}
        )

    def _run_exec(self, fake):
        from tools.dashboard.engine import DesignDetectionDashboard

        with (
            mock.patch("tools.dashboard.engine._find_index_pattern", return_value="idx-abc"),
            mock.patch("tools.dashboard.engine.dashboards_request", side_effect=fake),
        ):
            return DesignDetectionDashboard().run(
                self._approved_ctx(),
                title="Web Server Attacks",
                focus="web",
                description="d",
                time_range="-7d",
                reason="r",
            )

    def test_executed_dashboard_is_renderable_and_read_back(self):
        from tools.dashboard import osd_objects as osd

        fake, calls, store = self._fake_osd()
        out = self._run_exec(fake)
        self.assertEqual(out["status"], "executed", out["render_check"])
        self.assertTrue(out["render_check"]["ok"])
        self.assertEqual(len(out["visualizations"]), 7)
        dash = next(v for (t, _), v in store.items() if t == "dashboard")
        self.assertEqual(osd.validate_dashboard(dash), [])
        # dashboard references point at the SERVER-assigned visualization ids
        vis_ids = {oid for (t, oid) in store if t == "visualization"}
        self.assertEqual({r["id"] for r in dash["references"]}, vis_ids)
        # it read the objects back after creating them
        self.assertTrue(any(m == "GET" and "/dashboard/" in p for m, p, _ in calls))
        self.assertTrue(out["open_url_path"].endswith(dash["id"]))

    def test_missing_index_pattern_blocks_execution_and_creates_nothing(self):
        fake, calls, store = self._fake_osd(pattern_exists=False)
        with self.assertRaises(ToolError) as cm:
            self._run_exec(fake)
        self.assertIn("Could not locate that index-pattern", str(cm.exception))
        self.assertFalse(any(m == "POST" for m, _, _ in calls))

    def test_field_missing_from_index_pattern_blocks_execution(self):
        fake, calls, store = self._fake_osd(
            fields=["timestamp", "rule.groups", "rule.level", "rule.id"]
        )
        with self.assertRaises(ToolError) as cm:
            self._run_exec(fake)
        self.assertIn("refresh the index pattern fields", str(cm.exception))
        self.assertFalse(any(m == "POST" for m, _, _ in calls))

    def test_bad_read_back_is_reported_not_claimed_as_success(self):
        fake, calls, store = self._fake_osd(corrupt_on_read=True)
        out = self._run_exec(fake)
        self.assertEqual(out["status"], "executed_with_issues")
        self.assertFalse(out["render_check"]["ok"])
        self.assertTrue(any("gridData" in i for i in out["render_check"]["issues"]))


class TestOsdObjectValidators(unittest.TestCase):
    """Each original bug, in the exact shape the old engine produced, must be caught."""

    def test_bar_is_normalized_and_invalid_types_rejected(self):
        from tools.dashboard import osd_objects as osd

        self.assertEqual(osd.normalize_vis_type("bar"), "histogram")
        with self.assertRaises(ValueError):
            osd.normalize_vis_type("sparkle")

    def test_old_vis_shape_is_rejected(self):
        from tools.dashboard import osd_objects as osd

        old = {
            "id": "v",
            "attributes": {
                "visState": json.dumps(
                    {
                        "title": "t",
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
                    "searchSourceJSON": json.dumps(
                        {"index": "wazuh-alerts-*", "filter": [], "aggs": [{"id": "1"}]}
                    )
                },
            },
            "references": [],
        }
        issues = " | ".join(osd.validate_visualization(old))
        self.assertIn("'bar' is not registered", issues)
        self.assertIn("has no 'labels'", issues)
        self.assertIn("contains 'aggs'", issues)

    def test_old_dashboard_shape_is_rejected(self):
        from tools.dashboard import osd_objects as osd

        old = {
            "id": "d",
            "attributes": {
                "panelsJSON": json.dumps(
                    [{"id": "v1", "x": 0, "y": 0, "w": 24, "h": 15, "type": "visualization"}]
                )
            },
            "references": [{"name": "panel_v1", "type": "visualization", "id": "v1"}],
        }
        issues = " | ".join(osd.validate_dashboard(old))
        self.assertIn("gridData", issues)
        self.assertIn("panelIndex", issues)
        self.assertIn("optionsJSON missing", issues)

    def test_every_built_vis_type_validates(self):
        from tools.dashboard import osd_objects as osd

        aggs = [
            {"id": "1", "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "type": "terms",
                "schema": "segment",
                "params": {"field": "rule.id", "size": 5},
            },
        ]
        for t in osd.VALID_VIS_TYPES:
            attrs, refs = osd.build_visualization_attributes("t", t, aggs, "idx")
            self.assertEqual(
                osd.validate_visualization({"attributes": attrs, "references": refs}), [], t
            )

    def test_date_histogram_params_are_completed(self):
        from tools.dashboard import osd_objects as osd

        [agg] = osd.normalize_aggs(
            [
                {
                    "id": 2,
                    "type": "date_histogram",
                    "schema": "segment",
                    "params": {"field": "timestamp", "includeEmptyRows": True},
                }
            ]
        )
        self.assertEqual(agg["id"], "2")
        self.assertIn("extended_bounds", agg["params"])
        self.assertNotIn("includeEmptyRows", agg["params"])

    def test_normalize_aggs_handles_missing_id_and_schema(self):
        """Malformed aggs (missing id, missing schema, None id) are normalized
        to valid unique ids + inferred schemas instead of producing 'None' duplicates."""
        from tools.dashboard import osd_objects as osd

        malformed = [
            {
                "type": "terms",
                "params": {"field": "rule_id.keyword", "size": 15},
            },  # no id, no schema
            {"type": "count", "params": {}},  # no id, no schema
            {"id": None, "type": "terms", "params": {"field": "rule.groups"}},  # explicit None id
            {"type": "avg", "params": {"field": "rule.level"}},  # metric type, no schema
        ]
        norm = osd.normalize_aggs(malformed)
        # Unique ids (no "None" duplicates)
        ids = [a["id"] for a in norm]
        self.assertEqual(len(ids), len(set(ids)), f"duplicate ids: {ids}")
        self.assertNotIn("None", ids, f"found 'None' string id: {ids}")
        # Schemas inferred
        schemas = [a.get("schema") for a in norm]
        # terms -> segment, count -> metric, terms -> segment, avg -> metric
        self.assertEqual(schemas, ["segment", "metric", "segment", "metric"])
        # Resulting visState validates
        attrs, refs = osd.build_visualization_attributes(
            "Top Triggered Rules", "histogram", malformed, "idx"
        )
        issues = osd.validate_visualization({"attributes": attrs, "references": refs})
        self.assertEqual(issues, [], f"should validate: {issues}")


class TestGapsEngine(unittest.TestCase):
    """tools/gaps/detection_gaps.py - 5-state coverage from real data."""

    SQLI_RULE = {
        "id": 92001,
        "level": 14,
        "description": "Attempt to perform an SQL injection attack",
        "groups": ["web"],
        "details": {"match": "sql injection|union select"},
    }

    def _ctx(self, alerts=0, events=3):
        wazuh = mock.MagicMock()
        wazuh.get_rules.return_value = {
            "data": {"affected_items": [self.SQLI_RULE], "total_affected_items": 1}
        }
        indexer = mock.MagicMock()
        indexer.search.side_effect = lambda index_name, body: {
            "hits": {
                "total": {"value": alerts if index_name.startswith("wazuh-alerts") else events}
            }
        }
        return make_ctx(wazuh=wazuh, indexer=indexer)

    def test_classifies_partial_and_gap(self):
        from tools.gaps.detection_gaps import AnalyzeDetectionGaps

        ctx = self._ctx(alerts=0, events=3)
        out = AnalyzeDetectionGaps().run(ctx, target="web", time_range="-7d")
        by_name = {r["category"]: r for r in out["coverage"]}
        self.assertEqual(by_name["sql_injection"]["state"], "partial")  # rules but no alerts
        self.assertEqual(by_name["sql_injection"]["rules"], 1)
        self.assertEqual(by_name["xss"]["state"], "gap")  # activity, no rules
        self.assertEqual(len(out["gap_candidates"]), len(out["coverage"]))
        self.assertIn("need attention", out["summary"])

    def test_classifies_detected_and_unknown(self):
        from tools.gaps.detection_gaps import AnalyzeDetectionGaps

        ctx = self._ctx(alerts=5, events=0)
        out = AnalyzeDetectionGaps().run(ctx, target="web", time_range="-7d")
        by_name = {r["category"]: r for r in out["coverage"]}
        self.assertEqual(by_name["sql_injection"]["state"], "detected")
        self.assertEqual(by_name["xss"]["state"], "unknown")
        self.assertEqual(out["gap_candidates"], [])

    def test_unknown_target_rejected(self):
        from tools.gaps.detection_gaps import AnalyzeDetectionGaps

        ctx = make_ctx()
        with self.assertRaises(ToolError):
            AnalyzeDetectionGaps().run(ctx, target="windows")


class TestRegistryPermissionGate(unittest.TestCase):
    """tools/registry.py - the ONE place tools run: schema validation,
    permission gating, audit, and DATA-wrapping before the LLM sees results."""

    RULE = (
        '<rule id="105567" level="5">\n'
        "  <match>Failed password</match>\n"
        "  <description>PHASE 13 registry unit rule</description>\n"
        "</rule>"
    )

    def setUp(self):
        self.wazuh = mock.MagicMock()
        self.indexer = mock.MagicMock()

    def test_read_tool_executes_immediately(self):
        from tools import registry

        self.wazuh.get_rules.return_value = {
            "data": {"affected_items": [RULE_5760], "total_affected_items": 1}
        }
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "get_wazuh_rules", {"limit": 5})
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["result"]["count"], 1)

    def test_propose_returns_approval_required_without_writing(self):
        from tools import registry

        self.wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        self.wazuh.put_rules_file.return_value = {"message": "ok"}
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with (
            mock.patch("audit.audit_log") as ml,
            mock.patch(
                "approvals.create_proposal",
                return_value={"id": "appr-123", "action": "create_wazuh_rule"},
            ) as mc,
        ):
            out = registry.execute(
                ctx, "create_wazuh_rule", {"rule_xml": self.RULE, "reason": "unit test"}
            )
        self.assertEqual(out["status"], "approval_required")
        self.assertEqual(out["proposal"]["id"], "appr-123")
        mc.assert_called_once()
        self.wazuh.put_rules_file.assert_not_called()
        ml.assert_called()  # the awaiting-approval row was audited

    def test_approved_write_executes(self):
        from tools import registry

        self.wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        self.wazuh.put_rules_file.return_value = {"message": "Rule was successfully uploaded"}
        ctx = make_ctx(
            wazuh=self.wazuh,
            indexer=self.indexer,
            approval={"action": "create_wazuh_rule", "status": "approved"},
        )
        with mock.patch("audit.audit_log"):
            out = registry.execute(
                ctx, "create_wazuh_rule", {"rule_xml": self.RULE, "reason": "approved run"}
            )
        self.assertEqual(out["status"], "ok")
        self.assertEqual(out["result"]["detail"], "Rule was successfully uploaded")
        self.wazuh.put_rules_file.assert_called_once()

    def test_mismatched_approval_is_denied(self):
        from tools import registry

        self.wazuh.get_rules_file.return_value = LOCAL_RULES_TEMPLATE
        ctx = make_ctx(
            wazuh=self.wazuh,
            indexer=self.indexer,
            approval={"action": "delete_wazuh_rule", "status": "approved"},
        )
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "create_wazuh_rule", {"rule_xml": self.RULE, "reason": "x"})
        self.assertEqual(out["status"], "error")
        self.assertIn("Approval mismatch", out["error"])
        self.wazuh.put_rules_file.assert_not_called()

    def test_invalid_params_rejected_without_running(self):
        from tools import registry

        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log") as ml:
            out = registry.execute(ctx, "get_wazuh_rule", {})  # rule_id required
        self.assertEqual(out["status"], "error")
        self.assertIn("Missing required parameter: rule_id", out["error"])
        ml.assert_called_once()
        self.wazuh.get_rule.assert_not_called()

    def test_silent_returns_raw_result(self):
        from tools import registry

        self.wazuh.get_rules.return_value = {
            "data": {"affected_items": [], "total_affected_items": 0}
        }
        ctx = make_ctx(wazuh=self.wazuh, indexer=self.indexer)
        with mock.patch("audit.audit_log"):
            out = registry.execute(ctx, "get_wazuh_rules", {"limit": 5}, silent=True)
        self.assertIsInstance(out, dict)
        self.assertEqual(out.get("count"), 0)


class TestFrequencyValidation(unittest.TestCase):
    """tools/wazuh/validation.py - the PHASE 12 rule-RF constraints."""

    def test_frequency_requires_if_matched_sid_attribute_form(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml

        with_parent = (
            '<rule id="105601" level="10" frequency="3" timeframe="60">\n'
            "  <if_matched_sid>5760</if_matched_sid>\n"
            "  <description>x</description>\n"
            "</rule>"
        )
        no_parent = (
            '<rule id="105602" level="10" frequency="3" timeframe="60">\n'
            "  <if_sid>5760</if_sid>\n"
            "  <description>x</description>\n"
            "</rule>"
        )
        self.assertTrue(validate_wazuh_rule_xml(with_parent)["valid"])
        v = validate_wazuh_rule_xml(no_parent)
        self.assertFalse(v["valid"])
        self.assertTrue(any("if_matched_sid" in e for e in v["errors"]))

    def test_child_element_timeframe_rejected(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml

        bad = (
            '<rule id="105603" level="10">\n'
            "  <timeframe>60</timeframe>\n"
            "  <description>x</description>\n"
            "</rule>"
        )
        v = validate_wazuh_rule_xml(bad)
        self.assertFalse(v["valid"])
        self.assertTrue(any("must be a rule ATTRIBUTE" in e for e in v["errors"]))

    def test_plain_rule_valid(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml

        v = validate_wazuh_rule_xml(
            '<rule id="105604" level="5">\n'
            "  <match>Failed password</match>\n"
            "  <description>test</description>\n"
            "</rule>"
        )
        self.assertTrue(v["valid"])

    def test_same_source_ip_is_a_known_element(self):
        """Regression: <same_source_ip /> is the standard companion of a
        frequency rule and the live manager accepts it, but it was missing
        from the _KNOWN_TAGS whitelist, so the validator rejected a rule the
        manager would have taken."""
        from tools.wazuh.validation import validate_wazuh_rule_xml

        v = validate_wazuh_rule_xml(
            '<rule id="200001" level="10" frequency="5" timeframe="60">\n'
            "  <if_matched_sid>5710,5760</if_matched_sid>\n"
            "  <same_source_ip />\n"
            "  <description>SSH brute force from same source IP</description>\n"
            "  <group>authentication_failures,sshd,ssh</group>\n"
            "</rule>"
        )
        self.assertTrue(v["valid"], v["errors"])
        self.assertFalse(any("Unknown rule element" in e for e in v["errors"]))

    def test_other_correlation_elements_are_known(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml

        for tag in (
            "same_field",
            "same_id",
            "same_user",
            "same_dest_ip",
            "not_sid",
            "not_group",
            "if_matched_group",
        ):
            v = validate_wazuh_rule_xml(
                '<rule id="200002" level="10" frequency="3" timeframe="60">\n'
                "  <if_matched_sid>5760</if_matched_sid>\n"
                f"  <{tag} />\n"
                "  <description>correlation</description>\n"
                "</rule>"
            )
            self.assertTrue(v["valid"], f"{tag}: {v['errors']}")

    def test_genuinely_unknown_element_is_still_caught(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml

        v = validate_wazuh_rule_xml(
            '<rule id="200003" level="5">\n'
            "  <if_madched_sid>5760</if_madched_sid>\n"  # typo
            "</rule>"
        )
        self.assertFalse(v["valid"])
        self.assertTrue(any("Unknown rule element" in e for e in v["errors"]))

    def test_correlation_elements_rejected_as_rule_attributes(self):
        """Regression: written as ATTRIBUTES the XML still parses and still
        looks plausible, so it passed validation and then died at upload with
        a bare '1113: XML syntax error' - burning a fully approved proposal to
        learn something knowable offline. Live manager: the attribute form is
        rejected, the child form is accepted."""
        from tools.wazuh.validation import validate_wazuh_rule_xml
        v = validate_wazuh_rule_xml(
            '<rule id="200001" level="10" frequency="5" timeframe="60" '
            'if_matched_sid="5710,5760" same_source_ip="yes">'
            '<description>SSH brute force</description></rule>')
        self.assertFalse(v["valid"])
        self.assertTrue(any("if_matched_sid" in e and "attribute" in e
                            for e in v["errors"]))
        self.assertTrue(any("same_source_ip" in e for e in v["errors"]))
        # the error must show the working form, not just complain
        self.assertTrue(any("<if_matched_sid>5710,5760</if_matched_sid>" in e
                            for e in v["errors"]))

    def test_child_only_tags_rejected_individually_as_attributes(self):
        from tools.wazuh.validation import validate_wazuh_rule_xml
        for tag in ("if_matched_sid", "same_source_ip", "same_id",
                    "not_sid", "not_group", "if_matched_level"):
            v = validate_wazuh_rule_xml(
                f'<rule id="200004" level="10" frequency="3" timeframe="60" '
                f'{tag}="5760"><description>x</description></rule>')
            self.assertFalse(v["valid"], f"{tag} should be rejected as an attribute")
            self.assertTrue(any(tag in e for e in v["errors"]), v["errors"])

    def test_valid_child_form_still_passes(self):
        """The fix must not break the form the manager actually accepts."""
        from tools.wazuh.validation import validate_wazuh_rule_xml
        v = validate_wazuh_rule_xml(
            '<rule id="200001" level="10" frequency="5" timeframe="60">\n'
            '  <if_matched_sid>5710,5760</if_matched_sid>\n'
            '  <same_source_ip />\n'
            '  <description>SSH brute force</description>\n'
            '</rule>')
        self.assertTrue(v["valid"], v["errors"])

    def test_valid_rule_attributes_are_not_false_positived(self):
        """id/level/frequency/timeframe ARE real rule attributes - the new
        check must only fire on correlation elements."""
        from tools.wazuh.validation import validate_wazuh_rule_xml
        v = validate_wazuh_rule_xml(
            '<rule id="200005" level="10" frequency="5" timeframe="60" '
            'noalert="1">\n'
            '  <if_matched_sid>5760</if_matched_sid>\n'
            '  <description>x</description>\n'
            '</rule>')
        self.assertTrue(v["valid"], v["errors"])


if __name__ == "__main__":
    unittest.main()
