"""
Hermetic tests for the PHASE 14 live-validation framework.

These never touch a live Wazuh environment: clients are fakes and the
approval/audit stores are not written. The real live runs happen only through
`python scripts/live_validation.py --live`.

Run: MOCK_MODE=true python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from live_validation import scenarios as scen
from live_validation.env import LiveEnv
from live_validation.evidence import Evidence, EvidenceLog


# --------------------------------------------------------------------------- #
# fakes
# --------------------------------------------------------------------------- #
class FakeWazuh:
    def _authenticate(self):
        return "JWT " + "x" * 100

    def get(self, path, params=None):
        if path == "/manager/info":
            return {"data": {"affected_items": [{"version": "v4.14.7"}]}}
        if path == "/manager/status":
            return {
                "data": {
                    "affected_items": [
                        {
                            "wazuh-analysisd": "running",
                            "wazuh-db": "running",
                            "wazuh-remoted": "running",
                            "wazuh-authd": "running",
                            "wazuh-modulesd": "running",
                            "wazuh-apid": "running",
                        }
                    ]
                }
            }
        return {"data": {"affected_items": []}}

    def get_manager_status(self):
        return self.get("/manager/status")

    def get_rule(self, rule_id):
        return {"data": {"affected_items": [{"id": rule_id}]} if rule_id == 5760 else []}

    def get_rules(self, **kw):
        return {"data": {"affected_items": []}}

    def get_rules_file(self, filename, raw=False):
        return '<ruleset><rule id="100001" level="10"><match>x</match></rule></ruleset>'


class FakeIndexer:
    def search(self, index, body):
        return {"hits": {"total": {"value": 716}}}

    def count(self, index, query=None):
        return 0

    def hits(self, index, body):
        return []


class FakeKB:
    def counts(self):
        return {"playbooks": 0, "cases": 0, "lessons": 0, "wazuh_docs": 5}

    def query(self, collection, text, n_results=4, where=None):
        return [{"id": "d1", "text": "frequency rules", "metadata": {}, "distance": 0.9}]


def make_env(**kw) -> LiveEnv:
    env = LiveEnv(
        wazuh=FakeWazuh(),
        indexer=FakeIndexer(),
        dashboards=lambda method, path, **kw2: {"total": 0},
        approvals_path="/tmp/nonexistent-approvals.json",
        audit_path="/tmp/nonexistent-audit.jsonl",
        **kw,
    )
    env._kb = FakeKB()
    return env


# --------------------------------------------------------------------------- #
# evidence
# --------------------------------------------------------------------------- #
class EvidenceTests(unittest.TestCase):
    def test_invalid_result_kind_rejected(self):
        with self.assertRaises(ValueError):
            Evidence("s", "step", "t", "bogus_kind", True)

    def test_error_row_cannot_pass(self):
        with self.assertRaises(ValueError):
            Evidence("s", "step", "t", "error", True)

    def test_rollup_pass_and_fail(self):
        log = EvidenceLog()
        log.step("a", "ok", "t1", "wazuh_confirmed", True)
        log.step("a", "bad", "t2", "error", False, detail="boom")
        log.step("b", "ok", "t3", "wazuh_confirmed", True)
        st = log.scenario_status("a")
        self.assertEqual(st["status"], "FAIL")
        self.assertEqual(st["failed"], 1)
        self.assertEqual(st["failures"][0]["detail"], "boom")
        self.assertEqual(log.scenario_status("b")["status"], "PASS")
        self.assertFalse(log.all_pass())

    def test_matrix_and_json(self):
        log = EvidenceLog()
        log.step("a", "ok", "t1", "wazuh_confirmed", True)
        self.assertIn("a", log.matrix())
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            log.to_json(path)
            data = json.loads(Path(path).read_text())
            self.assertEqual(data["summary"]["a"]["status"], "PASS")
            self.assertTrue(data["all_pass"])
        finally:
            Path(path).unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# env: propose / execute gates
# --------------------------------------------------------------------------- #
class EnvGateTests(unittest.TestCase):
    def setUp(self):
        self.env = make_env()

    @mock.patch("tools.registry.execute")
    def test_propose_routes_through_registry(self, reg):
        reg.return_value = {
            "status": "approval_required",
            "proposal": {"id": "appr-test123", "action": "create_wazuh_rule"},
        }
        outcome = self.env.propose("create_wazuh_rule", {"rule_xml": "<x/>", "reason": "r"})
        self.assertEqual(outcome["status"], "approval_required")
        self.assertEqual(outcome["proposal"]["id"], "appr-test123")

    @mock.patch("tools.registry.execute")
    def test_execute_approved_rejects_unapproved(self, reg):
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {
                "id": "p1",
                "status": "pending",
                "permission": "propose",
                "payload": {},
            }
            out = self.env.execute_approved({"id": "p1"})
        self.assertFalse(out["ok"])
        reg.assert_not_called()

    @mock.patch("tools.registry.execute")
    def test_execute_approved_requires_confirm_for_execute(self, reg):
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {
                "id": "p1",
                "status": "approved",
                "permission": "execute",
                "payload": {},
            }
            out = self.env.execute_approved({"id": "p1"})
        self.assertFalse(out["ok"])
        self.assertIn("confirm", out["error"])
        reg.assert_not_called()

    @mock.patch("tools.registry.execute")
    def test_execute_approved_with_confirm_runs_and_sets_approval(self, reg):
        self.env.confirm_execute = True
        reg.return_value = {"status": "ok", "result": {"status": "executed"}}
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {
                "id": "p1",
                "status": "approved",
                "permission": "execute",
                "action": "restart_wazuh_manager",
                "payload": {"a": 1},
            }
            out = self.env.execute_approved({"id": "p1"})
        self.assertTrue(out["ok"])
        ctx = reg.call_args[0][0]
        self.assertEqual(ctx.approval["id"], "p1")
        self.assertEqual(reg.call_args[0][1], "restart_wazuh_manager")

    @mock.patch("tools.registry.execute")
    def test_execute_approved_treats_status_error_as_failure(self, reg):
        reg.return_value = {"status": "error", "error": "api exploded"}
        with mock.patch("approvals.get_proposal") as getp:
            getp.return_value = {
                "id": "p1",
                "status": "approved",
                "permission": "propose",
                "payload": {},
            }
            out = self.env.execute_approved({"id": "p1"})
        self.assertFalse(out["ok"])
        self.assertIn("api exploded", out["error"])

    def test_preflight_happy_path(self):
        self.assertEqual(self.env.preflight(), [])

    def test_preflight_collects_problems(self):
        env = LiveEnv(
            wazuh=mock.Mock(_authenticate=mock.Mock(side_effect=RuntimeError("nope"))),
            indexer=mock.Mock(search=mock.Mock(side_effect=Exception("es down"))),
            dashboards=mock.Mock(side_effect=RuntimeError("dash down")),
        )
        problems = env.preflight()
        self.assertTrue(any("manager API auth failed" in p for p in problems))
        self.assertTrue(any("indexer search failed" in p for p in problems))
        self.assertTrue(any("dashboards API failed" in p for p in problems))


# --------------------------------------------------------------------------- #
# scenarios (hermetic)
# --------------------------------------------------------------------------- #
class EnvBaselineScenarioTests(unittest.TestCase):
    def test_env_baseline_passes_with_fakes(self):
        env = make_env()
        log = scen.run_scenario(env, "env_baseline", {})
        st = log.scenario_status("env_baseline")
        self.assertEqual(st["status"], "PASS", st["failures"])


class DetectionScenarioTests(unittest.TestCase):
    def _proposal_from_params(self, pid, params, permission="propose", action="create_wazuh_rule"):
        return {
            "id": pid,
            "status": "pending",
            "permission": permission,
            "action": action,
            "payload": {
                "rule_xml": params["rule_xml"],
                "overwrite": False,
                "reason": params.get("reason", ""),
            },
        }

    def test_detection_stops_at_approval_gate_when_not_auto(self):
        env = make_env()

        def fake_propose(tool_name, params, agent="phase14-validator"):
            if tool_name == "develop_wazuh_rule":
                p = self._proposal_from_params("appr-det01", params)
                return {"status": "approval_required", "proposal": p}
            raise AssertionError(f"unexpected propose {tool_name}")

        with mock.patch.object(env, "propose", side_effect=fake_propose):
            log = scen.run_scenario(env, "detection_ssh_rule", {})
        st = log.scenario_status("detection_ssh_rule")
        self.assertEqual(st["status"], "PASS", st["failures"])
        # deployed-verify step must be the skipped-info variant
        rows = {i.step: i for i in log.scenario_items("detection_ssh_rule")}
        self.assertIn("deployment (auto-approve off)", rows)
        self.assertEqual(rows["deployment (auto-approve off)"].result_kind, "info")
        # proposal payload completeness was asserted true
        self.assertTrue(rows["proposal created (no auto-deploy)"].refs["payload_complete"])

    def test_detection_auto_approve_path(self):
        env = make_env(auto_approve=True, confirm_execute=True)
        restart_proposal = {
            "id": "appr-det03",
            "status": "approved",
            "permission": "execute",
            "action": "restart_wazuh_manager",
            "payload": {"reason": "restart"},
        }

        def fake_propose(tool_name, params, agent="phase14-validator"):
            if tool_name == "develop_wazuh_rule":
                p = self._proposal_from_params("appr-det02", params)
                return {"status": "approval_required", "proposal": p}
            if tool_name == "restart_wazuh_manager":
                return {"status": "approval_required", "proposal": restart_proposal}
            raise AssertionError(f"unexpected propose {tool_name}")

        results = iter(
            [
                {
                    "ok": True,
                    "result": {
                        "status": "executed",
                        "rule_id": 100905,
                        "restart_required": True,
                        "detail": "PUT ok",
                    },
                },
                {"ok": True, "result": {"status": "executed"}},
            ]
        )

        def get_rule(rid):
            # rule is only present once the scenario records it as deployed
            if rid == 5760 or rid in env.created_rules:
                return {"data": {"affected_items": [{"id": rid}]}}
            return {"data": {"affected_items": []}}

        with (
            mock.patch.object(env, "propose", side_effect=fake_propose),
            mock.patch.object(env, "approve", side_effect=lambda p, by=None: p),
            mock.patch.object(env, "execute_approved", side_effect=lambda p: next(results)),
            mock.patch.object(env, "wait_for_manager", return_value=True),
            mock.patch.object(env, "wait_for_logtest", return_value=True),
            mock.patch.object(env, "wait_for_rule", return_value=(True, "")),
            mock.patch.object(env.wazuh, "get_rule", side_effect=get_rule),
            mock.patch(
                "tools.registry.execute",
                return_value={
                    "rule_id": 100905,
                    "frequency_rule": True,
                    "positive_pass": "10/10",
                    "negative_pass": "1/1",
                    "verified": True,
                },
            ) as reg,
        ):
            log = scen.run_scenario(env, "detection_ssh_rule", {})
        st = log.scenario_status("detection_ssh_rule")
        self.assertEqual(st["status"], "PASS", st["failures"])
        rows = {i.step: i for i in log.scenario_items("detection_ssh_rule")}
        self.assertEqual(rows["rule deployment"].result_kind, "wazuh_confirmed")
        self.assertEqual(rows["manager restart"].result_kind, "wazuh_confirmed")
        self.assertTrue(rows["rule loaded after restart"].passed)
        self.assertTrue(rows["verify rule deployment"].passed)
        # verify_rule_deployment went through the real registry gate
        self.assertEqual(reg.call_args[0][1], "verify_rule_deployment")


class StreamedAlertScenarioTests(unittest.TestCase):
    def test_streamed_alert_full_chain(self):
        env = make_env()
        fed: dict[str, str] = {}

        def fake_feed(lines, **kw):
            fed["first"] = lines[0] if lines else ""
            return len(lines)

        # baseline(0) -> after-alert(3) -> after-cleanup(0)
        counts = iter([0, 3, 0])

        def fake_count(index, query):
            try:
                return next(counts)
            except StopIteration:
                return 0

        def fake_hits(index, body):
            fl = fed.get("first", "no marker yet")
            return [
                {
                    "id": "9001.1",
                    "rule": {"id": "5715", "level": 10, "description": "SSHD brute force"},
                    "full_log": fl,
                    "data": {"srcip": "203.0.113.60"},
                    "_id": "abc123",
                }
            ]

        with (
            mock.patch.object(env.indexer, "count", side_effect=fake_count),
            mock.patch.object(env.indexer, "hits", side_effect=fake_hits),
            mock.patch(
                "tools.registry.execute",
                side_effect=lambda ctx, tool, params, **kw: {
                    "rule_id": "5715",
                    "rule_level": 10,
                    "rule_description": "SSHD brute force",
                    "rule_groups": ["syslog", "sshd"],
                    "full_log": fed.get("first", ""),
                    "mitre": {},
                },
            ) as reg,
            mock.patch.object(env, "delete_by_query", return_value={"deleted": 3}),
        ):
            log = scen.run_scenario(env, "streamed_ssh_alert", {"feed": fake_feed})
        st = log.scenario_status("streamed_ssh_alert")
        self.assertEqual(st["status"], "PASS", st["failures"])
        rows = {i.step: i for i in log.scenario_items("streamed_ssh_alert")}
        self.assertEqual(rows["feed syslog events"].refs["sent"], 12)
        self.assertEqual(rows["alert observed in indexer"].refs["alert_id"], "9001.1")
        self.assertTrue(rows["why did alert trigger"].passed)
        self.assertTrue(rows["cleanup: delete_by_query marker"].passed)
        self.assertEqual(reg.call_args[0][1], "why_did_alert_trigger")


class SecurityScenarioTests(unittest.TestCase):
    def test_tool_args_rejections(self):
        env = make_env()
        # schema-level rejections happen in the registry before any client call
        with mock.patch.object(
            env,
            "propose",
            side_effect=[
                {"status": "error", "error": "rule_xml: required"},
                {"status": "error", "error": "rule_xml must be a string"},
                {"status": "error", "error": "Rule failed static validation"},
                {"status": "approval_required", "proposal": {"id": "appr-sec"}},
                {"status": "error", "error": "oversized"},
                {"status": "error", "error": "positive_samples: required"},
                {"status": "error", "error": "panels must reference visualization ids"},
                {"status": "error", "error": "panels must be a list"},
            ],
        ):
            log = scen.run_scenario(env, "security_tool_args", {})
        st = log.scenario_status("security_tool_args")
        self.assertEqual(st["status"], "PASS", st["failures"])
        for item in log.scenario_items("security_tool_args"):
            self.assertEqual(item.result_kind, "blocked", item.step)

    def test_query_safety_with_fakes(self):
        env = make_env()
        with mock.patch.object(
            env.wazuh, "get_rules", return_value={"data": {"affected_items": []}}
        ):
            log = scen.run_scenario(env, "security_query_safety", {})
        st = log.scenario_status("security_query_safety")
        self.assertEqual(st["status"], "PASS", st["failures"])


# --------------------------------------------------------------------------- #
# investigation / bypass / injection scenarios
# --------------------------------------------------------------------------- #
class InvestigationScenarioTests(unittest.TestCase):
    def test_ip_web_and_alert_follow_ups(self):
        env = make_env()

        def fake_exec(ctx, tool, params, **kw):
            if tool == "investigate_ip":
                if params.get("ip") == "45.124.37.241":
                    return {
                        "ip": "45.124.37.241",
                        "total_alerts": 42,
                        "max_level": 10,
                        "top_rules": [{"id": 5715, "hits": 40, "level": 10}],
                        "rule_groups": [("authentication_failures", 42)],
                        "mitre_techniques": ["T1110.001"],
                        "first_seen": "2026-09-24T00:00:00",
                        "last_seen": "2026-09-24T06:00:00",
                    }
                return {
                    "ip": "203.0.113.201",
                    "total_alerts": 0,
                    "max_level": None,
                    "top_rules": [],
                    "rule_groups": [],
                    "mitre_techniques": [],
                    "timeline": [],
                }
            if tool == "why_did_alert_trigger":
                return {
                    "rule_id": "5760",
                    "rule_level": 5,
                    "rule_description": "sshd: authentication failed.",
                    "rule_groups": ["syslog", "sshd"],
                    "full_log": "Oct 24 06:00:10 testhost sshd[1000]: Failed password for x",
                }
            return {"status": "ok"}

        def fake_count(index, query):
            if "sample-security" in index:
                return 500
            return 0

        with (
            mock.patch("tools.registry.execute", side_effect=fake_exec),
            mock.patch.object(env.indexer, "count", side_effect=fake_count),
            mock.patch.object(
                env.indexer,
                "hits",
                return_value=[
                    {
                        "id": "9000.1",
                        "rule": {"id": "5760"},
                        "full_log": "sshd failed",
                        "timestamp": "2026-09-24T06:00:00Z",
                    }
                ],
            ),
        ):
            logs = {
                name: scen.run_scenario(env, name, {})
                for name in (
                    "investigation_ip",
                    "investigation_web",
                    "investigation_existing_alert",
                )
            }
        for name, log in logs.items():
            st = log.scenario_status(name)
            self.assertEqual(st["status"], "PASS", (name, st["failures"]))

        rows = {i.step: i for i in logs["investigation_web"].scenario_items("investigation_web")}
        self.assertEqual(rows["real index web telemetry"].refs["count"], 0)
        self.assertEqual(rows["demo index web telemetry"].refs["count"], 500)
        self.assertEqual(rows["demo index web telemetry"].refs["provenance"], "demo")
        rows = {
            i.step: i
            for i in logs["investigation_existing_alert"].scenario_items(
                "investigation_existing_alert"
            )
        }
        self.assertTrue(rows["explain real alert"].passed)
        self.assertEqual(
            rows["explain real alert"].refs["doc_rule_id"],
            rows["explain real alert"].refs["explained_rule_id"],
        )

    def test_cold_ip_honesty(self):
        env = make_env()

        def fake_exec(ctx, tool, params, **kw):
            return {
                "ip": "203.0.113.201",
                "total_alerts": 0,
                "max_level": None,
                "top_rules": [],
                "rule_groups": [],
                "mitre_techniques": [],
                "timeline": [],
            }

        with mock.patch("tools.registry.execute", side_effect=fake_exec):
            log = scen.run_scenario(env, "investigation_ip", {})
        rows = {i.step: i for i in log.scenario_items("investigation_ip")}
        self.assertTrue(rows["investigate cold ip"].passed)
        self.assertIn("does NOT imply", rows["investigate cold ip"].detail)


class ApprovalBypassTests(unittest.TestCase):
    def test_write_gates_block_without_approval(self):
        env = make_env()
        env.confirm_execute = True  # CLI sets this under --auto-approve

        def fake_exec(ctx, tool, params, **kw):
            # registry gate: write tools demand approval, but the file is
            # never touched - the gate fires before any manager call
            if tool in ("create_wazuh_rule", "restart_wazuh_manager", "delete_wazuh_rule"):
                return {
                    "status": "approval_required",
                    "proposal": {
                        "id": f"appr-{tool}",
                        "action": tool,
                        "permission": "execute"
                        if tool in ("restart_wazuh_manager", "delete_wazuh_rule")
                        else "propose",
                        "payload": params or {},
                    },
                }
            return {"status": "ok"}

        with (
            mock.patch("tools.registry.execute", side_effect=fake_exec),
            mock.patch.object(
                env,
                "propose",
                return_value={
                    "status": "approval_required",
                    "proposal": {
                        "id": "appr-delete",
                        "action": "delete_wazuh_rule",
                        "permission": "execute",
                        "payload": {"rule_id": 424242},
                    },
                },
            ),
            mock.patch.object(
                env, "approve", side_effect=lambda p, by=None: {**p, "status": "approved"}
            ),
            mock.patch.object(
                env,
                "execute_approved",
                return_value={
                    "ok": False,
                    "error": "EXECUTE-level action: requires an explicit "
                    "confirmation on top of the approval",
                },
            ),
            mock.patch.object(
                env.wazuh,
                "get_rule",
                side_effect=lambda rid: {
                    "data": {"affected_items": [{"id": rid}]}
                    if rid in (5760, 100001, 424242)
                    else []
                },
            ),
        ):
            log = scen.run_scenario(env, "security_approval_bypass", {"bypass_rule_id": "424242"})
        st = log.scenario_status("security_approval_bypass")
        self.assertEqual(st["status"], "PASS", st["failures"])
        rows = {i.step: i for i in log.scenario_items("security_approval_bypass")}
        for step in (
            "create rule without approval",
            "restart without approval",
            "delete rule without approval",
            "nothing deleted",
            "no rule deployed",
            "execute without confirm",
            "refused execute left rule intact",
        ):
            self.assertTrue(rows[step].passed, step)
            self.assertEqual(rows[step].result_kind, "wazuh_confirmed", step)


class PromptInjectionTests(unittest.TestCase):
    def test_data_hygiene(self):
        env = make_env()
        log = scen.run_scenario(env, "security_prompt_injection", {})
        st = log.scenario_status("security_prompt_injection")
        self.assertEqual(st["status"], "PASS", st["failures"])


class SyslogListenerHelperTests(unittest.TestCase):
    def test_block_fallbacks_and_detection(self):
        env = make_env()
        # hermetic: simulate docker being unavailable -> no false positives
        with mock.patch.object(env, "docker_exec", side_effect=RuntimeError("no docker")):
            self.assertFalse(env.has_syslog_514())
        # block builder (docker inspect fails -> loopback-only allowed-ips,
        # one element per IP - Wazuh rejects comma lists with error 1237)
        block = env._syslog_remote_block()
        self.assertIn("<allowed-ips>127.0.0.1</allowed-ips>", block)
        self.assertNotIn("127.0.0.1,", block)
        self.assertIn("<connection>syslog</connection>", block)
        self.assertIn("<port>514</port>", block)
        self.assertIn("<protocol>udp</protocol>", block)
        # the removal regex must strip a block with multiple allowed-ips
        import re

        config = (
            "<ossec_config>\n  <remote>\n    <connection>secure</connection>\n  </remote>\n"
            + block
            + "</ossec_config>"
        )
        pat = (
            r"\s*<remote>\s*<connection>syslog</connection>\s*"
            r"<port>514</port>\s*<protocol>udp</protocol>\s*"
            r"(?:(?:<allowed-ips>[^<]+</allowed-ips>\s*)+)?</remote>"
        )
        stripped = re.sub(pat, "", config)
        self.assertNotIn("<connection>syslog</connection>", stripped)
        self.assertIn("<connection>secure</connection>", stripped)


class DashboardWorkflowTests(unittest.TestCase):
    def test_full_dashboard_chain(self):
        env = make_env()

        def fake_propose(tool_name, params):
            return {
                "status": "approval_required",
                "proposal": {
                    "id": "appr-dash",
                    "action": "design_detection_dashboard",
                    "permission": "propose",
                    "payload": {
                        k: params[k]
                        for k in ("title", "focus", "description", "reason")
                        if k in params
                    },
                    "generated_config": {
                        "title": params["title"],
                        "focus": params["focus"],
                        "index_pattern": "wazuh-alerts-*",
                        "visualizations": [{"slug": "a", "title": "t", "vis_type": "metric"}],
                        "panelsJSON": '[{"id":"vis-a","x":0,"y":0,"w":24,"h":15}]',
                    },
                },
            }

        def fake_exec(ctx, tool, params, **kw):
            if tool == "get_index_schema":
                return {"fields": [{"name": "rule.groups"}, {"name": "data.srcip"}]}
            if tool == "verify_opensearch_query":
                return {"valid": True, "matched": 42}
            if tool == "get_wazuh_dashboards":
                return {
                    "dashboards": [
                        {"id": "dash-1", "title": "PHASE14 validation 120101", "panels": 3}
                    ]
                }
            return {"status": "ok"}

        audit_rows = [
            {
                "tool": "design_detection_dashboard",
                "permission": "propose",
                "approval_status": "approved",
                "execution_status": "success",
                "result": "created",
            }
        ]

        with (
            mock.patch("tools.registry.execute", side_effect=fake_exec),
            mock.patch.object(env, "propose", side_effect=fake_propose),
            mock.patch.object(
                env, "approve", side_effect=lambda p, by=None: {**p, "status": "approved"}
            ),
            mock.patch.object(
                env,
                "execute_approved",
                return_value={
                    "ok": True,
                    "result": {
                        "dashboard_id": "dash-1",
                        "title": "PHASE14 validation 120101",
                        "visualizations": [{"slug": "a", "id": "vis-1"}],
                    },
                },
            ),
            mock.patch.object(env, "audit_rows", return_value=audit_rows),
        ):
            log = scen.run_scenario(env, "dashboard_workflow", {"focus": "ssh"})
        st = log.scenario_status("dashboard_workflow")
        self.assertEqual(st["status"], "PASS", st["failures"])
        rows = {i.step: i for i in log.scenario_items("dashboard_workflow")}
        self.assertTrue(rows["design dashboard proposal"].refs["payload_complete"])
        self.assertTrue(rows["dashboard creation"].passed)
        self.assertEqual(rows["dashboard creation"].refs["dashboard_id"], "dash-1")
        self.assertTrue(rows["dashboard exists with panels"].passed)
        self.assertTrue(rows["audit trail for create"].passed)
        self.assertIn("dash-1", env.created_dashboards)


class DetectionGapsTests(unittest.TestCase):
    def test_taxonomy_honesty(self):
        env = make_env()
        rows = [
            {
                "category": "ssh metrics",
                "key": "SSH unknown-user abuse",
                "state": "gap",
                "rules": 0,
                "alerts_seen": 0,
                "raw_events_seen": 12,
            },
            {
                "category": "ssh oddports",
                "key": "SSH odd ports",
                "state": "covered_no_events",
                "rules": 2,
                "alerts_seen": 0,
                "raw_events_seen": 0,
            },
            {
                "category": "ssh olympics",
                "key": "SSH olympics",
                "state": "unknown",
                "rules": 0,
                "alerts_seen": 0,
                "raw_events_seen": 0,
            },
        ]

        def fake_exec(ctx, tool, params, **kw):
            return {
                "target": "ssh",
                "time_range": "-7d",
                "coverage": rows,
                "gap_candidates": [r for r in rows if r["state"] in ("gap", "partial")],
                "summary": "1 category needs attention",
            }

        with mock.patch("tools.registry.execute", side_effect=fake_exec):
            log = scen.run_scenario(env, "detection_gaps", {"gaps_target": "ssh"})
        st = log.scenario_status("detection_gaps")
        self.assertEqual(st["status"], "PASS", st["failures"])
        items = log.scenario_items("detection_gaps")
        notes = {i.step: i.detail for i in items}
        self.assertIn("clear detection-gap candidate", notes["gap row: SSH unknown-user abuse"])
        self.assertIn("NOT proof of detection", notes["gap row: SSH odd ports"])


class CliTests(unittest.TestCase):
    def test_refuses_without_live_flag(self):
        from live_validation.cli import main

        with mock.patch("config.cfg.MOCK_MODE", False):
            self.assertEqual(main(["--scenario", "env_baseline"]), 2)

    def test_refuses_in_mock_mode(self):
        from live_validation.cli import main

        with mock.patch("config.cfg.MOCK_MODE", True):
            self.assertEqual(main(["--live"]), 2)

    @mock.patch("live_validation.env.LiveEnv")
    @mock.patch("live_validation.scenarios.run_scenario")
    @mock.patch("config.cfg.MOCK_MODE", False)
    def test_happy_path_writes_evidence(self, run_scenario, live_env_cls):
        from live_validation.cli import main

        env_instance = mock.Mock()
        env_instance.preflight.return_value = []
        live_env_cls.return_value = env_instance
        slog = EvidenceLog()
        slog.step("env_baseline", "ok", "t", "wazuh_confirmed", True)
        run_scenario.return_value = slog
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "evidence.json"
            rc = main(["--live", "--scenario", "env_baseline", "--out", str(out)])
            self.assertEqual(rc, 0)
            data = json.loads(out.read_text())
            self.assertEqual(data["summary"]["env_baseline"]["status"], "PASS")

    @mock.patch("live_validation.env.LiveEnv")
    @mock.patch("config.cfg.MOCK_MODE", False)
    def test_unknown_scenario_exits_2(self, live_env_cls):
        from live_validation.cli import main

        live_env_cls.return_value.preflight.return_value = []
        self.assertEqual(main(["--live", "--scenario", "does_not_exist"]), 2)


if __name__ == "__main__":
    unittest.main()
