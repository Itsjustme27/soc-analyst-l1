"""
Tests for the terminal agent (scripts_engineer_cli.py).

Drives the REAL CLI entry point (argparse -> EngineerCLI -> SOCEngineer) with
a scripted LLM provider, so the wiring under test is exactly what an operator
runs. The real tool loop and registry are exercised in test 4 (live step
rendering) with a stubbed Wazuh API; audit writes are mocked so tests never
touch data/*.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import scripts_engineer_cli as cli_mod  # noqa: E402
from config import cfg  # noqa: E402
from llm.base import LLMResponse, ToolCall  # noqa: E402


def _answer(message: str, data: dict | None = None) -> LLMResponse:
    return LLMResponse(
        tool_calls=[
            ToolCall(
                id="t",
                name="answer_user",
                input={"answer": message, "data": data or {}},
            )
        ]
    )


class ScriptedModel:
    """Scripted provider: pops the next LLMResponse per chat() call, or fails."""

    def __init__(self, script, fail=False):
        self.script = list(script)
        self.fail = fail
        self.calls: list[dict] = []

    def chat(self, *, system, messages, tools, max_tokens, **kw):
        self.calls.append({"system": system, "messages": list(messages)})
        if self.fail:
            raise RuntimeError("gateway down")
        return self.script.pop(0)


@contextmanager
def _engineer(model: ScriptedModel, wazuh: mock.MagicMock | None = None):
    """Patch the LLM provider + SIEM clients + audit so nothing touches the
    real manager, chroma, or data/* audit files. Yields (wazuh, audit_mock)."""
    wazuh = wazuh or mock.MagicMock()
    wazuh.get_rules.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
    with (
        mock.patch("agent.soc_engineer.get_provider", return_value=model),
        mock.patch("agent.soc_engineer.WazuhManagerAPI", return_value=wazuh),
        mock.patch("agent.soc_engineer.IndexerClient", return_value=mock.MagicMock()),
        mock.patch("audit.audit_log") as am,
    ):
        yield wazuh, am


def _run(args: list[str]) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_mod.main(args)
    return code, buf.getvalue()


class TestCliOneShot(unittest.TestCase):
    def test_one_shot_reply_exit_zero(self):
        model = ScriptedModel([_answer("hello analyst")])
        with _engineer(model):
            code, out = _run(["-m", "hi"])
        self.assertEqual(code, 0)
        self.assertIn("hello analyst", out)

    def test_every_turn_is_audited_with_skills_and_session(self):
        model = ScriptedModel([_answer("done")])
        with _engineer(model) as (_, am):
            code, _ = _run(["-m", "hi", "--with-skill", "mitre-mapping", "--session", "s1"])
        self.assertEqual(code, 0)
        cli_rows = [c for c in am.call_args_list if c.kwargs.get("tool") == "cli"]
        self.assertEqual(len(cli_rows), 1)
        row = cli_rows[0]
        self.assertEqual(row.kwargs["action"], "engineer_turn")
        self.assertEqual(row.kwargs["params"]["session"], "s1")
        self.assertIn("mitre-mapping", row.kwargs["params"]["skills"])
        self.assertEqual(row.kwargs["agent"], "soc_engineer_cli")

    def test_answer_user_step_is_rendered_live(self):
        model = ScriptedModel([_answer("done")])
        with _engineer(model):
            code, out = _run(["-m", "hi"])
        self.assertEqual(code, 0)
        self.assertIn("\u2192 answer_user", out)

    def test_llm_failure_exits_two(self):
        model = ScriptedModel([], fail=True)
        with _engineer(model):
            code, out = _run(["-m", "hi"])
        self.assertEqual(code, 2)
        self.assertIn("provider failed", out)

    def test_tool_budget_exhaustion_exits_two(self):
        # a model that never terminates: after MAX_TOOL_TURNS the loop yields
        # the budget reply (unknown tool -> error result, loop continues).
        script = [
            LLMResponse(tool_calls=[ToolCall(id="t", name="not_a_real_tool", input={})])
            for _ in range(12)
        ]
        model = ScriptedModel(script)
        with _engineer(model):
            code, out = _run(["-m", "hi"])
        self.assertEqual(code, 2)
        self.assertIn("tool budget", out)

    def test_json_mode_output_shape(self):
        model = ScriptedModel([_answer("done", data={"k": 1})])
        with _engineer(model):
            code, out = _run(["-m", "hi", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["reply"], "done")
        self.assertEqual(payload["data"]["k"], 1)
        self.assertIn("transcript", payload)
        self.assertNotIn("\u2192", out)  # no live rendering in json mode


class TestCliSkills(unittest.TestCase):
    def test_list_skills_prints_packs(self):
        code, out = _run(["--list-skills"])
        self.assertEqual(code, 0)
        for name in ("wazuh-rule-authoring", "incident-triage", "mitre-mapping"):
            self.assertIn(name, out)

    def test_skills_injected_into_system_prompt(self):
        model = ScriptedModel([_answer("ok")])
        with _engineer(model):
            code, _ = _run(["-m", "hi", "--with-skill", "mitre-mapping"])
        self.assertEqual(code, 0)
        self.assertIn("<SKILL name='mitre-mapping'", model.calls[0]["system"])
        self.assertIn("UNTRUSTED DATA", model.calls[0]["system"])
        self.assertIn("T1110", model.calls[0]["system"])

    def test_unknown_skill_fails_fast_exit_one(self):
        code, out = _run(["-m", "hi", "--with-skill", "missing-pack"])
        self.assertEqual(code, 1)
        self.assertIn("missing-pack", out)


class TestCliSessions(unittest.TestCase):
    def test_session_persists_and_resumes(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(cli_mod, "SESSIONS_DIR", Path(td)):
                model = ScriptedModel([_answer("first answer")])
                with _engineer(model):
                    code, _ = _run(["-m", "analyze sshd", "--session", "ssh"])
                self.assertEqual(code, 0)
                path = Path(td) / "ssh.jsonl"
                self.assertTrue(path.exists())
                rows = [json.loads(l) for l in path.read_text().splitlines()]
                self.assertEqual(rows[0]["user"], "analyze sshd")
                self.assertEqual(rows[0]["reply"], "first answer")

                # resume from the persisted turn
                args = cli_mod.parse(["--session", "ssh", "--resume"])
                cli = cli_mod.EngineerCLI(args)
                self.assertTrue(cli.history)
                self.assertEqual(cli.history[0]["role"], "user")
                self.assertEqual(cli.history[0]["content"], "analyze sshd")

    def test_list_sessions(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(cli_mod, "SESSIONS_DIR", Path(td)):
                code, out = _run(["--list-sessions"])
                self.assertEqual(code, 0)
                self.assertIn("No sessions yet", out)


class TestCliProposals(unittest.TestCase):
    def test_list_proposals_pending(self):
        with mock.patch(
            "approvals.list_proposals",
            return_value=[
                {
                    "id": "appr-1",
                    "action": "create_wazuh_rule",
                    "status": "pending",
                    "permission": "propose",
                    "created_at": "2026-01-01T00:00:00",
                    "reason": "detect web shell",
                }
            ],
        ):
            code, out = _run(["--list-proposals", "pending"])
        self.assertEqual(code, 0)
        self.assertIn("appr-1", out)
        self.assertIn("create_wazuh_rule", out)

    def test_approve_flag_wires_approvals(self):
        with (
            mock.patch(
                "approvals.approve", return_value={"id": "appr-1", "status": "approved"}
            ) as ap,
            mock.patch("approvals.public_view", side_effect=lambda r: r),
            mock.patch("audit.audit_log") as am,
        ):
            code, _ = _run(["--approve", "appr-1"])
        self.assertEqual(code, 0)
        ap.assert_called_once_with(
            "appr-1", by=cfg.ENGINE_USER, identity_verified=False, path=cfg.APPROVALS_PATH
        )
        # the human approval act itself lands in the audit trail (UI parity)
        approved = [c for c in am.call_args_list if c.kwargs.get("action") == "proposal_approved"]
        self.assertEqual(len(approved), 1)
        self.assertEqual(approved[0].kwargs["tool"], "approval_center")
        self.assertEqual(approved[0].kwargs["permission"], "human")
        self.assertEqual(approved[0].kwargs["result"]["proposal_id"], "appr-1")
        self.assertEqual(approved[0].kwargs["result"]["by"], cfg.ENGINE_USER)

    def test_approve_policy_denial_is_friendly(self):
        import approvals as approvals_mod

        def _deny(*a, **kw):
            raise approvals_mod.ApprovalPolicyError("no self-approval")

        with mock.patch("approvals.approve", side_effect=_deny), mock.patch("audit.audit_log"):
            code, out = _run(["--approve", "appr-1"])
        self.assertEqual(code, 1)
        self.assertIn("policy", out)

    def test_execute_forwards_confirm_flag(self):
        with (
            mock.patch(
                "approval_executor.execute_proposal", return_value={"ok": True, "http_status": 200}
            ) as ex,
            mock.patch("approvals.get_proposal"),
        ):
            code_no, _ = _run(["--execute", "appr-1"])
            code_yes, _ = _run(["--execute", "appr-1", "--confirm"])
        self.assertEqual(code_no, 0)
        self.assertEqual(code_yes, 0)
        self.assertFalse(ex.call_args_list[0].kwargs["confirm"])
        self.assertTrue(ex.call_args_list[1].kwargs["confirm"])


class TestCliArgparse(unittest.TestCase):
    def test_json_requires_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--json"])

    def test_resume_requires_session(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--resume"])

    def test_approve_conflicts_with_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--approve", "appr-1", "-m", "hi"])


class TestCliLiveToolStep(unittest.TestCase):
    def test_tool_call_rendered_and_executed(self):
        script = [
            LLMResponse(tool_calls=[ToolCall(id="t1", name="get_wazuh_rules", input={"limit": 1})]),
            _answer("rules listed"),
        ]
        model = ScriptedModel(script)
        with _engineer(model) as (wazuh, _):
            code, out = _run(["-m", "list rules"])
        self.assertEqual(code, 0)
        self.assertIn("\u2192 get_wazuh_rules", out)
        self.assertIn("rules listed", out)
        wazuh.get_rules.assert_called_once()


class TestCliSkillOps(unittest.TestCase):
    def test_add_skill_flag_installs_into_skills_root(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as root:
            src = Path(td) / "stealth-rule"
            src.mkdir()
            (src / "SKILL.md").write_text(
                "---\nname: stealth-rule\ndescription: stealthy detection\nversion: 1.0.0\n---\n# Stealth\nDetect stealthy stuff.\n",
                encoding="utf-8",
            )
            with mock.patch("agent.skills.DEFAULT_SKILLS_ROOT", Path(root)):
                code, out = _run(["--add-skill", str(src)])
            self.assertEqual(code, 0)
            self.assertIn("installed skill stealth-rule", out)
            self.assertTrue((Path(root) / "stealth-rule" / "SKILL.md").exists())

    def test_add_skill_flag_rejects_bad_source(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as root:
            with mock.patch("agent.skills.DEFAULT_SKILLS_ROOT", Path(root)):
                code, out = _run(["--add-skill", td])
            self.assertEqual(code, 1)
            self.assertIn("not a skill pack", out)

    def test_new_skill_flag_scaffolds_template(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch("agent.skills.DEFAULT_SKILLS_ROOT", Path(td)):
                code, out = _run(["--new-skill", "dns-triage"])
            self.assertEqual(code, 0)
            self.assertIn("scaffolded", out)
            md = Path(td) / "dns-triage" / "SKILL.md"
            self.assertTrue(md.exists())
            self.assertIn("name: dns-triage", md.read_text(encoding="utf-8"))

    def test_add_skill_conflicts_with_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--add-skill", "/tmp/x", "-m", "hi"])


class TestCliRejectDetail(unittest.TestCase):
    def test_reject_flag_wires_and_audits(self):
        with (
            mock.patch(
                "approvals.reject", return_value={"id": "appr-1", "status": "rejected"}
            ) as rj,
            mock.patch("approvals.public_view", side_effect=lambda r: r),
            mock.patch("audit.audit_log") as am,
        ):
            code, _ = _run(["--reject", "appr-1", "--reason", "too noisy"])
        self.assertEqual(code, 0)
        rj.assert_called_once_with(
            "appr-1", by=cfg.ENGINE_USER, reason="too noisy", path=cfg.APPROVALS_PATH
        )
        rej = [c for c in am.call_args_list if c.kwargs.get("action") == "proposal_rejected"]
        self.assertEqual(len(rej), 1)
        self.assertEqual(rej[0].kwargs["result"]["reason"], "too noisy")
        self.assertEqual(rej[0].kwargs["permission"], "human")

    def test_proposal_detail_flag(self):
        with mock.patch(
            "approvals.get_proposal",
            return_value={
                "id": "appr-1",
                "action": "create_wazuh_rule",
                "generated_config": "<rule/>",
                "validation": {"valid": True},
            },
        ):
            code, out = _run(["--proposal", "appr-1"])
        self.assertEqual(code, 0)
        self.assertIn("appr-1", out)
        self.assertIn("<rule/>", out)

    def test_proposal_detail_not_found(self):
        with mock.patch("approvals.get_proposal", return_value=None):
            code, out = _run(["--proposal", "missing"])
        self.assertEqual(code, 1)
        self.assertIn("not found", out)


class TestCliAutoSkills(unittest.TestCase):
    def test_auto_skills_inject_suggestion_and_audit(self):
        model = ScriptedModel([_answer("done")])
        with _engineer(model) as (_, am):
            code, out = _run(["-m", "detect sshd brute force", "--auto-skills"])
        self.assertEqual(code, 0)
        self.assertIn("<SKILL name='mitre-mapping'", model.calls[0]["system"])
        self.assertIn("auto-activated skills: mitre-mapping", out)
        rows = [c for c in am.call_args_list if c.kwargs.get("tool") == "cli"]
        self.assertEqual(rows[0].kwargs["params"]["auto_skills"], ["mitre-mapping"])

    def test_auto_skills_off_by_default(self):
        model = ScriptedModel([_answer("done")])
        with _engineer(model) as (_, am):
            code, _ = _run(["-m", "detect sshd brute force"])
        self.assertEqual(code, 0)
        self.assertNotIn("<SKILL", model.calls[0]["system"])
        rows = [c for c in am.call_args_list if c.kwargs.get("tool") == "cli"]
        self.assertEqual(rows[0].kwargs["params"]["auto_skills"], [])


class TestCliTerminalOps(unittest.TestCase):
    def _cli(self):
        return cli_mod.EngineerCLI(
            mock.MagicMock(
                user="analyst",
                with_skill=[],
                session=None,
                resume=False,
                json=False,
                auto_skills=False,
            )
        )

    def test_pending_count_reads_approvals_store(self):
        cli = self._cli()
        with mock.patch("approvals.list_proposals", return_value=[{"id": "x"}]):
            self.assertEqual(cli._pending_count(), 1)
        with mock.patch("approvals.list_proposals", return_value=[]):
            self.assertEqual(cli._pending_count(), 0)

    def test_manager_status_runs_read_tool(self):
        wazuh = mock.MagicMock()
        wazuh.get_manager_status.return_value = {
            "data": {
                "affected_items": [
                    {
                        "wazuh-analysisd": "running",
                        "wazuh-db": "running",
                        "wazuh-csyslogd": "stopped",
                    }
                ]
            }
        }
        wazuh.base_url = "https://mock:55000"
        model = ScriptedModel([])  # never called - /status does not chat
        with _engineer(model, wazuh=wazuh) as (_ctx_wazuh, _):
            cli = self._cli()
            buf = io.StringIO()
            with redirect_stdout(buf):
                cli._manager_status()
            out = buf.getvalue()
        self.assertIn("manager: https://mock:55000", out)
        self.assertIn("running: wazuh-analysisd, wazuh-db", out)
        self.assertIn("stopped: wazuh-csyslogd", out)
        wazuh.get_manager_status.assert_called_once()


class TestCliFindToolsRender(unittest.TestCase):
    """Regression for scripts_engineer_cli.py:410: the find_tools event line
    used a \\u2026 escape inside an f-string *expression* part, which is a
    SyntaxError on Python 3.11 (only legal from 3.12+, PEP 701). The literal
    now lives outside the expression; these tests pin the rendered output."""

    def _render(self, found: list[str]) -> str:
        cli = cli_mod.EngineerCLI.__new__(cli_mod.EngineerCLI)
        cli.json_mode = False
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli._on_event("find_tools", {"query": "ssh brute force", "found": found})
        return buf.getvalue()

    def test_fewer_than_seven_results_no_ellipsis(self):
        out = self._render(["a", "b", "c"])
        self.assertTrue(out.endswith("a, b, c\n"), out)
        self.assertNotIn("\u2026", out)

    def test_empty_results_render_nothing(self):
        out = self._render([])
        self.assertTrue(out.endswith("nothing\n"), out)
        self.assertNotIn("\u2026", out)

    def test_more_than_six_results_truncate_with_ellipsis(self):
        out = self._render(["a", "b", "c", "d", "e", "f", "g"])
        self.assertTrue(out.endswith("a, b, c, d, e, f \u2026\n"), out)


if __name__ == "__main__":
    unittest.main()
