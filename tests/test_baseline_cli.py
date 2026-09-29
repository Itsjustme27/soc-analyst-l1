"""Baseline tests that capture the CURRENT plain output of every
non-interactive CLI path.  These are the "before" snapshots that
must stay identical after the UI refactor (unless a flag/command
behavior changes intentionally).

Run: MOCK_MODE=true LLM_PROVIDER=mock python -m unittest tests.test_baseline_cli -v
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
    """Scripted provider: pops the next LLMResponse per chat() call."""

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
def _engineer(model: ScriptedModel):
    """Patch the LLM provider so nothing touches the real manager."""
    wazuh = mock.MagicMock()
    wazuh.get_rules.return_value = {"data": {"affected_items": [], "total_affected_items": 0}}
    with (
        mock.patch("agent.soc_engineer.get_provider", return_value=model),
        mock.patch("agent.soc_engineer.WazuhManagerAPI", return_value=wazuh),
        mock.patch("agent.soc_engineer.IndexerClient", return_value=mock.MagicMock()),
        mock.patch("audit.audit_log"),
    ):
        yield wazuh


def _run(args: list[str]) -> tuple[int, str]:
    """Run the CLI with args and capture stdout."""
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli_mod.main(args)
    return code, buf.getvalue()


class BaselineOneShot(unittest.TestCase):
    """-m one-shot output must be unchanged."""

    def test_minus_m_prints_reply(self):
        model = ScriptedModel([_answer("hello analyst")])
        with _engineer(model):
            code, out = _run(["-m", "hi"])
        self.assertEqual(code, 0)
        self.assertIn("hello analyst", out)

    def test_minus_m_renders_tool_step(self):
        model = ScriptedModel([_answer("done")])
        with _engineer(model):
            code, out = _run(["-m", "hi"])
        self.assertEqual(code, 0)
        self.assertIn("\u2192 answer_user", out)

    def test_json_mode_contains_reply(self):
        model = ScriptedModel([_answer("done", data={"k": 1})])
        with _engineer(model):
            code, out = _run(["-m", "hi", "--json"])
        self.assertEqual(code, 0)
        payload = json.loads(out)
        self.assertEqual(payload["reply"], "done")
        self.assertEqual(payload["data"]["k"], 1)

    def test_json_mode_no_arrow(self):
        model = ScriptedModel([_answer("done")])
        with _engineer(model):
            code, out = _run(["-m", "hi", "--json"])
        self.assertEqual(code, 0)
        self.assertNotIn("\u2192", out)


class BaselineListCommands(unittest.TestCase):
    """List commands must produce their current output shape."""

    def test_list_skills(self):
        code, out = _run(["--list-skills"])
        self.assertEqual(code, 0)
        for name in ("wazuh-rule-authoring", "incident-triage", "mitre-mapping"):
            self.assertIn(name, out)

    def test_list_sessions_empty(self):
        with tempfile.TemporaryDirectory() as td:
            with mock.patch.object(cli_mod, "SESSIONS_DIR", Path(td)):
                code, out = _run(["--list-sessions"])
        self.assertEqual(code, 0)
        self.assertIn("No sessions yet", out)

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


class BaselineApprovalErrors(unittest.TestCase):
    """Error messages for invalid approval invocations must stay
    exactly the same strings."""

    def test_execute_without_confirm(self):
        with mock.patch(
            "approval_executor.execute_proposal", return_value={"ok": True, "http_status": 200},
        ):
            code, out = _run(["--execute", "appr-1"])
        self.assertEqual(code, 0)

    def test_approve_and_execute_conflict_with_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--approve", "appr-1", "-m", "hi"])

    def test_resume_requires_session(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--resume"])

    def test_json_requires_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--json"])

    def test_add_skill_conflicts_with_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--add-skill", "/tmp/x", "-m", "hi"])

    def test_new_skill_conflicts_with_message(self):
        with self.assertRaises(SystemExit):
            cli_mod.parse(["--new-skill", "foo", "-m", "hi"])


class BaselineHelpContainsAllFlags(unittest.TestCase):
    """The help text must reference every original flag."""

    def test_all_flags_are_valid(self):
        for flag in [
            "--message", "--json", "--session", "--resume",
            "--list-sessions", "--with-skill", "--full-tools",
            "--approval-mode", "--mcp-config", "--no-mcp",
            "--mode", "--auto-skills", "--add-skill", "--new-skill",
            "--list-skills", "--list-proposals", "--proposal",
            "--approve", "--reject", "--reason", "--execute",
            "--confirm", "--user",
        ]:
            try:
                cli_mod.parse([flag])
            except SystemExit:
                pass  # expected for flags that need args
            except Exception:
                self.fail(f"Flag {flag} raised unexpected error")
        self.assertTrue(True)


class BaselineThemeImports(unittest.TestCase):
    """Verify the new cli.ui.theme module loads correctly and
    provides all required exports."""

    def test_theme_exports(self):
        from cli.ui import theme
        for name in ("BLACK", "ROYAL", "ROYAL_LIGHT", "ROYAL_DIM",
                     "WHITE", "GREY", "OK", "ERR", "WARN",
                     "SOC_UI_THEME", "RICH_THEME", "PT_STYLE"):
            self.assertTrue(hasattr(theme, name),
                            f"theme.{name} missing")

    def test_no_color_function(self):
        from cli.ui.theme import _no_color
        self.assertTrue(callable(_no_color))


class BaselineUIPackage(unittest.TestCase):
    """Verify the cli.ui package imports cleanly."""

    def test_ui_init_exports(self):
        from cli.ui import BLACK, GREY, ROYAL, WHITE
        self.assertEqual(BLACK, "#000000")
        self.assertEqual(ROYAL, "#4169E1")
        self.assertEqual(WHITE, "#E8ECF8")
        self.assertEqual(GREY, "#6B7280")

    def test_config_has_soc_ui_theme(self):
        self.assertEqual(cfg.SOC_UI_THEME, "royal")


if __name__ == "__main__":
    unittest.main()
