"""End-to-end MCP test against the real stdio fixture server
(tests/fixtures/mcp_threatintel_server.py). Skipped when the optional `mcp`
package isn't installed; CI installs requirements-mcp.txt so it runs there."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import guard  # noqa: E402
from cli.mcp_client import MCPManager, mcp_available  # noqa: E402
from llm.base import LLMResponse, ToolCall  # noqa: E402

FIXTURE = str(Path(__file__).parent / "fixtures" / "mcp_threatintel_server.py")


@unittest.skipUnless(mcp_available(), "optional 'mcp' package not installed")
class TestMCPEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mgr = MCPManager(
            {"ti": {"command": sys.executable, "args": [FIXTURE], "read_only_tools": ["lookup_ip"]}}
        )
        errors = cls.mgr.start_all()
        assert errors == {"ti": None}, errors

    @classmethod
    def tearDownClass(cls):
        cls.mgr.close()

    def test_tools_listed_with_operator_declared_read_only(self):
        tools = {t.id: t.read_only for t in self.mgr.tools()}
        self.assertEqual(tools, {"mcp__ti__lookup_ip": True, "mcp__ti__block_ip": False})

    def test_call_returns_text(self):
        out = self.mgr.call("mcp__ti__lookup_ip", {"ip": "1.2.3.4"})
        self.assertFalse(out["is_error"])
        self.assertIn("1.2.3.4", out["text"])

    def _middleware(self, approver):
        from cli.middleware import AgentLLM, MiddlewareConfig

        class Scripted:
            def __init__(self, script):
                self.script, self.calls = list(script), []

            def chat(self, *, system, messages, tools, max_tokens, **kw):
                self.calls.append([dict(m) for m in messages])
                return self.script.pop(0)

        return Scripted, AgentLLM, MiddlewareConfig

    def test_read_tool_output_reaches_model_wrapped(self):
        Scripted, AgentLLM, MiddlewareConfig = self._middleware(None)
        inner = Scripted(
            [
                LLMResponse(
                    tool_calls=[
                        ToolCall(id="1", name="mcp__ti__lookup_ip", input={"ip": "1.2.3.4"})
                    ]
                ),
                LLMResponse(content="done"),
            ]
        )
        llm = AgentLLM(inner, MiddlewareConfig(mcp=self.mgr))
        with mock.patch("audit.audit_log"):
            llm.chat(
                system="s",
                messages=[{"role": "user", "content": "check 1.2.3.4"}],
                tools=[],
                max_tokens=10,
            )
        tool_msg = inner.calls[1][-1]["content"]
        self.assertTrue(guard.is_wrapped(tool_msg, "TOOL_OUTPUT"))
        # the fixture's forged close tag must not survive as a real boundary
        self.assertTrue(guard.assert_no_instruction_confusion(tool_msg))

    def test_write_tool_refused_without_approval(self):
        Scripted, AgentLLM, MiddlewareConfig = self._middleware(None)
        inner = Scripted(
            [
                LLMResponse(
                    tool_calls=[ToolCall(id="1", name="mcp__ti__block_ip", input={"ip": "1.2.3.4"})]
                ),
                LLMResponse(content="ok"),
            ]
        )
        llm = AgentLLM(inner, MiddlewareConfig(mcp=self.mgr, mcp_approver=None))
        with (
            mock.patch("audit.audit_log") as audit_log,
            mock.patch.object(self.mgr, "call") as call,
        ):
            llm.chat(
                system="s",
                messages=[{"role": "user", "content": "block it"}],
                tools=[],
                max_tokens=10,
            )
        call.assert_not_called()
        self.assertIn(
            "did not approve", json.loads(guard.unwrap(inner.calls[1][-1]["content"]))["error"]
        )
        self.assertEqual(audit_log.call_args.kwargs["approval_status"], "denied")


if __name__ == "__main__":
    unittest.main()
