"""Misconfiguration must produce a message that names the fix, not a
misleading one (audit 2026-09-28)."""

from __future__ import annotations

import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

from tools.base import ToolError  # noqa: E402


class TestIndexerNotConfigured(unittest.TestCase):
    def test_empty_host_raises_a_clear_error_before_any_request(self):
        from connectors.siem.wazuh import WazuhConnector, WazuhNotConfigured

        conn = WazuhConnector(name="t", config={"host": ""})
        conn.host = ""
        with mock.patch("connectors.siem.wazuh.requests") as req:
            with self.assertRaises(WazuhNotConfigured) as cm:
                conn.post_field_caps_search({}, "wazuh-alerts-*")
            req.post.assert_not_called()
            req.get.assert_not_called()
        self.assertIn("WAZUH_HOST", str(cm.exception))


class TestRuleIdCheck(unittest.TestCase):
    XML = (
        '<rule id="105557" level="10"><if_sid>5760</if_sid>'
        "<match>Failed password</match><description>x</description></rule>"
    )

    def _run(self, get_rules):
        from tools.base import ToolContext
        from tools.detection.detection_engine import DevelopWazuhRule

        wazuh = mock.MagicMock()
        wazuh.get_rules.side_effect = get_rules
        ctx = ToolContext(wazuh=wazuh, indexer=mock.MagicMock())
        return DevelopWazuhRule().run(
            ctx,
            rule_xml=self.XML,
            positive_samples=["sshd: Failed password for root"],
            negative_samples=[],
            reason="r",
        )

    def test_unreachable_manager_says_so_instead_of_already_exists(self):
        def boom(**kw):
            raise ConnectionError("connection refused")

        with self.assertRaises(ToolError) as cm:
            self._run(boom)
        msg = str(cm.exception)
        self.assertNotIn("already exists", msg)
        self.assertIn("isn't reachable", msg)
        self.assertIn("WAZUH_API_URL", msg)

    def test_a_real_collision_still_blocks(self):
        with self.assertRaises(ToolError) as cm:
            self._run(lambda **kw: {"data": {"affected_items": [{"id": 105557}]}})
        self.assertIn("already exists", str(cm.exception))


if __name__ == "__main__":
    unittest.main()


class TestRepoHygiene(unittest.TestCase):
    """.mcp.json kept coming back into the repo (it auto-starts the test fixture
    server, whose tool returns an injection payload, for every CLI user)."""

    def test_mcp_config_is_an_example_and_ignored(self):
        import subprocess
        from pathlib import Path

        root = Path(__file__).resolve().parent.parent
        tracked = subprocess.run(["git", "ls-files", ".mcp.json"], cwd=root, capture_output=True, text=True)
        if tracked.returncode != 0:
            self.skipTest("not a git checkout")
        self.assertEqual(tracked.stdout.strip(), "", ".mcp.json must not be committed - use .mcp.json.example")
        self.assertTrue((root / ".mcp.json.example").exists())
        self.assertIn(".mcp.json", (root / ".gitignore").read_text().splitlines())
