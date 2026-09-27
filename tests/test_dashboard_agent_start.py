"""Regression tests: watcher spawn command line (dashboard.py).

Covers the CodeQL Critical "Uncontrolled command line" finding on this
branch (dashboard.py:819). The spawn command (`POST /api/agent/start` and
`POST /api/agents/start`) must never accept arbitrary user input:

  * a user-supplied ``--siem`` value is validated fail-closed against the
    same allowlist the watcher subprocess itself resolves (registered
    provider ids ∪ platform names) - anything else is rejected with 400,
    never sanitized or escaped;
  * a hostile ``agent_id`` is neutralized to the safe charset
    [A-Za-z0-9._-] by ``ac.sanitize_id()`` before it enters argv;
  * the process is spawned as an argv list with ``shell=False`` explicit.

Runs with MOCK_MODE only.
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import dashboard as dash  # noqa: E402
from dashboard import app  # noqa: E402

# Shell metacharacters the review asked the tests to smuggle.
METACHAR_PAYLOADS = [
    "wazuh; id > /tmp/pwned",
    "wazuh | sh",
    "wazuh$(id)",
    "wazuh`id`",
    "wazuh & echo pwned",
    "$(reboot)",
    "mock && rm -rf /",
]


class AgentStartCommandLine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_smuggled_provider_metachars_rejected_fail_closed(self):
        proc = mock.Mock()
        proc.pid = 4242
        for payload in METACHAR_PAYLOADS:
            with mock.patch.object(dash.subprocess, "Popen", return_value=proc) as popen:
                r = self.client.post(
                    "/api/agents/start",
                    json={"agent_id": "w1", "provider_id": payload},
                )
            self.assertEqual(r.status_code, 400, payload)
            popen.assert_not_called()
            with mock.patch.object(dash.subprocess, "Popen", return_value=proc) as popen:
                r = self.client.post("/api/agent/start", json={"provider_id": payload})
            self.assertEqual(r.status_code, 400, payload)
            popen.assert_not_called()

    def test_smuggled_agent_id_is_neutralized_not_passed_through(self):
        proc = mock.Mock()
        proc.pid = 4242
        with mock.patch.object(dash.subprocess, "Popen", return_value=proc) as popen:
            r = self.client.post(
                "/api/agents/start",
                json={
                    "agent_id": "sq; rm -rf / tmp$(reboot)`id`",
                    "provider_id": "wazuh",
                },
            )
        self.assertEqual(r.status_code, 200)
        cmd = popen.call_args.args[0]
        self.assertIsInstance(cmd, list)
        aid = cmd[cmd.index("--agent-id") + 1]
        self.assertRegex(aid, r"^[A-Za-z0-9._-]{1,64}$")
        self.assertNotIn(";", aid)
        self.assertNotIn("$", aid)
        self.assertNotIn("`", aid)
        self.assertEqual(cmd[cmd.index("--siem") + 1], "wazuh")
        self.assertIs(popen.call_args.kwargs.get("shell"), False)

    def test_valid_platform_and_provider_selectors_still_accepted(self):
        proc = mock.Mock()
        proc.pid = 4242
        for provider in ("wazuh", "mock", "env-mock"):
            with mock.patch.object(dash.subprocess, "Popen", return_value=proc) as popen:
                r = self.client.post(
                    "/api/agents/start",
                    json={"agent_id": f"watcher-{provider}", "provider_id": provider},
                )
            self.assertEqual(r.status_code, 200, provider)
            cmd = popen.call_args.args[0]
            self.assertEqual(cmd[cmd.index("--siem") + 1], provider)


if __name__ == "__main__":
    unittest.main()
