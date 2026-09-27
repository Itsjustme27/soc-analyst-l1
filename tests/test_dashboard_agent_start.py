"""Regression tests: watcher spawn (dashboard.py).

Covers the CodeQL Critical "Uncontrolled command line" finding on this
branch (dashboard.py:819). The start endpoints (`POST /api/agent/start`
and `POST /api/agents/start`) must never put external input on the
command line:

  * a user-supplied ``--siem`` selector is validated fail-closed against
    the same allowlist the watcher subprocess resolves (registered
    provider ids ∪ platform names) - anything else is rejected with 400,
    never sanitized or escaped;
  * argv stays a fully *static* list (python + run.py only): the
    validated selector and the sanitized agent id travel to the watcher
    in its process environment (SOC_WATCHER_*) - argument smuggling is
    impossible because no user data is ever part of the command line;
  * a hostile ``agent_id`` is still confined to the safe charset
    [A-Za-z0-9._-] by ``ac.sanitize_id()`` before it reaches the env;
  * the process is spawned with ``shell=False`` explicit.

Runs with MOCK_MODE only.
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
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

STATIC_CMD = [sys.executable, str(Path(dash.__file__).parent / "run.py")]


def _spawned(popen_mock) -> tuple[list, dict]:
    """Unpack (cmd, kwargs) captured at Popen without disturbing call order."""
    call = popen_mock.call_args
    return call.args[0], call.kwargs or {}


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

    def test_argv_is_fully_static_even_for_valid_start(self):
        """No user data may ever appear on the command line: argv is exactly
        [python, run.py] regardless of agent id or provider selector."""
        proc = mock.Mock()
        proc.pid = 4242
        with mock.patch.object(dash.subprocess, "Popen", return_value=proc) as popen:
            r = self.client.post(
                "/api/agents/start",
                json={"agent_id": "w1", "provider_id": "wazuh"},
            )
        self.assertEqual(r.status_code, 200)
        cmd, kwargs = _spawned(popen)
        self.assertEqual(cmd, STATIC_CMD)
        # the values are delivered via the environment, never via argv flags
        self.assertEqual(kwargs["env"]["SOC_WATCHER_AGENT_ID"], "w1")
        self.assertEqual(kwargs["env"]["SOC_WATCHER_SIEM"], "wazuh")
        self.assertNotIn("--agent-id", cmd)
        self.assertNotIn("--siem", cmd)
        self.assertIs(kwargs.get("shell"), False)

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
        cmd, kwargs = _spawned(popen)
        self.assertEqual(cmd, STATIC_CMD)
        env = kwargs["env"]
        aid = env["SOC_WATCHER_AGENT_ID"]
        self.assertRegex(aid, r"^[A-Za-z0-9._-]{1,64}$")
        self.assertNotIn(";", aid)
        self.assertNotIn("$", aid)
        self.assertNotIn("`", aid)
        self.assertEqual(env["SOC_WATCHER_SIEM"], "wazuh")
        self.assertIs(kwargs.get("shell"), False)

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
            cmd, kwargs = _spawned(popen)
            self.assertEqual(cmd, STATIC_CMD)
            self.assertEqual(kwargs["env"]["SOC_WATCHER_SIEM"], provider)
            self.assertEqual(kwargs["env"]["SOC_WATCHER_AGENT_ID"], f"watcher-{provider}")


if __name__ == "__main__":
    unittest.main()
