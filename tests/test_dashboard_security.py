"""Regression tests: no stack-trace exposure at the dashboard API boundary.

Covers the CodeQL Medium "Information exposure through an exception" finding
on this branch (dashboard.py:451): a per-alert ``str(e)`` used to flow into
the triage JSON response. Unexpected exceptions are now caught at the API
boundary:

  * generic ``except Exception`` catch-alls return a stable message
    (``_safe_error``) while the full traceback goes to the server log only;
  * a global ``@app.errorhandler(Exception)`` returns a generic JSON 500 for
    anything unhandled; standard HTTP errors (404/405/...) pass through.

These tests assert the failure responses contain no file paths, line numbers
or exception class names - both for the boundary handler directly and for
the flagged triage sink through real request dispatch. Runs with MOCK_MODE
only, and mutates no global config (the handler is exercised without
dispatch; the triage routes are exercised with mocked connector/agent).
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import dashboard as dash  # noqa: E402
from dashboard import app  # noqa: E402


def _assert_no_traceback_leak(test_case: unittest.TestCase, raw: str) -> None:
    for needle in ("Traceback", 'File "', "line ", ".py", "/etc/", "RuntimeError"):
        test_case.assertNotIn(needle, raw, f"traceback material leaked: {raw!r}")


class ExceptionExposureBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_boundary_handler_returns_generic_500(self):
        with app.app_context():
            resp_tuple = dash._handle_unhandled_exception(RuntimeError("boom /etc/shadow line 42"))
        self.assertEqual(resp_tuple[1], 500)
        raw = resp_tuple[0].get_data(as_text=True)
        self.assertEqual(resp_tuple[0].get_json(), {"error": "Internal server error."})
        _assert_no_traceback_leak(self, raw)

    def test_boundary_handler_passes_http_errors_through(self):
        from werkzeug.exceptions import HTTPException

        exc = HTTPException(404)
        with app.app_context():
            out = dash._handle_unhandled_exception(exc)
        self.assertIs(out, exc)

    def test_triage_pull_failure_is_generic(self):
        conn = mock.Mock()
        conn.get_new_alerts.side_effect = RuntimeError("pull failed /etc/shadow.py:42")
        provider = {"name": "MockSIEM", "platform": "mock"}
        with mock.patch.object(dash, "_connector_or_error", return_value=(conn, None, provider)):
            r = self.client.post("/api/providers/any/triage", json={"limit": 5})
        self.assertEqual(r.status_code, 502)
        self.assertEqual(r.get_json(), {"error": "Failed to pull alerts."})
        _assert_no_traceback_leak(self, r.get_data(as_text=True))

    def test_triage_per_alert_failure_is_generic(self):
        conn = mock.Mock()
        conn.get_new_alerts.return_value = [
            {"alert_id": "A1", "rule_id": "r1", "data": {"title": "boom"}}
        ]
        provider = {"name": "MockSIEM", "platform": "mock"}

        class BoomTriageAgent:
            def __init__(self, siem=None):  # noqa: D107
                pass

            def triage(self, alert):  # noqa: D102
                raise RuntimeError("triage exploded /opt/soc/dashboard.py:42")

        with (
            mock.patch.object(dash, "_connector_or_error", return_value=(conn, None, provider)),
            mock.patch.object(dash, "TriageAgent", BoomTriageAgent),
        ):
            r = self.client.post("/api/providers/any/triage", json={"limit": 5})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["results"][0]["error"], "Triage failed for this alert.")
        _assert_no_traceback_leak(self, r.get_data(as_text=True))

    def test_agent_start_400_is_generic_not_the_value_error_message(self):
        """The fail-closed start rejection must only ever echo the stable
        message - never the ValueError repr, class name, file paths, or the
        offending (smuggled) user string."""
        with self.subTest(route="legacy /api/agent/start"):
            r = self.client.post(
                "/api/agent/start", json={"provider_id": "wazuh; id > /etc/hosts"}
            )
            self.assertEqual(r.status_code, 400)
            self.assertEqual(
                r.get_json()["error"],
                "Could not start the watcher: unknown SIEM/pipeline.",
            )
            raw = r.get_data(as_text=True)
            self.assertNotIn("ValueError", raw)
            self.assertNotIn("wazuh;", raw)  # user payload must not be echoed
            _assert_no_traceback_leak(self, raw)
        with self.subTest(route="named /api/agents/start"):
            r = self.client.post(
                "/api/agents/start",
                json={"agent_id": "w1", "provider_id": "wazuh; id > /etc/hosts"},
            )
            self.assertEqual(r.status_code, 400)
            self.assertEqual(
                r.get_json()["error"],
                "Could not start the watcher: unknown SIEM/pipeline.",
            )
            raw = r.get_data(as_text=True)
            self.assertNotIn("ValueError", raw)
            self.assertNotIn("wazuh;", raw)
            _assert_no_traceback_leak(self, raw)


if __name__ == "__main__":
    unittest.main()
