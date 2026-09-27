"""
Hermetic tests for the Wazuh dashboard saved-objects client (session auth).

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from unittest import mock

from tools.base import ToolError
from tools.dashboard import client as dash_client
from tools.dashboard.client import dashboards_request


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = "" if isinstance(payload, dict) else str(payload)

    def json(self):
        return self._payload


def _reset():
    dash_client._LOGGED_IN_USER = None


class DashboardClientAuthTests(unittest.TestCase):
    def setUp(self):
        _reset()
        self._session = mock.MagicMock()
        self._session.request.return_value = FakeResponse({"saved_objects": []})
        self._session.post.return_value = FakeResponse({"username": "admin"})
        patcher = mock.patch.object(dash_client, "_SESSION", self._session)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._sources = mock.patch.object(
            dash_client,
            "_credential_sources",
            return_value=[("dashuser", "dashpass"), ("idxuser", "idxpass")],
        )
        self._sources.start()
        self.addCleanup(self._sources.stop)
        # Hermetic: ignore operator .env WAZUH_DASHBOARD_URL.
        self._url = mock.patch.object(
            dash_client.cfg, "WAZUH_DASHBOARD_URL", "https://localhost:443"
        )
        self._url.start()
        self.addCleanup(self._url.stop)

    def test_first_request_logs_in_once(self):
        result = dashboards_request("GET", "/api/saved_objects/_find", params={"type": "dashboard"})
        self.assertEqual(result, {"saved_objects": []})
        self._session.post.assert_called_once()
        login_call = self._session.post.call_args
        self.assertEqual(login_call.args[0], "https://localhost:443/auth/login")
        self.assertEqual(
            login_call.kwargs["json"], {"username": "dashuser", "password": "dashpass"}
        )
        self.assertEqual(login_call.kwargs["headers"], {"osd-xsrf": "true"})
        self.assertEqual(dash_client._LOGGED_IN_USER, "dashuser")
        self._session.request.assert_called_once()

    def test_authenticated_request_skips_relogin(self):
        dash_client._LOGGED_IN_USER = "dashuser"
        dashboards_request("GET", "/x")
        self._session.post.assert_not_called()

    def test_falls_back_to_indexer_creds(self):
        self._session.post.side_effect = [
            FakeResponse({"error": "Unauthorized"}, status=401),
            FakeResponse({"username": "idxuser"}),
        ]
        dashboards_request("GET", "/x")
        posts = self._session.post.call_args_list
        self.assertEqual(posts[0].kwargs["json"], {"username": "dashuser", "password": "dashpass"})
        self.assertEqual(posts[1].kwargs["json"], {"username": "idxuser", "password": "idxpass"})
        self.assertEqual(dash_client._LOGGED_IN_USER, "idxuser")

    def test_all_creds_rejected_raises_without_password(self):
        self._session.post.return_value = FakeResponse({"error": "Unauthorized"}, status=401)
        with self.assertRaises(ToolError) as cm:
            dashboards_request("GET", "/x")
        self.assertNotIn("dashpass", str(cm.exception))
        self.assertNotIn("idxpass", str(cm.exception))

    def test_401_relogin_and_retry(self):
        dash_client._LOGGED_IN_USER = "dashuser"
        self._session.request.side_effect = [
            FakeResponse({"error": "Unauthorized"}, status=401),
            FakeResponse({"saved_objects": [{"id": "d1"}]}),
        ]
        result = dashboards_request("GET", "/api/saved_objects/_find")
        self.assertEqual(result, {"saved_objects": [{"id": "d1"}]})
        self.assertEqual(self._session.request.call_count, 2)
        self._session.post.assert_called_once()  # single re-login

    def test_state_changing_requests_send_xsrf_header(self):
        dash_client._LOGGED_IN_USER = "dashuser"
        dashboards_request("POST", "/api/saved_objects/dashboard", body={"attributes": {}})
        req = self._session.request.call_args
        self.assertEqual(req.kwargs["headers"], {"osd-xsrf": "true"})
        self.assertEqual(req.kwargs["json"], {"attributes": {}})
        self.assertEqual(req.args[0], "POST")

    def test_dashboards_api_error_raises_tool_error(self):
        dash_client._LOGGED_IN_USER = "dashuser"
        self._session.request.return_value = FakeResponse({"message": "bad payload"}, status=400)
        with self.assertRaises(ToolError) as cm:
            dashboards_request("PUT", "/api/saved_objects/dashboard/x")
        self.assertIn("bad payload", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
