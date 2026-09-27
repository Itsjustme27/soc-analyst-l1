"""
Offline tests for the multi-SIEM layer: registry, mock connector, the
provider store, and the dashboard API. No network / API keys required.

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from connectors.siem import SIEMConnector, get_siem_connector, list_siem_platforms
from connectors.siem.mock import MockSiemConnector
from connectors.siem.splunk import SplunkConnector


class TestQRadarQuerySafety(unittest.TestCase):
    """search_related_events builds an Ariel query by interpolation - the
    values must be fail-closed literals so alert-derived data can never break
    out of the WHERE clause (bandit B608)."""

    def _conn(self):
        from connectors.siem.qradar import QRadarConnector

        return QRadarConnector(name="qt", config={"host": "https://qradar.example:443"})

    def test_search_uses_properly_quoted_literals(self):
        conn = self._conn()
        captured = {}
        conn._run_ariel = lambda q: captured.setdefault("q", q) or []
        conn.search_related_events(host="10.0.0.9", user="svc-alerts")
        q = captured["q"]
        self.assertIn("(sourceIP='10.0.0.9' OR destinationIP='10.0.0.9' OR hostname='10.0.0.9')", q)
        self.assertIn("userName='svc-alerts'", q)

    def test_search_without_filters_still_builds(self):
        conn = self._conn()
        captured = {}
        conn._run_ariel = lambda q: captured.setdefault("q", q) or []
        conn.search_related_events()
        self.assertIn("WHERE 1=1", captured["q"])

    def test_search_rejects_quote_injection(self):
        conn = self._conn()
        conn._run_ariel = lambda q: []
        with self.assertRaises(ValueError):
            conn.search_related_events(host="10.0.0.9' OR 1=1 --")
        with self.assertRaises(ValueError):
            conn.search_related_events(user="x'; DROP TABLE events; --")
        with self.assertRaises(ValueError):
            conn.search_related_events(host='10.0.0.9" OR 1=1')

    def test_search_rejects_non_literal_charset(self):
        conn = self._conn()
        conn._run_ariel = lambda q: []
        with self.assertRaises(ValueError):
            conn.search_related_events(host="10.0.0.9 } UNION SELECT *")


class TestRegistry(unittest.TestCase):
    def test_all_expected_platforms_registered(self):
        for p in ("splunk", "qradar", "elastic", "sentinel", "wazuh", "mock"):
            self.assertIn(p, list_siem_platforms())

    def test_factory_returns_mock(self):
        conn = get_siem_connector("mock", name="test-mock")
        self.assertIsInstance(conn, MockSiemConnector)
        self.assertIsInstance(conn, SIEMConnector)

    def test_unknown_platform_raises(self):
        with self.assertRaises(ValueError):
            get_siem_connector("does-not-exist")

    def test_default_from_env(self):
        # No SIEM_PROVIDER set in the environment -> config default 'splunk'.
        import os

        if "SIEM_PROVIDER" not in os.environ:
            conn = get_siem_connector()
            self.assertIsInstance(conn, SplunkConnector)

    def test_connector_config_override_wins(self):
        conn = get_siem_connector(
            "splunk", name="x", config={"host": "https://staging.splunk:8089"}
        )
        self.assertEqual(conn.host, "https://staging.splunk:8089")
        self.assertEqual(conn.name, "x")


class TestMockSiemConnector(unittest.TestCase):
    def setUp(self):
        self.conn = MockSiemConnector(name="Test-Mock 1")

    def test_returns_normalized_alerts(self):
        alerts = self.conn.get_new_alerts()
        self.assertTrue(alerts)
        for a in alerts:
            for key in (
                "alert_id",
                "rule_id",
                "rule_name",
                "severity",
                "description",
                "raw_fields",
            ):
                self.assertIn(key, a)

    def test_ids_are_namespaced_per_provider(self):
        other = MockSiemConnector(name="Test-Mock 2")
        ids_a = {a["alert_id"] for a in self.conn.get_new_alerts()}
        ids_b = {a["alert_id"] for a in other.get_new_alerts()}
        self.assertTrue(ids_a.isdisjoint(ids_b))  # no collisions across providers

    def test_search_related_events(self):
        rows = self.conn.search_related_events(user="jsmith")
        self.assertTrue(rows)
        self.assertEqual(self.conn.search_related_events(user="nobody"), [])

    def test_test_connection_ok(self):
        r = self.conn.test_connection()
        self.assertTrue(r["ok"])
        self.assertIn("latency_ms", r)

    def test_interface_conformance(self):
        for method in (
            "get_new_alerts",
            "search_related_events",
            "close_notable",
            "test_connection",
        ):
            self.assertTrue(callable(getattr(self.conn, method)))


class TestProviderStore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "providers.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_add_load_remove_roundtrip(self):
        import siem_providers as store

        added = store.add_provider(
            {
                "name": "QA Splunk",
                "platform": "splunk",
                "config": {"host": "https://qa.splunk:8089", "token": "sekret"},
            },
            path=self.path,
        )
        self.assertEqual(added["source"], "dashboard")
        self.assertEqual(added["platform"], "splunk")

        providers = store.load_providers(self.path)
        self.assertTrue(any(p["id"] == added["id"] for p in providers))

        self.assertTrue(store.remove_provider(added["id"], path=self.path))
        providers = store.load_providers(self.path)
        self.assertFalse(any(p["id"] == added["id"] for p in providers))

    def test_env_providers_cannot_be_removed(self):
        import siem_providers as store

        env = store.env_seeded_providers()
        self.assertTrue(any(p["id"] == "env-mock" for p in env))
        # mock is always seeded, so load_providers always has at least one entry
        providers = store.load_providers(self.path)
        self.assertTrue(any(p["id"] == "env-mock" for p in providers))

    def test_validation_errors(self):
        import siem_providers as store

        with self.assertRaises(store.ProviderError):
            store.add_provider({"name": "", "platform": "splunk"}, path=self.path)
        with self.assertRaises(store.ProviderError):
            store.add_provider({"name": "x", "platform": "not-a-siem"}, path=self.path)

    def test_redact_provider_masks_secret_fields_only(self):
        import siem_providers as store

        added = store.add_provider(
            {
                "name": "QA Splunk",
                "platform": "splunk",
                "config": {"host": "https://qa.splunk:8089", "token": "sekret"},
            },
            path=self.path,
        )
        redacted = store.redact_provider(added)
        self.assertEqual(
            redacted["config"]["host"], "https://qa.splunk:8089"
        )  # not secret - untouched
        self.assertNotEqual(redacted["config"]["token"], "sekret")  # secret - masked
        self.assertNotIn("sekret", str(redacted))
        # the real (unredacted) value is unaffected by producing a redacted copy
        self.assertEqual(added["config"]["token"], "sekret")

    def test_redact_provider_mock_platform_has_no_secrets(self):
        import siem_providers as store

        mock_provider = {"id": "env-mock", "name": "Mock SIEM", "platform": "mock", "config": {}}
        self.assertEqual(store.redact_provider(mock_provider), mock_provider)


class TestDashboardAuth(unittest.TestCase):
    """DASHBOARD_TOKEN gate - off by default, on when set, page shell always loads."""

    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def setUp(self):
        from config import cfg

        self._orig_token = cfg.DASHBOARD_TOKEN
        self._orig_users = getattr(cfg, "DASHBOARD_USERS", "")

    def tearDown(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = self._orig_token
        cfg.DASHBOARD_USERS = self._orig_users

    def test_no_token_configured_means_open(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = ""
        r = self.client.get("/api/providers")
        self.assertEqual(r.status_code, 200)

    def test_api_call_without_token_is_401(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = "s3cr3t"
        r = self.client.get("/api/providers")
        self.assertEqual(r.status_code, 401)

    def test_page_shell_always_loads(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = "s3cr3t"
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)

    def test_bearer_header_authorizes(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = "s3cr3t"
        r = self.client.get("/api/providers", headers={"Authorization": "Bearer s3cr3t"})
        self.assertEqual(r.status_code, 200)

    def test_wrong_bearer_token_is_401(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = "s3cr3t"
        r = self.client.get("/api/providers", headers={"Authorization": "Bearer wrong"})
        self.assertEqual(r.status_code, 401)

    def test_query_param_authorizes(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = "s3cr3t"
        r = self.client.get("/api/providers?token=s3cr3t")
        self.assertEqual(r.status_code, 200)

    def test_token_comparisons_use_compare_digest(self):
        # Both the shared-token check and the per-user lookup must compare in
        # constant time (no early-exit length/char shortcuts -> timing oracle).
        import hmac
        from unittest import mock

        from config import cfg
        from dashboard import _token_ok, _token_user, app

        cfg.DASHBOARD_TOKEN = "shared-secret"
        cfg.DASHBOARD_USERS = "alice:alice-tok:approver"

        with app.test_request_context(
            "/api/providers", headers={"Authorization": "Bearer shared-secret"}
        ):
            with mock.patch("dashboard.hmac.compare_digest", wraps=hmac.compare_digest) as cd:
                self.assertTrue(_token_ok())
                # a shared token is not a verified per-user identity
                self.assertIsNone(_token_user())
            self.assertTrue(cd.called)

        with app.test_request_context(
            "/api/providers", headers={"Authorization": "Bearer alice-tok"}
        ):
            with mock.patch("dashboard.hmac.compare_digest", wraps=hmac.compare_digest) as cd2:
                self.assertEqual(_token_user(), ("alice", "approver"))
            self.assertTrue(cd2.called)

    def test_wrong_per_user_token_is_401(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = ""
        cfg.DASHBOARD_USERS = "alice:alice-tok:approver"
        r = self.client.get("/api/providers", headers={"Authorization": "Bearer wrong-tok"})
        self.assertEqual(r.status_code, 401)

    def test_valid_per_user_token_authorizes(self):
        from config import cfg

        cfg.DASHBOARD_TOKEN = ""
        cfg.DASHBOARD_USERS = "alice:alice-tok:approver,bob:bob-tok:viewer"
        r = self.client.get("/api/providers", headers={"Authorization": "Bearer bob-tok"})
        self.assertEqual(r.status_code, 200)


class TestDashboardAPI(unittest.TestCase):
    """Runs the Flask app against the test client - offline."""

    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_platforms(self):
        r = self.client.get("/api/platforms")
        body = r.get_json()
        platforms = {p["platform"] for p in body["platforms"]}
        self.assertIn("splunk", platforms)
        self.assertIn("sentinel", platforms)
        # every platform's field metadata is serializable
        for p in body["platforms"]:
            self.assertIsInstance(p["fields"], list)

    def test_providers_list_has_mock(self):
        r = self.client.get("/api/providers")
        ids = {p["id"] for p in r.get_json()["providers"]}
        self.assertIn("env-mock", ids)

    def test_add_delete_provider(self):
        payload = {
            "name": "API Test QRadar",
            "platform": "qradar",
            "config": {"host": "https://qradar.test", "token": "t0ken"},
        }
        r = self.client.post("/api/providers", json=payload)
        self.assertEqual(r.status_code, 201)
        pid = r.get_json()["provider"]["id"]
        self.assertNotIn("t0ken", r.get_data(as_text=True))  # secret never echoed back

        r = self.client.get("/api/providers")
        self.assertIn(pid, {p["id"] for p in r.get_json()["providers"]})
        self.assertNotIn("t0ken", r.get_data(as_text=True))  # ...nor on a later list

        r = self.client.delete(f"/api/providers/{pid}")
        self.assertEqual(r.status_code, 200)

    def test_delete_env_provider_refused(self):
        r = self.client.delete("/api/providers/env-mock")
        self.assertEqual(r.status_code, 404)

    def test_mock_provider_test_and_alerts(self):
        r = self.client.post("/api/providers/env-mock/test")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

        r = self.client.get("/api/providers/env-mock/alerts")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertGreater(body["count"], 0)
        self.assertEqual(body["platform"], "mock")

    def test_index_renders(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("SOC Triage", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
