"""
Offline tests for the Wazuh SIEM connector - mocked HTTP, no Wazuh needed.

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from unittest import mock

from connectors.siem import SIEMConnector, get_siem_connector, list_siem_platforms
from connectors.siem.wazuh import WazuhConnector, wazuh_severity


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _hit(source, doc_id="alert123"):
    return {"_id": doc_id, "_source": source}


def _sample_source(**overrides):
    src = {
        "id": "1810012345",
        "timestamp": "2026-09-23T10:00:00.000Z",
        "rule": {
            "id": "5712",
            "level": 10,
            "description": "Multiple failed logins",
            "groups": ["authentication_failures"],
            "mitre": {
                "id": ["T1110"],
                "tactic": ["Credential Access"],
                "technique": ["Brute Force"],
            },
        },
        "agent": {"id": "001", "name": "wks-fin-0231", "ip": "10.0.0.55"},
        "manager": {"name": "wazuh.manager"},
        "data": {"srcip": "185.220.101.7", "srcport": "45678", "dstip": "10.0.0.10"},
        "full_log": "User 'jsmith' failed to login 5 times from 185.220.101.7.",
    }
    src.update(overrides)
    return src


class TestWazuhSeverity(unittest.TestCase):
    def test_level_mapping(self):
        self.assertEqual(wazuh_severity(15), "critical")
        self.assertEqual(wazuh_severity(12), "critical")
        self.assertEqual(wazuh_severity("10"), "high")
        self.assertEqual(wazuh_severity(9), "high")
        self.assertEqual(wazuh_severity(6), "medium")
        self.assertEqual(wazuh_severity(3), "low")
        self.assertEqual(wazuh_severity(0), "info")
        self.assertEqual(wazuh_severity("n/a"), "unknown")


class TestWazuhRegistry(unittest.TestCase):
    def test_platform_registered(self):
        self.assertIn("wazuh", list_siem_platforms())
        conn = get_siem_connector(
            "wazuh", name="w", config={"host": "https://wazuh:9200", "verify_ssl": False}
        )
        self.assertIsInstance(conn, WazuhConnector)
        self.assertIsInstance(conn, SIEMConnector)
        self.assertEqual(conn.host, "https://wazuh:9200")
        self.assertFalse(conn.verify)

    def test_config_override_wins(self):
        conn = WazuhConnector(
            config={"host": "https://wazuh:9200", "username": "u", "password": "p"}
        )
        self.assertEqual(conn.username, "u")
        self.assertEqual(conn.password, "p")
        self.assertEqual(conn.index, "wazuh-alerts-*")


class TestWazuhCredentialGuard(unittest.TestCase):
    """WazuhConnector should refuse the admin/admin default against a
    non-local host outside MOCK_MODE - see wazuh.py's docstring/guard."""

    def setUp(self):
        from config import cfg

        self._orig_mock_mode = cfg.MOCK_MODE
        self._orig_password = cfg.WAZUH_PASSWORD
        cfg.MOCK_MODE = False
        # Hermetic: clear WAZUH_PASSWORD so resolve_cfg() falls back to the
        # silent "admin" default. Without this, a real WAZUH_PASSWORD in
        # .env (used by live connectors) would legitimately bypass the guard
        # and these tests would not exercise the guard itself.
        cfg.WAZUH_PASSWORD = ""

    def tearDown(self):
        from config import cfg

        cfg.MOCK_MODE = self._orig_mock_mode
        cfg.WAZUH_PASSWORD = self._orig_password

    def test_default_creds_against_local_host_ok(self):
        WazuhConnector(config={"host": "https://localhost:9200"})  # should not raise

    def test_default_creds_against_remote_host_raises(self):
        with self.assertRaises(ValueError):
            WazuhConnector(config={"host": "https://wazuh.prod.corp.local:9200"})

    def test_explicit_password_against_remote_host_ok(self):
        WazuhConnector(
            config={"host": "https://wazuh.prod.corp.local:9200", "password": "a-real-password"}
        )

    def test_mock_mode_bypasses_the_guard(self):
        from config import cfg

        cfg.MOCK_MODE = True
        WazuhConnector(config={"host": "https://wazuh.prod.corp.local:9200"})  # should not raise


class TestWazuhConnector(unittest.TestCase):
    def setUp(self):
        self.conn = WazuhConnector(
            name="wazuh-test", config={"host": "https://wazuh:9200", "verify_ssl": False}
        )

    @mock.patch("connectors.siem.wazuh.requests.post")
    def test_get_new_alerts_normalizes(self, post):
        post.return_value = FakeResponse(
            {
                "hits": {
                    "hits": [
                        _hit(_sample_source()),
                        _hit(
                            _sample_source(
                                id=None,
                                rule={"id": "x", "level": 6},
                                data={"srcip": "10.1.1.1", "winuser": "jsmith"},
                            ),
                            doc_id="alert124",
                        ),
                    ]
                }
            }
        )
        alerts = self.conn.get_new_alerts()
        self.assertEqual(len(alerts), 2)

        a = alerts[0]
        self.assertEqual(a["alert_id"], "1810012345")
        self.assertEqual(a["rule_id"], "5712")
        self.assertEqual(a["rule_name"], "Multiple failed logins")
        self.assertEqual(a["severity"], "high")  # rule.level 10
        self.assertEqual(a["host"], "wks-fin-0231")
        self.assertEqual(a["src_ip"], "185.220.101.7")
        self.assertIn("user", a)

        # rule.level 6 -> medium; winuser -> user
        b = alerts[1]
        self.assertEqual(b["severity"], "medium")
        self.assertEqual(b["user"], "jsmith")
        self.assertEqual(b["alert_id"], "alert124")  # falls back to doc _id
        self.assertEqual(b["rule_id"], "x")

        # query was sent to the alerts index
        self.assertIn("wazuh-alerts-*/_search", post.call_args.args[0])

    @mock.patch("connectors.siem.wazuh.requests.post")
    def test_search_related_events_uses_archives_and_terms(self, post):
        post.return_value = FakeResponse({"hits": {"hits": [_hit(_sample_source())]}})
        rows = self.conn.search_related_events(host="wks-fin-0231", user="jsmith")
        self.assertEqual(len(rows), 1)
        url = post.call_args.args[0]
        body = post.call_args.kwargs["json"]
        self.assertIn("wazuh-archives-*/_search", url)
        # both host and user produced term clauses
        should = body["query"]["bool"]["should"]
        fields = [s["term"] for s in should]
        self.assertTrue(any("agent.name" in t for t in fields))
        self.assertTrue(
            any("data.srcuser" in t for t in fields) or any("data.winuser" in t for t in fields)
        )

    @mock.patch("connectors.siem.wazuh.requests.get")
    def test_ping(self, get):
        get.return_value = FakeResponse({"cluster_name": "wazuh-cluster"})
        r = self.conn.test_connection()
        self.assertTrue(r["ok"])
        self.assertIn("cluster wazuh-cluster", r["detail"])

    @mock.patch("connectors.siem.wazuh.requests.get")
    def test_ping_failure_reported(self, get):
        get.side_effect = ConnectionError("boom")
        r = self.conn.test_connection()
        self.assertFalse(r["ok"])
        self.assertIn("boom", r["detail"])

    @mock.patch("connectors.siem.wazuh.requests.post")
    def test_close_notable_annotates_doc(self, post):
        post.return_value = FakeResponse({"result": "updated"})
        self.conn.close_notable("alert123", "closed", "benign - confirmed phishing block")
        url = post.call_args.args[0]
        self.assertTrue(url.endswith("wazuh-alerts-*/_update/alert123"))
        self.assertEqual(post.call_args.kwargs["json"]["doc"]["soc_agent_status"], "closed")


if __name__ == "__main__":
    unittest.main()
