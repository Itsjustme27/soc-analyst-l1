"""
Offline tests for the new dashboard panels: chat agent, lookup tables CRUD,
and the Flask route coverage. Runs with MOCK_MODE only — no API keys, no network.

Run: cd soc-agent && ./venv/bin/python -m unittest tests.test_dashboard_panels -v
"""

from __future__ import annotations

import os
import tempfile
import time
import unittest
from pathlib import Path

# Force mock mode before importing anything that touches LLM keys
os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)


class TestLookupTablesOffline(unittest.TestCase):
    """Unit tests for lookup_tables.py against a temp file — no Flask needed."""

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.tmp.write("{}")
        self.tmp.close()
        self.path = Path(self.tmp.name)

    def tearDown(self):
        self.path.unlink(missing_ok=True)

    def test_list_empty(self):
        import lookup_tables as lk

        self.assertEqual(lk.list_lookup_tables(path=self.path), [])

    def test_create_and_read(self):
        import lookup_tables as lk

        t = lk.create_lookup_table("bad_ips", "Known bad IPs", path=self.path)
        self.assertEqual(t["description"], "Known bad IPs")
        self.assertEqual(
            lk.read_lookup_table("bad_ips", path=self.path)["description"], "Known bad IPs"
        )

    def test_upsert_and_delete_entry(self):
        import lookup_tables as lk

        lk.create_lookup_table("watchlist", path=self.path)
        lk.upsert_lookup_entry("watchlist", "1.2.3.4", {"reason": "scanner"}, path=self.path)
        self.assertEqual(
            lk.lookup_entry("watchlist", "1.2.3.4", path=self.path)["reason"], "scanner"
        )
        self.assertTrue(lk.delete_lookup_entry("watchlist", "1.2.3.4", path=self.path))
        self.assertIsNone(lk.lookup_entry("watchlist", "1.2.3.4", path=self.path))

    def test_delete_missing_key_fails(self):
        import lookup_tables as lk

        lk.create_lookup_table("x", path=self.path)
        self.assertFalse(lk.delete_lookup_entry("x", "nope", path=self.path))

    def test_delete_table(self):
        import lookup_tables as lk

        lk.create_lookup_table("delme", path=self.path)
        self.assertTrue(lk.delete_lookup_table("delme", path=self.path))
        self.assertIsNone(lk.read_lookup_table("delme", path=self.path))

    def test_search_lookup(self):
        import lookup_tables as lk

        lk.create_lookup_table("intel", path=self.path)
        lk.upsert_lookup_entry("intel", "hash1", {"label": "malware"}, path=self.path)
        hits = lk.search_lookup("intel", "malware", path=self.path)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["key"], "hash1")


class TestChatAgentToolCalls(unittest.TestCase):
    """Test ChatAgent tool dispatch — offline, mock mode."""

    def test_list_lookup_tables_tool(self):
        from agent.chat_agent import ChatAgent

        a = ChatAgent()
        result = a._execute_tool("list_lookup_tables", {})
        self.assertIsInstance(result, list)

    def test_write_lookup_table_upsert(self):
        import importlib

        from agent.chat_agent import ChatAgent

        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, dir="/tmp")
        tmp.close()
        orig = os.getenv("LOOKUP_TABLES_PATH", "")
        os.environ["LOOKUP_TABLES_PATH"] = tmp.name
        try:
            import lookup_tables

            importlib.reload(lookup_tables)
            a = ChatAgent()
            r = a._execute_tool(
                "write_lookup_table",
                {"name": "test_tbl", "action": "upsert", "key": "k1", "value": {"a": 1}},
            )
            self.assertTrue(r.get("updated"))
            self.assertEqual(r["action"], "upsert")
            self.assertEqual(r["key"], "k1")
        finally:
            Path(tmp.name).unlink(missing_ok=True)
            if orig:
                os.environ["LOOKUP_TABLES_PATH"] = orig
            else:
                os.environ.pop("LOOKUP_TABLES_PATH", None)

    def test_write_lookup_table_clear(self):
        import importlib

        from agent.chat_agent import ChatAgent

        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, dir="/tmp")
        tmp.write(b'{"tbl":{"entries":{"k1":1,"k2":2},"updated":"now"}}')
        tmp.close()
        orig = os.getenv("LOOKUP_TABLES_PATH", "")
        os.environ["LOOKUP_TABLES_PATH"] = tmp.name
        try:
            import lookup_tables

            importlib.reload(lookup_tables)
            a = ChatAgent()
            r = a._execute_tool("write_lookup_table", {"name": "tbl", "action": "clear"})
            self.assertTrue(r.get("updated"))
            self.assertEqual(r["action"], "clear")
        finally:
            Path(tmp.name).unlink(missing_ok=True)
            if orig:
                os.environ["LOOKUP_TABLES_PATH"] = orig
            else:
                os.environ.pop("LOOKUP_TABLES_PATH", None)

    def test_unknown_tool_raises(self):
        from agent.chat_agent import ChatAgent

        a = ChatAgent()
        with self.assertRaises(ValueError):
            a._execute_tool("nonexistent_tool", {})

    def test_get_alerts_without_siem_returns_error(self):
        from agent.chat_agent import ChatAgent

        a = ChatAgent()
        r = a._execute_tool("get_alerts", {})
        self.assertIn("error", r)


class TestDashboardRoutesOffline(unittest.TestCase):
    """Flask test-client coverage for the three new panel routes."""

    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()
        # Use a temp lookup store so we don't mutate repo state
        cls.tmp_lookup = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        cls.tmp_lookup.write("{}")
        cls.tmp_lookup.close()
        cls.orig_lookup_path = os.getenv("LOOKUP_TABLES_PATH", "")
        os.environ["LOOKUP_TABLES_PATH"] = cls.tmp_lookup.name
        # Also clear any leftover chat/triage logs
        Path("data/chat_log.jsonl").unlink(missing_ok=True)
        Path("data/triage_log.jsonl").unlink(missing_ok=True)

    @classmethod
    def tearDownClass(cls):
        Path(cls.tmp_lookup.name).unlink(missing_ok=True)
        if cls.orig_lookup_path:
            os.environ["LOOKUP_TABLES_PATH"] = cls.orig_lookup_path
        else:
            os.environ.pop("LOOKUP_TABLES_PATH", None)
        Path("data/chat_log.jsonl").unlink(missing_ok=True)
        Path("data/triage_log.jsonl").unlink(missing_ok=True)
        # Clean agent artifacts
        from config import cfg

        for p in [cfg.AGENT_HEARTBEAT_PATH, cfg.AGENT_STOP_FILE]:
            Path(p).unlink(missing_ok=True)

    def test_health(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "ok")

    def test_chat_requires_message(self):
        r = self.client.post("/api/chat", json={})
        self.assertEqual(r.status_code, 400)
        body = r.get_json()
        self.assertIn("error", body)

    def test_chat_with_message(self):
        r = self.client.post("/api/chat", json={"message": "hello"})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("reply", body)
        self.assertIn("transcript_len", body)

    def test_chat_history_empty(self):
        # Ensure a clean state — remove any leftover chat log from prior runs
        Path("data/chat_log.jsonl").unlink(missing_ok=True)
        r = self.client.get("/api/chat/history")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["count"], 0)
        # Clean up after
        Path("data/chat_log.jsonl").unlink(missing_ok=True)

    def test_chat_append_then_read_back(self):
        self.client.post("/api/chat", json={"message": "test msg"})
        r = self.client.get("/api/chat/history?limit=10")
        body = r.get_json()
        self.assertGreaterEqual(body["count"], 1)
        entry = body["entries"][0]
        self.assertIn("message", entry)
        self.assertIn("reply", entry)

    def test_lookup_tables_list(self):
        r = self.client.get("/api/lookup-tables")
        self.assertEqual(r.status_code, 200)
        self.assertIn("tables", r.get_json())

    def test_lookup_create_duplicate_raises_409(self):
        r1 = self.client.post(
            "/api/lookup-tables",
            json={"name": "test_dup_" + str(int(time.time())), "description": "d"},
        )
        self.assertEqual(r1.status_code, 201)
        name = r1.get_json()["table"]["name"]
        r2 = self.client.post("/api/lookup-tables", json={"name": name, "description": "d2"})
        self.assertEqual(r2.status_code, 409)

    def test_lookup_read_missing(self):
        r = self.client.get("/api/lookup-tables/nonexist")
        self.assertEqual(r.status_code, 404)

    def test_lookup_upsert_and_read(self):
        self.client.post("/api/lookup-tables", json={"name": "ip", "description": "bad ips"})
        r = self.client.post(
            "/api/lookup-tables/ip/entries/1.2.3.4", json={"value": {"reason": "scan"}}
        )
        self.assertEqual(r.status_code, 200)
        r2 = self.client.get("/api/lookup-tables/ip")
        body = r2.get_json()
        self.assertIn("1.2.3.4", body["table"]["entries"])

    def test_lookup_delete_entry_and_table(self):
        self.client.post("/api/lookup-tables", json={"name": "del", "description": "x"})
        self.client.post("/api/lookup-tables/del/entries/k", json={"value": 1})
        r = self.client.delete("/api/lookup-tables/del/entries/k")
        self.assertEqual(r.status_code, 200)
        r2 = self.client.delete("/api/lookup-tables/del")
        self.assertEqual(r2.status_code, 200)
        r3 = self.client.get("/api/lookup-tables/del")
        self.assertEqual(r3.status_code, 404)

    def test_agent_status(self):
        r = self.client.get("/api/agent")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("running", body)
        self.assertIn("last_heartbeat", body)

    def test_agent_start_stops_cleanly(self):
        r = self.client.post("/api/agent/start", json={})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body.get("ok"))
        pid = body.get("pid")
        self.assertIsInstance(pid, int)

        r2 = self.client.post("/api/agent/stop", json={})
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.get_json()["ok"])

        # Clean up any heartbeat/stop artifacts left by the test
        from config import cfg

        for p in [cfg.AGENT_HEARTBEAT_PATH, cfg.AGENT_STOP_FILE]:
            Path(p).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
