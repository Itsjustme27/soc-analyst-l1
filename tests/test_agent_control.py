"""
Hermetic tests for the multi-agent overnight-watcher control:

  - agent_control plumbing (path safety, pid-preserving heartbeats, overview)
  - run.py heartbeat-every-cycle fix (the "cannot stop the agent" bug: an idle
    SIEM used to leave the heartbeat stuck at "starting" so the dashboard
    disabled the Stop button)
  - dashboard /api/agents endpoints: overview counts, spawn (with log capture),
    graceful stop (SIGTERM + stop-file), the KILL switch (SIGKILL), and log tail

Runs with MOCK_MODE only — no API keys, no network, and every spawned watcher
is either a mocked Popen or a real throwaway `sleep` process.

Run: cd soc-agent && ./venv/bin/python -m unittest tests.test_agent_control -v
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

# Force mock mode before importing anything that touches LLM keys
os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

BASE = Path(__file__).resolve().parent.parent
os.chdir(BASE)


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class TestSanitizeId(unittest.TestCase):
    """Agent ids become safe path segments - never able to traverse."""

    def test_traversal_and_junk_are_contained(self):
        import agent_control as ac

        self.assertEqual(ac.sanitize_id("a/b"), "a-b")
        self.assertEqual(ac.sanitize_id(".."), "default")
        self.assertEqual(ac.sanitize_id("../etc/passwd"), "etc-passwd")
        self.assertEqual(ac.sanitize_id("wazuh é!x"), "wazuh-x")
        self.assertEqual(ac.sanitize_id(""), "default")
        self.assertEqual(ac.sanitize_id(None), "default")
        # no slash can ever survive into a filesystem path
        self.assertNotIn("/", ac.sanitize_id("../../etc/shadow"))

    def test_default_keeps_legacy_layout_and_named_is_scoped(self):
        import agent_control as ac

        self.assertNotEqual(ac.heartbeat_path("default").parent, ac.heartbeat_path("wazuh").parent)
        self.assertEqual(ac.heartbeat_path("wazuh").name, "heartbeat.json")
        self.assertEqual(ac.log_file_path("wazuh").name, "run.log")


class AgentControlTestBase(unittest.TestCase):
    """Isolates agent state in a fresh temp dir (cfg.AGENT_DIR) per test."""

    def setUp(self):
        from config import cfg

        self.tmp = tempfile.mkdtemp(prefix="agent_ctl_")
        self._patch = mock.patch.object(cfg, "AGENT_DIR", self.tmp)
        self._patch.start()
        self.addCleanup(self._patch.stop)
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.addCleanup(self._clean_legacy_artifacts)

    @staticmethod
    def _clean_legacy_artifacts():
        from config import cfg

        for p in [cfg.AGENT_HEARTBEAT_PATH, cfg.AGENT_STOP_FILE, cfg.AGENT_LOG_FILE]:
            Path(p).unlink(missing_ok=True)


class TestRunHeartbeatEveryCycle(AgentControlTestBase):
    """Regression for the "I can only start, never stop" bug."""

    def test_idle_siem_still_writes_running_heartbeat(self):
        import run as runm

        with mock.patch.object(runm, "AGENT_ID", "t-idle"):

            class FakeSiem:
                name = "mock"

                def get_new_alerts(self):
                    return []

            should_stop = runm._run_cycle(FakeSiem(), cycle=3, exit_after=0)
            self.assertFalse(should_stop)  # keep watching
            hb_path = runm.heartbeat_path()
            self.assertTrue(hb_path.exists(), "heartbeat must be written even with zero alerts")
            hb = json.loads(hb_path.read_text())
            self.assertEqual(hb["status"], "running")
            self.assertEqual(hb["cycle"], 3)
            self.assertEqual(hb["triaged_this_cycle"], 0)
            self.assertEqual(hb["alerts_seen"], 0)

    def test_heartbeat_preserves_pid_across_cycle_updates(self):
        import agent_control as ac

        ac.write_heartbeat(
            "t-pid", {"status": "starting", "pid": 12345, "at": _ts(), "reason": "started"}
        )
        # the per-cycle write does not carry a pid - it must be preserved
        ac.write_heartbeat(
            "t-pid", {"status": "running", "cycle": 1, "alerts_seen": 0, "triaged_this_cycle": 0}
        )
        hb = ac.read_heartbeat("t-pid")
        self.assertEqual(hb["pid"], 12345)
        self.assertEqual(hb["status"], "running")
        self.assertEqual(hb["cycle"], 1)

    def test_idle_watcher_exits_on_stop_file(self):
        """The 'can't stop it' bug: an idle watcher ignored the stop-file."""
        import agent_control as ac
        import run as runm

        with mock.patch.object(runm, "AGENT_ID", "t-idle"):

            class FakeSiem:
                name = "mock"

                def get_new_alerts(self):
                    return []

            sp = ac.stop_file_path("t-idle")
            sp.parent.mkdir(parents=True, exist_ok=True)
            sp.touch()  # dashboard pressed Stop
            should_stop = runm._run_cycle(FakeSiem(), cycle=1, exit_after=0)
            self.assertTrue(should_stop, "an idle watcher must honour the stop-file")


class TestDashboardAgentEndpoints(AgentControlTestBase):
    """Flask test-client coverage for the /api/agents endpoints."""

    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_agents_overview_counts(self):
        import agent_control as ac

        ac.write_heartbeat(
            "wazuh",
            {
                "status": "running",
                "pid": os.getpid(),
                "at": _ts(),
                "cycle": 2,
                "alerts_seen": 7,
                "triaged_this_cycle": 1,
            },
        )
        ac.write_heartbeat("splunk", {"status": "stopped", "at": _ts(), "reason": "stop requested"})
        r = self.client.get("/api/agents")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        ids = {a["agent_id"] for a in body["agents"]}
        self.assertEqual(ids, {"wazuh", "splunk"})
        self.assertEqual(body["counts"], {"deployed": 2, "running": 1, "stopped": 1})
        # the running one resolves through real process liveness
        by_id = {a["agent_id"]: a for a in body["agents"]}
        self.assertTrue(by_id["wazuh"]["running"])
        self.assertFalse(by_id["splunk"]["running"])

    def test_agents_start_spawns_with_agent_id_and_log_redirect(self):
        import agent_control as ac
        import dashboard as dash

        proc = mock.Mock()
        proc.pid = 4242
        with mock.patch.object(dash.subprocess, "Popen", return_value=proc) as popen:
            r = self.client.post(
                "/api/agents/start", json={"agent_id": "sq/1", "provider_id": "wazuh"}
            )
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertEqual(body["agent_id"], "sq-1")
        self.assertEqual(body["pid"], 4242)

        args, kwargs = popen.call_args
        cmd = args[0]
        self.assertTrue(any(c.endswith("run.py") for c in cmd), cmd)
        self.assertEqual(cmd[cmd.index("--agent-id") + 1], "sq-1")
        self.assertEqual(cmd[cmd.index("--siem") + 1], "wazuh")
        # output must be captured to the agent's run.log, never DEVNULL
        self.assertEqual(kwargs["stderr"], subprocess.STDOUT)
        self.assertIsNotNone(kwargs["stdout"])
        self.assertTrue(
            kwargs["stdout"].name.endswith(os.path.join("sq-1", "run.log")),
            f"stdout target was {kwargs['stdout'].name}",
        )

        # dashboard heartbeat makes the pid visible immediately
        hb = ac.read_heartbeat("sq-1")
        self.assertEqual(hb["pid"], 4242)
        self.assertEqual(hb["status"], "starting")

    def test_agents_start_conflicts_when_already_running(self):
        import agent_control as ac

        ac.write_heartbeat("busy", {"status": "running", "pid": os.getpid(), "at": _ts()})
        r = self.client.post("/api/agents/start", json={"agent_id": "busy"})
        self.assertEqual(r.status_code, 409)
        self.assertIn("already running", r.get_json()["error"])

    def test_graceful_stop_terms_process_and_drops_stop_file(self):
        import agent_control as ac

        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: victim.kill() if victim.poll() is None else None)
        ac.write_heartbeat(
            "grace", {"status": "running", "pid": victim.pid, "at": _ts(), "cycle": 4}
        )
        r = self.client.post("/api/agents/grace/stop", json={})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["killed"])
        victim.wait(timeout=10)
        # Unix: SIGTERM -> -15. Windows reports the same signal as unsigned 15.
        self.assertIn(victim.returncode, (-15, 15))
        self.assertTrue(ac.stop_file_path("grace").exists())

    def test_kill_switch_sigkills_and_marks_stopped(self):
        import agent_control as ac

        victim = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        self.addCleanup(lambda: victim.kill() if victim.poll() is None else None)
        ac.write_heartbeat("victim", {"status": "running", "pid": victim.pid, "at": _ts()})
        r = self.client.post("/api/agents/victim/kill", json={})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["ok"])
        self.assertTrue(body["killed"])
        victim.wait(timeout=10)  # SIGKILL is immediate - no graceful exit
        self.assertIsNotNone(victim.poll())
        hb = ac.read_heartbeat("victim")
        self.assertEqual(hb["status"], "stopped")
        self.assertIn("kill", hb.get("reason", ""))
        self.assertTrue(ac.stop_file_path("victim").exists())
        # status reports not-running once the pid is gone
        self.assertFalse(ac.status("victim")["running"])

    def test_agent_logs_returns_tail(self):
        import agent_control as ac

        log = ac.log_file_path("logger")
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("".join(f"line {i}\n" for i in range(1, 11)))
        r = self.client.get("/api/agents/logger/logs?lines=3")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["lines"], ["line 8", "line 9", "line 10"])
        self.assertEqual(body["agent"]["agent_id"], "logger")
        self.assertFalse(body["agent"]["running"])

    def test_agent_logs_unknown_agent_is_empty(self):
        r = self.client.get("/api/agents/never-deployed/logs?lines=10")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body["lines"], [])
        self.assertEqual(body["agent"]["agent_id"], "never-deployed")

    def test_stop_finds_watcher_without_heartbeat_pid(self):
        """Stop must still kill a watcher whose heartbeat lost its pid
        (older watchers overwrote the pid after the first alert cycle)."""
        import agent_control as ac

        watcher = subprocess.Popen(
            [
                sys.executable,
                "run.py",
                "--agent-id",
                "ghost",
                "--provider",
                "mock",
                "--interval",
                "60",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(lambda: watcher.kill() if watcher.poll() is None else None)
        try:
            time.sleep(6)  # let it boot and write heartbeats
        finally:
            pass
        # simulate an old-code heartbeat that has no pid at all
        ac.write_heartbeat("ghost", {"status": "running", "at": _ts()})
        hb = ac.read_heartbeat("ghost")
        hb.pop("pid", None)
        ac.heartbeat_path("ghost").write_text(json.dumps(hb))
        self.assertIsNone(ac.read_heartbeat("ghost").get("pid"))
        # /proc discovery must find it anyway
        self.assertIn(watcher.pid, ac.find_watcher_pids("ghost"))

        r = self.client.post("/api/agents/ghost/stop", json={})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        watcher.wait(timeout=15)
        self.assertIsNotNone(watcher.poll(), "watcher must die via /proc discovery")
        # Unix watchers exit 0 after handling SIGTERM+stop-file; Windows
        # TerminateProcess via SIGTERM typically yields 15.
        self.assertIn(watcher.returncode, (0, 15, -15))
        self.assertTrue(ac.stop_file_path("ghost").exists())

    def test_legacy_default_agent_status_and_stop_still_work(self):
        import agent_control as ac

        r = self.client.get("/api/agent")
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("running", body)
        self.assertIn("last_heartbeat", body)
        self.assertEqual(body["agent_id"], "default")
        # stop with no live watcher is graceful: ok, not killed, stop file set.
        # Deterministic: no heartbeat pid and no /proc-discovered watcher.
        ac.write_heartbeat("default", {"status": "running"})
        hb = ac.read_heartbeat("default")
        hb.pop("pid", None)
        ac.heartbeat_path("default").write_text(json.dumps(hb))
        with mock.patch("dashboard.ac.find_watcher_pids", return_value=[]):
            r2 = self.client.post("/api/agent/stop", json={})
        self.assertEqual(r2.status_code, 200)
        body2 = r2.get_json()
        self.assertTrue(body2["ok"])
        self.assertFalse(body2["killed"])
        self.assertTrue(ac.stop_file_path("default").exists())


if __name__ == "__main__":
    unittest.main()
