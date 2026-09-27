"""
Overnight-watcher control plumbing, shared by run.py (the watcher process)
and dashboard.py (spawn / signal / tail logs).

Each watcher is an "agent" identified by an `agent_id`:

  - ``default`` keeps the legacy single-watcher paths (AGENT_STOP_FILE,
    AGENT_HEARTBEAT_PATH, AGENT_LOG_FILE) so nothing that already reads
    data/agent_*.json breaks.
  - any other id lives under <AGENT_DIR>/<agent_id>/ with heartbeat.json,
    stop.txt and run.log.

Status is derived from the heartbeat file plus *process liveness* (the pid the
watcher writes into its heartbeat must actually be alive) and the heartbeat
age. If the watcher dies the dashboard reflects it immediately, even before a
fresh heartbeat arrives.
"""

from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from config import cfg

# Heartbeat fresher than this (seconds) counts as "recently alive".
AGENT_POLL_TOLERANCE = 120


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def sanitize_id(agent_id: str | None) -> str:
    """Coerce an agent id to a safe path segment; never can traverse."""
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (agent_id or "default").strip(" "))[:64]
    return s.strip(".-") or "default"


def agent_dir(agent_id: str) -> Path:
    return Path(cfg.AGENT_DIR or "data/agents") / sanitize_id(agent_id)


def heartbeat_path(agent_id: str) -> Path:
    aid = sanitize_id(agent_id)
    if aid == "default":
        return Path(cfg.AGENT_HEARTBEAT_PATH or "data/agent_heartbeat.json")
    return agent_dir(aid) / "heartbeat.json"


def stop_file_path(agent_id: str) -> Path:
    aid = sanitize_id(agent_id)
    if aid == "default":
        return Path(cfg.AGENT_STOP_FILE or "data/agent_stop.txt")
    return agent_dir(aid) / "stop.txt"


def log_file_path(agent_id: str) -> Path:
    aid = sanitize_id(agent_id)
    if aid == "default":
        return Path(cfg.AGENT_LOG_FILE or "data/agent_run.log")
    return agent_dir(aid) / "run.log"


# --------------------------------------------------------------------------- #
# Heartbeat IO
# --------------------------------------------------------------------------- #
def read_heartbeat(agent_id: str) -> dict:
    p = heartbeat_path(agent_id)
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def write_heartbeat(agent_id: str, state: dict) -> None:
    """Atomically write a heartbeat, preserving the pid across updates.

    The watcher rewrites the heartbeat every cycle (even with no alerts), so
    the pid is merged from the previous heartbeat to keep the dashboard able
    to signal the live process.
    """
    prior = read_heartbeat(agent_id)
    merged = dict(prior)
    merged.update(state)
    merged.setdefault("pid", prior.get("pid"))
    p = heartbeat_path(agent_id)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(merged, indent=2, default=str))
    tmp.replace(p)


def mark_stopped(agent_id: str, reason: str, **extra) -> None:
    state = {"status": "stopped", "at": time.strftime("%Y-%m-%dT%H:%M:%S"), "reason": reason}
    state.update(extra)
    write_heartbeat(agent_id, state)


# --------------------------------------------------------------------------- #
# Liveness + status
# --------------------------------------------------------------------------- #
def _proc_state(pid) -> str | None:
    """/proc process state char (R/S/D/T/Z/...), or None when not readable."""
    try:
        stat = Path(f"/proc/{int(pid)}/stat").read_text(errors="replace")
        return stat[stat.rfind(")") + 2] if ")" in stat else None
    except (OSError, ValueError):
        return None


def pid_alive(pid) -> bool:
    """True when the pid is a live, non-zombie process.

    `os.kill(pid, 0)` alone is not enough on Linux: it also succeeds on zombies
    (dead children awaiting reap), which would make a stopped watcher look alive.
    On Windows there is no /proc and `os.kill(pid, 0)` is not a reliable
    existence check, so we use OpenProcess + GetExitCodeProcess instead.
    """
    try:
        pid_i = int(pid)
    except (TypeError, ValueError):
        return False
    if os.name == "nt":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        STILL_ACTIVE = 259
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid_i)
        if not handle:
            return False
        exit_code = ctypes.c_ulong()
        ok = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
        ctypes.windll.kernel32.CloseHandle(handle)
        return bool(ok) and exit_code.value == STILL_ACTIVE
    try:
        os.kill(pid_i, 0)
        return _proc_state(pid_i) not in (None, "Z")
    except (ProcessLookupError, PermissionError, OSError, TypeError, ValueError):
        return False


def _iso_age(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        import datetime

        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return (datetime.datetime.now(datetime.timezone.utc) - dt).total_seconds()
    except Exception:  # noqa: BLE001
        return None


def status(agent_id: str) -> dict:
    """Current status of one agent: running/stopped + last activity counters."""
    hb = read_heartbeat(agent_id)
    raw_status = hb.get("status")
    pid = hb.get("pid")
    alive = bool(pid) and pid_alive(pid)
    age = _iso_age(hb.get("at"))
    if alive and raw_status in ("running", "starting"):
        running = True
    elif not alive:
        running = False
    else:
        running = alive and (age is None or age < AGENT_POLL_TOLERANCE)
    return {
        "agent_id": sanitize_id(agent_id),
        "running": running,
        "status": raw_status or ("running" if alive else "stopped"),
        "pid": pid,
        "last_heartbeat": hb.get("at"),
        "last_heartbeat_age_s": age,
        "cycle": hb.get("cycle"),
        "triaged_this_cycle": hb.get("triaged_this_cycle"),
        "alerts_seen": hb.get("alerts_seen"),
        "stop_file_present": stop_file_path(agent_id).exists(),
        "log_exists": log_file_path(agent_id).exists(),
        "reason": hb.get("reason"),
    }


def list_agents() -> list[dict]:
    """Every agent the dashboard knows about (deployed), default first."""
    names: list[str] = []
    base = Path(cfg.AGENT_DIR or "data/agents")
    if base.is_dir():
        for child in sorted(base.iterdir()):
            if not child.is_dir():
                continue
            has_state = any((child / f).exists() for f in ("heartbeat.json", "stop.txt", "run.log"))
            if has_state:
                names.append(child.name)
    # The legacy default agent counts too when it has any artifact.
    if any(
        p.exists()
        for p in (heartbeat_path("default"), stop_file_path("default"), log_file_path("default"))
    ):
        names = ["default"] + [n for n in names if n != "default"]
    return [status(n) for n in names]


def counts(agents: list[dict] | None = None) -> dict:
    agents = agents if agents is not None else list_agents()
    running = sum(1 for a in agents if a["running"])
    return {
        "deployed": len(agents),
        "running": running,
        "stopped": len(agents) - running,
    }


def tail_lines(path: Path, n: int) -> list[str]:
    """Return the last `n` lines of a text file without loading it all."""
    n = max(1, min(int(n), 5000))
    try:
        with path.open("r", errors="replace") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 8192 * n))
            data = f.read()
    except OSError:
        return []
    lines = data.splitlines()
    return lines[-n:]


def _find_watcher_pids_windows(aid: str) -> list[int]:
    """Windows equivalent of /proc cmdline scan (via Win32_Process)."""
    import json
    import subprocess

    # Compress JSON so a single process is an object and many are an array.
    script = (
        "$rows = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.CommandLine -and ($_.CommandLine -like '*run.py*') } | "
        "ForEach-Object { [PSCustomObject]@{ pid = $_.ProcessId; cmd = $_.CommandLine } }); "
        "if ($rows.Count -eq 0) { '' } else { $rows | ConvertTo-Json -Compress }"
    )
    try:
        raw = subprocess.check_output(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
            text=True,
            errors="replace",
            timeout=20,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return []
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    found: list[int] = []
    for item in data or []:
        cmd = str(item.get("cmd") or "")
        try:
            pid = int(item.get("pid"))
        except (TypeError, ValueError):
            continue
        args = cmd.split()
        if "--agent-id" in args:
            i = args.index("--agent-id")
            if i + 1 < len(args) and args[i + 1].strip("\"'") == aid:
                if pid_alive(pid):
                    found.append(pid)
        elif aid == "default" and "run.py" in cmd:
            if pid_alive(pid):
                found.append(pid)
    return sorted(set(found))


def find_watcher_pids(agent_id: str) -> list[int]:
    """Pids of live `run.py` watchers for `agent_id`, found via /proc cmdline
    (Linux) or Win32_Process command lines (Windows).

    This is the authoritative process discovery used by Stop/Kill: it works
    even when the heartbeat pid is missing or stale (e.g. a watcher started
    outside the dashboard, or an older watcher whose heartbeat file lost its
    pid after the first alert cycle). For the default agent it also matches
    legacy invocations (`python run.py` with no --agent-id at all).
    """
    import glob

    aid = sanitize_id(agent_id)
    if os.name == "nt":
        return _find_watcher_pids_windows(aid)
    found: list[int] = []
    try:
        entries = glob.glob("/proc/[0-9]*/cmdline")
    except OSError:
        return found
    for path in entries:
        try:
            raw = Path(path).read_bytes().split(b"\x00")
        except OSError:
            continue
        args = [p for p in (a.decode(errors="replace") for a in raw) if p]
        if not args or not any("run.py" in a for a in args):
            continue
        if "--agent-id" in args:
            i = args.index("--agent-id")
            if i + 1 < len(args) and args[i + 1] == aid:
                if _proc_state(int(Path(path).parent.name)) != "Z":
                    found.append(int(Path(path).parent.name))
        elif aid == "default":
            # legacy `python run.py` with no agent-id - it IS the default watcher
            if _proc_state(int(Path(path).parent.name)) != "Z":
                found.append(int(Path(path).parent.name))
    return sorted(set(found))
