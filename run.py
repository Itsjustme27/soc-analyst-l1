"""
run.py - the actual SOC analyst, as an overnight watcher.

This is the process you leave running overnight ("run through the night") and
shut off when you're finished ("shi if needed") from the dashboard. It links
the *real* stubs together:

  - SIEM  : whatever the dashboard registered (siem_providers.json) or the
            env-seeded Wazuh connection from .env (SIEM_PROVIDER=wazuh).
  - LLM   : the configured provider (FreeLLMAPI gateway / OpenAI-compatible
            endpoint; 429 + 5xx + network-error retries with backoff are
            already handled inside the provider so one free-gateway 429 does
            not abort a whole overnight batch).
  - Agent : the real TriageAgent tool-loop - the same one the dashboard runs
            for single-alert triage. Every verdict is appended to the audit
            log (data/chat_log.jsonl) with the full transcript.

Run modes
---------
    python run.py                 # watch mode (default): loop forever
    python run.py --exit-after 50 # run ~50 alert cycles then exit cleanly
    python run.py --interval 60   # sleep 60s between polls
    python run.py --siem <id>     # SIEM provider id from the dashboard store
    python run.py --agent-id <id> # named watcher (dashboard spawns these -
                                  # state/logs live under data/agents/<id>/)
    python run.py --provider mock # force the mock LLM (offline dev/CI)

The dashboard spawns watchers with a fully static argv and delivers the
selector/identity via the process environment instead (SOC_WATCHER_SIEM,
SOC_WATCHER_AGENT_ID) - env wins over the CLI flags above, which remain for
direct/manual invocations.

Clean shutdown is honoured three ways - all exit 0 so the dashboard/CI sees a
clean stop:
  1. SIGINT / SIGTERM (Ctrl+C, `kill <pid>`, dashboard "stop" button).
  2. `--exit-after N` (run at most N poll cycles).
  3. A stop-file (default data/agent_stop.txt), created by the dashboard's
     "Stop overnight run" button - checked once per cycle, so you can stop it
     remotely without needing the terminal.

The watcher writes its heartbeat *every* poll cycle (even when there are no
alerts) plus an initial "starting" heartbeat on boot, so the dashboard always
knows it is alive and can signal it - an idle SIEM must not look "stopped".
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

import agent_control as ac
import notify
import rules
from agent.triage_agent import TriageAgent, needs_human_review
from config import cfg
from llm import get_provider
from siem_providers import connector_for, load_providers, resolve_connector

AGENT_ID = "default"
_CYCLES_DONE = 0


# --------------------------------------------------------------------------- #
# Stop-file + heartbeat plumbing (shared with the dashboard "agent control").
# --------------------------------------------------------------------------- #
def stop_file_path() -> Path:
    return ac.stop_file_path(AGENT_ID)


def heartbeat_path() -> Path:
    return ac.heartbeat_path(AGENT_ID)


def write_heartbeat(state: dict[str, Any]) -> None:
    # The watcher always knows its own pid - guarantee it is in every heartbeat
    # so the dashboard can signal the process even if it spawned this watcher
    # without writing one itself.
    state.setdefault("pid", os.getpid())
    ac.write_heartbeat(AGENT_ID, state)


def read_heartbeat() -> dict[str, Any]:
    return ac.read_heartbeat(AGENT_ID)


def mark_stopped(reason: str = "stop requested") -> None:
    ac.mark_stopped(AGENT_ID, reason, cycles=_CYCLES_DONE)


# --------------------------------------------------------------------------- #
def _pull_alerts(siem) -> list[dict[str, Any]]:
    """Best-effort pull of new alerts from whatever SIEM is connected."""
    if siem is None:
        return []
    try:
        return siem.get_new_alerts() or []
    except Exception as e:  # noqa: BLE001 - a dead connection shouldn't kill the watch
        print(f"  [run] SIEM pull failed (will retry next cycle): {e}")
        return []


def _run_cycle(siem, *, cycle: int, exit_after: int) -> bool:
    """Run one poll cycle. Returns True when the watcher should stop."""
    alerts = _pull_alerts(siem)
    if not alerts:
        if stop_file_path().exists():
            return True  # dashboard Stop pressed - exit at end of cycle
        if cycle == 1:
            print("  [run] No alerts in the first poll - watching...")
        # Heartbeat EVERY cycle, even with nothing to triage - this is how the
        # dashboard knows the watcher is alive and enables its Stop button.
        write_heartbeat(
            {
                "status": "running",
                "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "cycle": cycle,
                "triaged_this_cycle": 0,
                "alerts_seen": 0,
            }
        )
        return False

    agent = TriageAgent(siem=siem)
    triaged = 0
    # This is the same audit trail main.py/dashboard.py write to - the
    # variable used to fall back to "data/chat_log.jsonl" (a confusing
    # leftover from the chat-agent panel's own, separate log) even though
    # cfg.TRIAGE_LOG_PATH is never actually empty; that dead fallback is
    # gone now, and this always lands in data/triage_log.jsonl by default.
    log = Path(cfg.TRIAGE_LOG_PATH or "data/triage_log.jsonl")

    for alert in alerts:
        if stop_file_path().exists():
            return True
        try:
            rule_matches = rules.evaluate_all(alert)
        except Exception as e:  # noqa: BLE001 - a bad rule should never kill the watch
            print(f"  [run] rule evaluation failed for {alert.get('alert_id')}: {e}")
            rule_matches = []
        triggered = [m for m in rule_matches if m["triggered"]]
        if triggered:
            print(
                f"  [run] cycle {cycle}: {alert.get('alert_id')} matched rule(s): "
                f"{', '.join(m['name'] for m in triggered)}"
            )
            try:
                notify.notify_rule_matches(alert, rule_matches)
            except Exception as e:  # noqa: BLE001 - a bad webhook must never kill the watch
                print(f"  [run] notify failed (continuing): {e}")

        try:
            result = agent.triage(alert)
        except Exception as e:  # noqa: BLE001 - never let one alert kill the watch
            print(f"  [run] triage failed for {alert.get('alert_id')}: {e}")
            continue
        entry = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "provider": (siem.name if siem is not None else "none"),
            "alert_id": alert.get("alert_id"),
            "result": result.to_dict()
            if hasattr(result, "to_dict")
            else {
                "verdict": result.verdict,
                "confidence": result.confidence,
                "recommended_action": result.recommended_action,
                "rationale": (result.rationale or "")[:500],
            },
            "rule_matches": rule_matches,
            "needs_human_review": needs_human_review(result, rule_matches),
            "cycle": cycle,
        }
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        triaged += 1
        print(
            f"  [run] cycle {cycle}: {alert.get('alert_id')} -> "
            f"{result.verdict} ({result.confidence:.2f})"
        )

    write_heartbeat(
        {
            "status": "running",
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "cycle": cycle,
            "triaged_this_cycle": triaged,
            "alerts_seen": len(alerts),
        }
    )
    if exit_after and cycle >= exit_after:
        print(f"  [run] reached --exit-after {exit_after} cycles; stopping.")
        return True
    return False


# --------------------------------------------------------------------------- #
def run_watch(*, siem, interval: float, exit_after: int) -> int:
    global _CYCLES_DONE
    stop = stop_file_path()
    stop.unlink(missing_ok=True)

    def _on_signal(signum, _frame):
        print(f"  [run] signal {signum} received - shutting down cleanly.")
        mark_stopped()
        sys.exit(0)

    signal.signal(signal.SIGINT, _on_signal)
    signal.signal(signal.SIGTERM, _on_signal)

    # Initial heartbeat so the dashboard sees a live pid immediately, even
    # before the first poll cycle finishes.
    write_heartbeat(
        {
            "status": "starting",
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "cycle": 0,
            "alerts_seen": 0,
            "triaged_this_cycle": 0,
            "reason": "started",
        }
    )

    print("=" * 66)
    print(
        f" SOC overnight watcher · agent={AGENT_ID or 'default'} "
        f"siem={siem.name if siem is not None else 'none'}"
    )
    print(
        f" LLM={cfg.LLM_PROVIDER} · retries={cfg.LLM_MAX_RETRIES} "
        f"(backoff {cfg.LLM_RETRY_BACKOFF_BASE}s)"
    )
    print(f" interval={interval}s · exit_after={exit_after or 'forever'}")
    print(f" stop-file: {stop}   (create this file to stop from the dashboard)")
    print(f" audit:     {cfg.TRIAGE_LOG_PATH}")
    print("=" * 66)

    cycle = 0
    while True:
        cycle += 1
        _CYCLES_DONE = cycle
        # Stop-file is checked EVERY cycle, before anything else - an idle
        # watcher (no alerts to triage) must still honour a dashboard Stop.
        if stop_file_path().exists():
            print("  [run] stop-file found - stopping.")
            mark_stopped()
            print("  [run] stop requested via stop-file; exiting 0.")
            return 0
        try:
            if _run_cycle(siem, cycle=cycle, exit_after=exit_after):
                mark_stopped()
                print("  [run] stop requested via stop-file/exit-after; exiting 0.")
                return 0
        except KeyboardInterrupt:
            mark_stopped()
            print("  [run] interrupted; exiting 0.")
            return 0
        except Exception as e:  # noqa: BLE001
            print(f"  [run] cycle {cycle} errored (continuing): {e}")
        time.sleep(interval)


# --------------------------------------------------------------------------- #
def main() -> int:  # pragma: no cover - thin argparse wrapper
    parser = argparse.ArgumentParser(description="SOC triage agent - overnight watcher")
    parser.add_argument(
        "--siem",
        default=None,
        help="SIEM provider id from the dashboard store, or a "
        "platform name to build from env creds (default: "
        "resolve_connector(None) -> env-seeded Wazuh/mock).",
    )
    parser.add_argument(
        "--provider",
        default=None,
        help="LLM provider override: anthropic|openai|google|mock|freellmapi",
    )
    parser.add_argument(
        "--agent-id",
        default="default",
        help="watcher id (dashboard spawns named watchers; state and "
        "logs live under data/agents/<id>/ - 'default' keeps the "
        "legacy data/agent_* paths)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=cfg.AGENT_POLL_INTERVAL,
        help="seconds between polls (default: AGENT_POLL_INTERVAL)",
    )
    parser.add_argument(
        "--exit-after",
        type=int,
        default=0,
        help="stop cleanly after N poll cycles (0 = run forever)",
    )
    args = parser.parse_args()

    # Watchers spawned by the dashboard receive their identity and SIEM
    # selector in the process environment: the dashboard keeps its argv
    # fully static (no user-controlled string may influence the command
    # line), so a spawned watcher finds its params in SOC_WATCHER_* here.
    # Direct invocations still pass --agent-id/--siem flags; env wins when
    # both are present.
    global AGENT_ID
    agent_id = os.environ.get("SOC_WATCHER_AGENT_ID") or args.agent_id
    AGENT_ID = ac.sanitize_id(agent_id)

    if args.provider:
        get_provider(args.provider)  # validate/instantiate early so a bad key fails fast

    siem = None
    siem_sel = os.environ.get("SOC_WATCHER_SIEM") or args.siem
    if siem_sel:
        sig = siem_sel
        match = next((p for p in load_providers() if str(p.get("id")) == sig), None)
        if match is None:
            # allow a bare platform name (wazuh/mock/...) -> use env creds
            try:
                siem = resolve_connector(sig)
            except ValueError as e:
                print(f"error: {e}")
                return 2
        else:
            siem = connector_for(match)
    else:
        siem = resolve_connector(None)

    return run_watch(siem=siem, interval=args.interval, exit_after=args.exit_after)


if __name__ == "__main__":
    sys.exit(main())
