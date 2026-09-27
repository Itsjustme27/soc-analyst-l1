"""
Entry point. Two modes:

  python main.py demo
      Runs the agent against seed_data/mock_alerts.json. Use this first -
      no credentials needed except ANTHROPIC_API_KEY, and set MOCK_MODE=true
      in .env so SIEM/CrowdStrike calls are stubbed.

  python main.py live [--siem <provider-id-or-platform>]
      Pulls real new alerts from the selected SIEM connection (default:
      SIEM_PROVIDER in .env) and triages each one against real CrowdStrike
      enrichment. Requires the relevant credentials and MOCK_MODE=false.
      --siem can be a dashboard-registered provider id (see python
      dashboard.py) or a platform name: splunk | qradar | elastic |
      sentinel | mock.

Every run writes one line per case to data/triage_log.jsonl - that's your
audit trail and also the input queue for the feedback CLI.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

import notify
import rules
from agent.triage_agent import TriageAgent, needs_human_review
from config import cfg
from connectors.siem import SIEMConnector


def _triage_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path) if path else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")
    )


def run_demo(provider: str | None = None):
    alerts = json.loads(Path("seed_data/mock_alerts.json").read_text())
    _run_batch(alerts, provider)


def run_live(provider: str | None = None, siem: str | None = None):
    from siem_providers import load_providers, resolve_connector

    try:
        connector = resolve_connector(siem)
    except ValueError as e:
        print(f"Error: {e}")
        print("Available connections/platforms:")
        for pid in sorted(p["id"] for p in load_providers()):
            print(f"  - {pid}")
        return
    print(f"Pulling alerts from SIEM provider: {connector.name} ({connector.platform})")
    try:
        alerts = connector.get_new_alerts()
    except Exception as e:  # noqa: BLE001 - unconfigured/unreachable provider
        print(f"Error pulling alerts from '{connector.name}': {e}")
        print(
            "Is the provider configured? Check the dashboard (python dashboard.py) "
            "for its status, or the matching <PLATFORM>_* vars in .env."
        )
        return
    if not alerts:
        print("No new alerts.")
        return
    _run_batch(alerts, provider, connector)


def _run_batch(alerts: list[dict], provider: str | None = None, siem: SIEMConnector | None = None):
    agent = TriageAgent(provider=provider, siem=siem)
    log_path = _triage_log_path()
    log_path.parent.mkdir(parents=True, exist_ok=True)

    for alert in alerts:
        alert_id = alert.get("alert_id", "unknown")
        print(
            f"\n{'=' * 70}\nTriaging {alert_id}: {alert.get('rule_name', alert.get('description', ''))}\n{'=' * 70}"
        )

        try:
            rule_matches = rules.evaluate_all(alert)
        except Exception as e:  # noqa: BLE001 - a bad rule should never block triage
            print(f"  [rules] evaluation failed (continuing without rule tags): {e}")
            rule_matches = []
        triggered = [m for m in rule_matches if m["triggered"]]
        if triggered:
            print(f"  Rule matches:       {', '.join(m['name'] for m in triggered)}")
            try:
                notify.notify_rule_matches(alert, rule_matches)
            except Exception as e:  # noqa: BLE001 - a bad webhook must never block triage
                print(f"  [notify] failed (continuing): {e}")

        result = agent.triage(alert)

        print(f"  Verdict:            {result.verdict}")
        print(f"  Confidence:         {result.confidence:.2f}")
        print(f"  Recommended action: {result.recommended_action}")
        print(f"  Rationale:          {result.rationale}")
        print(f"  Evidence used:      {result.evidence_used}")

        needs_human = needs_human_review(result, rule_matches)
        print(
            f"  --> {'NEEDS HUMAN REVIEW' if needs_human else 'auto-closeable (still logged for spot-check)'}"
        )

        with open(log_path, "a") as f:
            f.write(
                json.dumps(
                    {
                        "alert": alert,
                        "result": asdict(result),
                        "rule_matches": rule_matches,
                        "needs_human_review": needs_human,
                    },
                    default=str,
                )
                + "\n"
            )


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC L1 triage agent")
    parser.add_argument("mode", nargs="?", default="demo", choices=["demo", "live"])
    parser.add_argument(
        "--provider",
        default=None,
        help="LLM provider override: anthropic | openai | google | mock | freellmapi "
        "(default: LLM_PROVIDER from .env)",
    )
    parser.add_argument(
        "--siem",
        default=None,
        help="SIEM connection to pull alerts from (live mode): a provider id from the "
        "dashboard (python dashboard.py) or a platform: splunk | qradar | "
        "elastic | sentinel | mock (default: SIEM_PROVIDER from .env)",
    )
    args = parser.parse_args()

    if args.mode == "demo":
        run_demo(args.provider)
    else:
        run_live(args.provider, args.siem)
