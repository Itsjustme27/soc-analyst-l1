"""
Analyst-facing feedback loop.

  python feedback_cli.py review [--analyst NAME]
      Walk through cases in data/triage_log.jsonl that need human review,
      confirm or correct the agent's verdict. Every response is captured via
      MemoryStore.capture_feedback (see agent/memory.py) - this both logs
      raw feedback AND immediately stores the closed case into the RAG
      'cases' collection for future retrieval.

  python feedback_cli.py distill [--analyst NAME]
      Batch job (run nightly / weekly). Looks at recent disagreements and
      proposes candidate "lessons". YOU approve each one before it's written
      to the 'lessons' collection the live agent retrieves from - this is
      the human checkpoint that keeps self-improvement from drifting on
      noisy feedback.

Analyst identity: every correction and every lesson approval is tagged with
who did it (data/feedback_log.jsonl's "analyst" field; a lesson's
"approved_by" metadata) - this is a single free-text name, not an account
system (see dashboard.py's DASHBOARD_TOKEN docstring for why this project
doesn't do full multi-user auth). Resolved in this order: --analyst NAME,
then the ANALYST_NAME env var, then an interactive prompt (once per run).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from pathlib import Path

from agent.memory import MemoryStore
from config import cfg

TRIAGE_LOG = Path("data/triage_log.jsonl")
REVIEWED_MARKER = Path("data/reviewed_case_ids.json")


def _triage_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path) if path else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")
    )


def _load_reviewed() -> set[str]:
    if REVIEWED_MARKER.exists():
        return set(json.loads(REVIEWED_MARKER.read_text()))
    return set()


def _save_reviewed(ids: set[str]) -> None:
    REVIEWED_MARKER.write_text(json.dumps(sorted(ids)))


def _resolve_analyst(cli_value: str | None) -> str:
    """--analyst NAME > ANALYST_NAME env var > interactive prompt (once)."""
    if cli_value:
        return cli_value
    env_value = os.getenv("ANALYST_NAME", "").strip()
    if env_value:
        return env_value
    if sys.stdin.isatty():
        return input("Your name (for the audit trail - enter to leave blank): ").strip()
    return ""


def review(analyst: str = ""):
    triage_log = _triage_log_path()
    if not triage_log.exists():
        print("No triage log yet - run main.py first.")
        return

    store = MemoryStore()
    reviewed = _load_reviewed()
    records = [json.loads(l) for l in triage_log.read_text().splitlines()]

    pending = [r for r in records if r["needs_human_review"]]
    print(f"{len(pending)} case(s) flagged for review.")
    if analyst:
        print(f"Reviewing as: {analyst}")
    print()

    for rec in pending:
        alert = rec["alert"]
        result = rec["result"]
        case_id = alert.get("alert_id", str(uuid.uuid4()))
        if case_id in reviewed:
            continue

        print(f"\n--- {case_id}: {alert.get('rule_name', alert.get('description'))} ---")
        print(f"Agent verdict: {result['verdict']} (confidence {result['confidence']:.2f})")
        print(f"Agent rationale: {result['rationale']}")
        print(f"Recommended action: {result['recommended_action']}")

        answer = input("\nAgree with verdict? [y/n/skip]: ").strip().lower()
        if answer == "skip":
            continue
        if answer == "y":
            analyst_verdict = result["verdict"]
            reasoning = (
                input("Optional note (enter to skip): ").strip()
                or "Analyst confirmed agent verdict."
            )
        else:
            analyst_verdict = input(
                "Correct verdict [false_positive/true_positive/escalate]: "
            ).strip()
            reasoning = input("Why? (this becomes training signal - be specific): ").strip()

        store.capture_feedback(case_id, alert, result, analyst_verdict, reasoning, analyst=analyst)
        reviewed.add(case_id)
        _save_reviewed(reviewed)
        print("Feedback captured.")

    print("\nReview complete.")


def distill(analyst: str = ""):
    store = MemoryStore()
    # Look at all feedback ever captured; in production you'd pass the
    # timestamp of the last distill run instead of 0.
    candidates = store.distill_lessons(since_ts=0, min_records=3)

    if not candidates:
        print("No new generalizable lessons found (or not enough disagreement data yet).")
        return

    print(f"{len(candidates)} candidate lesson(s) found. Review each:\n")
    for c in candidates:
        print(f"\nProposed lesson: {c['lesson']}")
        print(f"Supporting cases: {c.get('supporting_case_ids', [])}")
        approve = input("Approve and add to agent memory? [y/n]: ").strip().lower()
        if approve == "y":
            store.approve_and_store_lesson(
                c["lesson"],
                {
                    "supporting_case_ids": json.dumps(c.get("supporting_case_ids", [])),
                    "added": time.time(),
                },
                approved_by=analyst,
            )
            print("Stored.")
        else:
            print("Skipped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SOC analyst feedback loop")
    parser.add_argument("cmd", nargs="?", default="review", choices=["review", "distill"])
    parser.add_argument(
        "--analyst",
        default=None,
        help="Your name, recorded with every correction/approval (default: "
        "ANALYST_NAME env var, or an interactive prompt).",
    )
    args = parser.parse_args()

    analyst_name = _resolve_analyst(args.analyst)
    if args.cmd == "review":
        review(analyst=analyst_name)
    elif args.cmd == "distill":
        distill(analyst=analyst_name)
