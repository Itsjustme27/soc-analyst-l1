"""
Scheduled digest reports - a periodic text summary built from metrics.py's
aggregates (optionally filtered to a period) and delivered via notify.py's
webhook. This is the piece you point cron/a scheduler at
(`python digest.py --period daily`), not something wired into the live
triage path - main.py/run.py/dashboard.py never call this on their own.

Period filtering only includes triage_log.jsonl entries that carry a real
"ts" timestamp - today, that's only run.py's watch-loop entries; main.py's
and the dashboard's on-demand entries don't record one (the same gap noted
throughout metrics.py, cases.py, and rules.py's backtest_rule()). A digest
run with --period daily/weekly against a log with no "ts"-bearing entries
will report zero activity even if alerts were actually triaged in that
window - use --period all to see everything regardless of timestamp.
"""

from __future__ import annotations

import time
from typing import Any

import cases
import metrics
import notify

PERIOD_SECONDS = {
    "daily": 24 * 3600,
    "weekly": 7 * 24 * 3600,
}


def _since_ts(period: str) -> float | None:
    if period == "all":
        return None
    if period not in PERIOD_SECONDS:
        raise ValueError(f"Unknown period '{period}'. Use: daily, weekly, all.")
    return time.time() - PERIOD_SECONDS[period]


def build_digest_text(period: str = "daily", *, top_n_rules: int = 5, top_n_cases: int = 5) -> str:
    """The human-readable digest body. Pure formatting over
    metrics.compute_metrics()/cases.group_cases() - no side effects."""
    since = _since_ts(period)
    m = metrics.compute_metrics(since_ts=since)

    label = {"daily": "Daily", "weekly": "Weekly", "all": "All-time"}.get(period, period)
    lines = [f"SOC triage digest ({label})"]

    if m["total_alerts"] == 0:
        lines.append("No triaged alerts in this period.")
        if since is not None:
            lines.append(
                "(Note: only run.py's watch-loop entries carry a timestamp - "
                "if you're only running main.py/the dashboard's on-demand triage, "
                "try --period all instead.)"
            )
        return "\n".join(lines)

    lines.append(f"Total alerts: {m['total_alerts']}")
    verdict_str = ", ".join(f"{v}: {n}" for v, n in sorted(m["verdict_totals"].items()))
    lines.append(f"Verdicts: {verdict_str}")
    lines.append(f"Needs human review: {m['needs_human_review_rate'] * 100:.0f}%")
    if m["analyst_agreement"]:
        aa = m["analyst_agreement"]
        lines.append(
            f"Analyst agreement: {aa['agreement_rate'] * 100:.0f}% ({aa['reviewed']} reviewed)"
        )

    if m["top_rules"]:
        lines.append("")
        lines.append("Top triggered rules:")
        for r in m["top_rules"][:top_n_rules]:
            lines.append(
                f"  - {r['name']}: {r['triggered']}x (TP rate {r['true_positive_rate'] * 100:.0f}%)"
            )

    if m["by_provider"]:
        lines.append("")
        lines.append("By SIEM provider:")
        for name, s in m["by_provider"].items():
            lines.append(
                f"  - {name}: {s['count']} alerts, {s['needs_review_rate'] * 100:.0f}% needs review"
            )

    try:
        window_minutes = max(
            cases.DEFAULT_WINDOW_MINUTES,
            (time.time() - since) / 60 if since else cases.DEFAULT_WINDOW_MINUTES,
        )
        grouped = [
            c for c in cases.group_cases(window_minutes=window_minutes) if c["alert_count"] >= 2
        ]
        if since is not None:
            grouped = [c for c in grouped if c["last_seen"] >= since]
        if grouped:
            lines.append("")
            lines.append("Notable clusters (2+ related alerts):")
            for c in grouped[:top_n_cases]:
                label = c["host"] or c["user"] or "?"
                lines.append(f"  - {label}: {c['alert_count']} alerts, tags={c['rule_tags']}")
    except Exception:  # noqa: BLE001 - the digest's headline numbers matter more than this extra section
        pass

    return "\n".join(lines)


def send_digest(period: str = "daily", *, target: str = "") -> dict[str, Any]:
    """Build the digest and send it through notify.py. Same guarantee as
    send_notification() - never raises, always logs locally to
    data/notifications.jsonl even if no webhook is configured."""
    text = build_digest_text(period)
    return notify.send_notification(text, target=target, extra={"kind": "digest", "period": period})


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    import argparse

    parser = argparse.ArgumentParser(description="Build and optionally send a SOC triage digest.")
    parser.add_argument("--period", default="daily", choices=["daily", "weekly", "all"])
    parser.add_argument(
        "--target", default="", help="Label included in the notification (e.g. '#soc-daily')."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the digest, don't send it via NOTIFY_WEBHOOK_URL.",
    )
    args = parser.parse_args()

    if args.dry_run:
        print(build_digest_text(args.period))
    else:
        result = send_digest(args.period, target=args.target)
        print(build_digest_text(args.period))
        print()
        print(f"[notify] sent={result['sent']} ok={result['ok']} detail={result['detail']}")
