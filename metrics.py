"""
Aggregate metrics computed from data/triage_log.jsonl (+ data/feedback_log.jsonl
for the analyst-agreement rate), backing the dashboard's 📊 Metrics panel.

Everything here is read-only and stateless - nothing is written, nothing is
cached, so it's always a live view of whatever's currently in the logs. Kept
as its own module (rather than inline in dashboard.py) so it's usable from a
CLI/notebook too, and independently testable without spinning up Flask.

compute_metrics() tolerates every triage_log.jsonl entry shape the three
writers (main.py, run.py, dashboard.py) produce - they differ slightly (only
run.py writes "ts" and "provider"; only main.py/dashboard.py write
"siem_provider" and "rule_matches" in every entry) - see the per-writer
comments below.
"""

from __future__ import annotations

import json
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from config import cfg

# (low, high) - high is exclusive except for the top bucket, which also
# catches an exact confidence of 1.0.
CONFIDENCE_BUCKETS: list[tuple[float, float]] = [(0.0, 0.5), (0.5, 0.7), (0.7, 0.9), (0.9, 1.0)]


def _triage_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path) if path else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")
    )


def _feedback_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path)
        if path
        else Path(getattr(cfg, "FEEDBACK_LOG_PATH", "") or "data/feedback_log.jsonl")
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def _day_of(entry: dict[str, Any]) -> str:
    # Only run.py's watch-loop entries carry "ts" - main.py's/dashboard.py's
    # on-demand entries don't (see the run.py fix in this same changeset).
    ts = entry.get("ts")
    return str(ts)[:10] if ts else "unknown"


def _confidence_bucket(conf: float) -> str:
    for lo, hi in CONFIDENCE_BUCKETS:
        if lo <= conf < hi or (hi == 1.0 and conf == 1.0):
            return f"{lo:.1f}-{hi:.1f}"
    return "unknown"


def _provider_name(entry: dict[str, Any]) -> str:
    # dashboard.py's on-demand triage route writes "siem_provider": {"name": ...};
    # run.py's watch loop writes a flat "provider": "<name>"; main.py's demo/live
    # batches write neither (no provider selection concept there).
    siem_provider = entry.get("siem_provider")
    if isinstance(siem_provider, dict) and siem_provider.get("name"):
        return siem_provider["name"]
    if entry.get("provider"):
        return entry["provider"]
    return "unknown"


def _entry_ts(entry: dict[str, Any]) -> float | None:
    ts = entry.get("ts")
    if not isinstance(ts, str):
        return None
    try:
        return time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        return None


def compute_metrics(
    *,
    log_path: str | Path | None = None,
    feedback_path: str | Path | None = None,
    since_ts: float | None = None,
) -> dict[str, Any]:
    """`since_ts`, when given, only includes entries with a real "ts" field
    at or after that time - see this module's "period filtering" note (and
    digest.py, which is the main caller that sets it). An entry with no
    "ts" at all (today, that's every main.py/dashboard.py on-demand triage
    entry - only run.py's watch-loop entries carry one) is EXCLUDED when
    since_ts is set, on the theory that a periodic report shouldn't claim
    an alert happened "this week" when it genuinely can't tell. Leave
    since_ts unset (the default) to see everything regardless of timestamp.
    """
    entries = _read_jsonl(_triage_log_path(log_path))
    if since_ts is not None:
        entries = [e for e in entries if (ts := _entry_ts(e)) is not None and ts >= since_ts]
    total = len(entries)

    verdict_totals: Counter = Counter()
    verdict_by_day: dict[str, Counter] = defaultdict(Counter)
    confidence_hist: Counter = Counter()
    needs_review_count = 0
    provider_stats: dict[str, dict[str, int]] = defaultdict(lambda: {"count": 0, "needs_review": 0})
    rule_stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"triggered": 0, "true_positive": 0}
    )

    for e in entries:
        result = e.get("result") or {}
        verdict = result.get("verdict", "unknown")
        confidence = result.get("confidence")
        needs_review = bool(e.get("needs_human_review"))

        verdict_totals[verdict] += 1
        verdict_by_day[_day_of(e)][verdict] += 1
        if isinstance(confidence, (int, float)):
            confidence_hist[_confidence_bucket(float(confidence))] += 1
        if needs_review:
            needs_review_count += 1

        provider = _provider_name(e)
        provider_stats[provider]["count"] += 1
        if needs_review:
            provider_stats[provider]["needs_review"] += 1

        for m in e.get("rule_matches") or []:
            if not m.get("triggered"):
                continue
            name = m.get("name") or m.get("rule_id") or "unknown"
            rule_stats[name]["triggered"] += 1
            if verdict == "true_positive":
                rule_stats[name]["true_positive"] += 1

    feedback = _read_jsonl(_feedback_log_path(feedback_path))
    analyst_agreement = None
    if feedback:
        agreed = sum(1 for f in feedback if f.get("agreed"))
        by_analyst: dict[str, dict[str, int]] = defaultdict(lambda: {"reviewed": 0, "agreed": 0})
        for f in feedback:
            name = f.get("analyst") or "unknown"
            by_analyst[name]["reviewed"] += 1
            if f.get("agreed"):
                by_analyst[name]["agreed"] += 1
        analyst_agreement = {
            "reviewed": len(feedback),
            "agreed": agreed,
            "agreement_rate": agreed / len(feedback),
            "by_analyst": {
                name: {
                    **s,
                    "agreement_rate": (s["agreed"] / s["reviewed"]) if s["reviewed"] else 0.0,
                }
                for name, s in sorted(by_analyst.items())
            },
        }

    return {
        "total_alerts": total,
        "needs_human_review_rate": (needs_review_count / total) if total else 0.0,
        "verdict_totals": dict(verdict_totals),
        "verdict_by_day": {day: dict(counts) for day, counts in sorted(verdict_by_day.items())},
        "confidence_distribution": {
            f"{lo:.1f}-{hi:.1f}": confidence_hist.get(f"{lo:.1f}-{hi:.1f}", 0)
            for lo, hi in CONFIDENCE_BUCKETS
        },
        "by_provider": {
            name: {
                **stats,
                "needs_review_rate": (stats["needs_review"] / stats["count"])
                if stats["count"]
                else 0.0,
            }
            for name, stats in sorted(provider_stats.items())
        },
        "top_rules": sorted(
            (
                {
                    "name": name,
                    "triggered": s["triggered"],
                    "true_positive": s["true_positive"],
                    "true_positive_rate": (s["true_positive"] / s["triggered"])
                    if s["triggered"]
                    else 0.0,
                }
                for name, s in rule_stats.items()
            ),
            key=lambda r: r["triggered"],
            reverse=True,
        ),
        "analyst_agreement": analyst_agreement,
    }


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    print(json.dumps(compute_metrics(), indent=2))
