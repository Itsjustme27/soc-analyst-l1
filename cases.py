"""
Case/incident grouping - clusters alerts from data/triage_log.jsonl by
shared host or user within a time window, so an analyst reviewing a flurry
of related alerts sees "3 alerts, same host, 10 minutes apart" as one case
instead of three unconnected rows. Read-only, in the same spirit as
metrics.py - nothing is written here, this is just a different view over
the same log.

Two alerts link into the same case when they share a non-empty host OR a
non-empty user (not necessarily both - a host detects a beacon and the
process ran under some user; either link is a real connection worth
grouping on) AND they're within CASE_WINDOW_MINUTES of each other. Grouping
uses union-find over pairwise links so a chain (A-B share a host, B-C share
a user) merges into one case even though A and C share nothing directly.

Like backtest_rule() and metrics.py, this tolerates the log's inconsistent
timestamping (only run.py's watch-loop entries carry a real "ts"; main.py's
and the dashboard's on-demand entries don't) - an entry with no "ts" is
treated as arriving one second after the previous entry, the same
convention used in rules.py's backtest_rule().
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from config import cfg

DEFAULT_WINDOW_MINUTES = 30
DEFAULT_SCAN_LIMIT = 500  # grouping is O(n^2) - bound the working set


def _triage_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path) if path else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")
    )


def _read_entries(path: Path, limit: int | None) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    lines = [l for l in path.read_text().splitlines() if l.strip()]
    if limit:
        lines = lines[-int(limit) :]
    out = []
    now = 0.0
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry.get("alert"), dict):
            continue
        ts_str = entry.get("ts")
        if ts_str:
            try:
                now = time.mktime(time.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                now += 1.0
        else:
            now += 1.0
        entry["_ts_epoch"] = now
        out.append(entry)
    return out


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, i: int, j: int) -> None:
        ri, rj = self.find(i), self.find(j)
        if ri != rj:
            self.parent[ri] = rj


def _shares_host_or_user(a: dict[str, Any], b: dict[str, Any]) -> bool:
    host_a, host_b = a.get("host"), b.get("host")
    if host_a and host_b and host_a == host_b:
        return True
    user_a, user_b = a.get("user"), b.get("user")
    if user_a and user_b and user_a == user_b:
        return True
    return False


def group_cases(
    *,
    log_path: str | Path | None = None,
    window_minutes: float = DEFAULT_WINDOW_MINUTES,
    limit: int | None = DEFAULT_SCAN_LIMIT,
) -> list[dict[str, Any]]:
    """Cluster recent triage log entries into cases. Returns cases newest-
    first, each: {case_id, host, user, alert_count, alert_ids, verdicts,
    needs_review_count, first_seen, last_seen, rule_tags}. Singleton alerts
    (nothing else nearby shares a host/user) are still returned as
    one-alert "cases" - this is a grouping view, not a filter."""
    entries = _read_entries(_triage_log_path(log_path), limit)
    n = len(entries)
    if n == 0:
        return []

    window_s = window_minutes * 60
    uf = _UnionFind(n)
    for i in range(n):
        alert_i = entries[i]["alert"]
        ts_i = entries[i]["_ts_epoch"]
        for j in range(i + 1, n):
            alert_j = entries[j]["alert"]
            if abs(entries[j]["_ts_epoch"] - ts_i) > window_s:
                continue
            if _shares_host_or_user(alert_i, alert_j):
                uf.union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)

    cases = []
    for root, indices in groups.items():
        members = [entries[i] for i in indices]
        alerts = [m["alert"] for m in members]
        hosts = {a.get("host") for a in alerts if a.get("host")}
        users = {a.get("user") for a in alerts if a.get("user")}
        verdicts: dict[str, int] = {}
        needs_review = 0
        rule_tags: set[str] = set()
        for m in members:
            v = (m.get("result") or {}).get("verdict", "unknown")
            verdicts[v] = verdicts.get(v, 0) + 1
            if m.get("needs_human_review"):
                needs_review += 1
            for match in m.get("rule_matches") or []:
                if match.get("triggered") and match.get("action", {}).get("tag"):
                    rule_tags.add(match["action"]["tag"])
        times = [m["_ts_epoch"] for m in members]

        cases.append(
            {
                "case_id": f"case-{root}",
                "host": sorted(hosts)[0]
                if len(hosts) == 1
                else (", ".join(sorted(hosts)) if hosts else None),
                "user": sorted(users)[0]
                if len(users) == 1
                else (", ".join(sorted(users)) if users else None),
                "alert_count": len(members),
                "alert_ids": [a.get("alert_id") for a in alerts],
                "verdicts": verdicts,
                "needs_review_count": needs_review,
                "rule_tags": sorted(rule_tags),
                "first_seen": min(times),
                "last_seen": max(times),
            }
        )

    cases.sort(key=lambda c: c["last_seen"], reverse=True)
    return cases


if __name__ == "__main__":  # pragma: no cover - thin CLI wrapper
    import argparse

    parser = argparse.ArgumentParser(
        description="Group data/triage_log.jsonl alerts into cases by shared host/user."
    )
    parser.add_argument("--window-minutes", type=float, default=DEFAULT_WINDOW_MINUTES)
    parser.add_argument("--limit", type=int, default=DEFAULT_SCAN_LIMIT)
    parser.add_argument(
        "--min-alerts", type=int, default=1, help="Only show cases with at least N alerts."
    )
    args = parser.parse_args()

    cases = group_cases(window_minutes=args.window_minutes, limit=args.limit)
    cases = [c for c in cases if c["alert_count"] >= args.min_alerts]
    if not cases:
        print("No cases found (or none met --min-alerts).")
    for c in cases:
        label = c["host"] or c["user"] or "(no host/user)"
        print(
            f"  {c['case_id']}  {label}  {c['alert_count']} alert(s)  "
            f"verdicts={c['verdicts']}  needs_review={c['needs_review_count']}  "
            f"tags={c['rule_tags']}"
        )
        print(f"    alerts: {', '.join(str(a) for a in c['alert_ids'])}")
