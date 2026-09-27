"""
Alert rules - deterministic pre-triage correlation/filtering for SOC ops.

Alerts are pulled from whatever SIEM is connected (Splunk/QRadar/Elastic/
Sentinel/Wazuh/mock) already normalized to the common shape (see
connectors/siem/base.py: alert_id, rule_name, severity, description, host,
user, src_ip, raw_fields). A "rule" here is a cheap, local, deterministic
check run against that normalized alert *before* it reaches the LLM triage
loop - same idea as a SIEM correlation search, but evaluated locally so it
costs nothing and never depends on the LLM being reachable.

A rule has two parts:

  match     - a condition tree (see `evaluate_condition`) checked against a
              single alert. Conditions can reference a lookup table (see
              lookup_tables.py) via the `in_lookup` operator, so watchlists
              built from the dashboard/chat agent feed straight into rules.
  threshold - optional. If present, the match alone isn't enough to fire:
              N matching alerts for the same `group_by` field value must
              land within `window_minutes` (e.g. "5 failed-login alerts for
              the same src_ip within 15 minutes"). Counts are kept in a
              small persistent state file (RULE_STATE_PATH) so the window
              survives across separate `main.py live` / `run.py` polls.

Rule dict shape:

    {
      "id": "rule-xxxxxxxxxx",
      "name": "Brute force from known-bad ASN",
      "description": "",
      "enabled": true,
      "match": {
        "mode": "all",                      # "all" or "any"
        "conditions": [
          {"field": "severity", "op": "in", "value": ["high", "critical"]},
          {"field": "raw_fields.mfa_satisfied", "op": "eq", "value": false},
          {"field": "src_ip", "op": "in_lookup", "value": "known_bad_ips"}
        ]
      },
      "threshold": {"group_by": "src_ip", "window_minutes": 15, "count": 5},
      "action": {"tag": "credential_stuffing", "escalate": true, "notify": ""},
      "created": "2026-09-24T...", "updated": "2026-09-24T..."
    }

`evaluate_all(alert)` is the entry point main.py / run.py / dashboard.py
call per alert - see their `rule_matches` wiring.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any

from config import cfg

DEFAULT_PATH = Path("data/rules.json")
DEFAULT_STATE_PATH = Path("data/rule_state.json")

VALID_OPS = (
    "eq",
    "neq",
    "contains",
    "not_contains",
    "in",
    "not_in",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "not_exists",
    "in_lookup",
    "regex",
)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# Storage - same atomic-write JSON pattern as lookup_tables.py.
# --------------------------------------------------------------------------- #
def _current_path(path: str | Path | None) -> Path:
    return Path(path) if path else Path(getattr(cfg, "RULES_PATH", "") or DEFAULT_PATH)


def _current_state_path(path: str | Path | None) -> Path:
    return Path(path) if path else Path(getattr(cfg, "RULE_STATE_PATH", "") or DEFAULT_STATE_PATH)


def _load(file: Path) -> dict[str, dict[str, Any]]:
    if not file.exists():
        return {}
    try:
        data = json.loads(file.read_text())
    except (json.JSONDecodeError, OSError):
        return {}
    return data if isinstance(data, dict) else {}


def _save(file: Path, rules: dict[str, dict[str, Any]]) -> None:
    file.parent.mkdir(parents=True, exist_ok=True)
    tmp = file.with_suffix(".tmp")
    tmp.write_text(json.dumps(rules, indent=2, default=str))
    tmp.replace(file)


# --------------------------------------------------------------------------- #
# CRUD - mirrors lookup_tables.py's function shapes 1:1 so the dashboard
# routes/tests read the same way as the existing lookup-tables ones.
# --------------------------------------------------------------------------- #
def list_rules(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Summaries for the dashboard list view."""
    rules = _load(_current_path(path))
    out = []
    for rid, r in rules.items():
        conditions = (r.get("match") or {}).get("conditions") or []
        out.append(
            {
                "id": rid,
                "name": r.get("name", rid),
                "description": r.get("description", ""),
                "enabled": bool(r.get("enabled", True)),
                "condition_count": len(conditions),
                "has_threshold": bool(r.get("threshold")),
                "action": r.get("action", {}),
                "updated": r.get("updated", ""),
            }
        )
    return sorted(out, key=lambda r: r["name"])


def read_rule(rule_id: str, path: str | Path | None = None) -> dict[str, Any] | None:
    return _load(_current_path(path)).get(rule_id)


def _validate(payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "").strip()
    if not name:
        raise RuleError("Name is required.")

    match = payload.get("match") or {}
    conditions = match.get("conditions") or []
    if not isinstance(conditions, list):
        raise RuleError("match.conditions must be a list.")
    for c in conditions:
        if not isinstance(c, dict) or "field" not in c or "op" not in c:
            raise RuleError("Each condition needs at least 'field' and 'op'.")
        if c["op"] not in VALID_OPS:
            raise RuleError(f"Unknown op '{c['op']}'. Valid: {', '.join(VALID_OPS)}")
    mode = match.get("mode", "all")
    if mode not in ("all", "any"):
        raise RuleError("match.mode must be 'all' or 'any'.")

    threshold = payload.get("threshold") or None
    if threshold:
        if not threshold.get("group_by"):
            raise RuleError("threshold.group_by is required when threshold is set.")
        threshold = {
            "group_by": str(threshold["group_by"]),
            "window_minutes": float(threshold.get("window_minutes", 15) or 15),
            "count": int(threshold.get("count", 5) or 5),
        }

    action = payload.get("action") or {}
    action = {
        "tag": str(action.get("tag") or "").strip(),
        "escalate": bool(action.get("escalate", False)),
        "notify": str(action.get("notify") or "").strip(),
    }

    return {
        "name": name,
        "description": str(payload.get("description") or "").strip(),
        "enabled": bool(payload.get("enabled", True)),
        "match": {"mode": mode, "conditions": conditions},
        "threshold": threshold,
        "action": action,
    }


def validate_rule(payload: dict[str, Any]) -> dict[str, Any]:
    """Public wrapper around `_validate` - lets callers (e.g. the dashboard's
    'preview an unsaved draft' route) validate + normalize a rule payload
    without writing it to the store."""
    return _validate(payload)


def create_rule(payload: dict[str, Any], path: str | Path | None = None) -> dict[str, Any]:
    file = _current_path(path)
    rules = _load(file)
    valid = _validate(payload)
    rid = f"rule-{uuid.uuid4().hex[:10]}"
    rule = {"id": rid, "created": now_iso(), "updated": now_iso(), **valid}
    rules[rid] = rule
    _save(file, rules)
    return rule


def update_rule(
    rule_id: str, payload: dict[str, Any], path: str | Path | None = None
) -> dict[str, Any] | None:
    """Partial update - only keys present in `payload` are changed."""
    file = _current_path(path)
    rules = _load(file)
    existing = rules.get(rule_id)
    if not existing:
        return None
    merged = {**existing, **payload}
    valid = _validate(merged)
    rules[rule_id] = {**existing, **valid, "id": rule_id, "updated": now_iso()}
    _save(file, rules)
    return rules[rule_id]


def delete_rule(rule_id: str, path: str | Path | None = None) -> bool:
    file = _current_path(path)
    rules = _load(file)
    if rule_id not in rules:
        return False
    del rules[rule_id]
    _save(file, rules)
    # Best-effort: also drop this rule's threshold counters so a deleted
    # rule doesn't leave orphaned state behind.
    try:
        state_file = _current_state_path(None)
        state = _load(state_file)
        if rule_id in state:
            del state[rule_id]
            _save(state_file, state)
    except OSError:
        pass
    return True


# --------------------------------------------------------------------------- #
# Import/export - portable rule sets across environments (analogous to
# seed_data/playbooks/*.md, but for rules; see seed_data/rules/). Exported
# rules carry no id/created/updated - those are per-environment bookkeeping,
# not part of the rule's actual definition - and rules match across an
# import/export round trip by NAME, since ids won't line up between
# environments.
# --------------------------------------------------------------------------- #
_PORTABLE_KEYS = ("name", "description", "enabled", "match", "threshold", "action")


def export_rules(
    rule_ids: list[str] | None = None, path: str | Path | None = None
) -> list[dict[str, Any]]:
    """Portable representation of some or all saved rules - no id/created/
    updated. `rule_ids=None` (default) exports everything."""
    rules = _load(_current_path(path))
    selected = (
        rules.values() if rule_ids is None else (rules[rid] for rid in rule_ids if rid in rules)
    )
    return [{k: r.get(k) for k in _PORTABLE_KEYS} for r in selected]


def import_rules(
    rule_defs: list[dict[str, Any]],
    *,
    on_conflict: str = "skip",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Import a list of portable rule dicts (as produced by export_rules(),
    or hand-written - e.g. seed_data/rules/*.json). Matches existing rules
    by NAME. `on_conflict`: "skip" (default - leave the existing rule alone)
    or "overwrite" (update it in place, keeping its id/created).

    Returns {"created": [...], "updated": [...], "skipped": [...], "errors": [...]}
    - each entry is the rule name; a validation error on one rule_def never
    aborts the whole batch."""
    if on_conflict not in ("skip", "overwrite"):
        raise RuleError("on_conflict must be 'skip' or 'overwrite'.")

    file = _current_path(path)
    existing = _load(file)
    by_name = {r.get("name"): rid for rid, r in existing.items()}

    created: list[str] = []
    updated: list[str] = []
    skipped: list[str] = []
    errors: list[dict[str, str]] = []

    for rule_def in rule_defs:
        name = rule_def.get("name")
        try:
            if name in by_name:
                if on_conflict == "skip":
                    skipped.append(name)
                    continue
                update_rule(by_name[name], rule_def, path=path)
                updated.append(name)
            else:
                new_rule = create_rule(rule_def, path=path)
                by_name[new_rule["name"]] = new_rule["id"]
                created.append(new_rule["name"])
        except RuleError as e:
            errors.append({"name": name or "(unnamed)", "error": str(e)})

    return {"created": created, "updated": updated, "skipped": skipped, "errors": errors}


def import_rules_from_file(
    file_path: str | Path,
    *,
    on_conflict: str = "skip",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Import from a JSON file - either a bare list of rule dicts, or
    {"rules": [...]} (what export_rules() writes when dumped with
    json.dump({"rules": export_rules()}, f))."""
    data = json.loads(Path(file_path).read_text())
    rule_defs = data.get("rules", data) if isinstance(data, dict) else data
    return import_rules(rule_defs, on_conflict=on_conflict, path=path)


# --------------------------------------------------------------------------- #
# Condition evaluation.
# --------------------------------------------------------------------------- #
def _get_field(alert: dict[str, Any], field: str) -> Any:
    """Dotted-path lookup, with a convenience fallback into raw_fields.

    ``severity`` reads ``alert['severity']``; ``mfa_satisfied`` isn't a
    top-level key on the normalized alert shape (see base.py) but usually
    lives under ``raw_fields``, so a bare name falls back there too - this
    keeps rule conditions ergonomic without forcing analysts to write
    ``raw_fields.mfa_satisfied`` for every SIEM-specific field.
    """

    def _walk(obj: Any, parts: list[str]) -> Any:
        for p in parts:
            if isinstance(obj, dict) and p in obj:
                obj = obj[p]
            else:
                return None
        return obj

    parts = field.split(".")
    val = _walk(alert, parts)
    if val is None and len(parts) == 1 and parts[0] != "raw_fields":
        val = _walk(alert.get("raw_fields") or {}, parts)
    return val


def _coerce_num(val: Any) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def evaluate_condition(condition: dict[str, Any], alert: dict[str, Any]) -> bool:
    field = condition.get("field", "")
    op = condition.get("op", "eq")
    expected = condition.get("value")
    actual = _get_field(alert, field)

    if op == "exists":
        return actual is not None
    if op == "not_exists":
        return actual is None

    if op == "in_lookup":
        # Intentionally NOT path-overridable like the rest of this module's
        # functions: a rule should always check the live, real lookup tables
        # (the ones the dashboard/chat agent write to), not a test fixture -
        # so this always reads cfg.LOOKUP_TABLES_PATH via lookup_entry()'s
        # own default. Tests exercise this against the real configured path
        # (see tests/test_rules.py's test_in_lookup) rather than trying to
        # redirect it - don't "fix" this into a path parameter.
        import lookup_tables as lookup

        if actual is None:
            return False
        return lookup.lookup_entry(str(expected), str(actual)) is not None

    if op == "regex":
        if actual is None:
            return False
        try:
            return re.search(str(expected), str(actual), re.IGNORECASE) is not None
        except re.error:
            return False

    if op in ("gt", "gte", "lt", "lte"):
        a, e = _coerce_num(actual), _coerce_num(expected)
        if a is None or e is None:
            return False
        return {"gt": a > e, "gte": a >= e, "lt": a < e, "lte": a <= e}[op]

    if op in ("in", "not_in"):
        values = expected if isinstance(expected, list) else [expected]
        norm_values = [str(v).lower() for v in values]
        hit = actual is not None and str(actual).lower() in norm_values
        return hit if op == "in" else not hit

    if op in ("contains", "not_contains"):
        if actual is None:
            return False  # a missing field never "contains" or "not_contains" anything meaningful
        if isinstance(actual, (list, tuple, set)):
            hit = str(expected).lower() in [str(v).lower() for v in actual]
        else:
            hit = str(expected).lower() in str(actual).lower()
        return hit if op == "contains" else not hit

    # eq / neq (default)
    if actual is None and expected is not None:
        eq = False
    else:
        eq = (
            str(actual).lower() == str(expected).lower()
            if isinstance(expected, str) or isinstance(actual, str)
            else actual == expected
        )
    return eq if op == "eq" else not eq


def evaluate_match(match: dict[str, Any], alert: dict[str, Any]) -> bool:
    conditions = match.get("conditions") or []
    if not conditions:
        return True  # a rule with no conditions matches every alert
    results = [evaluate_condition(c, alert) for c in conditions]
    return all(results) if match.get("mode", "all") == "all" else any(results)


# --------------------------------------------------------------------------- #
# Threshold/grouping state - counts matching alerts per group value within a
# rolling window, so e.g. "5 alerts for the same src_ip in 15 minutes" works
# across separate polls of main.py/run.py, not just within one batch.
# --------------------------------------------------------------------------- #
def _load_state(path: Path) -> dict[str, dict[str, list[float]]]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_state(path: Path, state: dict[str, dict[str, list[float]]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, default=str))
    tmp.replace(path)


def _apply_threshold(
    rule_id: str,
    threshold: dict[str, Any],
    alert: dict[str, Any],
    state: dict[str, dict[str, list[float]]],
    *,
    now: float,
) -> tuple[bool, int, str]:
    """Records this match and returns (threshold_met, count, group_value)."""
    group_value = str(_get_field(alert, threshold["group_by"]) or "unknown")
    window_s = float(threshold["window_minutes"]) * 60
    bucket = state.setdefault(rule_id, {})
    times = [t for t in bucket.get(group_value, []) if now - t <= window_s]
    times.append(now)
    bucket[group_value] = times
    return len(times) >= int(threshold["count"]), len(times), group_value


def evaluate_rule(
    rule: dict[str, Any],
    alert: dict[str, Any],
    *,
    state: dict[str, dict[str, list[float]]] | None = None,
    dry_run: bool = False,
    now: float | None = None,
) -> dict[str, Any]:
    """Evaluate one rule against one alert.

    `dry_run=True` (used by the dashboard's "test rule" action) evaluates
    without mutating/persisting threshold counters, so trying a rule out
    never perturbs its real window.
    """
    matched = evaluate_match(rule.get("match") or {}, alert)
    out = {
        "rule_id": rule.get("id"),
        "name": rule.get("name"),
        "matched": matched,
        "threshold_met": None,
        "count": None,
        "triggered": False,
        "action": rule.get("action") or {},
    }
    if not matched:
        return out

    threshold = rule.get("threshold")
    if not threshold:
        out["triggered"] = True
        return out

    now = time.time() if now is None else now
    if state is None:
        state = {}
    threshold_met, count, group_value = _apply_threshold(
        rule["id"],
        threshold,
        alert,
        state,
        now=now,
    )
    out["threshold_met"] = threshold_met
    out["count"] = count
    out["group_value"] = group_value
    out["triggered"] = threshold_met
    return out


def evaluate_all(
    alert: dict[str, Any],
    *,
    rules_path: str | Path | None = None,
    state_path: str | Path | None = None,
    dry_run: bool = False,
) -> list[dict[str, Any]]:
    """Evaluate every enabled rule against one alert.

    Returns only rules whose conditions matched (whether or not a threshold
    is still short of firing), so a caller can log "matched, 3/5 so far" as
    well as fully "triggered" rules. Persists threshold state once per call
    unless `dry_run` is set.
    """
    rules = _load(_current_path(rules_path))
    enabled = [r for r in rules.values() if r.get("enabled", True)]
    if not enabled:
        return []

    state_file = _current_state_path(state_path)
    state = _load_state(state_file) if not dry_run else _load_state(state_file).copy()
    now = time.time()

    results = []
    for rule in enabled:
        result = evaluate_rule(rule, alert, state=state, dry_run=dry_run, now=now)
        if result["matched"]:
            results.append(result)

    if not dry_run:
        _save_state(state_file, state)
    return results


# --------------------------------------------------------------------------- #
# Backtesting - "how often would this rule have fired on historical alerts,
# before I enable it live?" Never touches the real threshold state file.
# --------------------------------------------------------------------------- #
def backtest_rule(
    rule: dict[str, Any],
    *,
    log_path: str | Path | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Dry-run `rule` (a saved rule dict or an unsaved draft, same shape
    either way) against historical data/triage_log.jsonl entries.

    Historical entries don't all carry a reliable timestamp - only run.py's
    watch-loop entries write a "ts" field; main.py's and the dashboard's
    on-demand triage entries don't. So threshold windows here use each
    entry's "ts" when present and otherwise treat consecutive matched
    alerts as arriving one second apart. That's enough to see the rough
    shape ("this would have fired ~14 times across the last 200 alerts"),
    not to reproduce exact historical timing down to the second.
    """
    path = (
        Path(log_path)
        if log_path
        else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")
    )
    if not path.exists():
        return {
            "total_alerts": 0,
            "matched": 0,
            "triggered": 0,
            "sample": [],
            "note": f"No log file at {path} yet - run some triage first.",
        }

    lines = [l for l in path.read_text().splitlines() if l.strip()]
    if limit:
        lines = lines[-int(limit) :]  # most recent N entries

    state: dict[str, dict[str, list[float]]] = {}
    now = 0.0
    total = matched = triggered = 0
    sample: list[dict[str, Any]] = []

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        alert = entry.get("alert")
        if not isinstance(alert, dict):
            continue  # not a triage-log-shaped entry (e.g. a chat log line)
        total += 1

        ts_str = entry.get("ts")
        if ts_str:
            try:
                now = time.mktime(time.strptime(ts_str, "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                now += 1.0
        else:
            now += 1.0

        result = evaluate_rule(rule, alert, state=state, now=now)
        if result["matched"]:
            matched += 1
        if result["triggered"]:
            triggered += 1
            if len(sample) < 10:
                sample.append(
                    {
                        "alert_id": alert.get("alert_id"),
                        "ts": ts_str,
                        "count": result.get("count"),
                    }
                )

    return {
        "total_alerts": total,
        "matched": matched,
        "triggered": triggered,
        "sample": sample,
    }


if __name__ == "__main__":  # pragma: no cover - thin argparse wrapper
    import argparse

    parser = argparse.ArgumentParser(
        description="Alert rules CLI - list rules, or backtest one against data/triage_log.jsonl."
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="List saved rules.")

    exp = sub.add_parser("export", help="Export saved rules to a portable JSON file.")
    exp.add_argument("--out", default=None, help="Output file (default: print to stdout).")

    imp = sub.add_parser("import", help="Import rules from a portable JSON file.")
    imp.add_argument("file", help='JSON file - a bare list of rule dicts, or {"rules": [...]}.')
    imp.add_argument(
        "--overwrite",
        action="store_true",
        help="Update existing rules with the same name in place (default: skip conflicts).",
    )

    bt = sub.add_parser(
        "backtest", help="Backtest a saved rule against historical triage log entries."
    )
    bt.add_argument("rule_id", help="Rule id, e.g. rule-3c42ccde06 (see 'python rules.py list').")
    bt.add_argument(
        "--limit", type=int, default=None, help="Only look at the most recent N log entries."
    )
    bt.add_argument(
        "--log", default=None, help="Override the triage log path (default: cfg.TRIAGE_LOG_PATH)."
    )

    args = parser.parse_args()

    if args.cmd == "list":
        for r in list_rules():
            state = "enabled" if r["enabled"] else "disabled"
            thr = " [threshold]" if r["has_threshold"] else ""
            print(
                f"  {r['id']}  {state:8s}  {r['name']}{thr}  ({r['condition_count']} condition(s))"
            )
    elif args.cmd == "export":
        payload = {"rules": export_rules()}
        text = json.dumps(payload, indent=2)
        if args.out:
            Path(args.out).write_text(text)
            print(f"Exported {len(payload['rules'])} rule(s) to {args.out}")
        else:
            print(text)
    elif args.cmd == "import":
        result = import_rules_from_file(
            args.file, on_conflict="overwrite" if args.overwrite else "skip"
        )
        print(f"Created:  {len(result['created'])}  {result['created']}")
        print(f"Updated:  {len(result['updated'])}  {result['updated']}")
        print(f"Skipped:  {len(result['skipped'])}  {result['skipped']}")
        if result["errors"]:
            print("Errors:")
            for e in result["errors"]:
                print(f"  - {e['name']}: {e['error']}")
    elif args.cmd == "backtest":
        rule = read_rule(args.rule_id)
        if not rule:
            print(f"No such rule: {args.rule_id}")
            raise SystemExit(1)
        result = backtest_rule(rule, log_path=args.log, limit=args.limit)
        print(f"Rule: {rule['name']} ({args.rule_id})")
        print(f"  Log entries scanned: {result['total_alerts']}")
        print(f"  Conditions matched:  {result['matched']}")
        print(f"  Would have fired:    {result['triggered']}")
        if result.get("note"):
            print(f"  Note: {result['note']}")
        if result["sample"]:
            print("  Sample triggers (up to 10):")
            for s in result["sample"]:
                print(f"    - {s['alert_id']}  ts={s.get('ts') or '?'}  count={s.get('count')}")
