"""
Outbound notifications - fires when a triggered rule's `action.notify` field
(see rules.py) is set to something non-empty.

Deliberately small and generic rather than building per-platform (Slack API,
Teams API, PagerDuty, ...) integrations: `NOTIFY_WEBHOOK_URL` is posted a
Slack-incoming-webhook-compatible `{"text": "..."}` JSON body, which Slack,
Mattermost, and most "generic webhook" Teams/Discord connectors all accept
directly. If you need true per-rule channel routing, point `NOTIFY_WEBHOOK_URL`
at a small relay you control that fans out based on the `notify` field this
module includes in every payload - that's a config-only change on your side,
not a code change here.

Every call is also appended to `data/notifications.jsonl` regardless of
whether NOTIFY_WEBHOOK_URL is set, so there's always a local audit trail even
before a webhook is wired up (mirrors data/triage_log.jsonl's role).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import requests

from config import cfg

DEFAULT_LOG_PATH = Path("data/notifications.jsonl")


def _log_path() -> Path:
    return Path(getattr(cfg, "NOTIFICATIONS_LOG_PATH", "") or DEFAULT_LOG_PATH)


def _append_log(entry: dict[str, Any]) -> None:
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as f:
        f.write(json.dumps(entry, default=str) + "\n")


def send_notification(
    text: str, *, target: str = "", extra: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Send one notification. Never raises - a broken webhook must never take
    down triage. Always logs locally; only actually POSTs if a webhook URL is
    configured. Returns {"ok": bool, "sent": bool, "detail": str}."""
    entry: dict[str, Any] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "text": text,
        "target": target,
        "extra": extra or {},
    }

    webhook_url = getattr(cfg, "NOTIFY_WEBHOOK_URL", "")
    if not webhook_url:
        result = {
            "ok": True,
            "sent": False,
            "detail": "NOTIFY_WEBHOOK_URL not set - logged locally only.",
        }
        _append_log({**entry, "result": result})
        return result

    payload = {"text": f"[{target}] {text}" if target else text}
    try:
        r = requests.post(
            webhook_url,
            json=payload,
            timeout=float(getattr(cfg, "NOTIFY_TIMEOUT_SECONDS", 10) or 10),
        )
        r.raise_for_status()
        result = {"ok": True, "sent": True, "detail": f"HTTP {r.status_code}"}
    except Exception as e:  # noqa: BLE001 - a bad webhook should never crash a triage run
        result = {"ok": False, "sent": False, "detail": str(e)}

    _append_log({**entry, "result": result})
    return result


def notify_rule_matches(
    alert: dict[str, Any], rule_matches: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Convenience wrapper for the triage call sites: fires one notification
    per triggered rule whose action.notify is set, and returns the results
    (mainly for tests/debugging - callers don't need to do anything with them)."""
    results = []
    for match in rule_matches:
        if not match.get("triggered"):
            continue
        target = (match.get("action") or {}).get("notify") or ""
        if not target:
            continue
        alert_id = alert.get("alert_id", "?")
        alert_name = alert.get("rule_name", alert.get("description", ""))
        tag = (match.get("action") or {}).get("tag", "")
        text = f"Rule '{match.get('name')}' triggered on {alert_id} ({alert_name})"
        if tag:
            text += f" - tag: {tag}"
        results.append(
            send_notification(
                text, target=target, extra={"alert_id": alert_id, "rule_id": match.get("rule_id")}
            )
        )
    return results
