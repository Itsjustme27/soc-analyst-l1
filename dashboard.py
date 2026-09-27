"""
Simple SOC dashboard - connect to multiple SIEM platforms and manage providers.

  python dashboard.py            # then open http://127.0.0.1:5001

Features:
  - See every registered SIEM connection (env-seeded + dashboard-added) with
    its platform, status, and recent alerts.
  - Add a provider: pick a platform (Splunk / QRadar / Elastic / Sentinel /
    Mock), give it a name, fill in its connection details. Stored in
    data/siem_providers.json (see siem_providers.py). Secrets are saved in
    that file and never echoed back to the UI.
  - Test each connection (reachability + auth) with /api/providers/<id>/test.
  - Pull alerts per provider and run the triage agent on them right from the
    dashboard - results land in data/triage_log.jsonl like any other run.

API (JSON): /api/platforms, /api/providers,
            POST /api/providers, DELETE /api/providers/<id>,
            POST /api/providers/<id>/test, GET /api/providers/<id>/alerts,
            POST /api/providers/<id>/triage
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import signal
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

import agent_control as ac
import siem_providers as store
from agent.chat_agent import ChatAgent
from agent.triage_agent import TriageAgent, needs_human_review
from config import cfg
from connectors.siem import PLATFORM_FIELDS
from llm.base import LLMRateLimitedError

# SIGKILL is Unix-only; on Windows TerminateProcess is reached via SIGTERM.
_SIGKILL = getattr(signal, "SIGKILL", signal.SIGTERM)
import audit
import cases
import lookup_tables as lookup
import metrics
import notify
import rules

app = Flask(__name__)

logger = logging.getLogger("dashboard")

TRIAGE_LIMIT_DEFAULT = 5


def _safe_error(exc: BaseException, message: str) -> str:
    """Return a stable, generic message instead of exception internals.

    The full exception (type, message, traceback) is logged server-side only;
    the API client never sees file paths, line numbers or exception class
    names. Used at the API boundary when an unexpected exception is caught.
    """
    logger.exception("%s (%s): %r", message, type(exc).__name__, exc)
    return message


@app.errorhandler(Exception)
def _handle_unhandled_exception(exc: BaseException):
    """API boundary: unexpected exceptions must never leak a stack trace.

    Returns a generic JSON 500 - the full traceback goes to the server log
    only. Standard HTTP errors (404, 405, ...) pass through unchanged so
    Flask still renders their normal responses.
    """
    if isinstance(exc, HTTPException):
        return exc
    logger.exception("Unhandled exception in API request")
    return jsonify({"error": "Internal server error."}), 500


def _triage_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path) if path else Path(getattr(cfg, "TRIAGE_LOG_PATH", "") or "data/triage_log.jsonl")
    )


def _chat_log_path(path: str | Path | None = None) -> Path:
    return Path(path) if path else Path(getattr(cfg, "CHAT_LOG_PATH", "") or "data/chat_log.jsonl")


def _engineer_log_path(path: str | Path | None = None) -> Path:
    return (
        Path(path)
        if path
        else Path(getattr(cfg, "ENGINEER_LOG_PATH", "") or "data/engineer_log.jsonl")
    )


# --------------------------------------------------------------------------- #
# Auth - optional single-shared-secret token (DASHBOARD_TOKEN) and/or per-user
# tokens (DASHBOARD_USERS="user:token[:role],user:token[:role],...").
# When neither is set (the default) there is no auth, which is fine for strictly
# local use bound to 127.0.0.1; set one before pointing --host at anything else,
# since every route here (including ones that write to the SIEM, start/stop the
# overnight watcher, and CRUD lookup tables/rules) is otherwise wide open. The
# token is accepted as `Authorization: Bearer <token>` or `?token=<token>`; the
# page shell (`/`) always loads so the JS can read `?token=` off the URL and
# attach it to every subsequent /api/* call - see api() in index.html.
# With DASHBOARD_USERS, a valid Bearer token maps to a VERIFIED identity: the
# Approval Center uses it for separation of duties and ignores any
# client-supplied "by" field.
#
# Roles (F3): "viewer" (reads only), "approver" (reads + the Approval Center),
# "admin" (everything, incl. rules/lookup/provider CRUD and agent control). A
# DASHBOARD_USERS entry without an explicit role is an "admin", so existing
# configs keep exactly the access they had before roles existed.
#
# IMPORTANT: with auth DISABLED every request is a local-trust admin identity
# ("local-user", verified=False). That is the same posture as the ungated routes
# below and matches scripts_engineer_cli.py, which calls approvals.approve()
# with identity_verified=False and no token at all. The Approval Center is
# therefore usable out of the box; separation of duties switches on as soon as
# DASHBOARD_USERS is configured.
# --------------------------------------------------------------------------- #
ROLES = {"viewer": 1, "approver": 2, "admin": 3}
DEFAULT_ROLE = "admin"


def _auth_configured() -> bool:
    from config import cfg

    return bool(getattr(cfg, "DASHBOARD_TOKEN", "") or getattr(cfg, "DASHBOARD_USERS", ""))


def _supplied_token() -> str:
    supplied = request.headers.get("Authorization", "")
    if supplied.startswith("Bearer "):
        return supplied[len("Bearer ") :]
    return request.args.get("token", "")


def _token_ok() -> bool:
    from config import cfg

    if not getattr(cfg, "DASHBOARD_TOKEN", ""):
        return False
    return hmac.compare_digest(_supplied_token(), cfg.DASHBOARD_TOKEN)


def _token_user() -> tuple[str, str] | None:
    """Map a Bearer token to a verified (user, role) identity from DASHBOARD_USERS.
    None when per-user auth isn't configured or the token is unknown."""
    from config import cfg

    users_cfg = getattr(cfg, "DASHBOARD_USERS", "") or ""
    if not users_cfg:
        return None
    supplied = _supplied_token()
    if not supplied:
        return None
    for entry in users_cfg.split(","):
        parts = [p.strip() for p in entry.split(":")]
        if len(parts) < 2:
            continue
        user, tok = parts[0], parts[1]
        role = parts[2] if len(parts) > 2 else DEFAULT_ROLE
        if hmac.compare_digest(tok, supplied):
            return user, (role if role in ROLES else DEFAULT_ROLE)
    return None


def _identity() -> tuple[str, str, bool]:
    """(user, role, identity_verified) for the current request.

    A per-user token wins and is VERIFIED. A bare shared DASHBOARD_TOKEN is an
    unverified admin fallback that may self-declare "by". When no auth is
    configured at all this is a local-trust admin identity, matching the
    ungated routes - see the note in the auth block above."""
    user, role = _token_user() or (None, None)
    if user is not None:
        return user, role, True
    if _token_ok():
        body = request.get_json(force=True, silent=True) or {}
        return (body.get("by") or "dashboard-user"), DEFAULT_ROLE, False
    if not _auth_configured():
        return "local-user", DEFAULT_ROLE, False
    return "", "", False


def _unauthorized() -> tuple:
    """401 that says WHICH mistake the caller made. Distinguishing these matters:
    a caller that simply has no token configured needs to know auth is OFF
    (approvals work, unverified), not that its token was rejected."""
    hint = (
        "set Authorization: Bearer <token> or ?token=<token>"
        if _auth_configured()
        else "dashboard auth is disabled (no DASHBOARD_TOKEN/DASHBOARD_USERS), so "
        "this request is treated as local-trust; configure either to enable "
        "verified identities and separation of duties"
    )
    return jsonify({"error": f"Unauthorized - {hint}."}), 401


def _require_role(minimum: str):
    """Reject a request whose identity lacks `minimum` (403). Returns None when
    allowed. Read routes call neither this nor _verified_approver - they are
    covered by the before_request token gate alone."""
    if not _auth_configured():
        return None  # local-trust: the same posture as the ungated read routes
    user, role, _ = _identity()
    if not user:
        return _unauthorized()
    if ROLES.get(role, 0) < ROLES[minimum]:
        return jsonify(
            {
                "error": (
                    f"Forbidden - '{user}' has role '{role}'; '{minimum}' or higher is "
                    f"required for this action."
                )
            }
        ), 403
    return None


@app.before_request
def _require_dashboard_token():
    if not _auth_configured():
        return None  # auth disabled (default) - purely local use
    if request.path == "/":
        return None  # let the page shell load; every /api/* call below is still gated
    user, _ = _token_user() or (None, None)
    if user is not None or _token_ok():
        return None
    return _unauthorized()


def _audit_write(
    action: str,
    params: dict,
    result: object = None,
    *,
    execution_status: str = "success",
    error: str | None = None,
) -> None:
    """Audit a direct (non-proposal) dashboard write.

    The Approval Center routes have always logged their own acts, but the
    human-driven CRUD routes (rules, lookup tables, providers, agent control)
    did not - so a rule edited straight through the UI was invisible in
    /api/audit even though it lands in local_rules.xml. Every mutating route
    below calls this. Secrets are redacted by audit.audit_log itself."""
    user, _role, _verified = _identity()
    audit.audit_log(
        tool="dashboard_ui",
        action=action,
        permission="human",
        approval_status="not_required",
        execution_status=execution_status,
        error=error,
        params=params,
        result=result,
        user=user,
        agent="dashboard_ui",
    )


# --------------------------------------------------------------------------- #
def _connector_or_error(provider_id: str):
    provider = store.get_provider(provider_id)
    if not provider:
        return None, (jsonify({"error": f"Provider '{provider_id}' not found."}), 404), None
    try:
        conn = store.connector_for(provider)
    except Exception as e:  # noqa: BLE001
        return None, (jsonify({"error": _safe_error(e, "Could not build connector.")}), 400), None
    return conn, None, provider


# --------------------------------------------------------------------------- #
@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/health")
def health():
    from config import cfg

    return jsonify(
        {
            "status": "ok",
            "llm_provider": cfg.LLM_PROVIDER,
            "siem_provider": cfg.SIEM_PROVIDER,
            "mock_mode": cfg.MOCK_MODE,
        }
    )


@app.get("/api/platforms")
def api_platforms():
    out = []
    for key, meta in PLATFORM_FIELDS.items():
        out.append({"platform": key, **meta})
    return jsonify({"platforms": out})


@app.get("/api/metrics")
def api_metrics():
    """Aggregate stats over data/triage_log.jsonl (+ analyst-agreement rate
    from data/feedback_log.jsonl, when any review history exists) - see
    metrics.py for the actual computation."""
    return jsonify(metrics.compute_metrics())


@app.get("/api/cases")
def api_cases():
    """Alerts from data/triage_log.jsonl clustered by shared host/user
    within a time window - see cases.py. Query params: window_minutes,
    limit, min_alerts (default 1 - pass 2 to only see actual clusters)."""
    window = float(request.args.get("window_minutes", cases.DEFAULT_WINDOW_MINUTES))
    limit = int(request.args.get("limit", cases.DEFAULT_SCAN_LIMIT))
    min_alerts = int(request.args.get("min_alerts", 1))
    grouped = cases.group_cases(window_minutes=window, limit=limit)
    grouped = [c for c in grouped if c["alert_count"] >= min_alerts]
    return jsonify({"cases": grouped})


@app.get("/api/providers")
def api_providers():
    return jsonify({"providers": [store.redact_provider(p) for p in store.load_providers()]})


@app.post("/api/providers")
def api_add_provider():
    denied = _require_role("admin")
    if denied:
        return denied
    payload = request.get_json(force=True, silent=True) or {}
    try:
        provider = store.add_provider(payload)
    except store.ProviderError as e:
        _audit_write(
            "provider_add", {"provider": payload}, None, execution_status="failure", error=str(e)
        )
        return jsonify({"error": str(e)}), 400
    _audit_write("provider_add", {"provider": payload}, {"id": provider.get("id")})
    return jsonify({"provider": store.redact_provider(provider)}), 201


@app.delete("/api/providers/<provider_id>")
def api_delete_provider(provider_id: str):
    denied = _require_role("admin")
    if denied:
        return denied
    if not store.remove_provider(provider_id):
        return jsonify(
            {"error": "Provider not found, or it is env-seeded (edit .env to change it)."}
        ), 404
    _audit_write("provider_delete", {"provider_id": provider_id}, {"ok": True})
    return jsonify({"ok": True})


@app.post("/api/providers/<provider_id>/test")
def api_test(provider_id: str):
    conn, err, _ = _connector_or_error(provider_id)
    if err:
        return err
    return jsonify(conn.test_connection())


@app.get("/api/providers/<provider_id>/alerts")
def api_alerts(provider_id: str):
    conn, err, provider = _connector_or_error(provider_id)
    if err:
        return err
    limit = request.args.get("limit", default=100, type=int)
    try:
        alerts = conn.get_new_alerts()
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": _safe_error(e, "Failed to pull alerts.")}), 502
    return jsonify(
        {
            "provider_id": provider_id,
            "provider_name": provider["name"],
            "platform": provider["platform"],
            "count": len(alerts),
            "alerts": alerts[:limit],
        }
    )


@app.post("/api/providers/<provider_id>/triage")
def api_triage(provider_id: str):
    conn, err, provider = _connector_or_error(provider_id)
    if err:
        return err
    body = request.get_json(force=True, silent=True) or {}
    limit = int(body.get("limit", TRIAGE_LIMIT_DEFAULT))

    try:
        alerts = conn.get_new_alerts()
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": _safe_error(e, "Failed to pull alerts.")}), 502
    if not alerts:
        return jsonify(
            {"provider_id": provider_id, "triaged": 0, "results": [], "note": "No new alerts."}
        )

    try:
        agent = TriageAgent(siem=conn)
    except Exception as e:  # noqa: BLE001 - e.g. missing LLM key
        return jsonify({"error": _safe_error(e, "Could not start the triage agent.")}), 400

    _triage_log_path().parent.mkdir(parents=True, exist_ok=True)
    results = []
    for alert in alerts[:limit]:
        try:
            rule_matches = rules.evaluate_all(alert)
        except Exception:  # noqa: BLE001 - a bad rule should never block triage
            rule_matches = []
        triggered = [m for m in rule_matches if m["triggered"]]
        if triggered:
            try:
                notify.notify_rule_matches(alert, rule_matches)
            except Exception:  # noqa: BLE001 - a bad webhook must never block triage
                pass

        try:
            result = agent.triage(alert)
        except Exception as e:  # noqa: BLE001
            results.append(
                {
                    "alert_id": alert.get("alert_id", "?"),
                    "rule_id": alert.get("rule_id"),
                    "error": _safe_error(e, "Triage failed for this alert."),
                }
            )
            continue
        needs_human = needs_human_review(result, rule_matches)
        with open(_triage_log_path(), "a") as f:
            f.write(
                json.dumps(
                    {
                        "alert": alert,
                        "result": asdict(result),
                        "rule_matches": rule_matches,
                        "needs_human_review": needs_human,
                        "siem_provider": {
                            "id": provider_id,
                            "name": provider["name"],
                            "platform": provider["platform"],
                        },
                    },
                    default=str,
                )
                + "\n"
            )
        results.append(
            {
                "alert_id": alert.get("alert_id", "?"),
                "rule_id": alert.get("rule_id"),
                "rule_name": alert.get("rule_name", alert.get("description", "")),
                "verdict": result.verdict,
                "confidence": result.confidence,
                "recommended_action": result.recommended_action,
                "rationale": result.rationale,
                "rule_matches": [m["name"] for m in triggered],
                "needs_human_review": needs_human,
            }
        )

    return jsonify(
        {
            "provider_id": provider_id,
            "provider_name": provider["name"],
            "triaged": len(results),
            "results": results,
        }
    )


# --------------------------------------------------------------------------- #
# Chat agent route - conversational SOC assistant with R/W lookup tables.
# --------------------------------------------------------------------------- #
CHAT_LOG = Path("data/chat_log.jsonl")
CHAT_LIMIT_DEFAULT = 50


@app.post("/api/chat")
def api_chat():
    body = request.get_json(force=True, silent=True) or {}
    message = (body.get("message") or "").strip()
    provider_id = body.get("provider_id") or ""
    history = body.get("history") or []
    if not message:
        return jsonify({"error": "message is required."}), 400

    siem = None
    if provider_id:
        conn, err, _ = _connector_or_error(provider_id)
        if err:
            return err
        siem = conn

    try:
        agent = ChatAgent(siem=siem, provider_id=provider_id or None)
    except Exception as e:  # noqa: BLE001
        return jsonify({"error": _safe_error(e, "Could not start the chat agent.")}), 400

    try:
        result = agent.chat(user_message=message, history=history or [])
    except LLMRateLimitedError as e:
        # Upstream LLM gateway is rate limited. Answer 429 to the browser
        # (with the gateway's Retry-After when known) instead of a Flask 500
        # traceback - and never retry the message here, that would just keep
        # the key inside the rate-limit window.
        return jsonify(
            {
                "error": "The LLM gateway is rate limited; please wait a moment and try again.",
                "retry_after": e.retry_after,
                "request_id": e.request_id,
            }
        ), 429

    _chat_log_path().parent.mkdir(parents=True, exist_ok=True)
    with open(_chat_log_path(), "a") as f:
        f.write(
            json.dumps(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "message": message,
                    "reply": result.reply,
                    "data": result.data,
                    "transcript_len": len(result.transcript),
                },
                default=str,
            )
            + "\n"
        )

    return jsonify(
        {
            "reply": result.reply,
            "data": result.data,
            "transcript_len": len(result.transcript),
        }
    )


@app.get("/api/chat/history")
def api_chat_history():
    limit = int(request.args.get("limit", CHAT_LIMIT_DEFAULT))
    if not _chat_log_path().exists():
        return jsonify({"entries": [], "count": 0})
    entries = []
    for line in _chat_log_path().read_text().splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    entries = entries[-limit:]
    return jsonify({"entries": entries, "count": len(entries)})


# --------------------------------------------------------------------------- #
# Lookup-tables CRUD routes.
# --------------------------------------------------------------------------- #
@app.get("/api/lookup-tables")
def api_lookup_tables():
    return jsonify({"tables": lookup.list_lookup_tables()})


@app.post("/api/lookup-tables")
def api_create_lookup_table():
    denied = _require_role("admin")
    if denied:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or "").strip()
    description = (body.get("description") or "").strip()
    if not name:
        return jsonify({"error": "name is required."}), 400
    try:
        table = lookup.create_lookup_table(name, description)
    except KeyError as e:
        _audit_write(
            "lookup_table_create", {"name": name}, None, execution_status="failure", error=str(e)
        )
        return jsonify({"error": str(e)}), 409
    _audit_write(
        "lookup_table_create",
        {"name": name, "description": description},
        {"entry_count": len(table.get("entries") or {})},
    )
    return jsonify(
        {
            "table": {
                "name": name,
                "entry_count": len(table.get("entries") or {}),
                "updated": table.get("updated"),
            }
        }
    ), 201


@app.get("/api/lookup-tables/<name>")
def api_read_lookup_table(name: str):
    table = lookup.read_lookup_table(name)
    if not table:
        return jsonify({"error": f"Lookup table '{name}' not found."}), 404
    return jsonify({"name": name, "table": table})


@app.post("/api/lookup-tables/<name>/entries/<key>")
def api_upsert_lookup_entry(name: str, key: str):
    denied = _require_role("admin")
    if denied:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    value = body.get("value")
    try:
        table = lookup.upsert_lookup_entry(name, key, value)
    except Exception as e:  # noqa: BLE001
        _audit_write(
            "lookup_entry_upsert",
            {"name": name, "key": key},
            None,
            execution_status="failure",
            error=str(e),
        )
        return jsonify({"error": _safe_error(e, "Could not update lookup entry.")}), 400
    _audit_write(
        "lookup_entry_upsert",
        {"name": name, "key": key, "value": value},
        {"entry_count": len(table.get("entries") or {})},
    )
    return jsonify(
        {
            "name": name,
            "key": key,
            "entry_count": len(table.get("entries") or {}),
            "updated": table.get("updated"),
        }
    )


@app.delete("/api/lookup-tables/<name>/entries/<key>")
def api_delete_lookup_entry(name: str, key: str):
    denied = _require_role("admin")
    if denied:
        return denied
    ok = lookup.delete_lookup_entry(name, key)
    if not ok:
        return jsonify({"error": f"Key '{key}' not found in table '{name}'."}), 404
    _audit_write("lookup_entry_delete", {"name": name, "key": key}, {"ok": True})
    return jsonify({"ok": True})


@app.delete("/api/lookup-tables/<name>")
def api_delete_lookup_table(name: str):
    denied = _require_role("admin")
    if denied:
        return denied
    ok = lookup.delete_lookup_table(name)
    if not ok:
        return jsonify({"error": f"Lookup table '{name}' not found."}), 404
    _audit_write("lookup_table_delete", {"name": name}, {"ok": True})
    return jsonify({"ok": True})


# --------------------------------------------------------------------------- #
# Alert rules CRUD + test routes.
# --------------------------------------------------------------------------- #
@app.get("/api/rules/ops")
def api_rule_ops():
    """The valid condition operators - single source of truth is rules.VALID_OPS."""
    return jsonify({"ops": list(rules.VALID_OPS)})


@app.get("/api/rules")
def api_rules():
    return jsonify({"rules": rules.list_rules()})


@app.post("/api/rules")
def api_create_rule():
    denied = _require_role("admin")
    if denied:
        return denied
    payload = request.get_json(force=True, silent=True) or {}
    try:
        rule = rules.create_rule(payload)
    except rules.RuleError as e:
        _audit_write(
            "rule_create", {"rule": payload}, None, execution_status="failure", error=str(e)
        )
        return jsonify({"error": str(e)}), 400
    _audit_write("rule_create", {"rule": payload}, {"id": rule.get("id")})
    return jsonify({"rule": rule}), 201


@app.get("/api/rules/<rule_id>")
def api_read_rule(rule_id: str):
    rule = rules.read_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    return jsonify({"rule": rule})


@app.patch("/api/rules/<rule_id>")
def api_update_rule(rule_id: str):
    denied = _require_role("admin")
    if denied:
        return denied
    payload = request.get_json(force=True, silent=True) or {}
    try:
        rule = rules.update_rule(rule_id, payload)
    except rules.RuleError as e:
        _audit_write(
            "rule_update",
            {"rule_id": rule_id, "patch": payload},
            None,
            execution_status="failure",
            error=str(e),
        )
        return jsonify({"error": str(e)}), 400
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    _audit_write("rule_update", {"rule_id": rule_id, "patch": payload}, {"id": rule_id})
    return jsonify({"rule": rule})


@app.delete("/api/rules/<rule_id>")
def api_delete_rule(rule_id: str):
    denied = _require_role("admin")
    if denied:
        return denied
    if not rules.delete_rule(rule_id):
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    _audit_write("rule_delete", {"rule_id": rule_id}, {"ok": True})
    return jsonify({"ok": True})


@app.post("/api/rules/<rule_id>/backtest")
def api_backtest_rule(rule_id: str):
    """How often would this saved rule have fired on historical alerts?
    Reads data/triage_log.jsonl - never touches the real threshold state."""
    rule = rules.read_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    body = request.get_json(force=True, silent=True) or {}
    limit = body.get("limit")
    result = rules.backtest_rule(rule, limit=int(limit) if limit else None)
    return jsonify({"result": result})


@app.post("/api/rules/<rule_id>/test")
def api_test_rule(rule_id: str):
    """Dry-run a stored rule against a sample alert - never mutates threshold state."""
    rule = rules.read_rule(rule_id)
    if not rule:
        return jsonify({"error": f"Rule '{rule_id}' not found."}), 404
    body = request.get_json(force=True, silent=True) or {}
    alert = body.get("alert")
    if not isinstance(alert, dict):
        return jsonify({"error": "Provide 'alert' as a JSON object to test against."}), 400
    result = rules.evaluate_rule(rule, alert, dry_run=True)
    return jsonify({"result": result})


@app.post("/api/rules/preview")
def api_preview_rule():
    """Dry-run an unsaved rule draft against a sample alert (rule-builder 'test before save')."""
    body = request.get_json(force=True, silent=True) or {}
    draft = body.get("rule")
    alert = body.get("alert")
    if not isinstance(draft, dict) or not isinstance(alert, dict):
        return jsonify({"error": "Provide 'rule' and 'alert' as JSON objects."}), 400
    try:
        valid = rules.validate_rule(draft)
    except rules.RuleError as e:
        return jsonify({"error": str(e)}), 400
    valid["id"] = "preview"
    result = rules.evaluate_rule(valid, alert, dry_run=True)
    return jsonify({"result": result})


@app.get("/api/rules/export")
def api_export_rules():
    """Portable rule set (no id/created/updated) - download or pipe into
    seed_data/rules/ to share across environments."""
    rule_ids = request.args.getlist("id") or None
    return jsonify({"rules": rules.export_rules(rule_ids)})


@app.post("/api/rules/import")
def api_import_rules():
    denied = _require_role("admin")
    if denied:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    rule_defs = body.get("rules")
    if not isinstance(rule_defs, list):
        return jsonify({"error": "Provide 'rules' as a JSON list."}), 400
    on_conflict = "overwrite" if body.get("overwrite") else "skip"
    try:
        result = rules.import_rules(rule_defs, on_conflict=on_conflict)
    except rules.RuleError as e:
        _audit_write(
            "rule_import",
            {"count": len(rule_defs), "on_conflict": on_conflict},
            None,
            execution_status="failure",
            error=str(e),
        )
        return jsonify({"error": str(e)}), 400
    _audit_write("rule_import", {"count": len(rule_defs), "on_conflict": on_conflict}, result)
    return jsonify(result)


# --------------------------------------------------------------------------- #
# Agent control - overnight watchers: status, spawn, stop, KILL, logs.
# --------------------------------------------------------------------------- #
def _siem_selectors() -> set[str]:
    """Every selector `run.py --siem` accepts: provider ids + platform names.

    Mirrors siem_providers.resolve_connector() exactly so this allowlist can
    never drift from what the watcher subprocess resolves. Provider ids are
    generated as `siem-<uuid4 hex>` and platform names are fixed registry
    keys, so every member is plain [A-Za-z0-9._-] and inert as an argument.
    """
    return {p["id"] for p in store.load_providers()} | set(store.SIEM_PLATFORMS)


def _spawn_agent(agent_id: str, provider_id: str | None = None) -> int:
    """Start a run.py watcher for `agent_id`, capturing its output to run.log."""
    # Fail-closed (CodeQL: "Uncontrolled command line"): a user-supplied
    # --siem must resolve against the allowlist before it may enter the
    # command line; anything else is rejected outright, never sanitized or
    # escaped. The agent id is independently confined to a safe charset by
    # ac.sanitize_id() before it is used in argv or on the filesystem.
    if provider_id is not None and provider_id not in _siem_selectors():
        raise ValueError(f"Unknown SIEM/pipeline '{provider_id}'.")
    agent_id = ac.sanitize_id(agent_id)
    stop = ac.stop_file_path(agent_id)
    stop.parent.mkdir(parents=True, exist_ok=True)
    stop.unlink(missing_ok=True)

    log_path = ac.log_file_path(agent_id)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_fh = open(log_path, "ab")
    cmd = [sys.executable, str(Path(__file__).parent / "run.py"), "--agent-id", agent_id]
    if provider_id:
        cmd += ["--siem", provider_id]
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            shell=False,
        )
    finally:
        log_fh.close()
    # "starting" heartbeat with a visible pid until the watcher's first write.
    ac.write_heartbeat(
        agent_id,
        {
            "status": "starting",
            "pid": proc.pid,
            "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "reason": "started",
        },
    )
    return proc.pid


def _signal_agent(agent_id: str, sig: int) -> bool:
    """Signal a watcher AND drop its stop-file.

    The stop-file alone makes the watcher exit at the top of its next cycle
    (even when idle); the signal makes that immediate. Find the watcher by its
    live command line first (heartbeat pids can be stale or missing for older
    watchers), and only trust a heartbeat pid when /proc discovery found
    nothing to signal - so a recycled pid is never signalled by accident.
    """
    agent_id = ac.sanitize_id(agent_id)
    hb = ac.read_heartbeat(agent_id)
    try:
        pid = int(hb["pid"]) if hb.get("pid") else None
    except (TypeError, ValueError):
        pid = None
    proc_pids = ac.find_watcher_pids(agent_id)
    candidates = proc_pids or ([pid] if pid else [])
    hit = False
    for p in dict.fromkeys(candidates):
        try:
            os.kill(p, sig)
            hit = True
        except (ProcessLookupError, OSError):
            continue
    ac.stop_file_path(agent_id).touch(exist_ok=True)
    return hit


@app.get("/api/agent")
def api_agent_status():
    """Legacy single-agent status (default watcher)."""
    return jsonify(ac.status("default"))


@app.post("/api/agent/start")
def api_agent_start():
    """Legacy single-agent start (default watcher)."""
    denied = _require_role("admin")
    if denied:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    provider_id = (body.get("provider_id") or "").strip() or None
    try:
        pid = _spawn_agent("default", provider_id)
    except ValueError as e:
        _audit_write(
            "agent_start",
            {"agent_id": "default", "provider_id": provider_id},
            None,
            execution_status="failure",
            error=str(e),
        )
        return jsonify({"error": str(e)}), 400
    _audit_write("agent_start", {"agent_id": "default", "provider_id": provider_id}, {"pid": pid})
    return jsonify({"ok": True, "pid": pid})


@app.post("/api/agent/stop")
def api_agent_stop():
    """Legacy single-agent stop (default watcher)."""
    denied = _require_role("admin")
    if denied:
        return denied
    hit = _signal_agent("default", signal.SIGTERM)
    _audit_write("agent_stop", {"agent_id": "default"}, {"killed": hit})
    return jsonify({"ok": True, "killed": hit})


@app.get("/api/agents")
def api_agents():
    """All deployed watchers + deployed/running/stopped counts."""
    agents = ac.list_agents()
    return jsonify({"agents": agents, "counts": ac.counts(agents)})


@app.post("/api/agents/start")
def api_agents_start():
    """Deploy a named watcher, optionally pinned to a SIEM provider.

    agent_id defaults to the provider id (natural name for a per-provider
    watcher) or 'default'. Refuses to double-start a watcher that is alive.
    """
    denied = _require_role("admin")
    if denied:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    provider_id = (body.get("provider_id") or "").strip() or None
    agent_id = (
        ac.sanitize_id(body.get("agent_id"))
        if (body.get("agent_id") or "").strip()
        else (provider_id or "default")
    )
    if ac.status(agent_id)["running"]:
        return jsonify({"error": f"Watcher '{agent_id}' is already running."}), 409
    try:
        pid = _spawn_agent(agent_id, provider_id)
    except ValueError as e:
        _audit_write(
            "agent_start",
            {"agent_id": agent_id, "provider_id": provider_id},
            None,
            execution_status="failure",
            error=str(e),
        )
        return jsonify({"error": str(e)}), 400
    _audit_write("agent_start", {"agent_id": agent_id, "provider_id": provider_id}, {"pid": pid})
    return jsonify({"ok": True, "agent_id": agent_id, "pid": pid})


@app.post("/api/agents/<agent_id>/stop")
def api_agents_stop(agent_id: str):
    """Graceful stop: SIGTERM + stop-file (watcher exits cleanly end-of-cycle)."""
    denied = _require_role("admin")
    if denied:
        return denied
    hit = _signal_agent(agent_id, signal.SIGTERM)
    _audit_write("agent_stop", {"agent_id": ac.sanitize_id(agent_id)}, {"killed": hit})
    return jsonify({"ok": True, "agent_id": ac.sanitize_id(agent_id), "killed": hit})


@app.post("/api/agents/<agent_id>/kill")
def api_agents_kill(agent_id: str):
    """Kill switch: SIGKILL immediately, no cleanup. Leaves a stopped heartbeat."""
    denied = _require_role("admin")
    if denied:
        return denied
    aid = ac.sanitize_id(agent_id)
    hit = _signal_agent(aid, _SIGKILL)
    ac.mark_stopped(aid, "killed (SIGKILL)")
    _audit_write("agent_kill", {"agent_id": aid}, {"killed": hit})
    return jsonify({"ok": True, "agent_id": aid, "killed": hit})


@app.get("/api/agents/<agent_id>/logs")
def api_agents_logs(agent_id: str):
    """Tail of a watcher's captured output (the last N lines of run.log)."""
    aid = ac.sanitize_id(agent_id)
    lines_arg = request.args.get("lines", "200")
    try:
        n = int(lines_arg)
    except ValueError:
        n = 200
    log_path = ac.log_file_path(aid)
    lines = ac.tail_lines(log_path, n) if log_path.exists() else []
    return jsonify({"agent": ac.status(aid), "lines": lines, "total": len(lines)})


# --------------------------------------------------------------------------- #
# AI SOC Engineer - chat, focused builders, Approval Center, audit (PHASE 12).
# --------------------------------------------------------------------------- #
ENGINEER_LOG = Path("data/engineer_log.jsonl")
AUDIT_LOG = Path("data/audit_log.jsonl")


def _engineer_context(user: str = "dashboard-user", agent: str = "engineer_ui"):
    from tools.api_client import WazuhManagerAPI
    from tools.base import ToolContext
    from tools.indexer_client import IndexerClient

    return ToolContext(wazuh=WazuhManagerAPI(), indexer=IndexerClient(), user=user, agent=agent)


@app.post("/api/engineer/chat")
def api_engineer_chat():
    """Run the conversational AI SOC engineer. Tool activity and proposals are
    returned in the transcript; proposals are already persisted in the
    Approval Center (approvals.json).

    Gated at `approver` like /api/engineer/tool, because the agent loop runs
    tools through the same registry - leaving this open let a `viewer` reach
    tool execution and the proposal queue by going through chat instead.

    The engine is constructed with the CALLER's identity, not a hardcoded
    "dashboard-user". That string landed in every proposal's `user` field, and
    separation of duties compares that field against the approver: with a
    hardcoded proposer, `alice` proposing via chat and then approving it as
    `alice` compared "dashboard-user" != "alice", passed the self-approval
    block, and defeated it."""
    denied = _require_role("approver")
    if denied:
        return denied
    actor, _role, _verified = _identity()
    body = request.get_json(force=True, silent=True) or {}
    message = (body.get("message") or "").strip()
    history = body.get("history") or []
    if not message:
        return jsonify({"error": "message is required."}), 400
    try:
        from agent.soc_engineer import SOCEngineer

        engineer = SOCEngineer(user=actor or "dashboard-user")
        result = engineer.chat(user_message=message, history=list(history)[-20:])
    except Exception as e:  # noqa: BLE001 - surface provider/config errors to the UI
        return jsonify({"error": f"Engineer failed: {e}"}), 400

    _engineer_log_path().parent.mkdir(parents=True, exist_ok=True)
    with open(_engineer_log_path(), "a") as f:
        f.write(
            json.dumps(
                {
                    "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                    "message": message,
                    "reply": result.reply,
                    "proposal_ids": [p.get("id") for p in result.proposals],
                    "tool_calls": [
                        t.get("tool") for t in result.transcript if t.get("type") == "tool"
                    ],
                },
                default=str,
            )
            + "\n"
        )
    return jsonify(
        {
            "reply": result.reply,
            "data": result.data,
            "proposals": result.proposals,
            "transcript": result.transcript,
        }
    )


@app.get("/api/engineer/tools")
def api_engineer_tools():
    """Canonical tool metadata (name/description/permission) for the builder
    UIs - never arbitrary tool execution on its own."""
    from tools.registry import build_tools_meta

    return jsonify({"tools": build_tools_meta()})


@app.post("/api/engineer/tool")
def api_engineer_tool():
    """Run one tool with the standard safety model: READ tools execute
    immediately; PROPOSE/EXECUTE tools without an approved proposal produce an
    approval_required outcome that lands in the Approval Center (no write
    happens). The execute endpoint below is the only path that writes."""
    denied = _require_role("approver")
    if denied:
        return denied
    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("tool") or "").strip()
    params = body.get("params") or {}
    if not name:
        return jsonify({"error": "tool is required."}), 400
    from tools.registry import execute as run_tool

    ctx = _engineer_context(user=body.get("by") or "dashboard-user", agent="engineer_ui")
    outcome = run_tool(ctx, name, params)
    return jsonify(outcome)


# ------------------------- Approval Center ------------------------- #
@app.get("/api/proposals")
def api_proposals():
    import approvals

    status = request.args.get("status") or None
    return jsonify(
        {"proposals": [approvals.public_view(p) for p in approvals.list_proposals(status)]}
    )


def _verified_approver() -> tuple[str, bool] | None:
    """(user, identity_verified) for the current request, or None when auth IS
    configured but the request carried no valid credentials. Per-user tokens map
    to a VERIFIED identity; a bare shared token - or a local-trust request with
    auth disabled - is an unverified fallback."""
    user, _role, verified = _identity()
    return (user, verified) if user else None


@app.post("/api/proposals/<pid>/approve")
def api_proposal_approve(pid: str):
    import approvals

    denied = _require_role("approver")
    if denied:
        return denied
    approver = _verified_approver()
    if approver is None:
        return _unauthorized()
    by, verified = approver
    # A client-supplied "by" is ignored for verified identities: the token IS
    # the identity, so a proposer can never approve as someone else.
    try:
        proposal = approvals.approve(pid, by, identity_verified=verified)
    except approvals.ApprovalPolicyError as e:
        return jsonify({"error": str(e)}), 403
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    audit.audit_log(
        tool="approval_center",
        action="proposal_approved",
        permission="human",
        approval_status="approved",
        params={},
        result={"proposal_id": pid, "by": by, "identity_verified": verified},
    )
    return jsonify({"proposal": approvals.public_view(proposal)})


@app.post("/api/proposals/<pid>/reject")
def api_proposal_reject(pid: str):
    import approvals

    denied = _require_role("approver")
    if denied:
        return denied
    approver = _verified_approver()
    if approver is None:
        return _unauthorized()
    by, _ = approver
    body = request.get_json(force=True, silent=True) or {}
    reason = body.get("reason") or ""
    try:
        proposal = approvals.reject(pid, by, reason)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    audit.audit_log(
        tool="approval_center",
        action="proposal_rejected",
        permission="human",
        approval_status="rejected",
        params={},
        result={"proposal_id": pid, "by": by, "reason": reason},
    )
    return jsonify({"proposal": approvals.public_view(proposal)})


@app.post("/api/proposals/<pid>/cancel")
def api_proposal_cancel(pid: str):
    """Withdraw a proposal that is still pending OR already approved.

    `reject` only works on pending, which left an approved proposal as a
    permanent executable grant - the only exit from `approved` was execution.
    Cancelling is how a reviewer takes back a yes: the wrong payload was
    approved, a newer proposal superseded it, it was deployed by hand, or it
    was simply abandoned. Terminal proposals (executed/failed/expired/
    rejected/cancelled) and anything mid-flight (`executing`) are refused -
    history is not rewritten and we never race the executor."""
    import approvals

    denied = _require_role("approver")
    if denied:
        return denied
    approver = _verified_approver()
    if approver is None:
        return _unauthorized()
    by, _ = approver
    body = request.get_json(force=True, silent=True) or {}
    reason = body.get("reason") or ""
    try:
        proposal = approvals.cancel(pid, by, reason)
    except ValueError as e:
        return jsonify({"error": str(e)}), 409
    except KeyError as e:
        return jsonify({"error": str(e)}), 404
    audit.audit_log(
        tool="approval_center",
        action="proposal_cancelled",
        permission="human",
        approval_status="cancelled",
        params={},
        result={"proposal_id": pid, "by": by, "reason": reason},
    )
    return jsonify({"proposal": approvals.public_view(proposal)})


@app.post("/api/proposals/<pid>/execute")
def api_proposal_execute(pid: str):
    """Execute an approved proposal deterministically with its stored payload.
    This is the ONLY path that reaches Wazuh or a SIEM: the proposal is claimed
    atomically (single-use - a replay is 409), EXECUTE-level actions need an
    explicit 'confirm' flag, and the real tool runs with the STORED payload via
    approval_executor (no LLM involved). local_rules.xml is written only through
    these gated tools (put_rules_file is reachable from tools/ alone).

    The CRUD routes below are a different, deliberately-direct surface for a
    human editing LOCAL app config: /api/rules + /api/rules/import manage
    data/rules.json (the pre-triage filter store in rules.py, which imports
    nothing but stdlib+config and cannot reach Wazuh), /api/lookup-tables
    manages data/lookup_tables.json, and /api/providers manages
    data/siem_providers.json. None of them write to the SIEM or a Wazuh
    manager, so none of them can bypass this gate. They are still role-gated
    and audited."""
    import approval_executor
    from config import cfg

    body = request.get_json(force=True, silent=True) or {}
    denied = _require_role("approver")
    if denied:
        return denied
    approver = _verified_approver()
    if approver is None:
        return _unauthorized()
    by, verified = approver
    out = approval_executor.execute_proposal(
        pid,
        by=by,
        confirm=bool(body.get("confirm")),
        identity_verified=verified,
        ctx_factory=lambda by: _engineer_context(user=by, agent="approval_executor"),
        path=cfg.APPROVALS_PATH,
    )
    http_status = out.pop("http_status", 200)
    return jsonify(out), http_status


# ------------------------------ Audit log ------------------------------- #
@app.get("/api/audit")
def api_audit():
    limit = int(request.args.get("limit", 100))
    return jsonify({"entries": audit.read_audit_log(limit=limit)})


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SOC SIEM dashboard")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    parser.add_argument("--port", default=5001, type=int, help="bind port (default 5001)")
    args = parser.parse_args()

    print("=" * 60)
    print("SOC triage dashboard")
    print(f"  Open:      http://{args.host}:{args.port}")
    print(f"  Providers: {store.default_providers_path()}")
    if cfg.DASHBOARD_TOKEN:
        print("  Auth:      ON - open with ?token=<your DASHBOARD_TOKEN>")
    elif args.host not in ("127.0.0.1", "localhost"):
        print(
            "  Auth:      OFF - WARNING: binding to a non-local host with no "
            "DASHBOARD_TOKEN set means every route here is open to anyone "
            "who can reach this address. Set DASHBOARD_TOKEN in .env."
        )
    else:
        print(
            "  Auth:      OFF (fine for local-only use - set DASHBOARD_TOKEN before exposing this beyond 127.0.0.1)"
        )
    print("=" * 60)
    app.run(host=args.host, port=args.port, debug=False)
