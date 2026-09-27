"""
Wazuh logtest tools - test logs against the manager's deployed ruleset.

logtest on Wazuh 4.7+ only exercises the *deployed* ruleset (the API no
longer accepts a custom rule in the body). So this tool serves two purposes:

1. baseline checks: given a log line, which decoder + rule fire today and
   what fields decode - used before proposing a new rule,
2. post-deploy verification: after a rule is deployed (through the approval
   flow), re-run logtest to prove the new rule id matches the sample and
   does not match negative samples.

The detection engine combines static XML validation (before proposal) +
this tool (after deploy) so it never claims a rule works without the manager
confirming it.
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError


def _parse_logtest(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize both response shapes Wazuh has shipped:
    legacy {alerts: [...]} and 4.7+ {alert: bool, output: {...}}."""
    alerts = [a for a in (data.get("alerts") or []) if isinstance(a, dict)]
    if alerts:
        output = alerts[-1]
    else:
        output = data.get("output") or {}
    rule = output.get("rule") or {}
    matched = bool(rule) and bool(data.get("alert", True)) if rule else bool(data.get("alert"))
    if "alert" in data:  # 4.7+ authoritative
        matched = bool(data.get("alert"))
    return {
        "token": data.get("token"),
        "matched": matched,
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups") or [],
        "decoder": output.get("decoder") or {},
        "full_log": str(output.get("full_log") or "")[:1000],
        "fields": (output.get("fields") or {}),
        "messages": [str(m) for m in (data.get("messages") or [])],
        "location": data.get("location") or output.get("location"),
    }


class RunWazuhLogtest(BaseWazuhTool):
    name = "run_wazuh_logtest"
    description = (
        "Run Wazuh logtest: feed one log line through the manager's *deployed* ruleset "
        "and see which decoder + rule fire, plus the decoded fields. Use to verify a "
        "candidate rule after deployment, check how existing rules treat a log, or "
        "confirm a log format decodes at all. Pass 'log_format' of the source "
        "(syslog, json, eventlog, ...)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "log": {"type": "string", "description": "the log line to test"},
            "log_format": {
                "type": "string",
                "description": "syslog, json, eventlog, ... (default syslog)",
            },
            "location": {
                "type": "string",
                "description": "pretend source path, e.g. /var/log/auth.log",
            },
            "token": {"type": "string", "description": "reuse an existing logtest session token"},
        },
        "required": ["log"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        log = str(p["log"])
        if len(log) > 8000:
            raise ToolError("logtest log line too long (8000 chars max).")
        try:
            resp = ctx.wazuh.run_logtest(
                log,
                log_format=p.get("log_format"),
                location=p.get("location"),
                token=p.get("token"),
            )
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"logtest failed: {e}") from e
        data = resp.get("data") or {}
        return _parse_logtest(data)


class EndWazuhLogtestSession(BaseWazuhTool):
    name = "end_wazuh_logtest_session"
    description = "Close a logtest session (run_wazuh_logtest returns a token; close it when done)."
    input_schema = {
        "type": "object",
        "properties": {"token": {"type": "string"}},
        "required": ["token"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        try:
            resp = ctx.wazuh.end_logtest_session(p["token"])
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to close logtest session: {e}") from e
        return {"status": "closed" if resp.get("error") == 0 else "already_closed"}
