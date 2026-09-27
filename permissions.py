"""
Permission model for the AI SOC engineer.

Three levels, enforced server-side in tools/registry.py:

    READ        automatically permitted (searches, lists, status, ...)
    PROPOSE     the agent may generate/validate the action but the write
                itself requires an approved proposal (create/modify rule,
                decoder, dashboard, configuration)
    EXECUTE     high-risk: requires approval + explicit confirmation
                (delete rule/dashboard, restart manager, disable agent,
                block IP / active response)

Every tool class declares its own level (`permission` attribute on
BaseWazuhTool). This module is the single source of truth for what a level
means, for effective_level() (what a proposed action REALLY needs - a caller
can never downgrade a delete to 'propose'), and for check_can_run() which the
execute path calls before running anything.
"""

from __future__ import annotations

from tools.base import Permission, PermissionDenied

# High-risk action keywords - when a tool or proposal matches one of these,
# extra confirmation is required on top of approval (the "EXECUTE" band of
# the spec's safety model).
HIGH_RISK_ACTIONS = (
    "delete_",
    "restart",
    "disable",
    "block",
    "active_response",
    "remove_",
    "purge",
)

CONFIRM_REQUIRED_ACTIONS = (
    "delete_wazuh_rule",
    "delete_wazuh_decoder",
    "restart_wazuh_manager",
    "restart_wazuh_agent",
    "disable_wazuh_agent",
    "block_ip",
)

# Actions that sound like reads and are safe to execute immediately.
_READ_PREFIXES = (
    "get_",
    "list_",
    "search_",
    "find_",
    "show_",
    "verify_",
    "check_",
    "describe_",
    "fetch_",
    "tail_",
    "read_",
    "run_",
    "test_",
    "count_",
    "evaluate_",
    "preview_",
)

# Actions that are by definition writes (PROPOSE band).
_WRITE_PREFIXES = (
    "create_",
    "update_",
    "append_",
    "write_",
    "set_",
    "enable_",
    "save_",
    "import_",
    "install_",
    "design_",
    "generate_",
)


def is_high_risk(action: str) -> bool:
    """True when an action should require a second confirmation after
    approval (EXECUTE band)."""
    return any(action.lower().startswith(k) for k in HIGH_RISK_ACTIONS)


def effective_level(action: str, level: str | Permission | None = None) -> Permission:
    """What an action REALLY needs, regardless of what a caller claimed.

    Escalates: high-risk names (delete/restart/disable/block/purge/...) are
    always EXECUTE, and unknown actions are never READ (they default to
    PROPOSE, so the human still gets a look). The claimed level can never
    downgrade below the true level.
    """
    a = (action or "").lower()
    claimed = Permission(level) if isinstance(level, str) else (level or Permission.PROPOSE)

    if not a or is_high_risk(a) or a in CONFIRM_REQUIRED_ACTIONS:
        return Permission.EXECUTE
    if claimed == Permission.EXECUTE:
        return Permission.EXECUTE
    if a.startswith(_WRITE_PREFIXES):
        return Permission.PROPOSE
    if claimed == Permission.PROPOSE:
        return Permission.PROPOSE
    if a.startswith(_READ_PREFIXES):
        return Permission.READ
    # Unknown action with a READ claim: never READ - keep it visible to a human.
    return Permission.PROPOSE


def needs_confirmation(action: str, permission: str | None = None) -> bool:
    """True when an approved proposal still needs an explicit operator
    confirmation on top of the approval before it can execute."""
    if permission == "execute":
        return True
    return action in CONFIRM_REQUIRED_ACTIONS


def describe(level: Permission | str) -> str:
    if isinstance(level, str):
        level = Permission(level)
    return level.label


def check_can_run(
    permission: Permission | str, action: str, *, approved: bool = False, confirmed: bool = False
) -> None:
    """Server-side gate for executions. `approved` is whether the action has
    an approved proposal; `confirmed` is the extra confirmation an operator
    gives in the UI for high-risk actions. Raises PermissionDenied when
    anything is missing or the claimed level is weaker than the effective
    level the action really needs."""
    claimed = Permission(permission) if isinstance(permission, str) else permission
    needed = effective_level(action, claimed.value)
    if claimed.value != needed.value:
        raise PermissionDenied(
            f"Action '{action}' requires {needed.value.upper()} - the claimed "
            f"level '{claimed.value}' is too weak."
        )
    if needed == Permission.READ:
        return
    if not approved:
        raise PermissionDenied(
            f"Action '{action}' is a {needed.value.upper()} operation - it "
            "cannot run without an approved proposal."
        )
    if needed == Permission.EXECUTE and not confirmed:
        raise PermissionDenied(
            f"Action '{action}' needs an explicit confirmation on top of the approval."
        )


__all__ = [
    "Permission",
    "HIGH_RISK_ACTIONS",
    "CONFIRM_REQUIRED_ACTIONS",
    "is_high_risk",
    "effective_level",
    "needs_confirmation",
    "describe",
    "check_can_run",
]
