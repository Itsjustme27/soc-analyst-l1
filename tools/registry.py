"""
Tool registry for the AI SOC engineer.

Builds the canonical tool list the LLM sees ({name, description,
input_schema} - the shape every provider already translates) and is the ONE
place that runs a tool: it validates params, enforces the permission model,
audits every call, and wraps results as untrusted DATA before they re-enter
the conversation (guard.py).

    execute(ctx, tool_name, params) -> outcome dict

Outcome shapes:
    {"status": "ok", "result": <tool result>}                 (READ / executed)
    {"status": "approval_required", "proposal": <proposal>}   (write w/o approval)
    {"status": "error", "error": "..."}                       (raised failure)

The LLM can never bypass a write gate: create/update/delete tools raise
ApprovalRequired internally if ctx.approval is absent, and `execute` converts
that into the approval_required outcome.
"""

from __future__ import annotations

from typing import Any

import approvals
import audit
import guard
from tools.base import (
    ApprovalRequired,
    BaseWazuhTool,
    Permission,
    PermissionDenied,
    ToolContext,
    ToolError,
    ToolParamError,
)


def _collect_tool_classes() -> list[type[BaseWazuhTool]]:
    from tools.dashboard import TOOLS as DASHBOARD_TOOLS
    from tools.detection import TOOLS as DETECTION_TOOLS
    from tools.gaps import TOOLS as GAP_TOOLS
    from tools.indexer import TOOLS as INDEXER_TOOLS
    from tools.investigate import TOOLS as INVESTIGATE_TOOLS
    from tools.propose import ProposeAction
    from tools.rag import TOOLS as RAG_TOOLS
    from tools.wazuh import TOOLS as WAZUH_TOOLS

    return [
        *INDEXER_TOOLS,
        *WAZUH_TOOLS,
        *DASHBOARD_TOOLS,
        *INVESTIGATE_TOOLS,
        *DETECTION_TOOLS,
        *GAP_TOOLS,
        *RAG_TOOLS,
        ProposeAction,
    ]


ALL_TOOL_CLASSES: list[type[BaseWazuhTool]] = _collect_tool_classes()

# name -> instance
_TOOL_INSTANCES: dict[str, BaseWazuhTool] = {cls.name: cls() for cls in ALL_TOOL_CLASSES}


def tool_names() -> list[str]:
    return sorted(_TOOL_INSTANCES)


def get_tool(name: str) -> BaseWazuhTool:
    try:
        return _TOOL_INSTANCES[name]
    except KeyError:
        raise ToolError(f"Unknown tool '{name}'. Available: {', '.join(tool_names())}") from None


def build_tools_meta() -> list[dict[str, Any]]:
    """Canonical tool shape for the LLM providers."""
    return [tool.meta() for tool in _TOOL_INSTANCES.values()]


# READ-only tools get executed immediately; anything PROPOSE/EXECUTE only runs
# with an approved proposal. That mapping is enforced here and inside each
# write tool - defense in depth.
def _permission_level(tool: BaseWazuhTool) -> Permission:
    return tool.permission


def _store_proposal(
    proposed: dict[str, Any], ctx: ToolContext, tool: BaseWazuhTool, clean: dict[str, Any]
) -> dict[str, Any]:
    """Persist a tool's proposed action into the Approval Center so it gets an
    id humans can approve, and thread the id back through audit + the agent."""
    return approvals.create_proposal(
        action=proposed.get("action", tool.name),
        reason=proposed.get("reason", ""),
        payload=proposed.get("payload", {}),
        permission=proposed.get("permission", tool.permission.value),
        generated_config=proposed.get("generated_config"),
        validation=proposed.get("validation"),
        user=ctx.user,
        agent=ctx.agent,
    )


def execute(
    ctx: ToolContext,
    tool_name: str,
    params: dict[str, Any],
    *,
    silent: bool = False,
) -> dict[str, Any]:
    """Run a tool with full gating + audit. `silent=True` skips the
    conversation-ready wrapper (used by the dashboard's execute endpoint,
    which wants the raw result)."""
    tool = get_tool(tool_name)
    level = _permission_level(tool)

    # 1) schema-level parameter validation
    try:
        clean = tool.validate(params)
    except ToolParamError as e:
        audit.audit_log(
            tool=tool_name,
            params=tool.redact(params),
            permission=level.value,
            execution_status="rejected",
            error=str(e),
        )
        return {"status": "error", "error": str(e)}

    # 2) permission gate: READ runs now; PROPOSE/EXECUTE only with approval
    if level in (Permission.PROPOSE, Permission.EXECUTE) and (ctx.approval is None):
        try:
            tool.run(ctx, **clean)  # running without approval raises ApprovalRequired
            # A write tool that somehow ran without approval is a bug - treat
            # as denied and report.
            raise PermissionDenied(
                f"{tool_name} is a write tool but executed without an approved proposal."
            )
        except ApprovalRequired as e:
            proposal = _store_proposal(e.proposed_action, ctx, tool, clean)
            audit.audit_log(
                tool=tool_name,
                params=tool.redact(clean),
                permission=level.value,
                approval_status="proposed",
                execution_status="awaiting_approval",
                action=proposal.get("action", tool_name),
                result={"proposal_id": proposal.get("id")},
            )
            return {"status": "approval_required", "proposal": proposal}
        except PermissionDenied:
            raise

    # 3) run (READ here, or approved write)
    try:
        result = tool.run(ctx, **clean)
    except ApprovalRequired as e:
        proposal = _store_proposal(e.proposed_action, ctx, tool, clean)
        audit.audit_log(
            tool=tool_name,
            params=tool.redact(clean),
            permission=level.value,
            approval_status="proposed",
            execution_status="awaiting_approval",
            action=proposal.get("action", tool_name),
            result={"proposal_id": proposal.get("id")},
        )
        return {"status": "approval_required", "proposal": proposal}
    except (ToolError, PermissionDenied) as e:
        audit.audit_log(
            tool=tool_name,
            params=tool.redact(clean),
            permission=level.value,
            execution_status="failed",
            error=str(e),
        )
        if silent:
            raise
        return {"status": "error", "error": str(e)}
    except Exception as e:  # noqa: BLE001 - unexpected failure, still audited
        audit.audit_log(
            tool=tool_name,
            params=tool.redact(clean),
            permission=level.value,
            execution_status="failed",
            error=f"unexpected: {e}",
        )
        if silent:
            raise
        return {"status": "error", "error": f"unexpected failure: {e}"}

    approval_status = "approved" if ctx.approval else "not_required"
    audit.audit_log(
        tool=tool_name,
        params=tool.redact(clean),
        permission=level.value,
        approval_status=approval_status,
        execution_status="success",
        result=_result_summary(result),
    )

    if silent:
        return result if isinstance(result, dict) else {"result": result}

    # 4) wrap the result as DATA before it goes anywhere near the LLM
    capped = guard.limit_result_size(result)
    return {"status": "ok", "result": _as_jsonable(capped)}


def _as_jsonable(value: Any) -> Any:
    import json

    try:
        json.dumps(value, default=str)
        return value
    except (TypeError, ValueError):
        return {"repr": str(value)[:2000]}


def _result_summary(result: Any) -> Any:
    """Tiny summary for the audit row (never the full blob)."""
    return _as_jsonable(guard.limit_result_size(result, max_items=5))
