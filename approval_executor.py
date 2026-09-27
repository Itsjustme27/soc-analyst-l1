"""
The one code path that executes an approved proposal.

Used by dashboard.py (`POST /api/proposals/<id>/execute`) and by
live_validation/env.py - previously each had its own copy of these checks,
and neither marked a proposal as used, so one approval could be replayed
indefinitely. Order of operations:

  1. load the proposal (time-based expiry applied)
  2. it must be `approved`
  3. EXECUTE-level actions need `confirm=True` - the level is
     permissions.effective_level(), not just what the record says
  4. approvals.claim_for_execution(): atomic approved -> executing. This is
     the single-use gate; a replay/concurrent request fails here
  5. run the real tool with the STORED payload (no LLM involved)
  6. approvals.finish_execution(): executing -> executed | failed
  7. audit the outcome either way
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import approvals
import audit
import permissions
from tools.base import ToolContext


def execute_proposal(
    proposal_id: str,
    *,
    by: str,
    confirm: bool,
    ctx_factory: Callable[[str], ToolContext],
    identity_verified: bool = False,
    path: Any = None,
) -> dict[str, Any]:
    """Returns {"ok": bool, "error"?, "result"?, "http_status": int}."""

    # Every rejection below is audited before returning. An attempt that never
    # reaches the tool used to leave NO trace at all, because these early
    # returns all fired ahead of the success-path audit. That made a refused
    # execution indistinguishable from an attempt that was never made - which
    # is exactly the question you cannot answer when an operator says "execute
    # does nothing" and the audit log is empty. A gate rejection is the thing
    # most worth having a record of: it is someone probing the approval path.
    def _refuse(message: str, http_status: int, action_: str = "") -> dict[str, Any]:
        audit.audit_log(
            tool="approval_center",
            action="proposal_execution_refused",
            permission="human",
            approval_status=(p or {}).get("status") or "unknown",
            execution_status="refused",
            params={},
            user=by,
            error=message,
            result={
                "proposal_id": proposal_id,
                "tool": action_ or (p or {}).get("action", ""),
                "by": by,
                "identity_verified": identity_verified,
                "http_status": http_status,
            },
        )
        return {"ok": False, "error": message, "http_status": http_status}

    p = approvals.get_proposal(proposal_id, path=path)
    if not p:
        return _refuse(f"Proposal {proposal_id} not found.", 404)
    if p.get("status") != "approved":
        return _refuse(f"Proposal {proposal_id} is not approved (status: {p.get('status')}).", 409)
    action = p.get("action", "")
    if permissions.needs_confirmation(action, p.get("permission")) and not confirm:
        return _refuse(
            "EXECUTE-level action: this requires an explicit confirmation on top of the approval.",
            400,
            action,
        )

    try:
        claimed = approvals.claim_for_execution(
            proposal_id, by, path=path, identity_verified=identity_verified
        )
    except (ValueError, KeyError) as e:
        return _refuse(str(e), 409, action)

    ctx = ctx_factory(by)
    ctx.approval = claimed  # gates the tool's approve_or_raise

    import tools.registry as registry  # attribute lookup at call time (mockable)

    error: str | None = None
    result: Any = None
    try:
        result = registry.execute(ctx, action, claimed.get("payload") or {}, silent=True)
        if isinstance(result, dict) and result.get("status") == "error":
            error = result.get("error", "execution failed")
    except Exception as e:  # noqa: BLE001 - tool failure is recorded, not raised
        error = str(e)

    try:
        approvals.finish_execution(proposal_id, ok=error is None, error=error, path=path)
    except (ValueError, KeyError):
        pass  # record vanished/raced - the audit row below still captures the outcome

    audit.audit_log(
        tool="approval_center",
        action="proposal_executed" if error is None else "proposal_execution_failed",
        permission="human",
        approval_status="approved",
        execution_status="success" if error is None else "failed",
        params={},
        user=by,
        error=error,
        result={
            "proposal_id": proposal_id,
            "tool": action,
            "by": by,
            "identity_verified": identity_verified,
        },
    )
    if error is not None:
        out = {"ok": False, "error": error, "http_status": 200}
        if isinstance(result, dict):
            out["result"] = result
        return out
    return {"ok": True, "result": result, "http_status": 200}
