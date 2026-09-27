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
    p = approvals.get_proposal(proposal_id, path=path)
    if not p:
        return {"ok": False, "error": f"Proposal {proposal_id} not found.", "http_status": 404}
    if p.get("status") != "approved":
        return {
            "ok": False,
            "http_status": 409,
            "error": f"Proposal {proposal_id} is not approved (status: {p.get('status')}).",
        }
    action = p.get("action", "")
    if permissions.needs_confirmation(action, p.get("permission")) and not confirm:
        return {
            "ok": False,
            "http_status": 400,
            "error": "EXECUTE-level action: this requires an explicit confirmation "
            "on top of the approval.",
        }

    try:
        claimed = approvals.claim_for_execution(
            proposal_id, by, path=path, identity_verified=identity_verified
        )
    except (ValueError, KeyError) as e:
        return {"ok": False, "error": str(e), "http_status": 409}

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
