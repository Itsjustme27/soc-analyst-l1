"""
Inline approvals for the CLI (Codex / Claude Code style).

Instead of "/proposals -> /approve <id> -> /execute <id> --confirm", the CLI
shows each new proposal right after the turn that produced it and asks:

    [y] approve & run   [n] reject   [l] later   [a] always for <action> this session

It is a front end over the SAME machinery - approvals.approve() and
approval_executor.execute_proposal() (single-use claim, stored payload,
audit) - so nothing about the safety model changes:

  * EXECUTE-level actions (delete/restart/disable/block ...) never get an
    "always" option and need the word "yes" typed as the confirmation;
  * "always" is per action name, per CLI session, in memory only;
  * if policy needs more approvers (APPROVAL_*_MIN_APPROVERS), the proposal
    stays pending with a note - an inline "y" is one approval, not a bypass.

MCP tool calls that aren't marked read-only get the same kind of prompt
before they run: [y] once / [a] always this tool this session / [n] no.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

Ask = Callable[[str], str]
Out = Callable[[str], None]


def _short(text: Any, n: int) -> str:
    s = str(text or "")
    return s if len(s) <= n else s[: n - 1] + "…"


def render_proposal(p: dict[str, Any], out: Out, diff_lines: int = 30) -> None:
    val = p.get("validation") or {}
    level = str(p.get("permission") or "propose").upper()
    out(f"\n┌ proposal {p.get('id')} · {p.get('action')} · {level}")
    if p.get("reason"):
        out(f"│ reason: {_short(p['reason'], 200)}")
    if val:
        state = "valid" if val.get("valid") else "NOT valid"
        out(f"│ validation: {state}")
        for err in (val.get("errors") or [])[:5]:
            out(f"│   ! {_short(err, 200)}")
    diff = val.get("diff") or ""
    if diff:
        lines = diff.splitlines()
        for line in lines[:diff_lines]:
            out(f"│ {line}")
        if len(lines) > diff_lines:
            out(f"│ … {len(lines) - diff_lines} more line(s) - /proposals {p.get('id')}")
    elif p.get("generated_config") and not diff:
        out(f"│ config: {_short(p['generated_config'], 300)}")


def review_pending(
    proposals: list[dict[str, Any]],
    *,
    user: str,
    ask: Ask,
    out: Out = print,
    always: set[str],
    ctx_factory: Callable[[str], Any],
) -> list[dict[str, Any]]:
    """Walk new proposals interactively. Returns one outcome dict per proposal."""
    import approval_executor
    import approvals
    import audit
    import permissions

    outcomes = []
    seen = set()
    for summary in proposals:
        pid = summary.get("id")
        if not pid or pid in seen:
            continue
        seen.add(pid)
        p = approvals.get_proposal(pid)
        if not p or p.get("status") != "pending":
            continue
        execute_level = permissions.needs_confirmation(p.get("action", ""), p.get("permission"))
        render_proposal(p, out)

        if not execute_level and p.get("action") in always:
            choice = "y"
            out(f"└ auto-approved: 'always' is on for {p.get('action')} this session")
        else:
            opts = "[y] approve & run  [n] reject  [l] later"
            if not execute_level:
                opts += f"  [a] always for {p.get('action')}"
            choice = (ask(f"└ {opts} › ") or "").strip().lower()[:1]

        if choice == "a" and not execute_level:
            always.add(p.get("action"))
            choice = "y"
        if choice == "n":
            reason = (ask("  reason (optional) › ") or "").strip()
            approvals.reject(pid, by=user, reason=reason or "rejected inline")
            audit.audit_log(
                tool="approval_center",
                action="proposal_rejected_inline",
                permission="human",
                approval_status="rejected",
                params={},
                user=user,
                agent="soc_engineer_cli",
                result={"proposal_id": pid, "reason": reason},
            )
            out(f"  ✕ rejected {pid}")
            outcomes.append({"id": pid, "outcome": "rejected"})
            continue
        if choice != "y":
            out(f"  … left pending - /proposals {pid}")
            outcomes.append({"id": pid, "outcome": "pending"})
            continue
        if execute_level:
            typed = (
                (ask(f"  HIGH-RISK {p.get('action')}: type 'yes' to confirm › ") or "")
                .strip()
                .lower()
            )
            if typed != "yes":
                out(f"  … not confirmed - left pending ({pid})")
                outcomes.append({"id": pid, "outcome": "pending"})
                continue

        try:
            rec = approvals.approve(pid, by=user, identity_verified=False)
        except (ValueError, KeyError) as e:
            out(f"  ✕ approval refused: {e}")
            outcomes.append({"id": pid, "outcome": "refused", "error": str(e)})
            continue
        audit.audit_log(
            tool="approval_center",
            action="proposal_approved_inline",
            permission="human",
            approval_status=rec.get("status"),
            params={},
            user=user,
            agent="soc_engineer_cli",
            result={"proposal_id": pid, "identity_verified": False},
        )
        if rec.get("status") != "approved":
            need = rec.get("required_approvers", 1)
            have = len(rec.get("approvals") or [])
            out(
                f"  … approval recorded ({have}/{need}) - another approver is needed before it can run"
            )
            outcomes.append({"id": pid, "outcome": "awaiting_approvers"})
            continue
        res = approval_executor.execute_proposal(
            pid, by=user, confirm=execute_level, ctx_factory=ctx_factory, identity_verified=False
        )
        if res.get("ok"):
            detail = res.get("result")
            status = detail.get("status") if isinstance(detail, dict) else None
            out(f"  ✔ executed {pid}" + (f" ({status})" if status else ""))
            outcomes.append({"id": pid, "outcome": "executed", "result": detail})
        else:
            out(f"  ✕ execution failed: {_short(res.get('error'), 300)}")
            outcomes.append({"id": pid, "outcome": "failed", "error": res.get("error")})
    return outcomes


def mcp_approver(ask: Ask, out: Out = print) -> Callable[[Any, dict[str, Any]], bool]:
    """Build the per-call approval prompt for non-read MCP tools."""
    session_allowed: set[str] = set()

    def approve(tool: Any, args: dict[str, Any]) -> bool:
        if tool.id in session_allowed:
            out(f"  ↻ {tool.id} (always-allowed this session)")
            return True
        import json

        out(f"\n┌ MCP tool call · {tool.server} › {tool.name} (not read-only)")
        out(f"│ {_short(tool.description, 200)}")
        out(f"│ args: {_short(json.dumps(args, default=str), 400)}")
        choice = (
            ask(f"└ [y] run once  [a] always allow {tool.name} this session  [n] deny › ") or ""
        )
        choice = choice.strip().lower()[:1]
        if choice == "a":
            session_allowed.add(tool.id)
            return True
        return choice == "y"

    approve.session_allowed = session_allowed  # type: ignore[attr-defined]
    return approve
