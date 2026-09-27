"""
Approval Center store for the AI SOC engineer.

Write operations (PROPOSE/EXECUTE level tools) do not run on the agent's say
so: the tool raises ApprovalRequired with its proposal, the UI shows the
proposed action to a human, and execution only happens with an approved
proposal id. This module persists those proposals (data/approvals.json) and
tracks their lifecycle:

    pending -> approved -> executing -> executed | failed
           |-> rejected | expired

Approving is *not* executing: an approved proposal carries the exact action +
payload the tool needs, and the execute endpoint re-runs the real tool with
that payload (no LLM involved in the execution step - see docs/permissions.md).

Policy rules (all configurable, see config.py):

  * APPROVAL_EXPIRY_SECONDS - pending proposals older than this expire and
    cannot be approved.
  * APPROVAL_EXECUTION_WINDOW_SECONDS - an approved proposal must be claimed
    within this window (0 = no limit).
  * APPROVAL_BLOCK_SELF_APPROVAL - a verified approver may not approve their
    own proposal (separation of duties).
  * APPROVAL_PROPOSE_MIN_APPROVERS / APPROVAL_EXECUTE_MIN_APPROVERS - quorum
    required before a proposal flips to approved. The *current* config is
    consulted at approve time, so tightening the policy applies to proposals
    created before the change.

claim_for_execution() is the single-use gate: it atomically flips
approved -> executing under a file lock, so a replay or a concurrent request
can only ever win once.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

if os.name == "nt":
    import msvcrt
else:
    import fcntl

import permissions
from config import cfg

DEFAULT_APPROVALS_PATH = "data/approvals.json"


class ApprovalPolicyError(RuntimeError):
    """A policy rule (self-approval, duplicate approver, quorum) refused the
    action. Distinct from ValueError so the dashboard can map it to 403."""


# --------------------------------------------------------------------------- #
def _path(path: str | Path | None = None) -> Path:
    return Path(path or getattr(cfg, "APPROVALS_PATH", DEFAULT_APPROVALS_PATH))


def _load(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    return [p for p in data if isinstance(p, dict)]


def _save(items: list[dict[str, Any]], path: Path) -> None:
    """Atomic write: temp file + rename, so a crash never leaves a half-written
    store and no .tmp files are left behind."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(items, indent=2, default=str))
    os.replace(tmp, path)


@contextmanager
def _locked(path: Path) -> Iterator[None]:
    """Exclusive advisory lock around read-modify-write of the store. Claiming
    a proposal must be atomic so concurrent executes can't both win."""
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "a+b") as f:
        if os.name == "nt":
            # msvcrt locks a byte range from the current file position. Keep
            # one stable byte in the lock file so this also works on Windows.
            if f.tell() == 0:
                f.write(b"\0")
                f.flush()
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(f, fcntl.LOCK_UN)


def _now() -> float:
    return time.time()


def _required_now(item: dict[str, Any]) -> int:
    """Quorum required *today* - the current config, not what was stored at
    proposal creation, so tightening policy applies to older proposals."""
    perm = item.get("permission")
    min_count = (
        getattr(cfg, "APPROVAL_EXECUTE_MIN_APPROVERS", 1)
        if perm == "execute"
        else getattr(cfg, "APPROVAL_PROPOSE_MIN_APPROVERS", 1)
    )
    return max(int(min_count or 1), 1)


# --------------------------------------------------------------------------- #
def create_proposal(
    *,
    action: str,
    reason: str,
    payload: dict[str, Any],
    permission: str = "propose",
    generated_config: Any = None,
    validation: dict[str, Any] | None = None,
    user: str | None = None,
    agent: str = "soc_engineer",
    path: str | Path | None = None,
) -> dict[str, Any]:
    """Register a new pending proposal. Returns the stored record incl. id.
    The stored permission is the EFFECTIVE level (permissions.effective_level),
    so a caller cannot downgrade a delete/restart/block to 'propose'."""
    p = _path(path)
    effective = permissions.effective_level(action, permission)
    record = {
        "id": f"appr-{uuid.uuid4().hex[:12]}",
        "action": action,
        "reason": reason,
        "payload": payload,
        "permission": effective.value,
        "required_approvers": _required_now({"permission": effective.value}),
        "generated_config": generated_config,
        "validation": validation or {},
        "status": "pending",
        "created": _now(),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "user": user or getattr(cfg, "ENGINE_USER", "analyst"),
        "agent": agent,
        "approvals": [],
    }
    with _locked(p):
        items = _load(p)
        items.append(record)
        _save(items, p)
    return record


def list_proposals(
    status: str | None = None, path: str | Path | None = None
) -> list[dict[str, Any]]:
    p = _path(path)
    with _locked(p):
        items = _load(p)
        # expire stale pending proposals on read
        changed = False
        for item in items:
            if item.get("status") == "pending" and _now() - float(item.get("created", 0)) > getattr(
                cfg, "APPROVAL_EXPIRY_SECONDS", 86400
            ):
                item["status"] = "expired"
                changed = True
        if changed:
            _save(items, p)
    out = [i for i in items if status is None or i.get("status") == status]
    return out[::-1]  # newest first


def get_proposal(proposal_id: str, path: str | Path | None = None) -> dict[str, Any] | None:
    for item in _load(_path(path)):
        if item.get("id") == proposal_id:
            return item
    return None


def approve(
    proposal_id: str, by: str, path: str | Path | None = None, identity_verified: bool = False
) -> dict[str, Any]:
    """Approve a pending proposal. Expired ones cannot be approved. Policy:
    no self-approval for verified identities, one vote per approver, and a
    quorum (current config) before the proposal flips to approved."""
    p = _path(path)
    with _locked(p):
        items = _load(p)
        for item in items:
            if item.get("id") != proposal_id:
                continue
            if item["status"] == "expired":
                raise ValueError(
                    f"Proposal {proposal_id} has expired and can no longer be approved."
                )
            if item["status"] != "pending":
                raise ValueError(f"Proposal {proposal_id} is already {item['status']}.")
            if _now() - float(item.get("created", 0)) > getattr(
                cfg, "APPROVAL_EXPIRY_SECONDS", 86400
            ):
                item["status"] = "expired"
                _save(items, p)
                raise ValueError(
                    f"Proposal {proposal_id} has expired and can no longer be approved."
                )
            block_self = getattr(cfg, "APPROVAL_BLOCK_SELF_APPROVAL", True)
            if (
                identity_verified
                and block_self
                and str(item.get("user", "")).strip() == str(by).strip()
            ):
                raise ApprovalPolicyError(
                    "Separation of duties: the proposer cannot approve their own proposal."
                )
            approvers = [a.get("by") for a in item.get("approvals", [])]
            if by in approvers:
                raise ApprovalPolicyError(
                    f"{by} has already approved proposal {proposal_id} - one vote per approver."
                )
            item.setdefault("approvals", [])
            item["approvals"].append(
                {
                    "by": by,
                    "verified": bool(identity_verified),
                    "at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
            )
            item["approved_by"] = by
            if len(item["approvals"]) >= _required_now(item):
                item["status"] = "approved"
                item["approved_at"] = _now()
            _save(items, p)
            return item
    raise KeyError(f"Proposal {proposal_id} not found.")


def claim_for_execution(
    proposal_id: str, by: str, path: str | Path | None = None, identity_verified: bool = False
) -> dict[str, Any]:
    """Atomically claim an approved proposal: approved -> executing. This is
    the single-use gate - a replay or concurrent claim raises ValueError and
    only one caller can ever win."""
    p = _path(path)
    with _locked(p):
        items = _load(p)
        for item in items:
            if item.get("id") != proposal_id:
                continue
            if item["status"] in ("executing", "executed", "failed"):
                raise ValueError(
                    f"Proposal {proposal_id} is already {item['status']} - it cannot be claimed again."
                )
            if item["status"] != "approved":
                if item["status"] == "expired":
                    raise ValueError(f"Proposal {proposal_id} has expired.")
                raise ValueError(
                    f"Proposal {proposal_id} is not approved (status: {item['status']})."
                )
            window = int(getattr(cfg, "APPROVAL_EXECUTION_WINDOW_SECONDS", 0) or 0)
            approved_ts = float(item.get("approved_at") or item.get("created") or 0)
            if window > 0 and _now() - approved_ts > window:
                item["status"] = "expired"
                _save(items, p)
                raise ValueError(f"Proposal {proposal_id} expired before it could be executed.")
            item["status"] = "executing"
            item["claimed_by"] = by
            item["claimed_at"] = _now()
            item["identity_verified"] = bool(identity_verified)
            _save(items, p)
            return item
    raise KeyError(f"Proposal {proposal_id} not found.")


def finish_execution(
    proposal_id: str, *, ok: bool, error: str | None = None, path: str | Path | None = None
) -> dict[str, Any]:
    """executing -> executed (ok=True) or failed (ok=False). Terminal."""
    p = _path(path)
    with _locked(p):
        items = _load(p)
        for item in items:
            if item.get("id") != proposal_id:
                continue
            if item["status"] != "executing":
                raise ValueError(f"Proposal {proposal_id} is {item['status']}, not executing.")
            item["status"] = "executed" if ok else "failed"
            if error is not None:
                item["execution_error"] = str(error)
            item["executed_at"] = _now()
            _save(items, p)
            return item
    raise KeyError(f"Proposal {proposal_id} not found.")


def reject(
    proposal_id: str, by: str, reason: str = "", path: str | Path | None = None
) -> dict[str, Any]:
    p = _path(path)
    with _locked(p):
        items = _load(p)
        for item in items:
            if item.get("id") != proposal_id:
                continue
            if item["status"] != "pending":
                raise ValueError(f"Proposal {proposal_id} is already {item['status']}.")
            item["status"] = "rejected"
            item["rejected_by"] = by
            item["reject_reason"] = reason
            item["rejected_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            _save(items, p)
            return item
    raise KeyError(f"Proposal {proposal_id} not found.")


_CANCELLABLE = ("pending", "approved")


def cancel(
    proposal_id: str, by: str, reason: str = "", path: str | Path | None = None
) -> dict[str, Any]:
    """Withdraw a proposal: pending/approved -> cancelled.

    Without this, an approved proposal was a permanent grant: the only exit
    from `approved` was execution, so once a reviewer said yes the change
    could never be taken back. Stale approvals (wrong payload, superseded by
    a newer proposal, deployed by hand, or simply abandoned) stayed
    executable forever with no way to withdraw them.

    Terminal states are refused - a proposal that already ran is history and
    must not be rewritten, and `executing` is mid-flight so cancelling it
    would race the executor. The withdrawal is recorded (who/when/why) so the
    audit trail shows the grant was revoked rather than silently dropped.
    """
    p = _path(path)
    with _locked(p):
        items = _load(p)
        for item in items:
            if item.get("id") != proposal_id:
                continue
            if item["status"] not in _CANCELLABLE:
                raise ValueError(
                    f"Proposal {proposal_id} is {item['status']} and can no longer be cancelled."
                )
            item["status"] = "cancelled"
            item["cancelled_by"] = by
            item["cancel_reason"] = reason
            item["cancelled_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            _save(items, p)
            return item
    raise KeyError(f"Proposal {proposal_id} not found.")


def public_view(proposal: dict[str, Any]) -> dict[str, Any]:
    """Payload suitable for the UI/chat - never includes secrets (the payload
    is generated config the user needs to review, so it is shown; audit
    handles redaction of credential-bearing params at the tool layer)."""
    return {
        "id": proposal.get("id"),
        "action": proposal.get("action"),
        "reason": proposal.get("reason"),
        "permission": proposal.get("permission"),
        "generated_config": proposal.get("generated_config"),
        "validation": proposal.get("validation"),
        "status": proposal.get("status"),
        "created_at": proposal.get("created_at"),
        "user": proposal.get("user"),
        "required_approvers": proposal.get("required_approvers"),
        "approvals": proposal.get("approvals"),
        "cancelled_by": proposal.get("cancelled_by"),
        "cancel_reason": proposal.get("cancel_reason"),
    }
