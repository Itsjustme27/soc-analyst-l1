"""
Tool substrate for the AI SOC engineer: permission levels, the ToolContext a
tool runs inside, and the BaseWazuhTool interface every tool implements.

Safety model (see docs/permissions.md):

    READ     - executes immediately (search alerts/events, lists, status, ...)
    PROPOSE  - the tool can *plan* and produce a validated configuration, but
               the actual write requires an approved proposal from the
               Approval Center (create/modify rule, decoder, dashboard, ...)
    EXECUTE  - high-risk; requires an approved proposal AND an explicit
               confirmation on top (delete rule, restart manager, disable
               agent, active response, ...)

Enforcement happens in tools/registry.py, not in prompts: a write tool whose
context has no approved proposal returns an ApprovalRequired outcome instead
of performing the write. The LLM can never bypass this by rephrasing, because
the tool itself checks `ctx.approval`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from tools.api_client import WazuhManagerAPI
from tools.indexer_client import IndexerClient


class Permission(Enum):
    READ = "read"
    PROPOSE = "propose"
    EXECUTE = "execute"

    @property
    def label(self) -> str:
        return {
            Permission.READ: "READ - executes immediately",
            Permission.PROPOSE: "PROPOSE - requires human approval to execute",
            Permission.EXECUTE: "EXECUTE - requires approval + confirmation",
        }[self]


class ToolError(RuntimeError):
    """A tool failed for a surfaced reason (API down, bad input, ...)."""


class ToolParamError(ToolError):
    """Tool parameters failed validation."""


class PermissionDenied(ToolError):
    """The operation is not permitted for the current user/level."""


class ApprovalRequired(ToolError):
    """A write tool was called without an approved proposal.

    Carries the full proposal (proposed_action) so the caller can hand it to
    the Approval Center for human review.
    """

    def __init__(self, proposed_action: dict[str, Any]):
        super().__init__("This action requires human approval before it can be executed.")
        self.proposed_action = proposed_action


@dataclass
class ToolContext:
    """Everything a tool may touch, plus who/what it is acting for.

    `approval` is the approved proposal (from approvals.approve()) when a
    write tool is being executed for real; None means "planning/dry-run", in
    which case write tools raise ApprovalRequired with their proposal.
    """

    wazuh: WazuhManagerAPI
    indexer: IndexerClient
    user: str = "analyst"
    agent: str = "soc_engineer"
    approval: dict[str, Any] | None = None
    params: dict[str, Any] = field(default_factory=dict)

    # convenience accessors
    def approve_or_raise(self, proposed_action: dict[str, Any]) -> None:
        """Write-tool gate: raises ApprovalRequired unless an approved proposal
        matching this action is present.

        Only records with status 'approved' unlock a write - a forged record
        carrying 'pending'/'rejected'/'expired'/'executed'/None status is
        refused. 'executing' is also accepted: that is the claimed record
        approval_executor hands to the tool while running it (the claim is the
        single-use gate that already happened)."""
        if self.approval is None:
            raise ApprovalRequired(proposed_action)
        status = self.approval.get("status")
        if status not in ("approved", "executing"):
            raise PermissionDenied(
                f"Approval record for '{self.approval.get('action')}' is "
                f"{status or 'missing'} - only an approved proposal unlocks a write."
            )
        if self.approval.get("action") != proposed_action.get("action"):
            raise PermissionDenied(
                "Approval mismatch: proposal is for "
                f"'{self.approval.get('action')}' but the tool is executing "
                f"'{proposed_action.get('action')}'."
            )


class BaseWazuhTool(ABC):
    """Every engineer tool.

    Class attributes are the LLM-facing metadata (canonical tool shape
    `{name, description, input_schema}` the providers already speak) plus the
    permission classification the registry enforces.
    """

    name: str = ""
    description: str = ""
    input_schema: dict[str, Any] = {"type": "object", "properties": {}, "required": []}
    permission: Permission = Permission.READ
    # Tool blanking: params whose values should never be echoed to audit logs.
    secret_params: tuple[str, ...] = ()

    @abstractmethod
    def run(self, ctx: ToolContext, **params: Any) -> Any:
        """Execute the tool. Implementations must be deterministic and never
        fabricate API results: return only what the underlying API returned."""

    # ------------------------------------------------------------------ #
    def validate(self, params: dict[str, Any]) -> dict[str, Any]:
        """Validate + normalize params against input_schema. Raises
        ToolParamError. Default implementation checks required fields and
        basic JSON-schema types; tools override to tighten."""
        schema = self.input_schema
        props = schema.get("properties", {})
        for req in schema.get("required", []):
            if params.get(req) in (None, ""):
                raise ToolParamError(f"Missing required parameter: {req}")
        out: dict[str, Any] = {}
        for key, spec in props.items():
            if key not in params or params[key] in (None, ""):
                continue
            val = params[key]
            typ = spec.get("type")
            if typ == "integer":
                out[key] = int(val)
            elif typ == "number":
                out[key] = float(val)
            elif typ == "boolean":
                out[key] = str(val).strip().lower() in ("1", "true", "yes", "on")
            elif typ == "array":
                out[key] = val if isinstance(val, list) else [val]
            else:
                out[key] = val
        return out

    def redact(self, params: dict[str, Any]) -> dict[str, Any]:
        """Params with secrets masked, for audit logs."""
        out = dict(params)
        for key in self.secret_params:
            if key in out:
                out[key] = "••••••••"
        return out

    def meta(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "permission": self.permission.value,
        }
