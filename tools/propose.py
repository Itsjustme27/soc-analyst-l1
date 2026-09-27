"""
propose_action - generic proposal tool.

Some actions a SOC engineer may recommend have no automated executor in the
tool layer (e.g. 'block this IP via active response', 'rotate that credential',
'contact the asset owner'). This tool lets the agent formalize such a
recommendation through the same Approval Center as everything else. Once
approved, execution is *manual*: the proposal records the recommended steps and
the UI marks it as a manual action - the agent never claims it executed.
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext


class ProposeAction(BaseWazuhTool):
    name = "propose_action"
    description = (
        "Formalize a recommended action for human approval even when no tool can "
        "execute it automatically (e.g. 'block this IP via active response', "
        "'quarantine host', 'rotate credential'). The approved proposal is a "
        "manual action the team must carry out - this tool never executes it."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "action": {
                "type": "string",
                "description": "short imperative, e.g. 'block_ip 203.0.113.7'",
            },
            "reason": {"type": "string", "description": "why - evidence-based justification"},
            "steps": {"type": "array", "description": "recommended manual steps for the team"},
            "severity": {"type": "string", "description": "low | medium | high | critical"},
        },
        "required": ["action", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        proposed = {
            "action": str(p["action"]),
            "reason": str(p["reason"]),
            "payload": {"steps": p.get("steps") or [], "severity": p.get("severity", "medium")},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = {
            "steps": p.get("steps") or [],
            "severity": p.get("severity", "medium"),
        }
        proposed["validation"] = {
            "valid": True,
            "note": "Manual action proposal - execution is carried out by the team, not automated.",
        }
        ctx.approve_or_raise(proposed)
        return {
            "status": "manual_action_registered",
            "action": p["action"],
            "note": "Approved. This is a manual action for the team - no automated executor exists.",
        }
