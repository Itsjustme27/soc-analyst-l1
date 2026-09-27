"""
Wazuh manager configuration tools (read-only).
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError


class GetWazuhConfiguration(BaseWazuhTool):
    name = "get_wazuh_configuration"
    description = (
        "Read the Wazuh manager's effective configuration for a section "
        "(e.g. global, ruleset, syscheck, wodle). Useful before proposing config changes "
        "or explaining why an agent/report behaves as it does."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "section": {
                "type": "string",
                "description": "config section, e.g. global, ruleset, syscheck",
            },
            "field": {"type": "string", "description": "narrow to one field of the section"},
        },
        "required": ["section"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        try:
            resp = ctx.wazuh.get_manager_configuration(section=p["section"], field=p.get("field"))
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to read configuration '{p['section']}': {e}") from e
        data = resp.get("data", {})
        items = data.get("affected_items", [])
        config = items[0] if items else {}
        return {"section": p["section"], "config": config}
