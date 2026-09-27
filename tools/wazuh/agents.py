"""
Wazuh agents + manager/cluster status tools.
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError


def _agent_summary(item: dict[str, Any]) -> dict[str, Any]:
    os_ = item.get("os") or {}
    return {
        "id": item.get("id"),
        "name": item.get("name"),
        "ip": item.get("ip"),
        "status": item.get("status"),
        "os": os_.get("name"),
        "os_platform": os_.get("platform"),
        "version": item.get("version"),
        "group": item.get("group"),
        "last_keepalive": item.get("lastKeepAlive"),
    }


class GetWazuhAgents(BaseWazuhTool):
    name = "get_wazuh_agents"
    description = "List Wazuh agents (manager API) with optional status/group/platform filters."
    input_schema = {
        "type": "object",
        "properties": {
            "status": {
                "type": "string",
                "description": "active | disconnected | never_connected | pending",
            },
            "group": {"type": "string"},
            "platform": {"type": "string"},
            "search": {"type": "string"},
            "limit": {"type": "integer"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        limit = min(int(p.get("limit", 50) or 50), 500)
        try:
            resp = ctx.wazuh.get_agents(
                limit=limit,
                status=p.get("status"),
                group=p.get("group"),
                platform=p.get("platform"),
                search=p.get("search"),
            )
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to fetch agents: {e}") from e
        data = resp.get("data", {})
        agents = [_agent_summary(a) for a in data.get("affected_items", [])]
        return {
            "count": len(agents),
            "total": data.get("total_affected_items", len(agents)),
            "agents": agents,
        }


class GetWazuhAgent(BaseWazuhTool):
    name = "get_wazuh_agent"
    description = "Get one Wazuh agent's details by id (e.g. '000')."
    input_schema = {
        "type": "object",
        "properties": {"agent_id": {"type": "string"}},
        "required": ["agent_id"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        try:
            resp = ctx.wazuh.get_agent(p["agent_id"])
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to fetch agent {p['agent_id']}: {e}") from e
        data = resp.get("data", {})
        items = data.get("affected_items", [])
        if not items:
            raise ToolError(f"Agent {p['agent_id']} not found.")
        return {"agent": _agent_summary(items[0])}


class GetWazuhManagerStatus(BaseWazuhTool):
    name = "get_wazuh_manager_status"
    description = "Wazuh manager daemon status (which services are running/stopped)."
    input_schema = {"type": "object", "properties": {}}
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        try:
            resp = ctx.wazuh.get_manager_status()
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to fetch manager status: {e}") from e
        data = resp.get("data", {})
        items = data.get("affected_items", [])
        status = items[0] if items else {}
        running = [k for k, v in status.items() if v == "running"]
        stopped = [k for k, v in status.items() if v == "stopped"]
        return {
            "manager": ctx.wazuh.base_url,
            "daemons": status,
            "running": running,
            "stopped": stopped,
        }


class GetWazuhClusterStatus(BaseWazuhTool):
    name = "get_wazuh_cluster_status"
    description = "Wazuh cluster status (enabled + running, node info)."
    input_schema = {"type": "object", "properties": {}}
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        try:
            resp = ctx.wazuh.get_cluster_status()
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to fetch cluster status: {e}") from e
        data = resp.get("data", {})
        return {"enabled": data.get("enabled"), "running": data.get("running")}


class RestartWazuhManager(BaseWazuhTool):
    name = "restart_wazuh_manager"
    description = (
        "Restart the Wazuh manager. HIGH RISK (EXECUTE): requires approval AND "
        "explicit confirmation. Brief manager outage while it restarts."
    )
    input_schema = {
        "type": "object",
        "properties": {"reason": {"type": "string"}},
        "required": ["reason"],
    }
    permission = Permission.EXECUTE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        proposed = {
            "action": "restart_wazuh_manager",
            "reason": p.get("reason", ""),
            "payload": {"reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["validation"] = {"valid": True, "note": "Manager restart - expects brief outage."}
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.restart_manager()
        return {"status": "executed", "detail": resp.get("message")}


class DisableWazuhAgent(BaseWazuhTool):
    name = "disable_wazuh_agent"
    description = (
        "Remove an agent from the Wazuh manager (the only API-supported 'disable'). "
        "HIGH RISK (EXECUTE): requires approval AND explicit confirmation."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "agent_id": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["agent_id", "reason"],
    }
    permission = Permission.EXECUTE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        proposed = {
            "action": "disable_wazuh_agent",
            "reason": p.get("reason", ""),
            "payload": {"agent_id": p["agent_id"], "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["validation"] = {"valid": True, "note": "Agent removal from the manager."}
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.request(
            "DELETE", "/agents", params={"agents_list": p["agent_id"], "purge": False}
        )
        return {"status": "executed", "agent_id": p["agent_id"], "detail": resp.get("message")}
