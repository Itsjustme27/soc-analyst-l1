"""
Wazuh manager rules tools (Wazuh 4.14: rules are managed as files).

Read tools (get_wazuh_rules / get_wazuh_rule) are READ - they execute
immediately. Write tools (create/update/delete) never run on the agent's say
so: they fetch the current `local_rules.xml`, merge the change, produce a
unified diff for the approver, validate the result, and raise
ApprovalRequired unless the ToolContext carries an approved proposal for that
exact action. Execution writes the whole file back via PUT /rules/files.

Note: after a rule change the manager must restart for the ruleset to reload -
the proposal lists that as a follow-up EXECUTE (its own approval).
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.wazuh.local_rules import (
    LOCAL_RULES_FILE,
    merge_rule,
    remove_rule,
    replace_rule,
    unified_diff,
)
from tools.wazuh.validation import rule_id_from_xml, validate_wazuh_rule_xml


def _rule_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": item.get("id"),
        "level": item.get("level"),
        "description": item.get("description"),
        "groups": item.get("groups") or [],
        "mitre": item.get("mitre") or [],
        "filename": item.get("filename"),
        "status": item.get("status"),
        "details": item.get("details") or {},
    }


def _fetch_local_rules(ctx: ToolContext) -> str:
    try:
        return ctx.wazuh.get_rules_file(LOCAL_RULES_FILE, raw=True)
    except Exception as e:  # noqa: BLE001 - missing file = empty rules file
        if "not found" in str(e).lower():
            return ""
        raise ToolError(f"Failed to read {LOCAL_RULES_FILE}: {e}") from e


class GetWazuhRules(BaseWazuhTool):
    name = "get_wazuh_rules"
    description = (
        "List Wazuh detection rules from the manager (with optional group/level/search "
        "filters). Use to see existing detections before creating or gap-analyzing."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "search": {"type": "string", "description": "text search across rule fields"},
            "group": {"type": "string", "description": "group filter, e.g. 'web'"},
            "level": {"type": "integer", "description": "exact rule level filter 0-15"},
            "filename": {"type": "string", "description": "filter by ruleset filename"},
            "status": {"type": "string", "description": "enabled/disabled"},
            "limit": {"type": "integer", "description": "max rules (capped)"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        limit = min(int(p.get("limit", 50) or 50), 500)
        try:
            resp = ctx.wazuh.get_rules(
                limit=limit,
                search=p.get("search"),
                group=p.get("group"),
                level=p.get("level"),
                filename=p.get("filename"),
                status=p.get("status"),
            )
        except ToolError:
            raise
        except Exception as e:  # noqa: BLE001 - surface manager errors cleanly
            raise ToolError(f"Failed to fetch rules: {e}") from e
        data = resp.get("data", {})
        rules = [_rule_summary(r) for r in data.get("affected_items", [])]
        return {
            "count": len(rules),
            "total": data.get("total_affected_items", len(rules)),
            "rules": rules,
        }


class GetWazuhRule(BaseWazuhTool):
    name = "get_wazuh_rule"
    description = (
        "Get one Wazuh rule by id, including its XML definition when it lives in "
        "local_rules.xml - use before proposing a modification or to explain a detection."
    )
    input_schema = {
        "type": "object",
        "properties": {"rule_id": {"type": "integer"}},
        "required": ["rule_id"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        try:
            resp = ctx.wazuh.get_rule(p["rule_id"])
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to fetch rule {p['rule_id']}: {e}") from e
        data = resp.get("data", {})
        items = data.get("affected_items", [])
        if not items:
            raise ToolError(f"Rule {p['rule_id']} not found.")
        item = items[0]
        try:
            from tools.wazuh.local_rules import extract_rule_text

            xml = extract_rule_text(_fetch_local_rules(ctx), p["rule_id"]) or ""
        except Exception:  # noqa: BLE001
            xml = ""
        return {"rule": _rule_summary(item), "xml": xml}


class CreateWazuhRule(BaseWazuhTool):
    name = "create_wazuh_rule"
    description = (
        "Create a new Wazuh rule in local_rules.xml from its XML definition. Validates "
        "the XML, merges it into the rules file, and shows the exact diff. WRITE: requires "
        "human approval; after execution the manager must be restarted (separate approval) "
        "for the rule to load."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "rule_xml": {"type": "string", "description": "full <rule>...</rule> XML"},
            "overwrite": {
                "type": "boolean",
                "description": "replace an existing rule with the same id (default false)",
            },
            "reason": {
                "type": "string",
                "description": "why this rule is needed (shown to the approver)",
            },
        },
        "required": ["rule_xml", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        xml = str(p["rule_xml"]).strip()
        validation = validate_wazuh_rule_xml(xml)
        if not validation["valid"]:
            raise ToolError(
                "Rule failed static validation:\n- " + "\n- ".join(validation["errors"])
            )
        rule_id = rule_id_from_xml(xml)

        current = _fetch_local_rules(ctx)
        new_content, issues = merge_rule(current, xml, overwrite=bool(p.get("overwrite")))
        if issues and new_content == current:
            raise ToolError("; ".join(issues))
        diff = unified_diff(current, new_content)
        if not diff:
            raise ToolError("No change produced - the rule is already present identically.")

        proposed = {
            "action": "create_wazuh_rule",
            "reason": p.get("reason", ""),
            "payload": {
                "rule_xml": xml,
                "overwrite": bool(p.get("overwrite")),
                "reason": p.get("reason", ""),
            },
            "permission": self.permission.value,
        }
        proposed["generated_config"] = new_content
        proposed["validation"] = {
            "valid": True,
            **validation,
            "issues": issues,
            "diff": diff,
            "next_steps": [
                "restart_wazuh_manager (EXECUTE, own approval) to load the rule",
                "run_wazuh_logtest (READ) to verify the new rule fires",
            ],
        }
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.put_rules_file(LOCAL_RULES_FILE, new_content)
        data = resp.get("data", {})
        return {
            "status": "executed",
            "rule_id": rule_id,
            "file": (data.get("affected_items") or [LOCAL_RULES_FILE])[0],
            "restart_required": True,
            "detail": resp.get("message"),
        }


class UpdateWazuhRule(BaseWazuhTool):
    name = "update_wazuh_rule"
    description = (
        "Modify an existing rule in local_rules.xml: pass the rule id and the full "
        "updated <rule> XML. WRITE: validates, diffs, and requires human approval. "
        "Manager restart needed after execution (own approval)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "rule_id": {"type": "integer"},
            "rule_xml": {"type": "string", "description": "full updated <rule>...</rule> XML"},
            "reason": {
                "type": "string",
                "description": "what changed and why (shown to the approver)",
            },
        },
        "required": ["rule_id", "rule_xml", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        xml = str(p["rule_xml"]).strip()
        validation = validate_wazuh_rule_xml(xml)
        if not validation["valid"]:
            raise ToolError(
                "Rule failed static validation:\n- " + "\n- ".join(validation["errors"])
            )
        current = _fetch_local_rules(ctx)
        new_content, found, _issues = replace_rule(current, p["rule_id"], xml)
        if not found:
            raise ToolError(
                f"Rule {p['rule_id']} is not in {LOCAL_RULES_FILE} - cannot update it "
                "there. Create it or edit the file that owns it."
            )
        diff = unified_diff(current, new_content)
        proposed = {
            "action": "update_wazuh_rule",
            "reason": p.get("reason", ""),
            "payload": {"rule_id": p["rule_id"], "rule_xml": xml, "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = new_content
        proposed["validation"] = {
            "valid": True,
            "diff": diff,
            "next_steps": ["restart_wazuh_manager (own approval)", "run_wazuh_logtest to verify"],
        }
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.put_rules_file(LOCAL_RULES_FILE, new_content)
        return {
            "status": "executed",
            "rule_id": p["rule_id"],
            "restart_required": True,
            "detail": resp.get("message"),
        }


class DeleteWazuhRule(BaseWazuhTool):
    name = "delete_wazuh_rule"
    description = (
        "Remove a rule from local_rules.xml by id. HIGH RISK (EXECUTE): requires "
        "approval AND explicit confirmation. Shows the diff of what will be removed. "
        "Manager restart needed to apply (own approval)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "rule_id": {"type": "integer"},
            "reason": {"type": "string"},
        },
        "required": ["rule_id", "reason"],
    }
    permission = Permission.EXECUTE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        current = _fetch_local_rules(ctx)
        new_content, found = remove_rule(current, p["rule_id"])
        if not found:
            raise ToolError(
                f"Rule {p['rule_id']} is not in {LOCAL_RULES_FILE} (or the file does "
                "not exist) - nothing to delete."
            )
        diff = unified_diff(current, new_content)
        proposed = {
            "action": "delete_wazuh_rule",
            "reason": p.get("reason", ""),
            "payload": {"rule_id": p["rule_id"], "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["validation"] = {
            "valid": True,
            "diff": diff,
            "note": "Deletion requires approval + confirmation.",
            "next_steps": ["restart_wazuh_manager (own approval)"],
        }
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.put_rules_file(LOCAL_RULES_FILE, new_content)
        return {
            "status": "executed",
            "rule_id": p["rule_id"],
            "restart_required": True,
            "detail": resp.get("message"),
        }
