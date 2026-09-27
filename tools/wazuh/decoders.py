"""
Wazuh decoder tools.

Read tools (get_wazuh_decoders) are READ. Write tools manage decoders through
the file API (PUT /decoders/files/local_decoder.xml on 4.14): merge + diff +
approval-gated execution, mirroring the rules flow.
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.wazuh.local_rules import (
    LOCAL_DECODER_FILE,
    merge_decoder,
    remove_decoder,
    replace_decoder,
    unified_diff,
)
from tools.wazuh.validation import decoder_name_from_xml, validate_wazuh_decoder_xml


def _decoder_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": item.get("name"),
        "filename": item.get("filename"),
        "status": item.get("status"),
        "position": item.get("position"),
        "details": item.get("details") or {},
    }


def _fetch_local_decoders(ctx: ToolContext) -> str:
    try:
        return ctx.wazuh.get_decoders_file(LOCAL_DECODER_FILE, raw=True)
    except Exception as e:  # noqa: BLE001
        if "not found" in str(e).lower():
            return ""
        raise ToolError(f"Failed to read {LOCAL_DECODER_FILE}: {e}") from e


class GetWazuhDecoders(BaseWazuhTool):
    name = "get_wazuh_decoders"
    description = (
        "List Wazuh decoders from the manager (optional search/filename filters). "
        "Use before creating a rule to see which decoder already parses the log source."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "search": {"type": "string"},
            "filename": {"type": "string"},
            "limit": {"type": "integer"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        limit = min(int(p.get("limit", 50) or 50), 500)
        try:
            resp = ctx.wazuh.get_decoders(
                limit=limit, search=p.get("search"), filename=p.get("filename")
            )
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to fetch decoders: {e}") from e
        data = resp.get("data", {})
        decoders = [_decoder_summary(d) for d in data.get("affected_items", [])]
        return {
            "count": len(decoders),
            "total": data.get("total_affected_items", len(decoders)),
            "decoders": decoders,
        }


class CreateWazuhDecoder(BaseWazuhTool):
    name = "create_wazuh_decoder"
    description = (
        "Create a new Wazuh decoder in local_decoder.xml from its XML definition. "
        "Validates, merges, and diffs. WRITE: requires human approval. Manager restart "
        "needed after execution (own approval)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "decoder_xml": {"type": "string", "description": "full <decoder>...</decoder> XML"},
            "overwrite": {"type": "boolean", "description": "replace a decoder with the same name"},
            "reason": {"type": "string"},
        },
        "required": ["decoder_xml", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        xml = str(p["decoder_xml"]).strip()
        validation = validate_wazuh_decoder_xml(xml)
        if not validation["valid"]:
            raise ToolError(
                "Decoder failed static validation:\n- " + "\n- ".join(validation["errors"])
            )
        name = decoder_name_from_xml(xml)

        current = _fetch_local_decoders(ctx)
        if not p.get("overwrite"):
            if name and f'<decoder name="{name}"' in current:
                raise ToolError(
                    f"Decoder '{name}' already exists - set overwrite=true after review."
                )
        new_content, issues = merge_decoder(current, xml)
        if issues and new_content == current:
            raise ToolError("; ".join(issues))
        diff = unified_diff(current, new_content, filename=LOCAL_DECODER_FILE)
        if not diff:
            raise ToolError("No change produced.")

        proposed = {
            "action": "create_wazuh_decoder",
            "reason": p.get("reason", ""),
            "payload": {
                "decoder_xml": xml,
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
                "restart_wazuh_manager (own approval)",
                "run_wazuh_logtest to validate decode",
            ],
        }
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.put_decoders_file(LOCAL_DECODER_FILE, new_content)
        return {
            "status": "executed",
            "decoder": name,
            "restart_required": True,
            "detail": resp.get("message"),
        }


class ModifyWazuhDecoder(BaseWazuhTool):
    name = "modify_wazuh_decoder"
    description = (
        "Modify an existing decoder in local_decoder.xml. WRITE: validates, diffs, "
        "and requires human approval."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "decoder_name": {"type": "string"},
            "decoder_xml": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["decoder_name", "decoder_xml", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        xml = str(p["decoder_xml"]).strip()
        validation = validate_wazuh_decoder_xml(xml)
        if not validation["valid"]:
            raise ToolError(
                "Decoder failed static validation:\n- " + "\n- ".join(validation["errors"])
            )
        current = _fetch_local_decoders(ctx)
        new_content, found, _issues = replace_decoder(current, p["decoder_name"], xml)
        if not found:
            raise ToolError(f"Decoder '{p['decoder_name']}' is not in {LOCAL_DECODER_FILE}.")
        diff = unified_diff(current, new_content, filename=LOCAL_DECODER_FILE)
        proposed = {
            "action": "modify_wazuh_decoder",
            "reason": p.get("reason", ""),
            "payload": {
                "decoder_name": p["decoder_name"],
                "decoder_xml": xml,
                "reason": p.get("reason", ""),
            },
            "permission": self.permission.value,
        }
        proposed["generated_config"] = new_content
        proposed["validation"] = {
            "valid": True,
            "diff": diff,
            "next_steps": ["restart_wazuh_manager (own approval)"],
        }
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.put_decoders_file(LOCAL_DECODER_FILE, new_content)
        return {
            "status": "executed",
            "decoder": p["decoder_name"],
            "restart_required": True,
            "detail": resp.get("message"),
        }


class DeleteWazuhDecoder(BaseWazuhTool):
    name = "delete_wazuh_decoder"
    description = (
        "Remove a decoder from local_decoder.xml by name. HIGH RISK (EXECUTE): requires "
        "approval AND explicit confirmation."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "decoder_name": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["decoder_name", "reason"],
    }
    permission = Permission.EXECUTE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        current = _fetch_local_decoders(ctx)
        new_content, found = remove_decoder(current, p["decoder_name"])
        if not found:
            raise ToolError(f"Decoder '{p['decoder_name']}' is not in {LOCAL_DECODER_FILE}.")
        diff = unified_diff(current, new_content, filename=LOCAL_DECODER_FILE)
        proposed = {
            "action": "delete_wazuh_decoder",
            "reason": p.get("reason", ""),
            "payload": {"decoder_name": p["decoder_name"], "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["validation"] = {
            "valid": True,
            "diff": diff,
            "note": "Deletion requires approval + confirmation.",
            "next_steps": ["restart_wazuh_manager (own approval)"],
        }
        ctx.approve_or_raise(proposed)
        resp = ctx.wazuh.put_decoders_file(LOCAL_DECODER_FILE, new_content)
        return {
            "status": "executed",
            "decoder": p["decoder_name"],
            "restart_required": True,
            "detail": resp.get("message"),
        }
