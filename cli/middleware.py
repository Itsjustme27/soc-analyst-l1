"""
CLI-owned LLM middleware.

The CLI must not modify agent/, tools/ or dashboard code, but both agents
(ChatAgent, SOCEngineer) keep their model client in `self.llm` and call only
`self.llm.chat(system=, messages=, tools=, max_tokens=)`. AgentLLM wraps that
client, so every agentic feature below lives here, in CLI code:

  * guard wrapping - every role:"tool" message is wrapped as DATA with a
    nonce'd marker before the model sees it (the analyst agent sends raw
    json.dumps; the engineer already wraps, and wrapped content is left alone).
    The guard notice is appended to the system prompt.
  * skills catalog + load_skill - the model sees one line per installed skill
    and can pull a skill's full instructions in itself. Skills are operator-
    installed and trusted, so a loaded skill goes into the SYSTEM prompt; it is
    never returned as tool data.
  * delegate_to_agent - hand a task to another agent (analyst, engineer, or a
    skill-defined sub-agent) and get its answer back as untrusted DATA.
  * tool allowlist - a sub-agent only sees its allowed tools; a call to
    anything else is refused here before the agent can run it.
  * budget - hard cap on model calls per AgentLLM (per turn for sub-agents).
  * usage - token counts for /cost.

Virtual tools (load_skill, delegate_to_agent) are resolved inside chat(): the
middleware calls the model, handles virtual calls itself, feeds the results
back, and only returns to the agent once the model makes real tool calls or
answers. The agent never sees the virtual round-trips. A response that mixes
virtual and real calls gets the real ones bounced back ("call it again on its
own") so the agent's own tool loop always runs them - nothing is executed
here that would bypass the registry's permission/approval gate.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import guard
from cli import token_saver
from llm.base import LLMResponse

VIRTUAL_LOAD_SKILL = "load_skill"
VIRTUAL_DELEGATE = "delegate_to_agent"
VIRTUAL_FIND_TOOLS = "find_tools"
MAX_INTERNAL_ROUNDS = 6


@dataclass
class Usage:
    calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    # request-size estimates (chars): what was sent vs. what full mode would send
    sent_chars: int = 0
    full_chars: int = 0

    @property
    def saved_pct(self) -> int:
        return (
            0
            if not self.full_chars
            else max(0, round(100 - 100 * self.sent_chars / self.full_chars))
        )

    def add(self, usage: dict[str, Any] | None) -> None:
        self.calls += 1
        u = usage or {}
        self.prompt_tokens += int(u.get("prompt_tokens") or u.get("input_tokens") or 0)
        self.completion_tokens += int(u.get("completion_tokens") or u.get("output_tokens") or 0)

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


@dataclass
class MiddlewareConfig:
    """What this AgentLLM instance may do."""

    # system-prompt additions, recomputed on every model call
    extra_system: Callable[[], str] = lambda: ""
    # skills the model may load: name -> one-line description
    skill_catalog: Callable[[], dict[str, str]] = dict
    on_load_skill: Callable[[str], str] | None = None
    # sub-agents the model may delegate to: name -> description
    agents: Callable[[], dict[str, str]] = dict
    on_delegate: Callable[[str, str], Any] | None = None
    # real tools the model may call (None = everything the agent offers)
    tool_allowlist: set[str] | None = None
    max_calls: int | None = None
    wrap_tool_output: bool = True
    # emit a "tool_calls" event for real calls handed back to the agent (the
    # analyst agent has no on_step hook; the engineer's CLI already prints)
    announce_tools: bool = False
    on_event: Callable[[str, dict[str, Any]], None] = lambda kind, data: None
    usage: Usage = field(default_factory=Usage)
    # token saving (cli/token_saver.py); lean_state is shared per main agent
    lean: Callable[[], bool] = lambda: False
    lean_state: token_saver.LeanState = field(default_factory=token_saver.LeanState)
    # MCP: manager + approver(tool, args) -> bool for non-read tools (None = refuse)
    mcp: Any = None
    mcp_approver: Callable[[Any, dict[str, Any]], bool] | None = None
    audit_user: str = "cli"


def _virtual_tool_defs(cfg: MiddlewareConfig) -> list[dict[str, Any]]:
    defs = []
    if cfg.lean() or (cfg.mcp is not None and cfg.mcp.tools()):
        defs.append(
            {
                "name": VIRTUAL_FIND_TOOLS,
                "description": (
                    "Search ALL available tools (built-in Wazuh tools and connected MCP tools) "
                    "by keywords; matches become callable in your next step. Use it when the "
                    "tool you need isn't in your current list."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            }
        )
    catalog = cfg.skill_catalog() if cfg.on_load_skill else {}
    if catalog:
        defs.append(
            {
                "name": VIRTUAL_LOAD_SKILL,
                "description": (
                    "Load an installed skill pack's full instructions into your system prompt "
                    "when it's relevant to the task. Available: "
                    + "; ".join(f"{n} - {d}" for n, d in sorted(catalog.items()))
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {"name": {"type": "string", "enum": sorted(catalog)}},
                    "required": ["name"],
                },
            }
        )
    agents = cfg.agents() if cfg.on_delegate else {}
    if agents:
        defs.append(
            {
                "name": VIRTUAL_DELEGATE,
                "description": (
                    "Delegate a self-contained task to another agent and get its answer back. "
                    "Call it ON ITS OWN (not alongside other tools). Write the task so it "
                    "stands alone - the other agent does not see this conversation. Agents: "
                    + "; ".join(f"{n} - {d}" for n, d in sorted(agents.items()))
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "agent": {"type": "string", "enum": sorted(agents)},
                        "task": {"type": "string"},
                    },
                    "required": ["agent", "task"],
                },
            }
        )
    return defs


class AgentLLM:
    """Drop-in for an agent's `self.llm` (same chat() signature)."""

    def __init__(self, inner: Any, config: MiddlewareConfig):
        self.inner = inner
        self.cfg = config

    # agents occasionally call other provider helpers - pass them through
    def __getattr__(self, name: str) -> Any:
        return getattr(self.inner, name)

    def _budget_left(self) -> bool:
        return self.cfg.max_calls is None or self.cfg.usage.calls < self.cfg.max_calls

    def _prepare_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out = []
        for msg in messages:
            if (
                self.cfg.wrap_tool_output
                and msg.get("role") == "tool"
                and isinstance(msg.get("content"), str)
                and not guard.is_wrapped(msg["content"], "TOOL_OUTPUT")
            ):
                msg = {**msg, "content": guard.wrap_tool_output(msg["content"])}
            out.append(msg)
        return out

    def _system(self, system: str) -> str:
        parts = [system or ""]
        if guard.SYSTEM_GUARD_NOTICE not in (system or ""):
            parts.append(guard.SYSTEM_GUARD_NOTICE)
        extra = self.cfg.extra_system()
        if extra:
            parts.append(extra)
        return "\n\n".join(p for p in parts if p)

    def _mcp_tools(self) -> list[Any]:
        return list(self.cfg.mcp.tools()) if self.cfg.mcp is not None else []

    def _tools(self, tools: list[dict[str, Any]], user_text: str) -> list[dict[str, Any]]:
        allowed = self.cfg.tool_allowlist
        real = [
            t
            for t in tools or []
            if allowed is None or t.get("name") in allowed or t.get("name") == "answer_user"
        ]
        mcp = self._mcp_tools()
        if self.cfg.lean():
            real = self.cfg.lean_state.select(real, user_text)
            mcp_defs = [
                t.definition(token_saver.MAX_DESC)
                for t in mcp
                if t.id in self.cfg.lean_state.active
            ]
        else:
            mcp_defs = [t.definition() for t in mcp]
        return real + mcp_defs + _virtual_tool_defs(self.cfg)

    def _find_tools(self, query: str, all_tools: list[dict[str, Any]]) -> dict[str, Any]:
        builtin = self.cfg.lean_state.search(all_tools, query)
        mcp = self.cfg.mcp.search(query) if self.cfg.mcp is not None else []
        found = [
            {
                "name": t["name"],
                "description": token_saver._first_sentence(t.get("description", ""), 160),
            }
            for t in builtin
        ]
        found += [{"name": t.id, "description": t.definition(160)["description"]} for t in mcp]
        for f in found:
            self.cfg.lean_state.active.add(f["name"])
        self.cfg.on_event("find_tools", {"query": query, "found": [f["name"] for f in found]})
        return {
            "matches": found,
            "note": "These tools are now available in your next step."
            if found
            else "No matching tools.",
        }

    def _call_mcp(self, tc: Any) -> Any:
        tool = self.cfg.mcp.get_tool(tc.name) if self.cfg.mcp is not None else None
        args = tc.input if isinstance(tc.input, dict) else {}
        if tool is None:
            return {"error": f"MCP tool '{tc.name}' is not connected."}
        import audit

        if not tool.read_only:
            approved = bool(self.cfg.mcp_approver and self.cfg.mcp_approver(tool, args))
            if not approved:
                audit.audit_log(
                    tool=tc.name,
                    action="mcp_call",
                    permission="approval_required",
                    approval_status="denied",
                    execution_status="rejected",
                    params=args,
                    user=self.cfg.audit_user,
                    agent="soc_cli_mcp",
                )
                self.cfg.on_event("mcp_denied", {"name": tc.name})
                return {
                    "error": f"The operator did not approve '{tc.name}'. Do not retry it; "
                    "explain what you wanted to do instead."
                }
        self.cfg.on_event("mcp_call", {"name": tc.name, "input": args, "read_only": tool.read_only})
        self.cfg.lean_state.active.add(tc.name)
        try:
            result = self.cfg.mcp.call(tc.name, args)
            status = "failed" if result.get("is_error") else "success"
        except Exception as e:  # noqa: BLE001 - surface to the model, don't crash
            result, status = {"error": str(e)}, "failed"
        audit.audit_log(
            tool=tc.name,
            action="mcp_call",
            permission="read" if tool.read_only else "approved_inline",
            approval_status="n/a" if tool.read_only else "approved",
            execution_status=status,
            params=args,
            result=result,
            user=self.cfg.audit_user,
            agent="soc_cli_mcp",
        )
        return result

    def _handle_virtual(self, tc: Any, all_tools: list[dict[str, Any]]) -> Any:
        args = tc.input if isinstance(tc.input, dict) else {}
        if tc.name == VIRTUAL_LOAD_SKILL and self.cfg.on_load_skill:
            name = str(args.get("name", ""))
            self.cfg.on_event("load_skill", {"name": name})
            return {"status": "loaded", "note": self.cfg.on_load_skill(name)}
        if tc.name == VIRTUAL_DELEGATE and self.cfg.on_delegate:
            agent, task = str(args.get("agent", "")), str(args.get("task", ""))
            self.cfg.on_event("delegate", {"agent": agent, "task": task})
            return self.cfg.on_delegate(agent, task)
        if tc.name == VIRTUAL_FIND_TOOLS:
            return self._find_tools(str(args.get("query", "")), all_tools)
        return {"error": f"'{tc.name}' is not available here."}

    def chat(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
        **kw: Any,
    ) -> LLMResponse:
        msgs = self._prepare_messages(list(messages))
        if self.cfg.lean():
            msgs = token_saver.compact_old_tool_output(msgs)
        user_text = token_saver.latest_user_text(msgs)
        allowed = self.cfg.tool_allowlist
        all_real = [
            t
            for t in tools or []
            if allowed is None or t.get("name") in allowed or t.get("name") == "answer_user"
        ]
        for _ in range(MAX_INTERNAL_ROUNDS):
            if not self._budget_left():
                self.cfg.on_event("budget", {"max_calls": self.cfg.max_calls})
                return LLMResponse(
                    content="(Stopped: this agent's model-call budget is used up. "
                    "Report what you have so far.)"
                )
            tool_defs = self._tools(tools, user_text)  # recomputed: find_tools can add
            virtual = {d["name"] for d in _virtual_tool_defs(self.cfg)}
            mcp_names = {t.id for t in self._mcp_tools()}
            sys_text = self._system(system)
            self.cfg.usage.sent_chars += token_saver.estimate_chars(sys_text, msgs, tool_defs)
            self.cfg.usage.full_chars += token_saver.estimate_chars(
                sys_text,
                list(messages),
                list(tools or []) + [t.definition() for t in self._mcp_tools()],
            )
            resp = self.inner.chat(
                system=sys_text, messages=msgs, tools=tool_defs, max_tokens=max_tokens, **kw
            )
            self.cfg.usage.add(getattr(resp, "usage", None))
            calls = list(resp.tool_calls or [])
            intercepted = [
                tc
                for tc in calls
                if tc.name in virtual
                or tc.name in mcp_names
                or (allowed is not None and tc.name not in allowed and tc.name != "answer_user")
            ]
            if not intercepted:
                for tc in calls:
                    self.cfg.lean_state.active.add(tc.name)  # keep used tools in the lean set
                if calls and self.cfg.announce_tools:
                    self.cfg.on_event(
                        "tool_calls",
                        {"calls": [{"name": tc.name, "input": tc.input} for tc in calls]},
                    )
                return resp
            # Handle this round here; the agent never sees it.
            msgs.append(
                {
                    "role": "assistant",
                    "content": resp.content or "",
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "input": tc.input} for tc in calls
                    ],
                }
            )
            for tc in calls:
                if tc.name in virtual:
                    result = self._handle_virtual(tc, all_real)
                elif tc.name in mcp_names:
                    result = self._call_mcp(tc)
                elif allowed is not None and tc.name not in allowed and tc.name != "answer_user":
                    self.cfg.on_event("denied_tool", {"name": tc.name})
                    result = {"error": f"Tool '{tc.name}' is not permitted for this agent."}
                else:
                    result = {
                        "error": f"'{tc.name}' was not run: call it again on its own, "
                        "without find_tools/load_skill/delegate_to_agent/MCP tools in the same step."
                    }
                msgs.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": guard.wrap_tool_output(json.dumps(result, default=str)),
                    }
                )
        return LLMResponse(content="(Stopped: too many consecutive internal tool steps.)")
