"""
Token saving for the CLI's LLM calls (applied by cli/middleware.py).

Where the tokens go, measured on this codebase: the engineer sends ~41 tool
schemas (~23k chars, ~5.8k tokens) on EVERY model call, and one turn is
several calls. Long sessions also re-send every old tool result each call.

"lean" mode (the CLI default) cuts that without dropping capability:
  1. Tool subset - send a small core set + tools relevant to the latest user
     message + tools already used/discovered this session. Everything else
     stays reachable through the `find_tools` virtual tool, which returns
     matching names and activates their schemas for the next call.
  2. Shorter descriptions - tool descriptions trimmed to their first
     sentence (cap), property descriptions capped. Parameter names/types/
     required lists are never touched, so calls stay valid.
  3. Old tool output compaction - tool results from BEFORE the latest user
     message are cut to a short preview; the current turn's results are
     sent in full.

"full" mode sends everything unmodified. Estimates use ~4 chars/token.
"""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any

CORE_TOOLS = {
    "answer_user",
    "retrieve_wazuh_docs",
    "search_wazuh_alerts",
    "get_alerts",
    "get_alert_status",
}
MAX_DESC = 200
MAX_PROP_DESC = 90
OLD_TOOL_OUTPUT_CHARS = 500
MAX_RELEVANT = 10

_GENERIC = {
    "wazuh",
    "get",
    "set",
    "the",
    "and",
    "for",
    "with",
    "run",
    "end",
    "new",
    "all",
    "from",
    "this",
    "that",
    "what",
    "show",
    "list",
    "check",
    "please",
    "can",
    "you",
}
_WORD = re.compile(r"[a-z0-9]+")


def _stem(w: str) -> str:
    for suf in ("ing", "ies", "es", "s"):
        if w.endswith(suf) and len(w) - len(suf) >= 3:
            return w[: -len(suf)] + ("y" if suf == "ies" else "")
    return w


def _terms(text: str) -> set[str]:
    return {
        _stem(w) for w in _WORD.findall((text or "").lower()) if len(w) > 2 and w not in _GENERIC
    }


def _first_sentence(text: str, cap: int) -> str:
    text = (text or "").strip()
    m = re.search(r"(?<=[.!?])\s", text)
    s = text[: m.start()] if m and m.start() < cap else text
    return s if len(s) <= cap else s[: cap - 1] + "…"


def trim_tool(tool: dict[str, Any]) -> dict[str, Any]:
    t = copy.deepcopy(tool)
    t["description"] = _first_sentence(t.get("description", ""), MAX_DESC)
    props = (t.get("input_schema") or {}).get("properties") or {}
    for spec in props.values():
        if (
            isinstance(spec, dict)
            and isinstance(spec.get("description"), str)
            and len(spec["description"]) > MAX_PROP_DESC
        ):
            spec["description"] = spec["description"][: MAX_PROP_DESC - 1] + "…"
    return t


def relevance(tool: dict[str, Any], terms: set[str]) -> int:
    name_terms = _terms(tool.get("name", "").replace("_", " "))
    desc_terms = _terms(_first_sentence(tool.get("description", ""), 300))
    return 3 * len(name_terms & terms) + len(desc_terms & terms)


@dataclass
class LeanState:
    """Per-agent session memory of which tools the model has needed."""

    active: set[str] = field(default_factory=set)

    def select(
        self, tools: list[dict[str, Any]], latest_user_text: str, core: set[str] = CORE_TOOLS
    ) -> list[dict[str, Any]]:
        terms = _terms(latest_user_text)
        scored = sorted(((relevance(t, terms), t) for t in tools), key=lambda x: -x[0])
        relevant = {t["name"] for s, t in scored[:MAX_RELEVANT] if s > 0}
        keep = core | self.active | relevant
        return [trim_tool(t) for t in tools if t.get("name") in keep]

    def search(
        self, tools: list[dict[str, Any]], query: str, limit: int = 8
    ) -> list[dict[str, Any]]:
        terms = _terms(query)
        scored = sorted(((relevance(t, terms), t) for t in tools), key=lambda x: -x[0])
        return [t for s, t in scored[:limit] if s > 0]


def latest_user_text(messages: list[dict[str, Any]]) -> str:
    for m in reversed(messages):
        if m.get("role") == "user" and isinstance(m.get("content"), str):
            return m["content"]
    return ""


def compact_old_tool_output(
    messages: list[dict[str, Any]], limit: int = OLD_TOOL_OUTPUT_CHARS
) -> list[dict[str, Any]]:
    """Shorten tool results that came before the latest user message."""
    last_user = max((i for i, m in enumerate(messages) if m.get("role") == "user"), default=-1)
    out = []
    for i, m in enumerate(messages):
        c = m.get("content")
        if i < last_user and m.get("role") == "tool" and isinstance(c, str) and len(c) > limit:
            m = {
                **m,
                "content": c[:limit] + f"\n…[earlier tool output trimmed from {len(c)} chars]",
            }
        out.append(m)
    return out


def estimate_chars(system: str, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> int:
    return (
        len(system or "")
        + len(json.dumps(messages, default=str))
        + len(json.dumps(tools, default=str))
    )
