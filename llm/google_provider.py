"""Google Gemini provider (REST API - no extra SDK dependency)."""

from __future__ import annotations

import json
from typing import Any

import requests

from config import cfg
from llm.base import LLMProvider, LLMResponse, ToolCall

# Separator used to make Gemini function-call ids round-trippable without
# provider state: "get_host_info::call_0" -> name is "get_host_info".
_ID_SEP = "::"


def to_google_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Canonical tool shape -> Gemini function declarations."""
    return [
        {
            "functionDeclarations": [
                {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
                }
                for t in tools
            ]
        }
    ]


def to_google_contents(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalized -> Gemini `contents`.

    Gemini wants every `functionResponse` as a `user` part immediately after
    the model's `functionCall` turn, so consecutive tool results are collapsed
    into a single user message. Function calls are matched back by name
    (encoded in the normalized tool_call_id).
    """
    out: list[dict[str, Any]] = []
    pending_responses: list[dict[str, Any]] = []

    def flush():
        if pending_responses:
            out.append({"role": "user", "parts": list(pending_responses)})
            pending_responses.clear()

    for m in messages:
        role = m["role"]
        if role == "user":
            flush()
            out.append({"role": "user", "parts": [{"text": m["content"]}]})
        elif role == "assistant":
            flush()
            parts: list[dict[str, Any]] = []
            if m.get("content"):
                parts.append({"text": m["content"]})
            for tc in m.get("tool_calls") or []:
                parts.append({"functionCall": {"name": tc["name"], "args": tc["input"]}})
            out.append({"role": "model", "parts": parts})
        elif role == "tool":
            call_id = str(m["tool_call_id"])
            name = call_id.rsplit(_ID_SEP, 1)[0] if _ID_SEP in call_id else call_id
            try:
                parsed: Any = json.loads(m["content"])
            except json.JSONDecodeError:
                parsed = {"content": m["content"]}
            pending_responses.append({"functionResponse": {"name": name, "response": parsed}})
        else:
            raise ValueError(f"unknown normalized message role: {role}")
    flush()
    return out


class GoogleProvider(LLMProvider):
    name = "google"

    def __init__(self):
        if not cfg.GOOGLE_API_KEY:
            raise ValueError(
                "GOOGLE_API_KEY is not set. Add it to .env, or set LLM_PROVIDER "
                "to another backend (see .env.example)."
            )
        self._api_key = cfg.GOOGLE_API_KEY

    def _model(self) -> str:
        return cfg.GOOGLE_MODEL or cfg.AGENT_MODEL

    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self._model()}:generateContent"
        payload: dict[str, Any] = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": to_google_contents(messages),
        }
        if tools:
            payload["tools"] = to_google_tools(tools)

        resp = requests.post(url, params={"key": self._api_key}, json=payload, timeout=120)
        resp.raise_for_status()
        data = resp.json()

        candidates = data.get("candidates") or [{}]
        parts = (candidates[0].get("content") or {}).get("parts") or []

        text = "".join(p.get("text", "") for p in parts if "text" in p)
        calls = []
        for i, p in enumerate(parts):
            fc = p.get("functionCall")
            if fc:
                args = fc.get("args") or {}
                if not isinstance(args, dict):
                    args = {}
                calls.append(
                    ToolCall(
                        id=f"{fc['name']}{_ID_SEP}call_{i}",
                        name=fc["name"],
                        input=args,
                    )
                )
        return LLMResponse(content=text, tool_calls=calls)
