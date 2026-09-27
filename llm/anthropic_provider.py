"""Anthropic Claude provider (the original default)."""

from __future__ import annotations

from typing import Any

import anthropic

from config import cfg
from llm.base import LLMProvider, LLMResponse, ToolCall


class AnthropicProvider(LLMProvider):
    name = "anthropic"

    def __init__(self):
        if not cfg.ANTHROPIC_API_KEY:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. Add it to .env, or set "
                "LLM_PROVIDER to another backend (see .env.example)."
            )
        self._client = anthropic.Anthropic(api_key=cfg.ANTHROPIC_API_KEY)

    # ------------------------------------------------------------------ #
    def _model(self) -> str:
        return cfg.ANTHROPIC_MODEL or cfg.AGENT_MODEL

    def to_anthropic_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Normalized -> Anthropic wire format.

        Anthropic models tool results as `user` messages containing
        `tool_result` blocks, and does not allow two consecutive user
        messages - so consecutive tool results are collapsed into one.
        """
        out: list[dict[str, Any]] = []
        pending_results: list[dict[str, Any]] = []

        def flush():
            if pending_results:
                out.append({"role": "user", "content": list(pending_results)})
                pending_results.clear()

        for m in messages:
            role = m["role"]
            if role == "user":
                flush()
                out.append({"role": "user", "content": m["content"]})
            elif role == "assistant":
                flush()
                blocks: list[dict[str, Any]] = []
                if m.get("content"):
                    blocks.append({"type": "text", "text": m["content"]})
                for tc in m.get("tool_calls") or []:
                    blocks.append(
                        {
                            "type": "tool_use",
                            "id": tc["id"],
                            "name": tc["name"],
                            "input": tc["input"],
                        }
                    )
                out.append({"role": "assistant", "content": blocks})
            elif role == "tool":
                pending_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": m["tool_call_id"],
                        "content": m["content"],
                    }
                )
            else:
                raise ValueError(f"unknown normalized message role: {role}")
        flush()
        return out

    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": self._model(),
            "max_tokens": max_tokens,
            "system": system,
            "messages": self.to_anthropic_messages(messages),
        }
        if tools:  # tools are already in Anthropic shape
            kwargs["tools"] = tools

        resp = self._client.messages.create(**kwargs)
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [
            ToolCall(id=b.id, name=b.name, input=b.input)
            for b in resp.content
            if b.type == "tool_use"
        ]
        return LLMResponse(content=text, tool_calls=calls)
