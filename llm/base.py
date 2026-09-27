"""
Provider-agnostic LLM layer.

The rest of the codebase talks to a single interface (`LLMProvider.chat`) and
never sees provider-specific wire formats. Adding a new provider (or swapping
the default) touches nothing outside this package.

Normalized (provider-agnostic) message format - what callers pass in and what
the agent loop builds:

- User message:      {"role": "user", "content": "<text>"}
- Assistant message: {"role": "assistant", "content": "<text>",
                      "tool_calls": [{"id", "name", "input"}, ...]}   # optional
- Tool result:       {"role": "tool", "tool_call_id": "<id>", "content": "<json str>"}

Tool definitions are kept in one canonical shape across providers:
    {"name": str, "description": str, "input_schema": {...json schema...}}
Each provider translates that canonical shape (and the messages above) into
its own wire format and back.
"""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from config import cfg

# Structured per-attempt LLM tracing. One JSON line per attempt emitted by the
# OpenAI-compatible transport. Never includes API keys or prompt contents.
_llm_logger = logging.getLogger("soc.llm")


def trace_llm(**fields: Any) -> None:
    """Emit one structured JSON line for an LLM transport event.

    Only known-safe fields are ever passed in - never the API key and never
    prompt/system/message contents (that is enforced by the call sites, and
    the transport never receives those objects with their secrets).
    """
    if not cfg.LLM_TRACE_REQUESTS:
        return
    event = fields.pop("event", "llm.request")
    try:
        _llm_logger.info(json.dumps({"event": event, **fields}))
    except Exception:  # noqa: BLE001 - logging must never break a request
        _llm_logger.info("event=%s", event)


class LLMError(Exception):
    """Base for provider/transport errors surfaced to callers."""


class LLMRateLimitedError(LLMError):
    """The upstream gateway kept returning 429 after bounded retries.

    Carries enough detail for the HTTP layer to answer client-side 429s
    (including a Retry-After value when the gateway supplied one).
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = 429,
        retry_after: float | None = None,
        request_id: str | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after
        self.request_id = request_id


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]


@dataclass
class LLMResponse:
    """What a provider returns for one model call."""

    content: str = ""  # free text; empty when the model only made tool calls
    tool_calls: list[ToolCall] = field(default_factory=list)
    usage: dict[str, Any] = field(default_factory=dict)  # prompt/completion/total tokens
    request_id: str = ""  # trace id of the underlying transport call

    @property
    def text(self) -> str:
        return self.content


class LLMProvider(ABC):
    name: str = "base"

    @abstractmethod
    def chat(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        max_tokens: int,
    ) -> LLMResponse:
        """Send a chat completion with optional tool calling.

        `tools` uses the canonical shape above. `messages` uses the normalized
        format described in this module's docstring.
        """

    def chat_text(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
    ) -> str:
        """Chat completion without tools - returns just the text.

        Convenience for free-text calls (lesson distillation etc.). Raises if
        the model tries to call a tool anyway.
        """
        resp = self.chat(system=system, messages=messages, tools=[], max_tokens=max_tokens)
        if resp.tool_calls:
            raise RuntimeError(
                f"{self.name} provider returned a tool call in a no-tools call: "
                f"{[tc.name for tc in resp.tool_calls]}"
            )
        return resp.content
