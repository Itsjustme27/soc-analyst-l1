"""
OpenAI-compatible chat completions provider.

Works with any server that speaks the OpenAI `/chat/completions` protocol:
OpenAI, OpenRouter, Azure OpenAI, Ollama, vLLM, LM Studio, DeepSeek, Together,
Groq, ... Just point OPENAI_BASE_URL at it. Implemented with plain `requests`
so no extra SDK dependency is required.
"""

from __future__ import annotations

import email.utils
import json
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import requests

from config import cfg
from llm.base import LLMError, LLMProvider, LLMRateLimitedError, LLMResponse, ToolCall, trace_llm

# Statuses worth retrying. 429 (rate limit) gets its own, much smaller budget:
# a rate-limited key needs *time*, not more requests, and retrying it hard just
# keeps it inside the rate-limit window.
_RETRYABLE_5XX = (500, 502, 503, 504)


def _coerce_tool_input(arguments: str | None) -> dict[str, Any]:
    """Tool arguments must be a JSON *object*.

    Gateways sometimes return truncated or malformed arguments - most often a
    bare scalar like ``true``/``null`` when max_tokens cuts the model's JSON
    mid-argument. Any non-object value is dropped to ``{}`` so consumers never
    see a bool/list/str where a dict is expected (previously a bool input made
    the agent crash with "'bool' object has no attribute 'get'")."""
    try:
        parsed = json.loads(arguments or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def to_openai_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Canonical tool shape -> OpenAI 'function' tools."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        }
        for t in tools
    ]


def to_openai_messages(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalized -> OpenAI chat message list."""
    out: list[dict[str, Any]] = []
    for m in messages:
        role = m["role"]
        if role == "user":
            out.append({"role": "user", "content": m["content"]})
        elif role == "assistant":
            msg: dict[str, Any] = {"role": "assistant"}
            msg["content"] = m.get("content") or None
            tool_calls = [
                {
                    "id": tc["id"],
                    "type": "function",
                    "function": {"name": tc["name"], "arguments": json.dumps(tc["input"])},
                }
                for tc in m.get("tool_calls") or []
            ]
            if tool_calls:
                msg["tool_calls"] = tool_calls
            out.append(msg)
        elif role == "tool":
            out.append({"role": "tool", "tool_call_id": m["tool_call_id"], "content": m["content"]})
        else:
            raise ValueError(f"unknown normalized message role: {role}")
    return out


def _parse_retry_after(value: str | None) -> float | None:
    """Parse a Retry-After header (delta-seconds or HTTP-date) -> seconds."""
    if not value:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        pass
    try:
        dt = email.utils.parsedate_to_datetime(value)
        return max(0.0, (dt - datetime.now(timezone.utc)).total_seconds())
    except Exception:  # noqa: BLE001
        return None


class OpenAICompatProvider(LLMProvider):
    name = "openai"

    def __init__(self):
        self._api_key = cfg.OPENAI_API_KEY
        self._base_url = cfg.OPENAI_BASE_URL.rstrip("/")

    def _model(self) -> str:
        return cfg.OPENAI_MODEL or cfg.AGENT_MODEL

    # --- small hooks so subclasses (e.g. FreeLLMAPI) can reuse the exact
    #     wire logic while swapping endpoints/models or adding observability.
    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def _build_payload(self, *, system, messages, tools, max_tokens, model=None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "model": model or self._model(),
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}] + to_openai_messages(messages),
        }
        if tools:
            payload["tools"] = to_openai_tools(tools)
        return payload

    def _build_and_post(
        self, *, system, messages, tools, max_tokens, model=None, request_id=None
    ) -> requests.Response:
        payload = self._build_payload(
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
            model=model,
        )
        return self._post(payload, request_id=request_id)

    def _wait_seconds(self, attempt: int, retry_after: str | None = None) -> float:
        """Sleep duration before retry `attempt` (0-based past failures).

        Retry-After (when the gateway sends one) takes priority; otherwise a
        bounded exponential backoff. Both are capped at LLM_RETRY_BACKOFF_MAX
        so a gateway asking for an absurdly long wait can't stall a batch.
        Plus a touch of jitter to de-synchronize retry storms.
        """
        wait = _parse_retry_after(retry_after)
        if wait is None:
            wait = cfg.LLM_RETRY_BACKOFF_BASE ** (attempt + 1)
        wait = min(float(wait), cfg.LLM_RETRY_BACKOFF_MAX)
        return max(0.0, wait + random.uniform(0, 0.5))

    def _retry_sleep(
        self,
        attempt: int,
        retry_after: str | None,
        *,
        request_id,
        model,
        status: int,
        latency_ms: float,
        error: str | None = None,
    ) -> None:
        wait = self._wait_seconds(attempt, retry_after)
        trace_llm(
            event="llm.retry",
            request_id=request_id,
            attempt=attempt,
            model=model,
            status=status,
            latency_ms=round(latency_ms, 1),
            retry_after=retry_after,
            sleep_s=round(wait, 1),
            error=error,
        )
        time.sleep(wait)

    def _post(self, payload: dict[str, Any], *, request_id: str | None = None) -> requests.Response:
        """POST /chat/completions with bounded retry/backoff for transient failures.

        Free gateways (FreeLLMAPI, OpenRouter free tier, ...) throw 429s and
        occasional 5xx under load; one failed call should not kill a whole
        triage batch. Behavior:

          - 429 (rate limit): retried at most LLM_429_MAX_RETRIES times,
            honoring Retry-After when present, then raises LLMRateLimitedError
            so the HTTP layer can answer client-side 429s. This intentionally
            does NOT hammer the gateway - a rate-limited key needs time.
          - 5xx + network errors: retried at most LLM_MAX_RETRIES times with
            bounded exponential backoff (LLM_RETRY_BACKOFF_MAX cap), then
            raise LLMError.
          - Auth/etc. errors (401/403/400/...): never retried, re-raised.

        Every attempt emits one structured `soc.llm` log line (request_id,
        attempt, model, status, latency, retry_after) - never keys or prompts.
        """
        model = payload.get("model", self._model())
        budget_429 = cfg.LLM_429_MAX_RETRIES
        budget_5xx = cfg.LLM_MAX_RETRIES
        attempt = 0
        while True:
            t0 = time.time()
            try:
                resp = self._post_once(payload)
                # Defense in depth: _post_once normally raises on failure, but a
                # subclass transport could return >=400 without raising.
                resp.raise_for_status()
                latency_ms = (time.time() - t0) * 1000
                trace_llm(
                    event="llm.try",
                    request_id=request_id,
                    attempt=attempt,
                    model=model,
                    status=resp.status_code,
                    latency_ms=round(latency_ms, 1),
                    retry_after=None,
                )
                return resp
            except requests.HTTPError as e:
                status = e.response.status_code if e.response is not None else 0
                latency_ms = (time.time() - t0) * 1000
                retry_after = (
                    (e.response.headers or {}).get("Retry-After")
                    if e.response is not None
                    else None
                )
                if status == 429:
                    if budget_429 > 0:
                        budget_429 -= 1
                        self._retry_sleep(
                            attempt,
                            retry_after,
                            request_id=request_id,
                            model=model,
                            status=status,
                            latency_ms=latency_ms,
                            error=str(e)[:120],
                        )
                        attempt += 1
                        continue
                    trace_llm(
                        event="llm.failed",
                        request_id=request_id,
                        attempt=attempt,
                        model=model,
                        status=status,
                        latency_ms=round(latency_ms, 1),
                        retry_after=retry_after,
                        error=str(e)[:120],
                    )
                    raise LLMRateLimitedError(
                        f"LLM gateway rate limited (HTTP 429) after "
                        f"{cfg.LLM_429_MAX_RETRIES + 1} attempts",
                        status=429,
                        retry_after=_parse_retry_after(retry_after),
                        request_id=request_id,
                    ) from e
                if status in _RETRYABLE_5XX:
                    if budget_5xx > 0:
                        budget_5xx -= 1
                        self._retry_sleep(
                            attempt,
                            retry_after,
                            request_id=request_id,
                            model=model,
                            status=status,
                            latency_ms=latency_ms,
                            error=str(e)[:120],
                        )
                        attempt += 1
                        continue
                    trace_llm(
                        event="llm.failed",
                        request_id=request_id,
                        attempt=attempt,
                        model=model,
                        status=status,
                        latency_ms=round(latency_ms, 1),
                        retry_after=retry_after,
                        error=str(e)[:120],
                    )
                    raise LLMError(
                        f"LLM gateway error (HTTP {status}) after {cfg.LLM_MAX_RETRIES + 1} attempts"
                    ) from e
                trace_llm(
                    event="llm.failed",
                    request_id=request_id,
                    attempt=attempt,
                    model=model,
                    status=status,
                    latency_ms=round(latency_ms, 1),
                    retry_after=retry_after,
                    error=str(e)[:120],
                )
                raise  # don't retry auth errors (401/403) etc.
            except requests.RequestException as e:
                latency_ms = (time.time() - t0) * 1000
                if budget_5xx > 0:
                    budget_5xx -= 1
                    self._retry_sleep(
                        attempt,
                        None,
                        request_id=request_id,
                        model=model,
                        status=0,
                        latency_ms=latency_ms,
                        error=str(e)[:120],
                    )
                    attempt += 1
                    continue
                raise LLMError(
                    f"LLM request failed after {cfg.LLM_MAX_RETRIES + 1} attempts: {e}"
                ) from e

    def _post_once(self, payload: dict[str, Any]) -> requests.Response:
        resp = requests.post(
            f"{self._base_url}/chat/completions",
            headers=self._headers(),
            json=payload,
            timeout=120,
        )
        resp.raise_for_status()
        return resp

    def _parse_response(self, resp: requests.Response) -> LLMResponse:
        body = resp.json()
        msg = body["choices"][0]["message"]

        calls = []
        for tc in msg.get("tool_calls") or []:
            calls.append(
                ToolCall(
                    id=tc["id"],
                    name=tc["function"]["name"],
                    input=_coerce_tool_input(tc["function"]["arguments"]),
                )
            )
        return LLMResponse(
            content=msg.get("content") or "",
            tool_calls=calls,
            usage=body.get("usage") or {},
        )

    # ------------------------------------------------------------------ #
    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        request_id = uuid.uuid4().hex[:12]
        resp = self._build_and_post(
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=max_tokens,
            request_id=request_id,
        )
        out = self._parse_response(resp)
        out.request_id = request_id
        trace_llm(
            event="llm.done",
            request_id=request_id,
            model=resp.json().get("model"),
            status=resp.status_code,
            usage=out.usage or None,
            provider=None,
        )
        return out
