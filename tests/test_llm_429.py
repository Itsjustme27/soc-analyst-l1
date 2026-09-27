"""
Hermetic tests for the LLM 429 / rate-limit hardening:

  - 429s are retried a *bounded* number of times (LLM_429_MAX_RETRIES), then
    surface as LLMRateLimitedError (no retry storm, no raw 500 tracebacks)
  - Retry-After (delta-seconds AND HTTP-date) is honored, capped at
    LLM_RETRY_BACKOFF_MAX
  - repeated 429s never exceed the budget
  - FreeLLMAPI fallback: ONE extra attempt with an alternate model on 429,
    and never when FREELLMAPI_FALLBACK_ENABLED=false
  - single /api/chat multi-call budgeting: a plain-text answer makes exactly
    one LLM call; tool flows never exceed the tool-turn budget
  - structured tracing never logs API keys or prompt contents
  - the dashboard maps an upstream 429 to HTTP 429 (not a Flask 500)

Run: python -m unittest tests.test_llm_429 -v
"""

from __future__ import annotations

import os
import unittest
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import requests  # noqa: E402

from config import cfg  # noqa: E402
from llm.base import LLMError, LLMRateLimitedError, LLMResponse, ToolCall  # noqa: E402
from llm.freellmapi_provider import FreeLLMAPIProvider  # noqa: E402
from llm.openai_compat_provider import OpenAICompatProvider  # noqa: E402


def _resp(status, headers=None, body=None):
    """Minimal requests.Response stand-in (raise_for_status + .json())."""

    class _FakeResp:
        def __init__(self, status, headers, body):
            self.status_code = status
            self.headers = headers or {}
            self._body = body
            self.url = "http://localhost:3001/v1/chat/completions"

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.HTTPError(
                    f"{self.status_code} Client Error: rate limited",
                    response=self,
                )

        def json(self):
            if self._body is None:
                return {}
            return self._body

    return _FakeResp(status, headers, body)


def _chat_body(content="hi", usage=None):
    return {
        "model": "probe-model",
        "choices": [{"message": {"role": "assistant", "content": content}}],
        "usage": usage or {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
    }


def _chat_call(kwargs=None):
    base = dict(system="sys", messages=[{"role": "user", "content": "hi"}], tools=[], max_tokens=10)
    base.update(kwargs or {})
    return base


class TestRateLimitBackoff(unittest.TestCase):
    def setUp(self):
        self.slept: list[float] = []
        sleeper = mock.patch("llm.openai_compat_provider.time.sleep", side_effect=self.slept.append)
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def test_429_retried_bounded_times_then_rate_limited_error(self):
        with mock.patch.object(cfg, "LLM_429_MAX_RETRIES", 2):
            with mock.patch(
                "llm.openai_compat_provider.requests.post", return_value=_resp(429)
            ) as post:
                with self.assertRaises(LLMRateLimitedError) as ctx:
                    OpenAICompatProvider().chat(**_chat_call())
        # Exactly initial + 2 retries - a storm would exceed this.
        self.assertEqual(post.call_count, 3)
        self.assertEqual(ctx.exception.status, 429)
        self.assertTrue(ctx.exception.request_id)
        # Backoff happened between attempts (one sleep per retry).
        self.assertEqual(len(self.slept), 2)

    def test_429_sleeps_backoff_without_retry_after(self):
        with mock.patch.object(cfg, "LLM_429_MAX_RETRIES", 1):
            with mock.patch(
                "llm.openai_compat_provider.requests.post",
                side_effect=[_resp(429), _resp(200, body=_chat_body(content="ok"))],
            ) as post:
                out = OpenAICompatProvider().chat(**_chat_call())
        self.assertEqual(out.content, "ok")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(len(self.slept), 1)
        # First failure (attempt 0) -> base ** 1 = 1.5s + jitter(0..0.5).
        self.assertGreaterEqual(self.slept[0], 1.5)
        self.assertLess(self.slept[0], 2.1)

    def test_retry_after_delta_seconds_honored(self):
        with (
            mock.patch(
                "llm.openai_compat_provider.requests.post",
                side_effect=[
                    _resp(429, headers={"Retry-After": "5"}),
                    _resp(200, body=_chat_body(content="ok")),
                ],
            ) as post,
            mock.patch.object(cfg, "LLM_429_MAX_RETRIES", 1),
        ):
            out = OpenAICompatProvider().chat(**_chat_call())
        self.assertEqual(out.content, "ok")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(len(self.slept), 1)
        # Gateway asked for 5s -> honored (cap is 30s, so no truncation).
        self.assertGreaterEqual(self.slept[0], 5.0)
        self.assertLess(self.slept[0], 5.6)

    def test_retry_after_http_date_honored_and_capped(self):
        from datetime import datetime, timedelta, timezone
        from email.utils import format_datetime

        future = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=60))
        with (
            mock.patch(
                "llm.openai_compat_provider.requests.post",
                side_effect=[
                    _resp(429, headers={"Retry-After": future}),
                    _resp(200, body=_chat_body(content="ok")),
                ],
            ) as post,
            mock.patch.object(cfg, "LLM_429_MAX_RETRIES", 1),
        ):
            out = OpenAICompatProvider().chat(**_chat_call())
        self.assertEqual(out.content, "ok")
        self.assertEqual(post.call_count, 2)
        self.assertEqual(len(self.slept), 1)
        # HTTP-date says 60s, but the cap LLM_RETRY_BACKOFF_MAX=30 applies.
        self.assertGreaterEqual(self.slept[0], 30.0)
        self.assertLess(self.slept[0], 30.6)

    def test_repeated_429_never_exceeds_budget(self):
        # Every attempt 429s; the provider must stop after the bounded budget
        # regardless of how many it could theoretically try.
        with mock.patch.object(cfg, "LLM_429_MAX_RETRIES", 2):
            with mock.patch(
                "llm.openai_compat_provider.requests.post", return_value=_resp(429)
            ) as post:
                with self.assertRaises(LLMRateLimitedError):
                    OpenAICompatProvider().chat(**_chat_call())
        self.assertEqual(post.call_count, 3)  # exactly cap+1, never more

    def test_5xx_retried_with_bounded_backoff_then_llm_error(self):
        with mock.patch.object(cfg, "LLM_MAX_RETRIES", 1):
            with mock.patch(
                "llm.openai_compat_provider.requests.post", return_value=_resp(503)
            ) as post:
                with self.assertRaises(LLMError) as ctx:
                    OpenAICompatProvider().chat(**_chat_call())
        self.assertEqual(post.call_count, 2)
        self.assertNotIsInstance(ctx.exception, LLMRateLimitedError)

    def test_auth_error_not_retried(self):
        with mock.patch(
            "llm.openai_compat_provider.requests.post", return_value=_resp(401)
        ) as post:
            with self.assertRaises(requests.HTTPError):
                OpenAICompatProvider().chat(**_chat_call())
        self.assertEqual(post.call_count, 1)  # 401/403 are never retried
        self.assertEqual(self.slept, [])


class TestProviderFallback(unittest.TestCase):
    def setUp(self):
        self.slept: list[float] = []
        sleeper = mock.patch("llm.openai_compat_provider.time.sleep", side_effect=self.slept.append)
        sleeper.start()
        self.addCleanup(sleeper.stop)

    def test_fallback_uses_alternate_model_on_rate_limit(self):
        captured: dict[str, list] = {"models": []}

        def _side(payload):
            # Emulate the real _post_once: raise_for_status() before returning.
            # Every 'auto' attempt 429s (exhausting the primary budget so the
            # fallback fires); the alternate model succeeds.
            captured["models"].append(payload["model"])
            if payload["model"] == "auto":
                r = _resp(429, headers={"Retry-After": "1"})
            else:
                r = _resp(200, body=_chat_body(content="fallback ok"))
            r.raise_for_status()
            return r

        with (
            mock.patch.object(OpenAICompatProvider, "_post_once", side_effect=_side),
            mock.patch.object(cfg, "FREELLMAPI_FALLBACK_ENABLED", True),
        ):
            prov = FreeLLMAPIProvider()
            with mock.patch.object(prov, "_select_fallback_model", return_value="claude-haiku-4-5"):
                out = prov.chat(**_chat_call())

        self.assertEqual(out.content, "fallback ok")
        # Primary auto attempts (cap+1 = 3) + exactly ONE fallback attempt.
        self.assertEqual(captured["models"], ["auto", "auto", "auto", "claude-haiku-4-5"])
        self.assertEqual(len(self.slept), 2)  # bounded settle within the primary only

    def test_fallback_disabled_never_makes_second_request(self):
        with mock.patch.object(cfg, "FREELLMAPI_FALLBACK_ENABLED", False):
            with mock.patch.object(cfg, "LLM_429_MAX_RETRIES", 1):
                with mock.patch(
                    "llm.openai_compat_provider.requests.post", return_value=_resp(429)
                ) as post:
                    prov = FreeLLMAPIProvider()
                    # _select_fallback_model is NOT stubbed here: it must
                    # return None when disabled (its real code checks cfg
                    # first and never fetches the model list).
                    with self.assertRaises(LLMRateLimitedError):
                        prov.chat(**_chat_call())
        # Auto budget only (cap+1) - no fallback request when disabled.
        self.assertEqual(post.call_count, 2)

    def test_fallback_surfaces_primary_429_when_fallback_also_429s(self):
        def _side(payload):
            r = _resp(429)
            r.raise_for_status()
            return r

        with (
            mock.patch.object(OpenAICompatProvider, "_post_once", side_effect=_side),
            mock.patch.object(cfg, "FREELLMAPI_FALLBACK_ENABLED", True),
        ):
            prov = FreeLLMAPIProvider()
            with mock.patch.object(prov, "_select_fallback_model", return_value="other-model"):
                with self.assertRaises(LLMRateLimitedError) as ctx:
                    prov.chat(**_chat_call())
        self.assertEqual(ctx.exception.status, 429)

    def test_failed_fallback_family_is_skipped_next_time(self):
        # First chat: fallback candidate 404s -> the family is remembered as bad.
        # Second chat: the picker must skip that family on the next selection.
        prov = FreeLLMAPIProvider()
        prov.last_routed_via = "groq/openai/gpt-oss-120b"
        with (
            mock.patch.object(
                prov, "_available_models", return_value=["auto", "claude-opus-4-5", "aion-3.0"]
            ),
            mock.patch.object(cfg, "FREELLMAPI_FALLBACK_ENABLED", True),
        ):
            self.assertEqual(prov._select_fallback_model(), "claude-opus-4-5")
            prov._remember_fallback_failure("claude-opus-4-5")
            # Family 'claude-opus-4-5' is now bad -> next candidate is aion-3.0.
            self.assertEqual(prov._select_fallback_model(), "aion-3.0")


class TestSingleChatBudgeting(unittest.TestCase):
    """One /api/chat must not multiply upstream LLM calls."""

    def _counting_llm(self, mode):
        class CountingLLM:
            def __init__(self):
                self.calls = 0

            def chat(self, **kw):
                self.calls += 1
                if mode == "plain":
                    return LLMResponse(content="plain answer")
                if mode == "tools_then_answer":
                    if self.calls == 1:
                        return LLMResponse(
                            content="",
                            tool_calls=[ToolCall(id="t1", name="get_alerts", input={})],
                        )
                    return LLMResponse(
                        content="",
                        tool_calls=[
                            ToolCall(id="t2", name="answer_user", input={"answer": "done"})
                        ],
                    )
                # mode == "never_answers": keeps returning tool calls forever
                return LLMResponse(
                    content="",
                    tool_calls=[ToolCall(id=f"t{self.calls}", name="get_alerts", input={})],
                )

        return CountingLLM()

    def test_plain_answer_makes_exactly_one_call(self):
        from agent.chat_agent import ChatAgent

        llm = self._counting_llm("plain")
        agent = ChatAgent(siem=None, provider_id=None)
        agent.llm = llm
        res = agent.chat(user_message="hello")
        self.assertEqual(llm.calls, 1)
        self.assertEqual(res.reply, "plain answer")

    def test_answer_via_tool_makes_bounded_calls(self):
        from agent.chat_agent import ChatAgent

        llm = self._counting_llm("tools_then_answer")
        agent = ChatAgent(siem=None, provider_id=None)
        agent.llm = llm
        res = agent.chat(user_message="hello")
        self.assertEqual(llm.calls, 2)
        self.assertEqual(res.reply, "done")

    def test_runaway_tool_loop_stops_at_budget(self):
        from agent.chat_agent import MAX_TOOL_TURNS, ChatAgent

        llm = self._counting_llm("never_answers")
        agent = ChatAgent(siem=None, provider_id=None)
        agent.llm = llm
        res = agent.chat(user_message="hello")
        # Even a model that never calls answer_user cannot exceed the budget.
        self.assertEqual(llm.calls, MAX_TOOL_TURNS)
        self.assertIn("tool budget", res.reply)


class TestEngineerMalformedToolInput(unittest.TestCase):
    """A truncated/malformed tool-arguments payload (a bare bool etc.) must
    never crash the engineer or analyst loops - it is normalized to {} and
    the request degrades gracefully instead of surfacing "'bool' object has
    no attribute 'get'" from the /api/engineer/chat endpoint."""

    def _engineer(self, fake_llm):
        from agent.soc_engineer import SOCEngineer

        eng = SOCEngineer()
        eng.llm = fake_llm
        return eng

    def test_answer_user_with_bool_input_does_not_crash(self):
        class FakeLLM:
            def chat(self, **kw):
                return LLMResponse(
                    content="",
                    tool_calls=[ToolCall(id="t1", name="answer_user", input=True)],
                )

        res = self._engineer(FakeLLM()).chat(user_message="hi")
        self.assertEqual(res.reply, "")
        # The bool was normalized to {} in the transcript, not stored raw.
        self.assertEqual(res.transcript[0]["tool_calls"][0]["input"], {})

    def test_bool_input_on_tool_is_normalized_and_loop_continues(self):
        class FakeLLM:
            def __init__(self):
                self.calls = 0

            def chat(self, **kw):
                self.calls += 1
                if self.calls == 1:
                    return LLMResponse(
                        content="",
                        tool_calls=[
                            ToolCall(id="t1", name="design_detection_dashboard", input=False)
                        ],
                    )
                return LLMResponse(
                    content="",
                    tool_calls=[ToolCall(id="t2", name="answer_user", input={"answer": "done"})],
                )

        with mock.patch(
            "agent.soc_engineer.run_tool", return_value={"status": "ok", "result": {}}
        ) as run:
            res = self._engineer(FakeLLM()).chat(user_message="hi")
        # The registry saw {} (not the raw bool); its own param validation
        # would report the missing-parameter error back to the model.
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[1], "design_detection_dashboard")
        self.assertEqual(run.call_args.args[2], {})
        self.assertEqual(res.reply, "done")

    def test_chat_agent_answer_user_with_bool_input_does_not_crash(self):
        from agent.chat_agent import ChatAgent

        class FakeLLM:
            def chat(self, **kw):
                return LLMResponse(
                    content="",
                    tool_calls=[ToolCall(id="t1", name="answer_user", input=False)],
                )

        agent = ChatAgent(siem=None, provider_id=None)
        agent.llm = FakeLLM()
        res = agent.chat(user_message="hi")
        self.assertEqual(res.reply, "")


class TestTracingNoSecrets(unittest.TestCase):
    def test_trace_lines_carry_fields_but_never_keys_or_prompts(self):
        secret_key = "sk-secret-that-must-never-appear-9f8e"
        prompt_marker = "prompt-text-that-must-not-leak-7742"
        with (
            mock.patch.object(cfg, "OPENAI_API_KEY", secret_key),
            mock.patch(
                "llm.openai_compat_provider.requests.post",
                side_effect=[
                    _resp(429, headers={"Retry-After": "2"}),
                    _resp(
                        200,
                        body=_chat_body(
                            content="hi",
                            usage={"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                        ),
                    ),
                ],
            ),
            mock.patch("llm.openai_compat_provider.time.sleep"),
        ):
            with self.assertLogs("soc.llm", level="INFO") as logs:
                OpenAICompatProvider().chat(
                    **_chat_call({"messages": [{"role": "user", "content": prompt_marker}]})
                )

        joined = "\n".join(logs.output)
        # Structured fields present for the try, retry, and done events.
        self.assertIn('"event": "llm.try"', joined)
        self.assertIn('"event": "llm.retry"', joined)
        self.assertIn('"event": "llm.done"', joined)
        self.assertIn("attempt", joined)
        self.assertIn("latency_ms", joined)
        self.assertIn("usage", joined)
        self.assertIn("retry_after", joined)
        # One consistent request_id threads through all three events.
        ids = {
            line.split('"request_id": "')[1].split('"')[0]
            for line in logs.output
            if '"request_id": "' in line
        }
        self.assertEqual(len(ids), 1)
        # ... and secrets never leak.
        self.assertNotIn(secret_key, joined)
        self.assertNotIn(prompt_marker, joined)


class TestApiChatMaps429(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_upstream_429_returns_http_429_not_500(self):
        from agent.chat_agent import ChatAgent

        with mock.patch.object(
            ChatAgent,
            "chat",
            side_effect=LLMRateLimitedError(
                "rate limited",
                status=429,
                retry_after=12.0,
                request_id="req123",
            ),
        ):
            r = self.client.post("/api/chat", json={"message": "hello"})
        self.assertEqual(r.status_code, 429)
        body = r.get_json()
        self.assertIn("error", body)
        self.assertEqual(body["retry_after"], 12.0)
        self.assertEqual(body["request_id"], "req123")


if __name__ == "__main__":
    unittest.main()
