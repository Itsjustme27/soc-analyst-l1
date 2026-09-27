"""
Offline tests for the pluggable LLM layer. No API keys required - the
provider wire-format conversions are tested directly, and the mock provider
drives the real TriageAgent end to end (RAG + mock enrichment + verdict).

Run: python -m unittest discover -s tests -v
"""

from __future__ import annotations

import unittest
from unittest import mock

from config import cfg
from llm import get_provider
from llm.anthropic_provider import AnthropicProvider
from llm.google_provider import GoogleProvider, to_google_contents
from llm.mock_provider import MockProvider
from llm.openai_compat_provider import OpenAICompatProvider, to_openai_messages, to_openai_tools

CANONICAL_TOOLS = [
    {
        "name": "retrieve_playbook",
        "description": "Retrieve the relevant SOC playbook.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    }
]

BRUTE_FORCE_ALERT = {
    "alert_id": "SPLK-10231",
    "rule_name": "Brute Force - Multiple Auth Failures Then Success",
    "severity": "high",
    "user": "jsmith",
    "src_ip": "185.220.101.7",
    "raw_fields": {"source_asn": "AS9009", "mfa_satisfied": False},
}

MALWARE_ALERT = {
    "alert_id": "SPLK-10245",
    "rule_name": "EDR Malware Detection - Suspicious Process",
    "host": "WKS-FIN-0231",
    "host_id": "mock-host-id-0231",
    "detection_id": "mock-detection-9981",
    "falcon_process_id": "mock-process-4471",
}

PHISHING_ALERT = {
    "alert_id": "SPLK-10250",
    "rule_name": "Phishing - User Reported Suspicious Email",
    "user": "agarcia",
    "raw_fields": {
        "sender": "it-support@corp-secure-login.net",
        "spf": "fail",
        "dkim": "fail",
        "link_clicked": False,
    },
}


class TestFactory(unittest.TestCase):
    def test_mock_instantiates_without_keys(self):
        self.assertIsInstance(get_provider("mock"), MockProvider)

    def test_freellmapi_registry(self):
        from llm import _PROVIDERS
        from llm.freellmapi_provider import FreeLLMAPIProvider

        self.assertIs(_PROVIDERS["freellmapi"], FreeLLMAPIProvider)
        self.assertTrue(issubclass(FreeLLMAPIProvider, OpenAICompatProvider))

    def test_freellmapi_defaults(self):
        from llm.freellmapi_provider import DEFAULT_BASE_URL, DEFAULT_MODEL, FreeLLMAPIProvider

        # Hermetic: ignore operator .env FREELLMAPI_* overrides.
        with (
            mock.patch.object(cfg, "FREELLMAPI_BASE_URL", ""),
            mock.patch.object(cfg, "FREELLMAPI_MODEL", ""),
            mock.patch.object(cfg, "FREELLMAPI_API_KEY", ""),
        ):
            p = FreeLLMAPIProvider()  # must not raise without a key
            self.assertEqual(p._base_url, DEFAULT_BASE_URL)
            self.assertEqual(p._model(), DEFAULT_MODEL)

    def test_dispatch_registry(self):
        # anthropic/openai/google need real keys at construction - check the
        # registry mapping instead of constructing them here.
        from llm import _PROVIDERS

        self.assertIs(_PROVIDERS["anthropic"], AnthropicProvider)
        self.assertIs(_PROVIDERS["openai"], OpenAICompatProvider)
        self.assertIs(_PROVIDERS["google"], GoogleProvider)
        self.assertIs(_PROVIDERS["mock"], MockProvider)

    def test_missing_key_raises_clear_error(self):
        from llm import google_provider

        if not google_provider.cfg.GOOGLE_API_KEY:
            with self.assertRaises(ValueError):
                get_provider("google")

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            get_provider("does-not-exist")


class TestAnthropicConversion(unittest.TestCase):
    def setUp(self):
        # Bypass __init__ (api key check) - only testing message conversion.
        self.provider = AnthropicProvider.__new__(AnthropicProvider)

    def test_assistant_renders_text_and_tool_use_blocks(self):
        out = self.provider.to_anthropic_messages(
            [
                {
                    "role": "assistant",
                    "content": "investigating",
                    "tool_calls": [
                        {"id": "a", "name": "retrieve_playbook", "input": {"query": "x"}}
                    ],
                },
            ]
        )
        self.assertEqual(out[0]["role"], "assistant")
        self.assertEqual(out[0]["content"][0], {"type": "text", "text": "investigating"})
        self.assertEqual(
            out[0]["content"][1],
            {"type": "tool_use", "id": "a", "name": "retrieve_playbook", "input": {"query": "x"}},
        )

    def test_consecutive_tool_results_collapse_into_one_user_message(self):
        out = self.provider.to_anthropic_messages(
            [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{"id": "c1", "name": "f", "input": {}}],
                },
                {"role": "tool", "tool_call_id": "c1", "content": '{"a": 1}'},
                {"role": "tool", "tool_call_id": "c2", "content": '{"b": 2}'},
            ]
        )
        # No two adjacent user messages; both results in one tool_result list.
        roles = [m["role"] for m in out]
        self.assertEqual(roles, ["user", "assistant", "user"])
        last = out[-1]
        self.assertEqual([b["type"] for b in last["content"]], ["tool_result", "tool_result"])
        self.assertEqual(last["content"][0]["tool_use_id"], "c1")


class TestOpenAIConversion(unittest.TestCase):
    def test_tools_shape(self):
        out = to_openai_tools(CANONICAL_TOOLS)
        self.assertEqual(out[0]["type"], "function")
        self.assertEqual(out[0]["function"]["name"], "retrieve_playbook")
        self.assertEqual(out[0]["function"]["parameters"]["type"], "object")

    def test_messages_round_trip(self):
        msgs = [
            {"role": "user", "content": "go"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [{"id": "t1", "name": "f", "input": {"x": 1}}],
            },
            {"role": "tool", "tool_call_id": "t1", "content": "result"},
        ]
        out = to_openai_messages(msgs)
        self.assertEqual(out[0]["role"], "user")
        self.assertEqual(out[1]["role"], "assistant")
        self.assertEqual(out[1]["tool_calls"][0]["function"]["name"], "f")
        self.assertEqual(out[1]["tool_calls"][0]["function"]["arguments"], '{"x": 1}')
        self.assertEqual(out[2]["role"], "tool")
        self.assertEqual(out[2]["tool_call_id"], "t1")


class TestGoogleConversion(unittest.TestCase):
    def setUp(self):
        self.provider = GoogleProvider.__new__(GoogleProvider)

    def test_function_response_collapse_and_name_recovery(self):
        msgs = [
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "get_host_info::call_0",
                        "name": "get_host_info",
                        "input": {"host_id": "h"},
                    },
                ],
            },
            {
                "role": "tool",
                "tool_call_id": "get_host_info::call_0",
                "content": '{"hostname": "WKS"}',
            },
        ]
        out = to_google_contents(msgs)
        self.assertEqual([m["role"] for m in out], ["model", "user"])
        self.assertEqual(out[0]["parts"][0]["functionCall"]["name"], "get_host_info")
        fr = out[1]["parts"][0]["functionResponse"]
        self.assertEqual(fr["name"], "get_host_info")
        self.assertEqual(fr["response"], {"hostname": "WKS"})

    def test_function_call_id_embeds_name(self):
        from llm.base import ToolCall

        tc = ToolCall(id="f::call_2", name="f", input={"k": "v"})
        name = tc.id.split("::", 1)[0]  # round-trip convention used by provider
        self.assertEqual(name, "f")


class TestMockProviderEndToEnd(unittest.TestCase):
    """Drives the real agent loop (RAG + mock enrichment) with the mock LLM."""

    @classmethod
    def setUpClass(cls):
        from agent.triage_agent import TriageAgent

        cls.agent = TriageAgent(provider="mock")

    def _tool_names(self, transcript):
        return [t["tool"] for t in transcript if "tool" in t]

    def test_brute_force(self):
        r = self.agent.triage(BRUTE_FORCE_ALERT)
        self.assertEqual(r.verdict, "true_positive")
        self.assertEqual(r.recommended_action, "escalate_to_l2")
        names = self._tool_names(r.transcript)
        for expected in (
            "retrieve_playbook",
            "retrieve_similar_cases",
            "retrieve_lessons",
            "search_related_events",
            "submit_verdict",
        ):
            self.assertIn(expected, names)
        self.assertTrue(r.rationale)
        self.assertEqual(len(r.evidence_used), 3)

    def test_malware(self):
        r = self.agent.triage(MALWARE_ALERT)
        self.assertEqual(r.verdict, "true_positive")
        self.assertEqual(r.recommended_action, "isolate_host")
        names = self._tool_names(r.transcript)
        for expected in (
            "get_host_info",
            "get_process_tree",
            "get_detection_details",
            "get_host_alert_history",
            "submit_verdict",
        ):
            self.assertIn(expected, names)

    def test_phishing(self):
        r = self.agent.triage(PHISHING_ALERT)
        self.assertEqual(r.verdict, "true_positive")
        self.assertEqual(r.recommended_action, "monitor")
        self.assertLess(r.confidence, 0.9)  # below auto-close threshold -> human review


class TestToolInputCoercion(unittest.TestCase):
    """Truncated/malformed tool arguments from the gateway must be normalized
    to {} instead of surfacing as a bare bool/list/str and crashing the agent
    with "'bool' object has no attribute 'get'"."""

    def _parse(self, arguments: str) -> dict:
        prov = OpenAICompatProvider.__new__(OpenAICompatProvider)

        class _Resp:
            def json(self):
                return {
                    "choices": [
                        {
                            "message": {
                                "content": "",
                                "tool_calls": [
                                    {
                                        "id": "t1",
                                        "type": "function",
                                        "function": {"name": "answer_user", "arguments": arguments},
                                    },
                                ],
                            }
                        }
                    ],
                }

        return prov._parse_response(_Resp()).tool_calls[0].input

    def test_valid_object_passthrough(self):
        self.assertEqual(self._parse('{"answer": "hi"}'), {"answer": "hi"})

    def test_bare_bool_normalized_to_empty_dict(self):
        # max_tokens truncation can leave the gateway returning `true`/`false`
        # as the whole arguments payload - the exact live crash this guards.
        self.assertEqual(self._parse("true"), {})
        self.assertEqual(self._parse("false"), {})

    def test_null_array_and_scalar_normalized(self):
        self.assertEqual(self._parse("null"), {})
        self.assertEqual(self._parse("[1, 2]"), {})
        self.assertEqual(self._parse('"oops"'), {})

    def test_invalid_json_normalized(self):
        self.assertEqual(self._parse('{"answer": '), {})  # truncated mid-object
        self.assertEqual(self._parse("nope"), {})

    def test_empty_arguments_normalized(self):
        self.assertEqual(self._parse(""), {})
        self.assertEqual(self._parse(None), {})


if __name__ == "__main__":
    unittest.main()
