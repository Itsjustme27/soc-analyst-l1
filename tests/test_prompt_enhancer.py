"""Prompt enhancer (prompt_enhancer.py) + its dashboard and CLI wiring.

Run: python -m unittest tests.test_prompt_enhancer -v
"""

from __future__ import annotations

import io
import json
import os
import unittest
from contextlib import redirect_stdout
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import prompt_enhancer as pe  # noqa: E402


class StubLLM:
    def __init__(self, reply):
        self.reply, self.calls = reply, []

    def chat_text(self, *, system, messages, max_tokens):
        self.calls.append(messages[0]["content"])
        if isinstance(self.reply, Exception):
            raise self.reply
        return self.reply if isinstance(self.reply, str) else json.dumps(self.reply)


class TestExtraction(unittest.TestCase):
    def test_facts_are_extracted_by_code(self):
        e = pe.extract_entities(
            "why did rule 5716 fire on host web-01 for user bob from 185.220.101.7 "
            "port 22, CVE-2024-3094, T1110.001, 10.0.0.0/8, evil.example.com"
        )
        self.assertEqual(e["ips"], ["185.220.101.7"])
        self.assertEqual(e["cidrs"], ["10.0.0.0/8"])
        self.assertEqual(e["rule_ids"], ["5716"])
        self.assertEqual(e["ports"], ["22"])
        self.assertEqual(e["cves"], ["CVE-2024-3094"])
        self.assertEqual(e["mitre"], ["T1110.001"])
        self.assertEqual(e["users"], ["bob"])
        self.assertEqual(e["hosts"], ["web-01"])
        self.assertIn("evil.example.com", e["domains"])

    def test_invalid_ips_and_ports_are_rejected(self):
        e = pe.extract_entities("999.1.1.1 and port 99999 and 1.2.3.4")
        self.assertEqual(e["ips"], ["1.2.3.4"])
        self.assertEqual(e["ports"], [])

    def test_time_ranges_normalize(self):
        for text, want in [
            ("last 24 hours", "-24h"),
            ("past 3 days", "-3d"),
            ("this week", "-7d"),
            ("yesterday", "-48h"),
            ("last month", "-30d"),
            ("over the last 15 minutes", "-15m"),
            ("since -12h", "-12h"),
            ("no time here", None),
        ]:
            self.assertEqual(pe.extract_time_range(text), want, text)


class TestKeywordFallback(unittest.TestCase):
    def test_multi_task_split(self):
        s = pe.enhance(
            "show me ssh brute force from 185.220.101.7 last 24h and make a rule for it",
            use_llm=False,
        )
        self.assertEqual({t["type"] for t in s["tasks"]}, {"investigate", "create_rule"})
        self.assertTrue(s["needs_confirmation"])
        self.assertEqual(s["time_range"], "-24h")

    def test_dashboard_request_does_not_become_an_investigation(self):
        s = pe.enhance("build a dashboard of web attacks by url", use_llm=False)
        self.assertEqual([t["type"] for t in s["tasks"]], ["create_dashboard"])
        self.assertTrue(any("time range" in a for a in s["ambiguities"]))

    def test_plain_question(self):
        s = pe.enhance("what is a SIEM", use_llm=False)
        self.assertEqual([t["type"] for t in s["tasks"]], ["question"])
        self.assertFalse(s["needs_confirmation"])


class TestLLMClassification(unittest.TestCase):
    def test_valid_reply_is_used(self):
        llm = StubLLM(
            {
                "tasks": [
                    {
                        "type": "create_rule",
                        "description": "ssh brute force rule",
                        "details": {"threshold": "5 in 2 minutes"},
                    }
                ],
                "ambiguities": ["threshold assumed"],
                "clarifying_question": "",
            }
        )
        s = pe.enhance("make a rule for ssh brute force", llm)
        self.assertEqual(s["source"], "llm")
        self.assertEqual(s["tasks"][0]["details"], {"threshold": "5 in 2 minutes"})
        self.assertIn("threshold assumed", s["ambiguities"])

    def test_only_the_user_text_is_sent(self):
        llm = StubLLM({"tasks": [{"type": "question", "description": "x"}]})
        pe.enhance("what is wazuh", llm)
        self.assertEqual(llm.calls, ["what is wazuh"])

    def test_unknown_task_types_are_dropped(self):
        llm = StubLLM(
            {
                "tasks": [
                    {"type": "delete_everything", "description": "x"},
                    {"type": "investigate", "description": "y"},
                ]
            }
        )
        s = pe.enhance("check 1.2.3.4", llm)
        self.assertEqual([t["type"] for t in s["tasks"]], ["investigate"])
        self.assertTrue(any("unknown task type" in n for n in s["notes"]))

    def test_hallucinated_identifiers_are_discarded(self):
        llm = StubLLM(
            {
                "tasks": [
                    {
                        "type": "investigate",
                        "description": "check it",
                        "details": {"ip": "8.8.8.8", "host": "dc-01", "focus": "ssh"},
                    }
                ]
            }
        )
        s = pe.enhance("check 1.2.3.4 for ssh", llm)
        self.assertEqual(s["tasks"][0]["details"], {"focus": "ssh"})
        self.assertEqual(s["entities"]["ips"], ["1.2.3.4"])  # facts from code, not the model

    def test_llm_failure_and_junk_fall_back_to_keywords(self):
        for reply in (RuntimeError("down"), "sure! here's a plan", {"tasks": []}):
            s = pe.enhance("build a dashboard of ssh failures", StubLLM(reply))
            self.assertEqual(s["source"], "rules", reply)
            self.assertEqual([t["type"] for t in s["tasks"]], ["create_dashboard"])

    def test_task_count_is_capped(self):
        llm = StubLLM({"tasks": [{"type": "question", "description": str(i)} for i in range(10)]})
        self.assertEqual(len(pe.enhance("q", llm)["tasks"]), pe.MAX_TASKS)


class TestSpecRoundTrip(unittest.TestCase):
    def test_validate_spec_reextracts_facts_from_the_original(self):
        spec = pe.enhance("check 1.2.3.4 last 3 days", use_llm=False)
        spec["entities"] = {"ips": ["6.6.6.6"]}  # a tampered client spec
        spec["time_range"] = "-999d"
        v = pe.validate_spec(spec)
        self.assertEqual(v["entities"]["ips"], ["1.2.3.4"])
        self.assertEqual(v["time_range"], "-3d")

    def test_validate_spec_rejects_garbage(self):
        for bad in (None, {}, {"original": "  "}, "x"):
            with self.assertRaises(ValueError):
                pe.validate_spec(bad)

    def test_render_and_summary(self):
        spec = pe.enhance("make a rule for ssh brute force from 1.2.3.4 last 24h", use_llm=False)
        block = pe.render_for_agent(spec)
        self.assertIn("user's own words above take precedence", block)
        payload = json.loads(block.split("```json\n")[1].split("\n```")[0])
        self.assertEqual(payload["entities"]["ips"], ["1.2.3.4"])
        lines = pe.summarize(spec)
        self.assertTrue(any(line.startswith("1. ") for line in lines))
        self.assertIn("Time range: -24h", lines)


class TestDashboardRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from dashboard import app

        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_enhance_endpoint(self):
        with mock.patch("dashboard._enhancer_llm", return_value=None):
            r = self.client.post(
                "/api/enhance", json={"message": "build a dashboard of ssh failures this week"}
            )
        body = r.get_json()
        self.assertEqual(r.status_code, 200)
        self.assertTrue(body["enabled"])
        self.assertTrue(body["spec"]["needs_confirmation"])
        self.assertTrue(body["summary"])

    def test_enhance_requires_a_message(self):
        self.assertEqual(self.client.post("/api/enhance", json={}).status_code, 400)

    def test_enhancer_can_be_disabled(self):
        from config import cfg

        with mock.patch.object(cfg, "PROMPT_ENHANCER", False):
            r = self.client.post("/api/enhance", json={"message": "hi"})
        self.assertEqual(r.get_json(), {"enabled": False})

    def test_engineer_chat_attaches_a_validated_spec(self):
        from dashboard import _message_with_spec

        msg = "make a rule for ssh brute force from 1.2.3.4"
        spec = pe.enhance(msg, use_llm=False)
        out, used = _message_with_spec(msg, spec)
        self.assertIn("Structured request from the prompt enhancer", out)
        self.assertTrue(out.startswith(msg))
        self.assertIsNotNone(used)

    def test_a_spec_for_a_different_message_is_ignored(self):
        from dashboard import _message_with_spec

        spec = pe.enhance("delete all rules", use_llm=False)
        out, used = _message_with_spec("what is wazuh", spec)
        self.assertEqual(out, "what is wazuh")
        self.assertIsNone(used)


class TestCLI(unittest.TestCase):
    def _cli(self, *argv):
        import scripts_engineer_cli as m

        return m.EngineerCLI(m.parse(["--no-mcp", *argv]))

    def test_write_request_asks_and_cancel_runs_nothing(self):
        cli = self._cli()
        cli._ask = lambda prompt: "c"
        spec = pe.enhance("build a dashboard of web attacks", use_llm=False)
        buf = io.StringIO()
        with redirect_stdout(buf):
            self.assertEqual(cli.confirm_spec(spec), "cancel")
        self.assertIn("here's what I understood", buf.getvalue())

    def test_question_runs_without_asking(self):
        cli = self._cli()
        cli._ask = lambda prompt: (_ for _ in ()).throw(AssertionError("must not prompt"))
        self.assertEqual(cli.confirm_spec(pe.enhance("what is a siem", use_llm=False)), "run")

    def test_no_enhance_flag_and_command(self):
        cli = self._cli("--no-enhance")
        self.assertIsNone(cli.enhance("make a rule"))
        buf = io.StringIO()
        with redirect_stdout(buf):
            cli._slash("/enhance on")
        self.assertTrue(cli.enhance_on)

    def test_run_turn_attaches_the_spec(self):
        cli = self._cli()
        seen = {}

        def fake_run(message, history, engineer_skills=None):
            seen["message"] = message
            from cli.agents import TurnResult

            return TurnResult(reply="ok", mode="engineer"), history

        spec = pe.enhance("make a rule for ssh brute force", use_llm=False)
        with (
            mock.patch.object(cli.runner, "run", side_effect=fake_run),
            mock.patch("audit.audit_log"),
        ):
            cli.run_turn("make a rule for ssh brute force", spec)
        self.assertIn("Structured request from the prompt enhancer", seen["message"])


if __name__ == "__main__":
    unittest.main()


class TestCLIHistoryHygiene(unittest.TestCase):
    def test_history_keeps_the_users_words_not_the_spec_block(self):
        import scripts_engineer_cli as m
        from cli.agents import TurnResult

        cli = m.EngineerCLI(m.parse(["--no-mcp"]))
        msg = "make a rule for ssh brute force"

        def fake_run(message, history, engineer_skills=None):
            assert "Structured request" in message  # the agent does get the spec
            return TurnResult(reply="ok", mode="engineer"), history + [
                {"role": "user", "content": message},
                {"role": "assistant", "content": "ok"},
            ]

        with (
            mock.patch.object(cli.runner, "run", side_effect=fake_run),
            mock.patch("audit.audit_log"),
        ):
            cli.run_turn(msg, pe.enhance(msg, use_llm=False))
        self.assertEqual(cli.history[0]["content"], msg)
