"""Terminal UX for scripts_engineer_cli.py: completion engine, @skill mentions,
status bar, reader selection, and a real prompt_toolkit session driven by
scripted keystrokes (skipped when prompt_toolkit isn't installed).

Run: python -m unittest tests.test_cli_terminal -v
"""

from __future__ import annotations

import io
import os
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import scripts_engineer_cli as cli_mod  # noqa: E402
from cli.completion import complete, mentioned_skills, parse_help  # noqa: E402
from cli.terminal import (  # noqa: E402
    PlainReader,
    make_reader,
    prompt_toolkit_available,
    toolbar_fragments,
)

COMMANDS = parse_help(cli_mod._HELP)


def make_cli():
    return cli_mod.EngineerCLI(cli_mod.parse(["--no-mcp"]))


class TestHelpParsing(unittest.TestCase):
    def test_every_help_command_is_completable(self):
        import re

        in_help = set(re.findall(r"^\s{2}(/[a-z][a-z-]*)", cli_mod._HELP, re.M)) | {"/quit"}
        self.assertEqual(set(COMMANDS), in_help)

    def test_repeated_commands_merge_usage(self):
        self.assertIn("start|stop <server>", COMMANDS["/mcp"].usage)
        self.assertFalse(COMMANDS["/mcp"].usage.startswith(" |"))


class TestCompletion(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cli = make_cli()

    def values(self, line):
        return [v for v, _ in complete(line, self.cli, COMMANDS)[1]]

    def test_command_names_with_descriptions(self):
        n, choices = complete("/mo", self.cli, COMMANDS)
        self.assertEqual(n, 3)
        self.assertEqual([v for v, _ in choices], ["/mode", "/model"])
        self.assertIn("show or switch", choices[0][1])

    def test_static_argument_choices(self):
        self.assertEqual(self.values("/mode "), ["analyst", "engineer"])
        self.assertEqual(self.values("/tokens f"), ["full"])
        self.assertEqual(self.values("/approvals "), ["ask", "manual"])
        self.assertIn("--confirm", self.values("/execute appr-1 --"))

    def test_live_sources(self):
        self.assertIn("mitre-mapping", self.values("/use "))
        self.assertIn("wazuh", self.values("/connect "))
        self.assertIn("mock", self.values("/model "))
        self.assertIn("analyst", self.values("/delegate "))
        self.assertEqual(self.values("/mcp "), ["tools", "start", "stop", "allow"])

    def test_mcp_subcommand_arguments(self):
        with (
            mock.patch("cli.completion.load_config", create=True),
            mock.patch("cli.mcp_client.load_config", return_value={"vt": {"command": "x"}}),
        ):
            self.assertEqual(self.values("/mcp start "), ["vt"])

    def test_proposal_ids_by_status(self):
        with tempfile.TemporaryDirectory() as d:
            import approvals
            from config import cfg

            with mock.patch.object(cfg, "APPROVALS_PATH", os.path.join(d, "a.json")):
                p = approvals.create_proposal(
                    action="create_wazuh_rule", reason="r", payload={}, user="u"
                )
                self.assertIn(p["id"], self.values("/approve "))
                self.assertNotIn(p["id"], self.values("/execute "))  # not approved yet

    def test_skill_mentions_in_messages(self):
        n, choices = complete("map this alert with @mit", self.cli, COMMANDS)
        self.assertEqual(n, 4)
        self.assertEqual([v for v, _ in choices], ["@mitre-mapping"])

    def test_plain_text_gets_no_completion(self):
        self.assertEqual(complete("show me ssh brute force", self.cli, COMMANDS), (0, []))

    def test_a_broken_source_never_breaks_typing(self):
        with mock.patch("agent.skills.discover_skills", side_effect=RuntimeError("disk gone")):
            self.assertEqual(self.values("/use "), [])


class TestMentions(unittest.TestCase):
    def test_only_installed_skills_count(self):
        self.assertEqual(
            mentioned_skills("use @mitre-mapping and @nope, email a@b.com", {"mitre-mapping"}),
            ["mitre-mapping"],
        )

    def test_mention_activates_skill_for_one_turn_only(self):
        from cli.agents import TurnResult

        cli = make_cli()
        seen = {}

        def fake_run(message, history, engineer_skills=None):
            seen["skills"] = engineer_skills
            return TurnResult(reply="ok", mode="engineer"), history

        buf = io.StringIO()
        with (
            mock.patch.object(cli.runner, "run", side_effect=fake_run),
            mock.patch("audit.audit_log"),
            redirect_stdout(buf),
        ):
            cli.run_turn("map this with @mitre-mapping")
        self.assertIn("mitre-mapping", seen["skills"])
        self.assertNotIn("mitre-mapping", cli.skills)  # not left active
        self.assertIn("skills for this turn: mitre-mapping", buf.getvalue())


class TestStatusBarAndReader(unittest.TestCase):
    def test_toolbar_shows_state(self):
        cli = make_cli()
        text = "".join(t for _, t in toolbar_fragments(cli, 3))
        for want in ("engineer", "3 pending approvals", "tokens lean", "Shift+Tab mode"):
            self.assertIn(want, text)
        self.assertNotIn("pending", "".join(t for _, t in toolbar_fragments(cli, 0)))

    def test_non_tty_and_plain_flag_use_plain_input(self):
        cli = make_cli()
        self.assertIsInstance(make_reader(cli, cli_mod._HELP, plain=True), PlainReader)
        with mock.patch("sys.stdin.isatty", return_value=False):
            self.assertIsInstance(make_reader(cli, cli_mod._HELP), PlainReader)

    def test_ctrl_c_clears_the_line_instead_of_exiting(self):
        cli = make_cli()
        inputs = iter([KeyboardInterrupt(), "/exit"])

        class R:
            backend = "plain"

            def read(self):
                x = next(inputs)
                if isinstance(x, BaseException):
                    raise x
                return x

            def close(self):
                pass

        cli._reader = R()
        with redirect_stdout(io.StringIO()):
            self.assertEqual(cli._repl_loop(), 0)


@unittest.skipUnless(prompt_toolkit_available(), "prompt_toolkit not installed")
class TestToolkitSession(unittest.TestCase):
    def _session(self, cli, keys):
        from prompt_toolkit.application import create_app_session
        from prompt_toolkit.input import create_pipe_input
        from prompt_toolkit.output import DummyOutput

        from cli.terminal import ToolkitReader

        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch.dict(os.environ, {"SOC_CLI_HISTORY": os.path.join(d, "h")}),
        ):
            with create_pipe_input() as inp, create_app_session(input=inp, output=DummyOutput()):
                reader = ToolkitReader(cli, cli_mod._HELP)

                def typist():
                    # keys arrive like a person types: completion runs in the
                    # background, so Tab must land before Enter does
                    for chunk in keys.split("|"):
                        time.sleep(0.25)
                        inp.send_text(chunk)

                threading.Thread(target=typist, daemon=True).start()
                return reader.read()

    def test_tab_completes_a_command(self):
        self.assertEqual(self._session(make_cli(), "/swi|\t|\r"), "/switch")

    def test_tab_completes_a_skill_argument(self):
        self.assertEqual(self._session(make_cli(), "/use mitre|\t|\r"), "/use mitre-mapping")

    def test_shift_tab_switches_mode(self):
        cli = make_cli()
        self._session(cli, "\x1b[Z|hi|\r")
        self.assertEqual(cli.runner.mode, "analyst")

    def test_alt_enter_inserts_a_newline(self):
        self.assertEqual(
            self._session(make_cli(), "line one|\x1b\r|line two|\r"), "line one\nline two"
        )


if __name__ == "__main__":
    unittest.main()
