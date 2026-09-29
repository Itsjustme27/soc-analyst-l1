"""
Interactive line editor for the terminal agent.

Three tiers, picked automatically:

  prompt_toolkit  (pip install -r requirements-cli.txt)
      completion menu with descriptions as you type, persistent history with
      Ctrl-R search and grey inline suggestions, a bottom status bar,
      Shift+Tab to switch analyst <-> engineer, Alt+Enter (or Esc then Enter)
      for a new line, Ctrl-C clears the line, Ctrl-D exits.
  readline        (standard library on Linux/macOS)
      Tab completion (press Tab twice to list) and persistent history.
  plain input()   when stdin isn't a terminal (pipes, tests) or with --plain.

All three share cli/completion.py, so what completes is identical.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any

from cli.completion import complete, parse_help

HISTORY_ENV = "SOC_CLI_HISTORY"


def history_path() -> Path:
    return Path(os.environ.get(HISTORY_ENV) or Path.home() / ".soc_cli_history")


def prompt_toolkit_available() -> bool:
    try:
        import prompt_toolkit  # noqa: F401

        return True
    except ImportError:
        return False


class PlainReader:
    backend = "plain"

    def __init__(self, cli: Any):
        self.cli = cli

    def read(self) -> str:
        # builtins.input looked up at call time, so tests can patch it
        return input(f"{self.cli.runner.mode} \u203a ")

    def close(self) -> None:
        pass


class ReadlineReader(PlainReader):
    backend = "readline"

    def __init__(self, cli: Any, help_text: str):
        super().__init__(cli)
        import readline

        self.readline = readline
        self.commands = parse_help(help_text)
        self._matches: list[str] = []
        readline.set_completer_delims(" \t\n")
        readline.set_completer(self._complete)
        # libedit (macOS system Python) uses a different binding syntax
        if "libedit" in (readline.__doc__ or ""):
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        try:
            readline.read_history_file(history_path())
        except (FileNotFoundError, OSError):
            pass
        readline.set_history_length(2000)

    def _complete(self, text: str, state: int) -> str | None:
        if state == 0:
            line = self.readline.get_line_buffer()[: self.readline.get_endidx()]
            _, choices = complete(line, self.cli, self.commands)
            self._matches = [v for v, _ in choices]
        return self._matches[state] if state < len(self._matches) else None

    def close(self) -> None:
        try:
            history_path().parent.mkdir(parents=True, exist_ok=True)
            self.readline.write_history_file(history_path())
        except OSError:
            pass


class ToolkitReader:
    backend = "prompt_toolkit"

    def __init__(self, cli: Any, help_text: str):
        from prompt_toolkit import PromptSession
        from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
        from prompt_toolkit.completion import Completer, Completion
        from prompt_toolkit.history import FileHistory
        from prompt_toolkit.key_binding import KeyBindings
        from prompt_toolkit.styles import Style

        self.cli = cli
        commands = parse_help(help_text)
        reader = self

        class _Completer(Completer):
            def get_completions(self, document, complete_event):  # noqa: ANN001
                n, choices = complete(document.text_before_cursor, reader.cli, commands)
                for value, meta in choices:
                    yield Completion(value, start_position=-n, display_meta=meta)

        kb = KeyBindings()

        @kb.add("s-tab")
        def _toggle_mode(event):  # noqa: ANN001
            runner = reader.cli.runner
            runner.set_mode("analyst" if runner.mode == "engineer" else "engineer")
            event.app.invalidate()

        @kb.add("escape", "enter")
        def _newline(event):  # noqa: ANN001
            event.current_buffer.insert_text("\n")

        history_path().parent.mkdir(parents=True, exist_ok=True)
        self._pending = (0.0, 0)
        self.session = PromptSession(
            history=FileHistory(str(history_path())),
            auto_suggest=AutoSuggestFromHistory(),
            completer=_Completer(),
            complete_while_typing=True,
            key_bindings=kb,
            bottom_toolbar=self.toolbar,
            style=Style.from_dict(
                {
                    "prompt.mode": "bold #f0b43c",
                    "bottom-toolbar": "noreverse #8ea2b5 bg:#0d151e",
                    "bottom-toolbar.key": "bold #e4ecf3 bg:#0d151e",
                    "bottom-toolbar.warn": "bold #f0b43c bg:#0d151e",
                    "completion-menu.completion": "bg:#1f2f40 #e4ecf3",
                    "completion-menu.completion.current": "bg:#f0b43c #231703",
                    "completion-menu.meta.completion": "bg:#182533 #8ea2b5",
                    "completion-menu.meta.completion.current": "bg:#f5c25c #231703",
                }
            ),
        )

    def _pending_count(self) -> int:
        # the toolbar redraws on every keystroke - read the approvals store at most every 5s
        ts, n = self._pending
        if time.time() - ts > 5:
            try:
                n = int(self.cli._pending_count() or 0)
            except Exception:  # noqa: BLE001
                n = 0
            self._pending = (time.time(), n)
        return n

    def toolbar(self) -> list[tuple[str, str]]:
        return toolbar_fragments(self.cli, self._pending_count())

    def _message(self) -> list[tuple[str, str]]:
        # a function, not a value: Shift+Tab redraws it with the new mode
        return [("class:prompt.mode", self.cli.runner.mode), ("", " \u203a ")]

    def read(self) -> str:
        return self.session.prompt(self._message)

    def close(self) -> None:
        pass


def toolbar_fragments(cli: Any, pending: int) -> list[tuple[str, str]]:
    """Bottom status bar: mode · model · MCP · pending approvals · tokens · hints."""
    parts: list[tuple[str, str]] = [("class:bottom-toolbar.key", f" {cli.runner.mode} ")]
    try:
        from cli import connections

        cur = connections.current_model()
        parts.append(("", f" {cur['backend']}{('/' + cur['model']) if cur.get('model') else ''} "))
    except Exception:  # noqa: BLE001
        pass
    mcp = getattr(cli, "mcp", None)
    if mcp is not None:
        live = len(mcp.connected())
        parts.append(("", f"\u00b7 MCP {live} "))
    if pending:
        parts.append(
            (
                "class:bottom-toolbar.warn",
                f"\u00b7 {pending} pending approval{'s' if pending != 1 else ''} ",
            )
        )
    parts.append(("", f"\u00b7 tokens {'lean' if cli.runner.lean else 'full'} "))
    parts.append(
        ("", "\u00b7 Tab complete \u00b7 Shift+Tab mode \u00b7 Alt+Enter newline \u00b7 /help ")
    )
    return parts


def make_reader(cli: Any, help_text: str, *, plain: bool = False) -> Any:
    """Best available reader for this terminal."""
    if plain or not (sys.stdin.isatty() and sys.stdout.isatty()):
        return PlainReader(cli)
    if prompt_toolkit_available():
        try:
            return ToolkitReader(cli, help_text)
        except Exception:  # noqa: BLE001 - odd terminals: degrade, don't crash
            pass
    try:
        return ReadlineReader(cli, help_text)
    except ImportError:  # Windows without pyreadline
        return PlainReader(cli)
