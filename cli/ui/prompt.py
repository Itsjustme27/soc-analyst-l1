"""Interactive prompt input using prompt_toolkit.

Provides a bordered input box with:
  - ``>`` prompt (royal accent) and ``? for shortcuts`` hint
  - Persistent history (~/.soc-agent/history) with up/down recall
  - Ctrl+R incremental search
  - Multiline: Alt+Enter (or Esc then Enter) inserts newline; Enter submits
  - Typing ``/`` opens a fuzzy-filtered completion menu with descriptions
  - Tab completion for /use (skill names), /mode (modes), /resume (sessions), @file paths
  - Shift+Tab cycles mode (analyst <-> engineer)
  - Ctrl+C clears line; twice quits; Ctrl+D quits
  - Esc cancels the current agent run and returns to prompt
"""
from __future__ import annotations

import os
from collections.abc import Callable, Iterable
from pathlib import Path

from prompt_toolkit import PromptSession
from prompt_toolkit.completion import (
    Completion,
    FuzzyCompleter,
    WordCompleter,
)
from prompt_toolkit.history import FileHistory
from prompt_toolkit.key_binding import KeyBindings

from cli.ui.theme import PT_STYLE

# --------------------------------------------------------------------------- #
# History
# --------------------------------------------------------------------------- #
_HISTORY_PATH = Path(os.path.expanduser("~/.soc-agent/history"))

def _ensure_history_dir() -> None:
    _HISTORY_PATH.parent.mkdir(parents=True, exist_ok=True)

_ensure_history_dir()

# --------------------------------------------------------------------------- #
# Completers
# --------------------------------------------------------------------------- #
def _make_slash_completer(
    commands: dict[str, str],
    skill_names: Iterable[str] | None = None,
    session_names: Iterable[str] | None = None,
    file_paths: Iterable[str] | None = None,
) -> FuzzyCompleter:
    """Build a fuzzy completer for / commands, /use skills, /resume sessions,
    and @file paths."""
    completions: list[Completion] = []
    for cmd, desc in commands.items():
        completions.append(Completion(cmd, display=cmd, display_meta=desc))
    if skill_names:
        for s in skill_names:
            completions.append(Completion(s, display=f"/use {s}"))
    if session_names:
        for s in session_names:
            completions.append(Completion(s, display=f"/resume {s}"))
    if file_paths:
        for f in file_paths:
            completions.append(Completion(f, display=f"@{f}"))
    return FuzzyCompleter(WordCompleter(completions, sentence=True))


# --------------------------------------------------------------------------- #
# Prompt session factory
# --------------------------------------------------------------------------- #
def create_prompt_session() -> PromptSession:
    """Create a prompt_toolkit PromptSession with history and key bindings."""
    return PromptSession(
        history=FileHistory(_HISTORY_PATH),
        style=PT_STYLE,
        complete_while_typing=True,
        search_ignore_case=True,
    )


def create_key_bindings(
    on_mode_switch: Callable[[], None] | None = None,
    on_cancel: Callable[[], None] | None = None,
) -> KeyBindings:
    """Create key bindings for the interactive prompt.

    Parameters
    ----------
    on_mode_switch:
        Called when Shift+Tab is pressed (cycle analyst <-> engineer).
    on_cancel:
        Called when Esc is pressed during agent execution (cancel current run).
    """
    kb = KeyBindings()

    @kb.add("escape")
    def _(event):
        """Escape cancels current run or clears line."""
        if on_cancel:
            on_cancel()
        event.current_buffer.reset()

    @kb.add("c-d")
    def _(event):
        """Ctrl+D quits the REPL."""
        event.app.exit(result="exit")

    @kb.add("tab", eager=True)
    def _(event):
        """Tab triggers completion."""
        event.current_buffer.complete_next()

    @kb.add("shift-tab", eager=True)
    def _(event):
        """Shift+Tab cycles mode (analyst <-> engineer)."""
        if on_mode_switch:
            on_mode_switch()

    @kb.add("alt-enter")
    def _(event):
        """Alt+Enter inserts a newline for multiline input."""
        event.current_buffer.insert_text("\n")

    return kb


# --------------------------------------------------------------------------- #
# Public prompt function
# --------------------------------------------------------------------------- #
def prompt_input(
    session: PromptSession | None = None,
    kb: KeyBindings | None = None,
    prompt_text: str = "> ",
    hint_text: str = "? for shortcuts",
    completer: FuzzyCompleter | None = None,
) -> str:
    """Display the bordered input box and return the user's input.

    Returns empty string on EOF (Ctrl+D).  Raises KeyboardInterrupt on
    Ctrl+C at the prompt.
    """
    if session is None:
        session = create_prompt_session()
    if kb is None:
        kb = create_key_bindings()
    _ensure_history_dir()

    return session.prompt(
        prompt_text,
        completer=completer,
        key_bindings=kb,
        bottom_toolbar=hint_text,
    )


__all__ = [
    "create_prompt_session",
    "create_key_bindings",
    "prompt_input",
    "_HISTORY_PATH",
    "_make_slash_completer",
]
