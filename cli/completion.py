"""
Tab completion for the terminal agent - pure Python, no terminal library.

The command list is PARSED FROM the CLI's HELP text, so /help and completion
can never drift apart: add a command to HELP and it completes. Argument
completion is data-driven - each (command, argument position) maps to a
source on the CLI (skills, MCP servers, proposal ids, ...), read live, so a
freshly installed skill or newly connected MCP server completes immediately.

Also completes `@skill` mentions anywhere in a message: `@mitre-mapping` in a
request activates that skill for that one turn.

Used by cli/terminal.py (prompt_toolkit or readline front end); tested
directly in tests/test_cli_terminal.py.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

Choice = tuple[str, str]  # (value, short description shown in the menu)
Source = Callable[[Any], list[Choice]]


@dataclass
class Command:
    name: str
    usage: str
    description: str


_HELP_LINE = re.compile(r"^\s{2}(/[a-z][a-z-]*)((?:,\s?/[a-z][a-z-]*|\s[^\s].*?)?)\s{2,}(\S.*)$")


def parse_help(help_text: str) -> dict[str, Command]:
    """{"/use": Command(...), ...} from lines like '  /use <name>   activate...'.
    Handles '/exit, /quit' and repeated commands (/mcp, /proposals) by merging."""
    out: dict[str, Command] = {}
    for line in help_text.splitlines():
        m = _HELP_LINE.match(line)
        if not m:
            continue
        head, rest, desc = m.group(1), m.group(2).strip(), m.group(3).strip()
        names = [head]
        if rest.startswith(","):  # "/exit, /quit"
            names += re.findall(r"/[a-z][a-z-]*", rest)
            rest = ""
        for name in names:
            if name in out:
                if rest and rest not in out[name].usage:
                    prev = out[name].usage
                    out[name].usage = f"{prev} | {rest}" if prev else rest
            else:
                out[name] = Command(name=name, usage=rest, description=desc)
    return out


# --------------------------------------------------------------------------- #
# live data sources - each takes the CLI object and never raises
# --------------------------------------------------------------------------- #
def _safe(fn: Callable[[Any], list[Choice]]) -> Source:
    def wrapped(cli: Any) -> list[Choice]:
        try:
            return fn(cli)
        except Exception:  # noqa: BLE001 - completion must never break typing
            return []

    return wrapped


@_safe
def skills(cli: Any) -> list[Choice]:
    from agent.skills import discover_skills

    active = set(getattr(cli, "skills", []) or [])
    return [
        (s.name, ("active · " if s.name in active else "") + s.description)
        for s in discover_skills()
    ]


@_safe
def active_skills(cli: Any) -> list[Choice]:
    return [(s, "active") for s in getattr(cli, "skills", []) or []]


@_safe
def mcp_servers(cli: Any) -> list[Choice]:
    from cli.mcp_client import load_config

    live = cli.mcp.connected() if getattr(cli, "mcp", None) else {}
    return [
        (n, "connected" if n in live else ("url" if s.get("url") else "stdio"))
        for n, s in load_config().items()
    ]


@_safe
def mcp_tools(cli: Any) -> list[Choice]:
    tools = cli.mcp.tools() if getattr(cli, "mcp", None) else []
    return [
        (t.id, ("READ · " if t.read_only else "needs approval · ") + t.description[:60])
        for t in tools
    ]


def _proposals(status: str | None) -> Source:
    @_safe
    def src(cli: Any) -> list[Choice]:
        import approvals

        return [
            (p["id"], f"{p.get('status')} · {p.get('action')}")
            for p in approvals.list_proposals(status=status)
        ][:50]

    return src


@_safe
def providers(cli: Any) -> list[Choice]:
    from cli import connections

    return [
        (p["id"], f"{p.get('platform')} · {p.get('name')}") for p in connections.list_providers()
    ]


@_safe
def platforms(cli: Any) -> list[Choice]:
    from cli import connections

    return [(k, (v or {}).get("label", k)) for k, v in connections.platforms().items()]


@_safe
def backends(cli: Any) -> list[Choice]:
    from cli import connections

    return [(b, "LLM backend") for b in connections.llm_backends()]


@_safe
def agents(cli: Any) -> list[Choice]:
    return [(n, d[:70]) for n, d in cli.runner.available_agents().items()]


def _const(*pairs: Choice) -> Source:
    return lambda cli: list(pairs)


ON_OFF = _const(("on", ""), ("off", ""))
STATUSES = _const(
    *[
        (s, "")
        for s in ("pending", "approved", "executing", "executed", "failed", "rejected", "expired")
    ]
)

# (command, arg index) -> source. For /mcp, the first arg is a subcommand and the
# second depends on it (keyed as "/mcp start" etc).
ARGS: dict[tuple[str, int], Source] = {
    ("/use", 0): skills,
    ("/unuse", 0): active_skills,
    ("/auto-skills", 0): ON_OFF,
    ("/mode", 0): _const(
        ("analyst", "L1 triage / investigation"), ("engineer", "rules, dashboards, gaps")
    ),
    ("/delegate", 0): agents,
    ("/delegation", 0): ON_OFF,
    ("/load-skills", 0): ON_OFF,
    ("/connect", 0): platforms,
    ("/disconnect", 0): providers,
    ("/test", 0): providers,
    ("/siem", 0): lambda cli: providers(cli) + [("off", "no live SIEM")],
    ("/model", 0): backends,
    ("/tokens", 0): _const(("lean", "trimmed tool set (default)"), ("full", "every tool schema")),
    ("/enhance", 0): ON_OFF,
    ("/approvals", 0): _const(("ask", "review inline after each turn"), ("manual", "use /approve")),
    ("/mcp", 0): _const(
        ("tools", "list MCP tools"),
        ("start", "connect a server"),
        ("stop", "disconnect a server"),
        ("allow", "always allow a tool"),
    ),
    ("/mcp tools", 0): mcp_servers,
    ("/mcp start", 0): mcp_servers,
    ("/mcp stop", 0): mcp_servers,
    ("/mcp allow", 0): lambda cli: [c for c in mcp_tools(cli) if "needs approval" in c[1]],
    ("/proposals", 0): lambda cli: STATUSES(cli) + _proposals(None)(cli),
    ("/approve", 0): _proposals("pending"),
    ("/reject", 0): _proposals("pending"),
    ("/execute", 0): _proposals("approved"),
}
FLAGS: dict[str, list[Choice]] = {"/execute": [("--confirm", "required for EXECUTE-level actions")]}


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #
_MENTION = re.compile(r"(?:^|\s)@([A-Za-z0-9_-]*)$")


def complete(line: str, cli: Any, commands: dict[str, Command]) -> tuple[int, list[Choice]]:
    """Completions for the text before the cursor.

    Returns (replace_len, choices): the last `replace_len` characters of `line`
    are the fragment being completed, and each choice replaces it."""
    # @skill mentions work anywhere in a normal message
    m = _MENTION.search(line)
    if m and not line.lstrip().startswith("/"):
        frag = m.group(1)
        return len(frag) + 1, [("@" + v, d) for v, d in skills(cli) if v.startswith(frag)]

    if not line.startswith("/"):
        return 0, []
    parts = line.split(" ")
    if len(parts) == 1:  # completing the command name itself
        frag = parts[0]
        return len(frag), sorted(
            (c.name, (c.usage + "  " if c.usage else "") + "- " + c.description)
            for c in commands.values()
            if c.name.startswith(frag)
        )

    cmd, args, frag = parts[0], [a for a in parts[1:-1] if a], parts[-1]
    key: tuple[str, int] | None = None
    if cmd == "/mcp" and args:
        key = (f"/mcp {args[0]}", len(args) - 1)
    else:
        key = (cmd, len(args))
    choices: list[Choice] = []
    if key in ARGS:
        choices = ARGS[key](cli)
    if frag.startswith("-") or (not choices and cmd in FLAGS):
        choices = choices + FLAGS.get(cmd, [])
    return len(frag), [(v, d) for v, d in choices if v.startswith(frag)]


def mentioned_skills(text: str, installed: set[str]) -> list[str]:
    """`@skill` mentions in a message that name an installed skill."""
    return [
        n
        for n in dict.fromkeys(re.findall(r"(?:^|\s)@([A-Za-z0-9_-]+)", text or ""))
        if n in installed
    ]
