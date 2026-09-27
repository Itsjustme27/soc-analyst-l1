"""
MCP (Model Context Protocol) client for the CLI - connect external tools the
way Claude Code / Codex do, without touching the agent or tool-registry code.

Config: `.mcp.json` in the repo root (or the path in $MCP_CONFIG), same shape
as Claude Code's:

    {
      "mcpServers": {
        "virustotal": {
          "command": "npx", "args": ["-y", "@example/vt-mcp"],
          "env": {"VT_API_KEY": "${VT_API_KEY}"},
          "read_only_tools": ["lookup_ip", "lookup_hash"]
        },
        "tickets": {"url": "https://mcp.example.com/mcp",
                    "headers": {"Authorization": "Bearer ${TICKETS_TOKEN}"}}
      }
    }

`${VAR}` is expanded from the environment, so secrets stay in .env, not in
the config file.

Permission model (enforced by cli/middleware.py, not by the server):
  * a tool is READ only if the operator lists it in `read_only_tools`
    (server-declared readOnlyHint annotations are NOT trusted unless the
    server sets "trust_read_only_hints": true);
  * everything else needs an inline human approval per call (or an explicit
    "always for this session" for that one tool);
  * in non-interactive runs (one-shot / --json) non-read MCP calls are refused.

The SDK is async; this manager runs one asyncio loop on a daemon thread and
keeps each server's session open on it, exposing a small sync API.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_CONFIG = Path(__file__).resolve().parent.parent / ".mcp.json"
TOOL_PREFIX = "mcp__"
_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class MCPError(RuntimeError):
    pass


def mcp_available() -> bool:
    try:
        import mcp  # noqa: F401
        return True
    except ImportError:
        return False


def _expand(value: Any) -> Any:
    if isinstance(value, str):
        def _repl(m: re.Match[str]) -> str:
            name = m.group(1)
            if name not in os.environ:
                logging.getLogger(__name__).warning(
                    "MCP config references ${%s} which is not set - substituting ''", name)
            return os.environ.get(name, "")
        return _ENV_RE.sub(_repl, value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def config_path() -> Path:
    return Path(os.environ.get("MCP_CONFIG") or DEFAULT_CONFIG)


def load_config(path: str | Path | None = None) -> dict[str, dict[str, Any]]:
    p = Path(path) if path else config_path()
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        raise MCPError(f"cannot read MCP config {p}: {e}") from e
    servers = data.get("mcpServers") or {}
    if not isinstance(servers, dict):
        raise MCPError(f"{p}: 'mcpServers' must be an object")
    out = {}
    for name, spec in servers.items():
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", name or ""):
            raise MCPError(f"invalid MCP server name {name!r} (letters, digits, _ and - only)")
        if not isinstance(spec, dict) or not (spec.get("command") or spec.get("url")):
            raise MCPError(f"MCP server {name!r} needs 'command' (stdio) or 'url' (HTTP)")
        out[name] = spec
    return out


def tool_id(server: str, tool: str) -> str:
    return f"{TOOL_PREFIX}{server}__{tool}"


def split_tool_id(name: str) -> tuple[str, str] | None:
    if not name.startswith(TOOL_PREFIX):
        return None
    server, sep, tool = name[len(TOOL_PREFIX):].partition("__")
    return (server, tool) if sep and server and tool else None


@dataclass
class MCPTool:
    server: str
    name: str
    description: str
    input_schema: dict[str, Any]
    read_only: bool

    @property
    def id(self) -> str:
        return tool_id(self.server, self.name)

    def definition(self, max_desc: int | None = None) -> dict[str, Any]:
        desc = self.description or ""
        if max_desc and len(desc) > max_desc:
            desc = desc[: max_desc - 1] + "…"
        tag = "READ" if self.read_only else "needs human approval"
        return {"name": self.id, "description": f"[MCP {self.server} · {tag}] {desc}",
                "input_schema": self.input_schema or {"type": "object", "properties": {}}}


@dataclass
class _Server:
    name: str
    spec: dict[str, Any]
    stack: Any = None
    session: Any = None
    tools: list[MCPTool] = field(default_factory=list)
    error: str | None = None


class MCPManager:
    def __init__(self, config: dict[str, dict[str, Any]] | None = None, timeout: float = 60.0):
        self.config = config if config is not None else {}
        self.timeout = timeout
        self._servers: dict[str, _Server] = {}
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ loop plumbing
    def _ensure_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is None:
            self._loop = asyncio.new_event_loop()
            self._thread = threading.Thread(target=self._loop.run_forever, name="mcp-loop", daemon=True)
            self._thread.start()
        return self._loop

    def _run(self, coro: Any, timeout: float | None = None) -> Any:
        fut = asyncio.run_coroutine_threadsafe(coro, self._ensure_loop())
        try:
            return fut.result(timeout or self.timeout)
        except TimeoutError as e:
            fut.cancel()
            raise MCPError("MCP call timed out") from e

    # ------------------------------------------------------------ servers
    async def _open(self, srv: _Server) -> None:
        from mcp import ClientSession
        stack = contextlib.AsyncExitStack()
        spec = _expand(srv.spec)
        try:
            if spec.get("command"):
                from mcp import StdioServerParameters
                from mcp.client.stdio import stdio_client
                env = {**os.environ, **(spec.get("env") or {})}
                params = StdioServerParameters(command=spec["command"], args=list(spec.get("args") or []),
                                               env=env, cwd=spec.get("cwd"))
                devnull = stack.enter_context(open(os.devnull, "w"))  # keep server stderr off the REPL
                read, write = await stack.enter_async_context(stdio_client(params, errlog=devnull))
            else:
                try:
                    from mcp.client.streamable_http import streamablehttp_client as http_client
                except ImportError:
                    from mcp.client.streamable_http import streamable_http_client as http_client
                streams = await stack.enter_async_context(
                    http_client(spec["url"], headers=spec.get("headers") or None))
                read, write = streams[0], streams[1]
            session = await stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            listed = await session.list_tools()
        except BaseException:
            await stack.aclose()
            raise
        allow = set(spec.get("read_only_tools") or [])
        trust_hints = bool(spec.get("trust_read_only_hints"))
        tools = []
        for t in getattr(listed, "tools", []) or []:
            ann = getattr(t, "annotations", None)
            hinted = bool(getattr(ann, "readOnlyHint", False)) if ann else False
            schema = getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or {}
            tools.append(MCPTool(server=srv.name, name=t.name, description=t.description or "",
                                 input_schema=dict(schema), read_only=t.name in allow or (trust_hints and hinted)))
        srv.stack, srv.session, srv.tools, srv.error = stack, session, tools, None

    def start(self, name: str) -> _Server:
        if not mcp_available():
            raise MCPError("the 'mcp' package isn't installed - run: pip install mcp")
        if name not in self.config:
            raise MCPError(f"no MCP server {name!r} in {config_path()}")
        srv = self._servers.get(name) or _Server(name=name, spec=self.config[name])
        self._servers[name] = srv
        if srv.session is None:
            try:
                self._run(self._open(srv))
            except Exception as e:  # noqa: BLE001
                srv.error = str(e) or e.__class__.__name__
                raise MCPError(f"{name}: {srv.error}") from e
        return srv

    def start_all(self) -> dict[str, str | None]:
        results = {}
        for name, spec in self.config.items():
            if spec.get("enabled", True) is False:
                continue
            try:
                self.start(name)
                results[name] = None
            except MCPError as e:
                results[name] = str(e)
        return results

    def stop(self, name: str) -> None:
        srv = self._servers.pop(name, None)
        if srv and srv.stack is not None:
            try:
                self._run(srv.stack.aclose(), timeout=10)
            except Exception:  # noqa: BLE001 - best-effort shutdown
                pass

    def close(self) -> None:
        for name in list(self._servers):
            self.stop(name)
        if self._loop is not None:
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._loop = None

    # ------------------------------------------------------------ tools
    def connected(self) -> dict[str, _Server]:
        return {n: s for n, s in self._servers.items() if s.session is not None}

    def tools(self) -> list[MCPTool]:
        return [t for s in self.connected().values() for t in s.tools]

    def get_tool(self, name: str) -> MCPTool | None:
        return next((t for t in self.tools() if t.id == name), None)

    def search(self, query: str, limit: int = 8) -> list[MCPTool]:
        terms = [w for w in re.findall(r"[a-z0-9]+", (query or "").lower()) if len(w) > 2]
        scored = []
        for t in self.tools():
            hay = f"{t.server} {t.name} {t.description}".lower()
            score = sum(hay.count(w) for w in terms)
            if score or not terms:
                scored.append((score, t))
        scored.sort(key=lambda x: -x[0])
        return [t for _, t in scored[:limit]]

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self.get_tool(name)
        if tool is None:
            raise MCPError(f"unknown MCP tool {name}")
        srv = self._servers[tool.server]

        async def _call():
            return await srv.session.call_tool(tool.name, arguments or {})

        res = self._run(_call())
        parts = []
        for c in getattr(res, "content", []) or []:
            if getattr(c, "type", "") == "text":
                parts.append(c.text)
            else:
                parts.append(f"[{getattr(c, 'type', 'content')} omitted]")
        structured = getattr(res, "structuredContent", None) or getattr(res, "structured_content", None)
        out: dict[str, Any] = {"server": tool.server, "tool": tool.name, "is_error": bool(getattr(res, "isError", False)),
                               "text": "\n".join(parts)}
        if structured:
            out["structured"] = structured
        return out
