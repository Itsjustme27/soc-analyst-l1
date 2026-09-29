"""Status bar builder for the interactive terminal UI.

Builds the bottom toolbar line showing:
  mode · session · active skills · approvals mode · pending count ·
  MCP state · lean/full tokens

All state is passed in as a dict; no global mutable state is used.
"""
from __future__ import annotations

from typing import Any

from cli.ui.theme import ROYAL, ROYAL_LIGHT, ROYAL_DIM, GREY, _no_color


def build_status_line(state: dict[str, Any]) -> str:
    """Build the status bar string from the current state dict.

    Parameters
    ----------
    state:
        Dict with keys: ``mode``, ``session``, ``skills``,
        ``approval_mode``, ``pending_count``, ``mcp_state``,
        ``token_mode``.  Missing keys render as ``-``.

    Returns
    -------
    A formatted status bar string suitable for prompt_toolkit's
    ``bottom_toolbar``.
    """
    mode = state.get("mode") or "-"
    session = state.get("session") or "-"
    skills = state.get("skills") or []
    approval_mode = state.get("approval_mode") or "-"
    pending = state.get("pending_count", 0)
    mcp = state.get("mcp_state") or "-"
    tokens = state.get("token_mode") or "-"

    skill_str = ",".join(skills[:3]) if skills else "none"
    if len(skills) > 3:
        skill_str += f"+{len(skills) - 3}"

    parts = [
        f" {mode} ",
        f"session:{session} ",
        f"skills:{skill_str} ",
        f"appr:{approval_mode} ",
        f"pending:{pending} ",
        f"mcp:{mcp} ",
        f"tokens:{tokens} ",
    ]

    if _no_color():
        return " | ".join(parts).strip()

    # Royal accent on separators, light text on segments
    return f"{ROYAL_LIGHT} | ".join(
        f"{SEG}" for SEG in parts
    ).strip()


def get_status_state(
    *,
    mode: str,
    session: str | None,
    skills: list[str],
    approval_mode: str,
    pending_count: int,
    mcp_connected: bool,
    mcp_tool_count: int,
    token_mode: str,
) -> dict[str, Any]:
    """Derive the status bar state dict from current runtime values."""
    if _no_color():
        return {
            "mode": mode,
            "session": session or "-",
            "skills": skills,
            "approval_mode": approval_mode,
            "pending_count": pending_count,
            "mcp_state": "connected" if mcp_connected else "off",
            "token_mode": token_mode,
        }
    return {
        "mode": mode,
        "session": session or "-",
        "skills": skills,
        "approval_mode": approval_mode,
        "pending_count": pending_count,
        "mcp_state": f"connected ({mcp_tool_count} tools)" if mcp_connected else "off",
        "token_mode": token_mode,
    }


__all__ = [
    "build_status_line",
    "get_status_state",
]
