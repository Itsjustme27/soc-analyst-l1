"""CLI UI package - presentation layer for scripts_engineer_cli.py.

All visual rendering, input handling, theming, and status-line
building lives here.  The rest of the codebase is untouched.
"""
from __future__ import annotations

from cli.ui.theme import (
    BLACK,
    ERR,
    GREY,
    OK,
    PT_STYLE,
    RICH_THEME,
    ROYAL,
    ROYAL_DIM,
    ROYAL_LIGHT,
    SOC_UI_THEME,
    WARN,
    WHITE,
)

__all__ = [
    "BLACK", "ERR", "GREY", "OK", "ROYAL", "ROYAL_DIM", "ROYAL_LIGHT",
    "SOC_UI_THEME", "WARN", "WHITE", "RICH_THEME", "PT_STYLE",
]
