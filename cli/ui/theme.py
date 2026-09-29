"""Royal blue + black theme.  The only place colors are defined.

Every colour used in the interactive UI must come from this module.
No hex literals or colour names appear elsewhere in cli/ui/.

Palette (define once, reference everywhere):
  BLACK       #000000  backgrounds of panels, input box, status bar, code blocks
  ROYAL       #4169E1  primary accent: prompt ">", borders, headings, spinner,
                        selected completion item, links, active status-bar segments
  ROYAL_LIGHT #7B9BFF  secondary text on black: tool step names, table headers, hints
  ROYAL_DIM   #2B4BB5  dividers, inactive borders, timestamps
  WHITE       #E8ECF8  main body text (soft white so it isn't harsh on black)
  GREY        #6B7280  muted text, "⎿" result lines, placeholder text

Status colours (small, consistent, safety-meaning only):
  approve/success = #3FB950, reject/error = #F85149, warning/pending = #E3B341
"""
from __future__ import annotations

import os

from prompt_toolkit.styles import Style
from rich.theme import Theme

# --------------------------------------------------------------------------- #
# Palette
# --------------------------------------------------------------------------- #
BLACK = "#000000"
ROYAL = "#4169E1"
ROYAL_LIGHT = "#7B9BFF"
ROYAL_DIM = "#2B4BB5"
WHITE = "#E8ECF8"
GREY = "#6B7280"

# Safety-status colours (allowed only for safety meaning)
OK = "#3FB950"
ERR = "#F85149"
WARN = "#E3B341"

SOC_UI_THEME = os.environ.get("SOC_UI_THEME", "royal")

# --------------------------------------------------------------------------- #
# rich theme
# --------------------------------------------------------------------------- #
RICH_THEME = Theme({
    "accent": f"bold {ROYAL}",
    "tool": ROYAL_LIGHT,
    "result": GREY,
    "muted": GREY,
    "border": ROYAL,
    "ok": OK,
    "err": ERR,
    "warn": WARN,
})

# --------------------------------------------------------------------------- #
# prompt_toolkit style
# --------------------------------------------------------------------------- #
PT_STYLE = Style.from_dict({
    "": f"{WHITE} bg:{BLACK}",
    "prompt": f"bold {ROYAL}",
    "bottom-toolbar": f"{ROYAL_LIGHT} bg:{BLACK}",
    "completion-menu": f"{WHITE} bg:{BLACK}",
    "completion-menu.completion.current": f"bg:{ROYAL} {BLACK}",
    "completion-menu.meta.completion": f"{GREY} bg:{BLACK}",
})

# --------------------------------------------------------------------------- #
# 256-color fallbacks (nearest to the palette above)
# --------------------------------------------------------------------------- #
ROYAL_256 = "62"
ROYAL_LIGHT_256 = "111"
WHITE_256 = "255"
GREY_256 = "245"
BLACK_256 = "16"
OK_256 = "46"
ERR_256 = "196"
WARN_256 = "214"

# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _no_color() -> bool:
    """Return True if the caller wants no colours."""
    if os.environ.get("NO_COLOR"):
        return True
    if os.environ.get("FORCE_COLOR") == "0":
        return True
    return False

__all__ = [
    "BLACK", "ROYAL", "ROYAL_LIGHT", "ROYAL_DIM", "WHITE", "GREY",
    "OK", "ERR", "WARN", "SOC_UI_THEME",
    "RICH_THEME", "PT_STYLE",
    "ROYAL_256", "ROYAL_LIGHT_256", "WHITE_256", "GREY_256",
    "BLACK_256", "OK_256", "ERR_256", "WARN_256",
    "_no_color",
]
