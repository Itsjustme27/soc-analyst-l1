"""Selects which shipped system-prompt set the agent loops should send.

Two complete prompt sets live side by side in this package:

``default``
    The original compact briefs in each agent module. This is the default,
    it is unchanged in behaviour, and it is the set the existing test
    suite asserts against.

``detailed``
    Longer, more explicit "SOC L1 Analyst" / "SOC Engineer" briefs covering
    mission, workflow, hard rules, judgment criteria and output style. The
    analyst brief is split along the same seam the code already uses - the
    triage half lives in ``triage_agent``, the conversational half in
    ``chat_agent``.

Set ``PROMPT_PROFILE=detailed`` to switch every loop at once. The two sets
coexist: picking one never mutates or removes the other, so reverting is a
one-line env change and not a code revert.
"""

from __future__ import annotations

from config import cfg

PROFILES: tuple[str, ...] = ("default", "detailed")
DEFAULT_PROFILE = "default"


def resolve(default_prompt: str, detailed_prompt: str) -> str:
    """Return the prompt for the active ``PROMPT_PROFILE``.

    An unrecognised profile falls back to ``default_prompt`` instead of
    raising, so a typo in ``.env`` degrades to the tested prompts rather
    than breaking agent import.
    """
    if getattr(cfg, "PROMPT_PROFILE", DEFAULT_PROFILE) == "detailed":
        return detailed_prompt
    return default_prompt


def active_profile() -> str:
    """Return the active profile name, normalised to a known value."""
    profile = getattr(cfg, "PROMPT_PROFILE", DEFAULT_PROFILE)
    return profile if profile in PROFILES else DEFAULT_PROFILE
