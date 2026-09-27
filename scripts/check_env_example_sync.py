#!/usr/bin/env python3
"""Fail if a config key in config.py is undocumented in .env.example.

Run in CI and pre-commit so the two never drift again. Purely additive -
safe to run anywhere, no network, no side effects.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    cfg = (ROOT / "config.py").read_text(encoding="utf-8")
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    cfg_keys = set(re.findall(r'os\.(?:getenv|_bool)\(\s*[\x27"]([A-Z0-9_]+)[\x27"]', cfg))
    env_keys = set(re.findall(r"^\s*#?\s*([A-Z0-9_]+)=", env, re.M))
    missing = sorted(cfg_keys - env_keys)
    if missing:
        print(f"config.py keys missing from .env.example: {missing}")
        return 1
    print("config/.env.example drift check OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())