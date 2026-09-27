"""Gate: no tracked .py may use syntax the project's Python 3.11 baseline bans.

The CI matrix runs the full test suite on Python 3.11, 3.12 and 3.13, so
nothing in the tree may rely on syntax that only exists in 3.12+ (PEP 701
relaxed the f-string tokenizer). This script statically enforces the
pre-3.12 f-string rules from any interpreter, so the 3.12/3.13 runners catch
a regression before the suite even runs:

  * a backslash inside the {expression} part of an f-string literal is a
    SyntaxError on 3.11 ("f-string expression part cannot include a
    backslash") - the escape must live in a plain string outside the braces.

Escapes in the *literal text* of an f-string (outside the braces) are fine and
are not flagged. The authoritative backstop remains the 3.11 CI job, which
compiles every module on import; this is a fast, portable pre-signal.

Usage:  python scripts/check_py311_syntax.py
Exit:   0 if clean, 1 on the first file that violates the rule.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

_PREFIXES = set("rRbBuUfF")
_PREFIXES_F = {"f", "F"}
_QUOTES = {'"', "'"}


def _fstring_problems(source: str) -> list[tuple[int, str]]:
    """Return [(line, message), ...] for pre-3.12 f-string violations in source."""
    problems: list[tuple[int, str]] = []
    i, n = 0, len(source)
    line = 1
    while i < n:
        ch = source[i]
        if ch == "\n":
            line += 1
        elif ch in _PREFIXES:
            # Collect a run of prefix letters (f, r, b, u) - a literal only
            # counts if it is an f-string (contains f/F) and starts a quote.
            j = i
            while j < n and source[j] in _PREFIXES:
                j += 1
            if j < n and source[j] in _QUOTES and (set(source[i:j]) & _PREFIXES_F):
                body_start_line = line
                # Determine the closing quote (single vs triple).
                q = source[j]
                triple = source.startswith(q * 3, j)
                k = j + (3 if triple else 1)
                while k < n:
                    if source[k] == "\\" and not triple:
                        k += 2
                        continue
                    if triple and source.startswith(q * 3, k):
                        k += 3
                        break
                    if not triple and source[k] == q:
                        k += 1
                        break
                    if source[k] == "\n":
                        line += 1
                    k += 1
                else:
                    # Unterminated literal; move past what we consumed and let
                    # the real interpreter report it - not our job here.
                    i = j + 1
                    continue
                body = source[j + (3 if triple else 1) : k - (3 if triple else 1)]
                expr_problems = _scan_expression_regions(body)
                for offset, message in expr_problems:
                    problems.append((body_start_line + offset, message))
                i = k
                continue
            i = j if j > i else i + 1
            continue
        i += 1
    return problems


def _scan_expression_regions(body: str) -> list[tuple[int, str]]:
    """Find {expression} regions inside an f-string body and lint them.

    Returns [(relative_line_offset, message), ...]. Handles {{ and }} literal
    escapes and nested braces; multi-line bodies are supported. The rule
    enforced here is the pre-3.12 tokenizer restriction on backslashes.
    """
    problems: list[tuple[int, str]] = []
    k, m = 0, len(body)
    depth = 0
    expr_start = None
    line = 0
    while k < m:
        ch = body[k]
        if ch == "\n":
            line += 1
            k += 1
            continue
        if depth == 0:
            if ch == "{":
                if k + 1 < m and body[k + 1] == "{":
                    k += 2  # escaped literal brace
                    continue
                depth = 1
                expr_start = k + 1
        else:
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    expr = body[expr_start:k]
                    if "\\" in expr:
                        problems.append((line, "backslash inside f-string expression"))
                    expr_start = None
        k += 1
    return problems


def main(argv: list[str]) -> int:
    root = pathlib.Path(argv[0]) if len(argv) > 0 else pathlib.Path(".")
    if root.is_file():
        files = [root]
    else:
        listed = subprocess.run(
            ["git", "ls-files", "*.py"], capture_output=True, text=True, cwd=root
        )
        if listed.returncode != 0:
            # Not a git checkout (or git missing): fall back to a plain walk.
            files = sorted(root.rglob("*.py"))
        else:
            files = [root / p for p in listed.stdout.splitlines()]

    failed = False
    for path in sorted(files):
        source = path.read_text(encoding="utf-8")
        for line_no, message in _fstring_problems(source):
            failed = True
            print(f"{path}:{line_no}: {message}")
    if failed:
        print("Python 3.11 f-string syntax gate FAILED.")
        return 1
    print(f"Python 3.11 f-string syntax gate OK ({len(files)} files).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
