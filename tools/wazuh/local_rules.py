"""
Read-modify-write helpers for Wazuh's `local_rules.xml` / `local_decoder.xml`.

Wazuh 4.14 manages rules as *files* (PUT /rules/files/{filename}), and the
convention is that custom rules live in `local_rules.xml` (auto-loaded by the
manager). Adding/updating/removing one rule therefore means: fetch the file,
merge the change into the XML, and propose writing the whole file back. This
module keeps that merge lossless (existing rules/comments preserved) and
produces a unified diff so the human approver sees exactly what changes.
"""

from __future__ import annotations

import difflib
import re
import xml.etree.ElementTree as ET
from typing import Any

from tools.base import ToolError

LOCAL_RULES_FILE = "local_rules.xml"
LOCAL_DECODER_FILE = "local_decoder.xml"

WRAP_GROUP = "local,syslog,sshd,"
WRAP_GROUP_OPEN = f'<group name="{WRAP_GROUP}">'
WRAP_GROUP_CLOSE = "</group>"


from tools.wazuh.xmlio import UnsafeXmlError, safe_fromstring


def parse_file(text: str) -> ET.Element | None:
    try:
        return safe_fromstring(text)
    except (ET.ParseError, UnsafeXmlError):
        return None


def _indent(elem: ET.Element, level: int = 0) -> str:
    """Serialise an element with readable 2-space indentation (the Wazuh
    convention).

    Attributes are emitted on EVERY element, not just leaves. They carry the
    rule's meaning - `id`, `level`, `frequency`, `timeframe` - so dropping them
    while re-indenting an element that has children silently writes a different,
    unusable rule to local_rules.xml.
    """
    pad = "  " * level
    attrs = "".join(f' {k}="{v}"' for k, v in elem.attrib.items())
    if len(elem) == 0:
        return f"{pad}<{elem.tag}{attrs}>{elem.text or ''}</{elem.tag}>"
    lines = [f"{pad}<{elem.tag}{attrs}>"]
    for child in elem:
        lines.append(_indent(child, level + 1))
    lines.append(f"{pad}</{elem.tag}>")
    return "\n".join(lines)


def _rule_block(rule_xml: str) -> str:
    """Normalise a standalone <rule>...</rule> snippet to a consistent,
    2-space-indented block (Wazuh comment style)."""
    root = safe_fromstring(rule_xml)
    attrs = "".join(f' {k}="{v}"' for k, v in root.attrib.items())
    body = "".join(_indent(c, 2) + "\n" for c in root)
    return f"<rule{attrs}>\n{body}</rule>"


def merge_rule(file_text: str, rule_xml: str, overwrite: bool = False) -> tuple[str, list[str]]:
    """Insert `rule_xml` into the local_rules.xml `file_text`. Returns the new
    file content + any issues. When `overwrite` is False and the id already
    exists, returns (file_text, [issue]) untouched."""
    issues: list[str] = []
    rule = safe_fromstring(rule_xml)
    rid = rule.attrib.get("id")
    if not rid:
        return file_text, ["rule has no id"]

    root = parse_file(file_text)
    if root is not None:
        for existing in list(root):
            if existing.tag == "rule" and existing.attrib.get("id") == rid:
                if overwrite:
                    idx = list(root).index(existing)
                    root.remove(existing)
                    root.insert(idx, rule)
                    issues.append(f"replaced existing rule {rid}")
                    return _serialize_file(root), issues
                issues.append(f"rule id {rid} already exists (set overwrite to replace)")
                return file_text, issues

    # not present (or file unparseable) -> append
    block = _rule_block(rule_xml)
    if root is None:
        new_text = f"<!-- Local rules -->\n\n{WRAP_GROUP_OPEN}\n\n{block}\n\n{WRAP_GROUP_CLOSE}\n"
        issues.append("file was empty/unparseable; created minimal local_rules.xml")
        return new_text, issues
    if root.tag == "group":
        # append before the closing tag, preserving the rest
        text_lines = file_text.splitlines(keepends=True)
        # find the last line that is the closing </group> of the root
        close_idx = None
        for i in range(len(text_lines) - 1, -1, -1):
            if text_lines[i].strip() == WRAP_GROUP_CLOSE:
                close_idx = i
                break
        if close_idx is not None:
            lines = text_lines[:close_idx] + [f"\n{block}\n\n"] + text_lines[close_idx:]
            issues.append(f"appended rule {rid}")
            return "".join(lines), issues
    # overwrite flow re-check: rule exists (ET scan above misses nested rules)
    existing_block = _find_rule_block(file_text, rid)
    if existing_block is not None and overwrite:
        new_text, found, _ = _replace_block(
            file_text, existing_block, block, f"replaced existing rule {rid}"
        )
        if found:
            return new_text, issues
    issues.append("could not locate insertion point (no <group> root) - manual edit needed")
    return file_text, issues


def _find_rule_block(file_text: str, rule_id: str | int) -> str | None:
    """Locate the exact text span of a <rule id="...">...</rule> block, so
    removal/replacement can be done as text surgery (preserving comments and
    formatting elsewhere in the file)."""
    target = re.escape(str(rule_id))
    m = re.search(rf'<rule\b(?=[^>]*\bid="{target}")[^>]*>.*?</rule>', file_text, re.DOTALL)
    return m.group(0) if m else None


def _replace_block(
    file_text: str, old_block: str, new_block: str | None, issue: str
) -> tuple[str, bool, list[str]]:
    issues: list[str] = []
    pos = file_text.find(old_block)
    if pos < 0:
        return file_text, False, ["rule block not found textually"]
    head, tail = file_text[:pos], file_text[pos + len(old_block) :]
    if new_block is None:
        # drop the block plus surrounding blank lines (collapse 3+ newlines)
        head = head.rstrip("\n")
        tail = tail.lstrip("\n")
        issues.append(issue)
        return f"{head}\n\n{tail}", True, issues
    issues.append(issue)
    return head + new_block + tail, True, issues


def remove_rule(file_text: str, rule_id: str | int) -> tuple[str, bool]:
    """Remove a rule by id from the file. Returns (new_content, found).
    Text-based: unrelated rules and comments are preserved verbatim."""
    block = _find_rule_block(file_text, rule_id)
    if block is None:
        return file_text, False
    new_text, found, _ = _replace_block(file_text, block, None, "")
    return new_text, found


def replace_rule(file_text: str, rule_id: str | int, rule_xml: str) -> tuple[str, bool, list[str]]:
    target = str(rule_id)
    block = _find_rule_block(file_text, target)
    if block is None:
        return file_text, False, [f"rule {target} not found in local_rules.xml"]
    new_block = _rule_block(rule_xml)
    return _replace_block(file_text, block, new_block, f"replaced rule {target}")


def _serialize_file(root: ET.Element) -> str:
    """Re-emit a whole parsed rules/decoder file, root element included.

    The root is the wrapper the manager requires (`<group name="local,...">`
    around every local rule, `<decoders>` around every local decoder). Dropping
    it and emitting only the children would produce a file Wazuh refuses to
    load - or worse, one that silently loads nothing.
    """
    return _indent(root, 0) + "\n"


def unified_diff(old: str, new: str, filename: str = LOCAL_RULES_FILE, n: int = 4) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(True),
            new.splitlines(True),
            fromfile=f"{filename} (current)",
            tofile=f"{filename} (proposed)",
            n=n,
        )
    )


def extract_rule_ids(file_text: str) -> list[str]:
    root = parse_file(file_text)
    if root is None:
        return []
    return [r.attrib.get("id", "") for r in root.iter("rule")]


def extract_rule_text(file_text: str, rule_id: str | int) -> str | None:
    target = str(rule_id)
    root = parse_file(file_text)
    if root is None:
        return None
    for r in root.iter("rule"):
        if r.attrib.get("id") == target:
            return _indent(r, 0)
    return None


# --------------------------------------------------------------------------- #
# decoders (local_decoder.xml is a sequence of <decoder> elements at root)
# --------------------------------------------------------------------------- #
def _decoder_block(decoder_xml: str) -> str:
    root = safe_fromstring(decoder_xml)
    attrs = "".join(f' {k}="{v}"' for k, v in root.attrib.items())
    body = "".join(_indent(c, 1) + "\n" for c in root)
    return f"<decoder{attrs}>\n{body}</decoder>"


def merge_decoder(file_text: str, decoder_xml: str) -> tuple[str, list[str]]:
    """Append a <decoder> to local_decoder.xml content. Returns new content +
    issues. If a decoder with the same name exists and overwrite is false
    (default), refuses to touch the file."""
    issues: list[str] = []
    root = safe_fromstring(decoder_xml)
    name = root.attrib.get("name")
    if not name:
        return file_text, ["decoder has no name"]
    existing = parse_file(file_text)
    if existing is not None:
        for d in list(existing):
            if d.tag == "decoder" and d.attrib.get("name") == name:
                issues.append(f"decoder '{name}' already exists - overwrite explicitly or rename")
                return file_text, issues
    block = _decoder_block(decoder_xml)
    if existing is not None and existing.tag == "decoders":
        text_lines = file_text.splitlines(keepends=True)
        for i in range(len(text_lines) - 1, -1, -1):
            if text_lines[i].strip() == "</decoders>":
                lines = text_lines[:i] + [f"\n{block}\n\n"] + text_lines[i:]
                issues.append(f"appended decoder '{name}'")
                return "".join(lines), issues
    tail = f"{block}\n" if file_text.endswith("\n") else f"\n{block}\n"
    issues.append(f"appended decoder '{name}'")
    return file_text + tail, issues


def remove_decoder(file_text: str, name: str) -> tuple[str, bool]:
    root = parse_file(file_text)
    if root is None:
        return file_text, False
    for d in list(root):
        if d.tag == "decoder" and d.attrib.get("name") == name:
            root.remove(d)
            return _serialize_file(root), True
    return file_text, False


def replace_decoder(file_text: str, name: str, decoder_xml: str) -> tuple[str, bool, list[str]]:
    issues: list[str] = []
    root = parse_file(file_text)
    if root is None:
        return file_text, False, ["local_decoder.xml is unparseable"]
    new = safe_fromstring(decoder_xml)
    for i, d in enumerate(list(root)):
        if d.tag == "decoder" and d.attrib.get("name") == name:
            root.remove(d)
            root.insert(i, new)
            issues.append(f"replaced decoder '{name}'")
            return _serialize_file(root), True, issues
    issues.append(f"decoder '{name}' not found in local_decoder.xml")
    return file_text, False, issues


def fetch_local_file(ctx: Any, filename: str) -> str:
    """Fetch a local rules/decoder file from the manager, returning '' for a
    missing file (fresh local rules file). Shared by rules/decoders tools and
    the detection engine."""
    try:
        return ctx.wazuh.get_rules_file(filename, raw=True)
    except Exception as e:  # noqa: BLE001 - missing file = empty file
        if "not found" in str(e).lower():
            return ""
        raise ToolError(f"Failed to read {filename}: {e}") from e


__all__ = [
    "LOCAL_RULES_FILE",
    "LOCAL_DECODER_FILE",
    "merge_rule",
    "remove_rule",
    "replace_rule",
    "merge_decoder",
    "remove_decoder",
    "replace_decoder",
    "unified_diff",
    "extract_rule_ids",
    "extract_rule_text",
]
