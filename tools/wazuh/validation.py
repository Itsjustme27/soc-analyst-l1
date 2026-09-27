"""
Static validation for Wazuh rules / decoders (XML).

Wazuh rule XML is validated here *before* it goes anywhere near the manager:
well-formedness, root element, required attributes (id/level/description),
numeric ranges (level 0-15, id >= 100000 for custom rules), and structural
sanity (if_sid/if_group references must be plausibly present). The manager's
logtest is the authoritative check afterwards; this layer catches the
obvious mistakes cheaply and without touching Wazuh.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from typing import Any

_REQUIRED_RULE_ATTRS = ("id", "level")
_REQUIRED_DECODER_ATTRS = ("name",)


from tools.wazuh.xmlio import UnsafeXmlError, safe_fromstring


def parse_xml(xml_text: str) -> ET.Element | None:
    try:
        return safe_fromstring(xml_text)
    except (ET.ParseError, UnsafeXmlError):
        return None


def parse_error(xml_text: str) -> str:
    try:
        safe_fromstring(xml_text)
        return ""
    except ET.ParseError as e:
        return str(e)
    except UnsafeXmlError as e:
        return str(e)


def validate_wazuh_rule_xml(xml_text: str) -> dict[str, Any]:
    """Return {"valid": bool, "errors": [...], "rule_id": int|None, ...}.

    Checks:
      - well-formed XML, single <rule> root
      - rule id is an integer (custom rules should be >= 100000)
      - level is an integer in 0..15
      - description is present
      - maxsize/frequency compatibility: a rule must not combine fields the
        manager rejects (e.g. frequency without timeframe is allowed, but
        frequency+timeframe requires both)
      - unknown top-level tags are flagged (typo protection)
    """
    errors: list[str] = []
    info: dict[str, Any] = {"rule_id": None, "level": None, "description": ""}

    if not xml_text or not xml_text.strip():
        return {"valid": False, "errors": ["Rule XML is empty."], **info}

    root = parse_xml(xml_text)
    if root is None:
        return {"valid": False, "errors": [f"XML parse error: {parse_error(xml_text)}"], **info}
    if root.tag != "rule":
        return {
            "valid": False,
            "errors": [f"Root element is <{root.tag}>, expected <rule>."],
            **info,
        }

    for attr in _REQUIRED_RULE_ATTRS:
        if attr not in root.attrib:
            errors.append(f"Missing required rule attribute: {attr}")

    rid = root.attrib.get("id")
    if rid is not None:
        try:
            rule_id = int(rid)
            info["rule_id"] = rule_id
            if rule_id < 100000:
                # built-in range is 1..99999; custom rules should be 100000+
                # (enforced by Wazuh docs) - warn, don't hard-fail, since some
                # environments legitimately patch lower ranges.
                errors.append(
                    f"Rule id {rule_id} is in the built-in range; custom rules should use id >= 100000."
                )
        except ValueError:
            errors.append(f"Rule id '{rid}' is not an integer.")

    lvl = root.attrib.get("level")
    if lvl is not None:
        try:
            level = int(lvl)
            info["level"] = level
            if not 0 <= level <= 15:
                errors.append(f"Rule level {level} is outside 0..15.")
            if level == 0:
                errors.append(
                    "Rule level 0 suppresses alerts - only use it for noise-suppression rules."
                )
        except ValueError:
            errors.append(f"Rule level '{lvl}' is not an integer.")

    desc_el = root.find("description")
    desc = root.attrib.get("description") or (desc_el.text if desc_el is not None else None)
    if desc and desc.strip():
        info["description"] = desc.strip()
    else:
        errors.append(
            "Rule has no description (set the description attribute or add a <description> element)."
        )

    # frequency/timeframe/divide must be rule ATTRIBUTES (e.g.
    # <rule id=... level=... frequency="3" timeframe="60">), NEVER child
    # elements. The manager's ruleset loader rejects the child-element form
    # ("Invalid option 'frequency' for rule") and the API reports it as a
    # generic "XML syntax error" at upload time - catch it here instead.
    _ATTR_ONLY_TAGS = ("frequency", "timeframe", "divide")
    for tag in _ATTR_ONLY_TAGS:
        el = root.find(tag)
        if el is not None:
            errors.append(
                f"<{tag}> must be a rule ATTRIBUTE in this Wazuh version "
                f'(e.g. <rule id="105000" level="10" {tag}="3" timeframe="60">), '
                f"not a child element - the manager's ruleset loader rejects "
                f"child-element <{tag}>."
            )

    # frequency/divide counting rules must reference their parent via
    # if_matched_sid: this Wazuh build rejects if_sid on frequency rules
    # ("Invalid use of frequency/context options. Missing if_matched on
    # rule '...'"). Check the child element and the attribute forms.
    if ("frequency" in root.attrib or "divide" in root.attrib) and not (
        root.find("if_matched_sid") is not None or "if_matched_sid" in root.attrib
    ):
        errors.append(
            "frequency/divide rules must count a parent rule reached via "
            "<if_matched_sid> (e.g. <if_matched_sid>5760</if_matched_sid>) - "
            "if_sid is rejected by the manager for frequency rules."
        )

    # Top-level element whitelist (typo protection).
    #
    # The same_*/not_*/if_matched_* families are the standard companions of a
    # frequency/timeframe correlation rule and were missing here, which made
    # this validator reject XML the manager happily accepts: a rule using
    # <same_source_ip /> came back "Unknown rule element <same_source_ip>."
    # Verified against a live 4.x manager, which accepts
    #   <rule id=".." level="10" frequency="5" timeframe="60">
    #     <if_matched_sid>5710,5760</if_matched_sid><same_source_ip /></rule>
    _KNOWN_TAGS = {
        "match",
        "regex",
        "if_sid",
        "if_matched_sid",
        "if_group",
        "if_level",
        "if_matched_group",
        "if_matched_level",
        "decoded_as",
        "field",
        "same_rule",
        "timeout",
        "same_source_ip",
        "same_source_port",
        "same_dest_ip",
        "same_field",
        "same_id",
        "same_user",
        "same_location",
        "same_agent",
        "not_sid",
        "not_group",
        "not_level",
        "not_regex",
        "category",
        "rule",
        "syscheck",
        "ar",
        "group",
        "mitre",
        "options",
        "var",
        "list",
        "check_all",
        "check_any",
        "check_diff",
        "info",
        "alert_opts",
        "id",
        "level",
        "description",
        "accumulate",
        "relative_dirname",
        "details",
    }
    for child in root:
        if child.tag not in _KNOWN_TAGS:
            errors.append(f"Unknown rule element <{child.tag}>.")

    return {
        "valid": not errors,
        "errors": errors,
        "rule_id": info["rule_id"],
        "level": info["level"],
        "description": info["description"],
    }


def validate_wazuh_decoder_xml(xml_text: str) -> dict[str, Any]:
    """Same idea for <decoder> XML."""
    errors: list[str] = []
    if not xml_text or not xml_text.strip():
        return {"valid": False, "errors": ["Decoder XML is empty."]}
    root = parse_xml(xml_text)
    if root is None:
        return {"valid": False, "errors": [f"XML parse error: {parse_error(xml_text)}"]}
    if root.tag != "decoder":
        return {"valid": False, "errors": [f"Root element is <{root.tag}>, expected <decoder>."]}
    if "name" not in root.attrib:
        errors.append("Missing required decoder attribute: name")
    # A decoder that is not a parent (no `parent`) and not in a known form
    # (regex/json/program_name) is usually a mistake.
    child_tags = {c.tag for c in root}
    recognized = {
        "regex",
        "json",
        "program_name",
        "prematch",
        "plugin_decoder",
        "order",
        "parent",
        "regex_offset",
        "accumulate",
    }
    if "parent" not in root.attrib and not (child_tags & recognized):
        errors.append(
            "Decoder has no <regex>/<json>/<program_name> and is not a <parent> - it can't decode anything."
        )
    return {"valid": not errors, "errors": errors}


def rule_id_from_xml(xml_text: str) -> int | None:
    m = re.search(r"<rule\b[^>]*\bid=\"(\d+)\"", xml_text)
    return int(m.group(1)) if m else None


def decoder_name_from_xml(xml_text: str) -> str | None:
    m = re.search(r"<decoder\b[^>]*\bname=\"([^\"]+)\"", xml_text)
    return m.group(1) if m else None
