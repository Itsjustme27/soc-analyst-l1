"""XXE-safe XML parsing for operator/LLM-supplied Wazuh rule and decoder XML,
and the inverse guard that keeps rule XML out of log *event* fields.

Wazuh rules/decoders are plain element trees - they never legitimately carry a
DTD or entity declarations. ElementTree does not fetch external entities, but
internal-entity expansion is still a foot-gun (billion-laughs) and scanners
flag every `fromstring` on untrusted input (bandit B314). We reject documents
that declare a DOCTYPE or ENTITY before parsing - fail-closed, no extra
dependency.

The other direction matters just as much. `logtest` (PUT /logtest, or the
/var/ossec/queue/sockets/logtest unix socket) is a per-EVENT decoder+rule
tester: its payload is `{log_format, location, event, token}` where `event` is
one real log line. Feeding it rule XML - a whole local_rules.xml blob, or a
line-by-line sweep of one - can only ever come back `No decoder matched.`
That is a harness bug wearing the costume of a manager verdict, so this module
also recognizes rule XML in an event field and refuses it (see
`ensure_real_event`). It lives here, next to the XML knowledge, because this
is the only module in tools/ with no dependency on tools.base, so both the
API client and the tool layer can import it without a cycle.
"""

from __future__ import annotations

import re
from xml.etree import ElementTree as ET

_DTD_ENTITY_MARKERS = ("<!DOCTYPE", "<!ENTITY")


class UnsafeXmlError(ValueError):
    """Raised when the XML declares a DTD or entity (XXE guard)."""


class NotALogEventError(ValueError):
    """Raised when something that is not a log line is used as a logtest event."""


# Markers split by how sure we are, so a plain application/web log line that
# happens to embed an HTML fragment ("<parent>" from a stack trace, "<field>"
# from a template engine) is not misfiled as a ruleset definition.
#
# _HARD_XML_MARKERS: cannot plausibly appear in a real Wazuh log line. One hit
# on a single line is decisive.
_HARD_XML_MARKERS = (
    "<?xml",
    "<!--",
    "<!doctype",
    "<rule",
    "</rule",
    "<decoder",
    "</decoder",
    "<if_sid",
    "<if_matched_sid",
    "<if_group",
    "<if_level",
    "<if_matched_group",
    "<if_matched_level",
    "<decoded_as",
    "<program_name",
    "<prematch",
    "<regex",
    "<srcip",
    "<srcport",
    "<dstip",
    "<user",
)

# _SOFT_XML_MARKERS: Wazuh ruleset tag names that a chatty app log could in
# principle contain. Two *distinct* hits on one line are decisive.
_SOFT_XML_MARKERS = (
    "<group",
    "<match",
    "<description",
    "<mitre",
    "<same_",
    "<not_",
    "<field",
    "<parent",
    "<var",
    "<check_",
    "<list",
    "<syscheck",
    "<category",
    "<options",
    "<details",
)

# Tag names of the Wazuh ruleset/decoder vocabulary. Used only for the
# whole-line shape checks below, where the text is *entirely* markup and there
# is no log content to weigh it against - so we can afford to require a known
# name instead of flagging any angle bracket.
_RULE_TAG_NAMES = frozenset(
    {
        "rule",
        "group",
        "decoder",
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
        "syscheck",
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
        "prematch",
        "program_name",
        "srcip",
        "srcport",
        "dstip",
        "user",
    }
)

# A line that IS one tag and nothing else: `<group name="local,">`,
# `</rule>`, `<if_sid>5716</if_sid>`, `<description>...</description>`.
# The tag name must start with a letter so an RFC3164 priority prefix
# (`<134>Dec 10 ... sshd[1]: ...`) can never match, and the payload of a
# paired tag must be tag-free.
_WHOLE_TAG_LINE = re.compile(r"^</?([A-Za-z_][\w.:-]*)(?:\s[^<>]*)?/?>$")
_WHOLE_PAIRED_LINE = re.compile(r"^<([A-Za-z_][\w.:-]*)(?:\s[^<>]*)?>([^<>]*)</\1>$")


def safe_fromstring(text: str) -> ET.Element:
    """Parse XML after rejecting DTD/entity declarations (fail-closed)."""
    upper = (text or "").upper()
    for marker in _DTD_ENTITY_MARKERS:
        if marker in upper:
            raise UnsafeXmlError(
                f"XML declares {marker.lower()} - DTD/entity declarations are "
                "rejected (XXE guard); remove the declaration first."
            )
    # nosec B314 - the XXE guard above already rejected any DTD/entity
    # declaration; this fromstring never sees untrusted declarations.
    return ET.fromstring(text)  # nosec B314


# --------------------------------------------------------------------------- #
# the inverse guard: rule XML is not a log event
# --------------------------------------------------------------------------- #
def looks_like_xml(text: str) -> bool:
    """True when `text` carries rule/decoder markup instead of a log line.

    Conservative in both directions. It fires on real markup
    (`<if_sid>5716</if_sid>`, `<?xml ...?>`, `<!-- ... -->`, a whole
    local_rules.xml blob, a single line of one) and on nothing else, so the
    `<`, `>`, `/` and `&` that ordinary syslog/web lines legitimately carry are
    never mistaken for tags.
    """
    stripped = (text or "").strip()
    if not stripped:
        return False
    lowered = stripped.lower()

    if any(marker in lowered for marker in _HARD_XML_MARKERS):
        return True
    if sum(1 for marker in _SOFT_XML_MARKERS if marker in lowered) >= 2:
        return True

    lines = [ln.strip() for ln in stripped.splitlines() if ln.strip()]
    if len(lines) == 1:
        # A single line that is nothing but one tag. A real syslog line always
        # carries a timestamp/host/program prefix (or at least some text
        # beside the angle brackets), so bare markup with no log content is
        # markup - this is the per-line-sweep case the incident produced, and
        # `<group ...>` / `</group>` / `<description>...</description>` lines
        # carry no hard marker of their own.
        m = _WHOLE_TAG_LINE.match(lines[0]) or _WHOLE_PAIRED_LINE.match(lines[0])
        if m and m.group(1).lower() in _RULE_TAG_NAMES:
            return True
    elif len(lines) > 1:
        # A multi-line blob made mostly of tags is markup even when we
        # recognise none of the individual tags: a real multi-line log record
        # is never majority lines that start with an angle bracket or a
        # closing tag.
        markup_lines = sum(1 for ln in lines if ln.startswith(("<", "?", "!", "#")))
        if markup_lines * 2 >= len(lines):
            return True
    return False


def ensure_real_event(text: str, *, field: str = "event") -> str:
    """Return `text` unchanged, or raise `NotALogEventError` if it is XML.

    Call this on every value headed for a logtest `event` field. The manager
    answers rule XML with `No decoder matched.` no matter what, so catching it
    here turns a silent stream of meaningless results into one clear error.
    """
    value = (text or "").strip()
    if not value:
        raise NotALogEventError(
            f"Refusing to logtest an empty {field}: logtest takes ONE real log line, "
            "not a rule definition."
        )
    if looks_like_xml(value):
        preview = " ".join(value.split())[:120]
        raise NotALogEventError(
            f"Refusing to send rule XML to logtest as {field!r}: logtest evaluates a "
            f"log EVENT, so a rule definition can only ever come back "
            f"'No decoder matched.'. The text looks like XML: {preview!r}. "
            "To test a candidate rule, load it into the ruleset (PUT /rules/files/"
            "local_rules.xml + manager restart) and pass a real sample log line as "
            f"{field} - see tools/wazuh/logtest.py::TestWazuhRule. Rule XML is checked "
            "for structure with tools/wazuh/validation.py (xmlio.safe_fromstring), "
            "never through the logtest socket."
        )
    return value


__all__ = [
    "UnsafeXmlError",
    "NotALogEventError",
    "safe_fromstring",
    "looks_like_xml",
    "ensure_real_event",
]
