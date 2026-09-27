"""XXE-safe XML parsing for operator/LLM-supplied Wazuh rule and decoder XML.

Wazuh rules/decoders are plain element trees - they never legitimately carry a
DTD or entity declarations. ElementTree does not fetch external entities, but
internal-entity expansion is still a foot-gun (billion-laughs) and scanners
flag every `fromstring` on untrusted input (bandit B314). We reject documents
that declare a DOCTYPE or ENTITY before parsing - fail-closed, no extra
dependency.
"""

from __future__ import annotations

from xml.etree import ElementTree as ET

_DTD_ENTITY_MARKERS = ("<!DOCTYPE", "<!ENTITY")


class UnsafeXmlError(ValueError):
    """Raised when the XML declares a DTD or entity (XXE guard)."""


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
