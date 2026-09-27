"""
Draft a Wazuh detection rule from a plain-language request.

WHY THIS EXISTS
`develop_wazuh_rule` is the evidence half of the workflow and it is strict on
purpose: it demands hand-written `rule_xml` plus at least one positive sample,
because those two are exactly the things a detection engineer should be
checking before anything is proposed. That strictness is correct - and it also
meant the Rule builder UI opened on three empty textareas, so the only way in
was "Starter rule", a hardcoded SSH-brute-force template. Ask for anything
else and you got that same template, which is how you end up proposing a rule
for something you never asked about.

So drafting is split in two, deliberately:

    draft_wazuh_rule        (this module) - generate. READ, writes nothing.
    develop_wazuh_rule                   - validate + propose. PROPOSE.

The drafter fills the form; the human reads the actual XML and the actual
sample logs before anything reaches the Approval Center. It never proposes, so
a hallucinated rule cannot become a pending approval on its own.

The drafter also self-checks: whatever it generates is run through the same
`validate_wazuh_rule_xml` the propose step uses, and the verdict travels back
with the draft so the UI can say "this will be rejected" before the user
clicks anything. Generating something that fails validation is a bug, not a
result - the caller decides whether to show it.

Negatives are OPTIONAL. A request like "detect X" has no natural near-miss
log, and inventing one teaches the model to pad; an empty list is a truthful
answer and `develop_wazuh_rule` copes with it (negatives only sharpen the
evidence, they are not required).
"""

from __future__ import annotations

import json
import re
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.wazuh.validation import validate_wazuh_rule_xml

_MAX_SAMPLES = 5
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)

_SYSTEM = """You write Wazuh detection rules. You are given a request, the log
format, and (optionally) a parent rule id to chain from. Reply with ONE JSON
object and nothing else.

Schema:
{
  "rule_xml": "<rule id=\\"...\\" level=\\"...\\" frequency=\\"...\\"> ... </rule>",
  "positive_samples": ["<a log line this rule MUST fire on>", ...],
  "negative_samples": ["<a log line this rule must NOT fire on>", ...],
  "log_format": "syslog|json|eventlog",
  "notes": "<one sentence: what fires and why>"
}

Rules:
- `rule_xml` MUST be a single complete <rule> element with a numeric id >= 100000.
- It must be VALID Wazuh rule XML: attributes quoted, child elements closed,
  decoders and <if_sid> values that exist.
- Use <if_sid> only when `parent_rule_id` is given; otherwise write a
  self-contained rule with a <match>/<regex> on the log content.
- If you use frequency=/divide=, you MUST count a parent reached via
  <if_matched_sid> - the manager rejects <if_sid> on a frequency rule. If
  `parent_rule_id` is given, emit <if_matched_sid>ID</if_matched_sid>; if it is
  not given, do not use frequency/divide at all.
- `positive_samples` MUST be realistic, complete log lines in the same format -
  the kind of line that really appears in that log. At least 2, at most 5.
  Vary them (different users/hosts/paths); do not return the same line twice.
- `negative_samples` are OPTIONAL. Return [] when you cannot think of a genuine
  near-miss. NEVER invent a filler negative. If you do return one, it must be a
  realistic line that is close to the positive but must not match.
- Do not wrap the JSON in markdown."""


def _parse_json_object(text: str) -> dict[str, Any] | None:
    """Pull a JSON object out of a model reply, tolerating fences/prose."""
    if not text:
        return None
    candidate = _FENCE.sub("", str(text)).strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start == -1 or end <= start:
        return None
    for blob in (candidate[start : end + 1], candidate):
        try:
            parsed = json.loads(blob)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None


def _as_lines(value: Any, limit: int) -> list[str]:
    """Coerce a model-supplied sample list to clean single-line strings.

    Samples are logs, so a multi-line string is a mistake worth flattening
    rather than passing through to logtest, which expects one event per line."""
    raw: list[Any]
    if isinstance(value, list):
        raw = value
    elif isinstance(value, str) and value.strip():
        raw = value.splitlines()
    else:
        return []
    out: list[str] = []
    for item in raw:
        line = " ".join(str(item).split()).strip()
        if line and line not in out:
            out.append(line)
        if len(out) >= limit:
            break
    return out


def _extract_rule_xml(obj: dict[str, Any]) -> str:
    """Get the <rule> element out, tolerating a reply that wrapped it in prose
    or returned the whole file rather than a single element."""
    xml = obj.get("rule_xml") or obj.get("xml") or ""
    if not isinstance(xml, str):
        return ""
    xml = _FENCE.sub("", xml).strip()
    match = re.search(r"<rule\b.*?</rule>", xml, re.S)
    return match.group(0).strip() if match else xml.strip()


class DraftWazuhRule(BaseWazuhTool):
    name = "draft_wazuh_rule"
    description = (
        "Turn a plain-language detection request into a reviewable DRAFT: candidate "
        "<rule> XML plus realistic positive log samples (and negative samples when a "
        "genuine near-miss exists - they are optional). Writes nothing and proposes "
        "nothing: the result is meant to be read and edited by a human, then passed to "
        "develop_wazuh_rule for validation and approval. Use this FIRST when someone "
        "describes a detection in words; use develop_wazuh_rule when you already have "
        "the XML and samples in hand."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "intent": {
                "type": "string",
                "description": (
                    "the detection in plain language, e.g. 'repeated SSH failed logins "
                    "from one source to many hosts'"
                ),
            },
            "log_format": {
                "type": "string",
                "description": "syslog | json | eventlog (default syslog)",
            },
            "parent_rule_id": {
                "type": "integer",
                "description": "optional if_sid parent - the rule that must fire first",
            },
            "log_sample": {
                "type": "string",
                "description": (
                    "optional REAL log line from the source, so the draft matches the "
                    "actual format instead of a guessed one"
                ),
            },
        },
        "required": ["intent"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        intent = str(p.get("intent") or "").strip()
        if not intent:
            raise ToolError("intent is required - describe the detection in plain language.")
        log_format = str(p.get("log_format") or "syslog").strip() or "syslog"
        parent = p.get("parent_rule_id")
        sample = str(p.get("log_sample") or "").strip()

        user_msg = f"Request: {intent}\nLog format: {log_format}"
        if parent:
            user_msg += f"\nParent rule for <if_sid>: {int(parent)}"
        if sample:
            user_msg += f"\nA real log line from this source:\n{sample[:500]}"

        try:
            reply = ctx.get_llm().chat_text(
                system=_SYSTEM, messages=[{"role": "user", "content": user_msg}], max_tokens=2000
            )
        except Exception as e:  # noqa: BLE001 - surfaced as a clean tool error
            raise ToolError(f"The rule drafter could not be reached: {e}") from e

        obj = _parse_json_object(reply)
        if obj is None:
            raise ToolError(
                "The drafter did not return usable JSON. Try rewording the request, or "
                "write the rule XML by hand."
            )

        rule_xml = _extract_rule_xml(obj)
        positives = _as_lines(obj.get("positive_samples"), _MAX_SAMPLES)
        negatives = _as_lines(obj.get("negative_samples"), _MAX_SAMPLES)

        if not rule_xml:
            raise ToolError("The drafter returned no <rule> XML - try rewording the request.")
        if not positives:
            raise ToolError(
                "The drafter returned no positive samples. develop_wazuh_rule needs at "
                "least one real log line the rule must fire on - add one by hand."
            )

        # Self-check with the same validator the propose step uses, so the UI can
        # flag a doomed draft before the user invests in it.
        validation = validate_wazuh_rule_xml(rule_xml)
        return {
            "status": "draft",
            "intent": intent,
            "log_format": str(obj.get("log_format") or log_format),
            "rule_xml": rule_xml,
            "positive_samples": positives,
            "negative_samples": negatives,
            "negatives_optional": True,
            "notes": str(obj.get("notes") or "")[:400],
            "parent_rule_id": int(parent) if parent else None,
            # valid=False here is expected sometimes - it is the drafter telling
            # the truth about its own output, not a tool failure.
            "static_validation": {
                "valid": validation["valid"],
                "errors": validation["errors"],
                "rule_id": validation.get("rule_id"),
            },
            "next_step": (
                "Review the XML and the samples, edit if needed, then run "
                "develop_wazuh_rule to validate against the manager and propose it."
            ),
        }


TOOLS = [DraftWazuhRule]
