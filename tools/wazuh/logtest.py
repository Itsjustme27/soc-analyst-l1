"""
Wazuh logtest tools - test a log EVENT against the manager's ruleset.

What logtest is
---------------
`logtest` is a per-event decoder+rule tester. The request shape is fixed, both
on the unix socket (``/var/ossec/queue/sockets/logtest``) and on the manager
REST endpoint (``PUT /logtest``)::

    {"log_format": "syslog",
     "location":   "master->/var/log/auth.log",
     "event":      "Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2",
     "token":      "<session token from the previous call; omit on the first>"}

`event` is **one real log line**. A rule definition is never an event: it must
be loaded into the ruleset the session evaluates against (upload
`local_rules.xml`, restart the manager) and then tested by submitting a real
sample log. Sending rule XML as `event` can only ever come back
`No decoder matched.`, for every single line of it - a harness bug that reads
exactly like a manager verdict, which is why `xmlio.ensure_real_event` refuses
rule XML at every boundary that feeds `event`.

The `status` a caller gets back distinguishes "the manager gave a verdict we
are willing to read" (`tested`) from every case where it did not: `catch_all`
(1002/1005 fired), `no_decode` (this sample decoded to nothing even though the
preflight line did), `not_matched` (a different rule fired), `no_alert` (the
candidate fired but was not alerted on). Only `tested` is a statement about
whether the rule works.

Why there is a preflight
------------------------
"No decoder matched" is only *meaningful* when the session actually has the
default decoders loaded (sshd, syslog, json, ...). If it does not, a perfectly
good sample log line fails to decode too, and every candidate-rule result is
silently garbage. So before trusting anything, `preflight_decoders` submits one
known-good canonical line and requires it to decode and fire the stock base
rule 5716. If that fails we raise a clear error instead of reporting
`no_decode` for the rest of the run.

The three jobs this module does
-------------------------------
1. `RunWazuhLogtest` - baseline: given a log line, which decoder + rule fire
   today, and what fields decode. Used before proposing a rule.
2. `TestWazuhRule` - candidate rule: load the rule into the ruleset, then
   submit ONE real sample event and report what fired. Approval-gated staging,
   never a rule XML in the event field.
3. `EndWazuhLogtestSession` - close the session the first two opened.

The detection engine (tools/detection/detection_engine.py) combines static XML
validation (tools/wazuh/validation.py, before proposal) + this module (after
staging/deploy) so it never claims a rule works without the manager confirming
it.
"""

from __future__ import annotations

import re
from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.wazuh.local_rules import LOCAL_RULES_FILE, fetch_local_file, merge_rule, unified_diff
from tools.wazuh.validation import validate_wazuh_rule_xml
from tools.wazuh.xmlio import NotALogEventError, ensure_real_event, looks_like_xml

# The canonical sample: the stock sshd decoder turns this into rule 5716
# ("sshd: authentication failed."). Kept in lockstep with the fixture at
# tests/fixtures/sample_events/sshd_failed_auth.log (a test pins the two
# together) so the preflight, the docs and the regression test all agree on one
# known-good line.
CANONICAL_SSHD_FAILED_LOG = (
    "Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2"
)
# The base rule that canonical line must fire. A candidate rule chaining
# if_sid: 5716 is only meaningful if 5716 actually exists and fires.
CANONICAL_BASE_RULE_ID = 5716
CANONICAL_BASE_RULE_DESC = "sshd: authentication failed."

# Wazuh's generic catch-all rules. 1002 is "Log collection: <location>" - the
# last-resort rule that matches literally anything that decoded but reached no
# other rule. If one of these fires on a candidate-rule test the candidate did
# NOT match; treating that as an ordinary "some other rule fired" result is how
# a broken harness passes itself off as a working rule, so it is reported
# loudly and separately.
CATCH_ALL_RULE_IDS = frozenset({1002, 1005})

# logtest `location` is "<component>-><path>". A bare path is assumed to be the
# manager's own log.
DEFAULT_LOCATION = "master->/var/log/auth.log"

_NO_DECODERS_ERROR = (
    "logtest session has no decoders loaded - the canonical sample line did not "
    "decode, so no candidate-rule result from this session can be trusted."
)

# The label a worked example carries when it is parked in an XML comment. Only
# a labelled line is a sample event; the rest of a comment is prose.
_SAMPLE_LABEL = re.compile(
    r"^\s*(?:sample(?:\s+event)?|test\s+log|log|event)\s*:\s*(\S.*)$", re.IGNORECASE
)


def normalize_location(location: str | None) -> str:
    """Coerce a location into logtest's `<component>-><path>` form.

    A bare path is the manager's own log (`master->/var/log/auth.log`); an
    agent-qualified location (`agent->/var/log/secure`) is passed through
    unchanged. A `location` without the `->` marker changes which decoder the
    manager picks, so getting this wrong is another way to end up with
    'No decoder matched.' on a perfectly good log line.
    """
    loc = (location or "").strip() or DEFAULT_LOCATION
    return loc if "->" in loc else f"master->{loc if loc.startswith('/') else '/' + loc}"


def is_catch_all_rule(rule_id: Any) -> bool:
    """True for Wazuh's generic catch-all rules (1002 / 1005)."""
    if rule_id in (None, ""):
        return False
    try:
        return int(rule_id) in CATCH_ALL_RULE_IDS
    except (TypeError, ValueError):
        return False


def _parse_logtest(data: dict[str, Any]) -> dict[str, Any]:
    """Normalize both response shapes Wazuh has shipped:
    legacy {alerts: [...]} and 4.7+ {alert: bool, output: {...}}."""
    alerts = [a for a in (data.get("alerts") or []) if isinstance(a, dict)]
    if alerts:
        output = alerts[-1]
    else:
        output = data.get("output") or {}
    rule = output.get("rule") or {}
    matched = bool(rule) and bool(data.get("alert", True)) if rule else bool(data.get("alert"))
    if "alert" in data:  # 4.7+ authoritative
        matched = bool(data.get("alert"))
    return {
        "token": data.get("token"),
        "matched": matched,
        "rule_id": rule.get("id"),
        "rule_level": rule.get("level"),
        "rule_description": rule.get("description"),
        "rule_groups": rule.get("groups") or [],
        "decoder": output.get("decoder") or {},
        "full_log": str(output.get("full_log") or "")[:1000],
        "fields": (output.get("fields") or {}),
        "messages": [str(m) for m in (data.get("messages") or [])],
        "location": data.get("location") or output.get("location"),
    }


def _no_decoder_matched(info: dict[str, Any]) -> bool:
    """True when the manager explicitly reported that nothing decoded it."""
    decoder = info.get("decoder") or {}
    if decoder.get("name"):
        return False
    blob = " ".join(info.get("messages") or []).lower()
    if "no decoder" in blob or "could not decode" in blob:
        return True
    # 4.7+ says it with a falsy decoder object and an empty rule.
    return not info.get("matched") and not info.get("rule_id") and not blob


# --------------------------------------------------------------------------- #
# the single place the logtest socket is called
# --------------------------------------------------------------------------- #
def logtest_event(
    wazuh: Any,
    event: str,
    *,
    log_format: str = "syslog",
    location: str | None = None,
    token: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    """Submit exactly ONE real log event to logtest. Returns (result, next_token).

    This is the only function in the codebase that talks to the logtest
    socket, and it refuses anything that is not a log line before it gets
    there. Every caller passes a real sample event; rule XML never reaches
    this point (see the module docstring).
    """
    try:
        safe_event = ensure_real_event(event)
    except NotALogEventError as e:
        raise ToolError(str(e)) from e
    try:
        resp = (
            wazuh.run_logtest(
                safe_event,
                log_format=log_format,
                location=normalize_location(location),
                token=token,
            )
            or {}
        )
    except Exception as e:  # noqa: BLE001 - surfaced as a tool error
        raise ToolError(f"logtest failed: {e}") from e
    data = resp.get("data") or {}
    return _parse_logtest(data), data.get("token") or token


def _close_session(wazuh: Any, token: str | None) -> None:
    if not token:
        return
    try:
        wazuh.end_logtest_session(token)
    except Exception:  # noqa: BLE001 - best-effort cleanup
        pass


def _msgs(info: dict[str, Any]) -> str:
    msgs = info.get("messages") or []
    return f" (manager said: {'; '.join(str(m) for m in msgs)})" if msgs else ""


# --------------------------------------------------------------------------- #
# preflight: prove the session can decode before trusting any verdict
# --------------------------------------------------------------------------- #
def preflight_decoders(
    wazuh: Any,
    *,
    log_format: str = "syslog",
    location: str | None = None,
) -> dict[str, Any]:
    """Submit the canonical known-good log line and require it to decode.

    Returns evidence dict on success. Raises ToolError when the canonical line
    does not decode or does not fire the stock base rule 5716 - at that point
    'No decoder matched' on some other sample is meaningless (it means the
    session has no decoders), so we fail loudly instead of letting the caller
    read a stream of meaningless results as rule behaviour.
    """
    where = normalize_location(location)
    token: str | None = None
    try:
        info, token = logtest_event(
            wazuh, CANONICAL_SSHD_FAILED_LOG, log_format=log_format, location=where
        )
    except ToolError as e:
        raise ToolError(
            f"{_NO_DECODERS_ERROR} The preflight sample "
            f"({CANONICAL_SSHD_FAILED_LOG!r}) did not get an answer from the "
            f"manager: {e}"
        ) from e
    finally:
        _close_session(wazuh, token)

    decoder = info.get("decoder") or {}
    fired = info.get("rule_id")
    evidence: dict[str, Any] = {
        "ok": False,
        "sample": CANONICAL_SSHD_FAILED_LOG,
        "expected_rule_id": CANONICAL_BASE_RULE_ID,
        "fired_rule_id": fired,
        "fired_description": info.get("rule_description"),
        "decoder": decoder.get("name"),
        "log_format": log_format,
        "location": where,
        "messages": (info.get("messages") or [])[:3],
    }
    if _no_decoder_matched(info):
        raise ToolError(
            f"{_NO_DECODERS_ERROR} The canonical sample "
            f"{CANONICAL_SSHD_FAILED_LOG!r} (log_format={log_format!r}, "
            f"location={where!r}) came back with no decoder{_msgs(info)}. Check "
            "that the manager has its default decoder set loaded (the ruleset "
            "and decoders directories are populated) and that wazuh-analysisd is "
            "running; do NOT read 'No decoder matched' on your own samples as a "
            "statement about your rules."
        )
    if str(fired) != str(CANONICAL_BASE_RULE_ID):
        raise ToolError(
            f"{_NO_DECODERS_ERROR} The canonical sample decoded (decoder="
            f"{decoder.get('name')!r}) but fired rule {fired} "
            f"({info.get('rule_description')!r}) instead of the stock base rule "
            f"{CANONICAL_BASE_RULE_ID} {CANONICAL_BASE_RULE_DESC!r}. That means "
            "this ruleset is not the standard one (or a local rule shadows it), "
            "so an if_sid chain built on 5716 cannot be validated here."
        )
    evidence["ok"] = True
    evidence["fired_description"] = info.get("rule_description") or CANONICAL_BASE_RULE_DESC
    return evidence


def sample_events_from_xml_comment(xml_text: str) -> list[str]:
    """Extract sample log lines that were parked in a local_rules.xml comment.

    Legacy convenience: rule files in the wild carry their worked example as
    an inline XML comment, e.g.
    ``<!-- sample: Dec 10 01:02:02 host sshd[1234]: Failed none ... -->``.
    Those lines are real events and belong in a fixture, not in a rules file a
    line-by-line harness can swallow. This helper exists so the transition is
    mechanical, and it returns ONLY the comment payload - never the tags, so a
    caller can no longer sweep `<if_sid>5716</if_sid>` into a logtest call.

    Only lines carrying an explicit sample label are harvested. Without that
    requirement every prose comment in a rules file (``<!-- Local rules -->``)
    would be handed back as if it were a log event, which is the mirror image
    of the bug this module exists to stop.
    """
    out: list[str] = []
    for m in re.finditer(r"<!--(.*?)-->", xml_text or "", re.DOTALL):
        for raw in m.group(1).splitlines():
            labelled = _SAMPLE_LABEL.match(raw)
            if not labelled:
                continue
            line = re.sub(r"\s*--+>?\s*$", "", labelled.group(1)).strip()
            if line and not looks_like_xml(line):
                out.append(line)
    return out


# --------------------------------------------------------------------------- #
# tools
# --------------------------------------------------------------------------- #
class RunWazuhLogtest(BaseWazuhTool):
    name = "run_wazuh_logtest"
    description = (
        "Run Wazuh logtest: feed ONE real log line through the manager's ruleset "
        "and see which decoder + rule fire, plus the decoded fields. Use to verify a "
        "deployed rule, check how existing rules treat a log, or confirm a log format "
        "decodes at all. The 'log' argument is a LOG LINE, never rule XML - a rule "
        "definition can only be tested with test_wazuh_rule, which loads it into the "
        "ruleset first. Pass 'log_format' of the source (syslog, json, eventlog, ...)."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "log": {
                "type": "string",
                "description": "ONE real log line to test (never a <rule> XML block)",
            },
            "log_format": {
                "type": "string",
                "description": "syslog, json, eventlog, ... (default syslog)",
            },
            "location": {
                "type": "string",
                "description": (
                    "source path, e.g. /var/log/auth.log (default master->/var/log/auth.log)"
                ),
            },
            "token": {"type": "string", "description": "reuse an existing logtest session token"},
            "preflight": {
                "type": "boolean",
                "description": (
                    "verify decoders are loaded with a canonical sample before the "
                    "result (default true); set false only for a raw one-off probe"
                ),
            },
        },
        "required": ["log"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        log = str(p["log"])
        if len(log) > 8000:
            raise ToolError("logtest log line too long (8000 chars max).")
        log_format = p.get("log_format") or "syslog"
        location = normalize_location(p.get("location"))
        # Prove the session can decode before reading a verdict off it, so a
        # decoder-less session is reported as such instead of answered.
        preflight: dict[str, Any] = {"ok": None, "skipped": True}
        if p.get("preflight", True):
            preflight = preflight_decoders(ctx.wazuh, log_format=log_format, location=location)
        try:
            # logtest_event refuses a rule definition in the event field before
            # the round trip: the manager's only possible answer is 'No decoder
            # matched.', and returning that verbatim is what made this look
            # like a real result for every line of a rules file.
            info, next_token = logtest_event(
                ctx.wazuh,
                log,
                log_format=log_format,
                location=location,
                token=p.get("token"),
            )
        except ToolError as e:
            raise ToolError(str(e)) from e
        if not p.get("token"):
            _close_session(ctx.wazuh, next_token)
        out = dict(info)
        out["log_format"] = log_format
        out["location"] = location
        out["preflight"] = preflight
        if is_catch_all_rule(info.get("rule_id")):
            out["catch_all_rule"] = True
            out["note"] = (
                f"Rule {info.get('rule_id')} is Wazuh's generic catch-all: the event "
                "decoded but matched no specific rule. This is not evidence that a "
                "candidate rule works."
            )
        return out


class TestWazuhRule(BaseWazuhTool):
    name = "test_wazuh_rule"
    description = (
        "Test ONE candidate <rule> against ONE real sample log line. The rule is "
        "loaded into the manager's ruleset first (merged into local_rules.xml, "
        "approval-gated), because logtest evaluates the ruleset, not a rule "
        "definition - rule XML is never sent as the event. Runs a decoder preflight "
        "first, then submits the sample exactly once and reports which rule fired, "
        "its level, and whether that is the candidate. A manager restart (EXECUTE, "
        "own approval) is needed after staging before the candidate can fire; the "
        "result says so explicitly instead of reporting a misleading null match."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "rule_xml": {
                "type": "string",
                "description": "full <rule>...</rule> XML (id >= 100000) under test",
            },
            "sample_event": {
                "type": "string",
                "description": (
                    "ONE real log line the rule must fire on (e.g. "
                    "'Dec 10 01:02:02 host sshd[1234]: Failed none for root from "
                    "1.1.1.1 port 1066 ssh2'). Never pass rule XML here."
                ),
            },
            "log_format": {"type": "string", "description": "logtest format (default syslog)"},
            "location": {"type": "string", "description": "source path (default auth.log)"},
            "expected_rule_id": {
                "type": "integer",
                "description": "rule id that must fire; defaults to the candidate's own id",
            },
            "stage": {
                "type": "boolean",
                "description": (
                    "write the candidate into local_rules.xml (default true). Set false "
                    "when the rule is already deployed and you are re-testing it"
                ),
            },
            "reason": {"type": "string", "description": "why this rule is being tested"},
        },
        "required": ["rule_xml", "sample_event", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        xml = str(p["rule_xml"]).strip()
        log_format = p.get("log_format") or "syslog"
        location = normalize_location(p.get("location"))
        stage = str(p.get("stage", True)).lower() not in ("0", "false", "no", "off")

        # 1) structure: pure XML parsing, no logtest. This is the layer that
        # answers "is this well-formed / are the attributes sane", and it must
        # never be confused with "does this rule match a log".
        validation = validate_wazuh_rule_xml(xml)
        if not validation["valid"]:
            raise ToolError(
                "Rule failed static validation:\n- " + "\n- ".join(validation["errors"])
            )
        rid = validation["rule_id"]

        # 2) the event must be a real log line, before anything else happens.
        try:
            sample = ensure_real_event(str(p["sample_event"]), field="sample_event")
        except NotALogEventError as e:
            raise ToolError(str(e)) from e
        expected = int(p.get("expected_rule_id") or rid or 0)

        # 3) prove the session can decode at all before trusting a verdict.
        preflight = preflight_decoders(ctx.wazuh, log_format=log_format, location=location)

        # 4) stage the candidate into the ruleset the session evaluates.
        #    logtest has no way to see a rule that only exists in this
        #    conversation; it must live in local_rules.xml.
        staged: dict[str, Any] = {"staged": False, "skipped": not stage}
        if stage:
            current = fetch_local_file(ctx, LOCAL_RULES_FILE)
            merged, issues = merge_rule(current, xml, overwrite=True)
            already = any("already exists" in i for i in issues)
            if merged == current:
                staged = {
                    "staged": False,
                    "already_present": True,
                    "issues": issues,
                    "file": LOCAL_RULES_FILE,
                }
            else:
                diff = unified_diff(current, merged)
                proposed = {
                    "action": "test_wazuh_rule",
                    "reason": p.get("reason", ""),
                    "payload": {
                        "rule_xml": xml,
                        "sample_event": sample,
                        "log_format": log_format,
                        "location": location,
                        "expected_rule_id": expected,
                        "stage": stage,
                        "reason": p.get("reason", ""),
                    },
                    "permission": self.permission.value,
                }
                proposed["generated_config"] = merged
                proposed["validation"] = {
                    "valid": True,
                    "errors": [],
                    "issues": issues,
                    "diff": diff,
                    "evidence": {"static": validation, "preflight": preflight},
                    "next_steps": [
                        f"restart_wazuh_manager (EXECUTE, own approval) so the manager "
                        f"loads {LOCAL_RULES_FILE}",
                        "re-run test_wazuh_rule (stage=false) to read the fired rule id",
                    ],
                }
                ctx.approve_or_raise(proposed)
                resp = ctx.wazuh.put_rules_file(LOCAL_RULES_FILE, merged)
                staged = {
                    "staged": True,
                    "replaced_existing": already,
                    "file": LOCAL_RULES_FILE,
                    "issues": issues,
                    "detail": resp.get("message"),
                }

        # 5) ONE logtest call, one real event. If the candidate is not loaded
        #    yet the manager cannot fire it, and we must say exactly that
        #    rather than dress up the catch-all as a result.
        info, next_token = logtest_event(
            ctx.wazuh, sample, log_format=log_format, location=location
        )
        _close_session(ctx.wazuh, next_token)

        fired = info.get("rule_id")
        fired_is_candidate = str(fired) == str(expected)
        matched = bool(info.get("matched")) and fired_is_candidate
        catch_all = is_catch_all_rule(fired)
        decoded = bool((info.get("decoder") or {}).get("name")) and not _no_decoder_matched(info)

        result: dict[str, Any] = {
            # "tested" means the manager gave a verdict we are willing to read.
            # Every other status is a statement that it did NOT, and each one
            # carries an error saying why.
            "status": "tested",
            "candidate_rule_id": rid,
            "expected_rule_id": expected,
            "fired_rule_id": fired,
            "fired_level": info.get("rule_level"),
            "fired_description": info.get("rule_description"),
            "decoder": (info.get("decoder") or {}).get("name"),
            "decoded": decoded,
            "matched": matched,
            "catch_all_rule": catch_all,
            "sample": sample,
            "log_format": log_format,
            "location": location,
            "static_validation": validation,
            "preflight": preflight,
            "staging": staged,
        }
        if catch_all:
            result["status"] = "catch_all"
            result["error"] = (
                f"Rule {fired} is Wazuh's generic catch-all, not rule {expected}. The "
                "event decoded, but the candidate did not match it. Do NOT read this "
                "as a null-match baseline: either the candidate is not loaded yet "
                "(stage the rule, restart the manager, re-run) or its match terms do "
                "not actually select this event."
            )
        elif not decoded:
            result["status"] = "no_decode"
            result["error"] = (
                "The sample decoded to nothing even though the canonical preflight "
                "line did. The sample is probably not in the declared log_format, or "
                "its location does not select a matching decoder."
            )
        elif not fired_is_candidate:
            result["status"] = "not_matched"
            result["error"] = (
                f"Rule {expected} did not fire; the manager fired rule {fired} "
                f"({info.get('rule_description')!r}) instead. If the candidate was just "
                "staged it is not loaded yet - restart the manager, then re-run with "
                "stage=false."
            )
        elif not matched:
            # The rule is the one that fired, but the manager did not flag it as
            # an alert (level 0 / <alert_options> noalert). Distinct from
            # "the rule did not match" and must not be reported as one.
            result["status"] = "no_alert"
            result["error"] = (
                f"Rule {expected} is the rule that fired, but the manager did not "
                "raise an alert for it. Usually its level is 0 or its <alert_opts> "
                "suppresses alerting - which is a configuration question, not a "
                "matching failure."
            )
        if staged.get("staged"):
            result["restart_required"] = True
            result["next_steps"] = [
                f"restart_wazuh_manager (EXECUTE, own approval) to load {LOCAL_RULES_FILE}",
                "re-run test_wazuh_rule with stage=false to read the fired rule id",
            ]
        return result


class EndWazuhLogtestSession(BaseWazuhTool):
    name = "end_wazuh_logtest_session"
    description = "Close a logtest session (run_wazuh_logtest returns a token; close it when done)."
    input_schema = {
        "type": "object",
        "properties": {"token": {"type": "string"}},
        "required": ["token"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        try:
            resp = ctx.wazuh.end_logtest_session(p["token"])
        except Exception as e:  # noqa: BLE001
            raise ToolError(f"Failed to close logtest session: {e}") from e
        return {"status": "closed" if resp.get("error") == 0 else "already_closed"}


TOOLS = [RunWazuhLogtest, TestWazuhRule, EndWazuhLogtestSession]
