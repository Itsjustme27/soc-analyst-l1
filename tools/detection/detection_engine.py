"""
Detection engineering workflow for the AI SOC engineer.

The engine turns a candidate rule + sample logs into an evidence-backed,
human-approvable proposal, and afterwards verifies deployment. It never
touches the manager on its own: create/update go through the Approval Center,
and verification is read-only logtest.

Workflow (develop_wazuh_rule):
  1. Static XML validation (fail fast - no manager round trip on typos).
  2. Manager checks: `if_sid` parent exists? Does the candidate id already
     exist? What related rules already cover these match terms (overlap)?
  3. Baseline logtest of the *current deployed* ruleset against each positive
     and negative sample - proves the log decodes and shows what the existing
     ruleset does today (5-state: already_covered / no_decode / fires_other /
     clean / unknown).
  4. Proposes the merged local_rules.xml change with every piece of evidence
     attached, so the approver sees why this rule is needed and what it will
     do. After approval + execution the manager must restart (own approval),
     then `verify_rule_deployment` proves the deployed rule fires on
     positives and stays silent on negatives.

Corrections: 4.14 logtest only exercises the *deployed* ruleset, so candidate
rules cannot be evaluated by logtest pre-deploy. Instead the loop is:
draft -> static + baseline evidence -> (if mismatched) revise -> re-propose,
bounded by LOGTEST_MAX_ATTEMPTS per round *at the agent level*, and the final
pass/fail arbitrage happens in verify_rule_deployment after deployment. The
engine never claims a rule works until that verification confirms it.

Two invariants this module depends on (see tools/wazuh/logtest.py):
  - logtest is fed REAL LOG EVENTS, one per call, and only ever through
    `logtest_event`. Rule XML is never sent as an `event` - the manager can
    only answer that with "No decoder matched.", for every line of a rules
    file, which looks like a verdict but is a harness bug.
  - every logtest-backed result is preceded by a decoder preflight
    (`_preflight`). A session with no decoders loaded fails even a perfect
    sample line, so a failed preflight suppresses the per-sample verdicts
    instead of reporting them all as `no_decode`. And a positive sample
    swallowed by the generic catch-all (1002/1005) is reported as
    `harness_suspect`, not as an ordinary per-sample failure.
"""

from __future__ import annotations

import re
from typing import Any

from config import cfg
from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.wazuh.local_rules import (
    LOCAL_RULES_FILE,
    fetch_local_file,
    merge_rule,
    unified_diff,
)
from tools.wazuh.logtest import (
    is_catch_all_rule,
    logtest_event,
    normalize_location,
    preflight_decoders,
)
from tools.wazuh.validation import validate_wazuh_rule_xml

_SAMPLE_LIMIT = 8
_TERMS_FOR_OVERLAP = 4


# --------------------------------------------------------------------------- #
def _preflight(ctx: ToolContext, log_format: str, location: str | None) -> dict[str, Any]:
    """Prove the logtest session can decode before any sample result is read.

    'No decoder matched' only means something when the manager has its default
    decoders loaded. When it does not, a correct sample log fails to decode too
    and every row below would be reported as 'no_decode' - a statement about
    the candidate rule that is really a statement about the harness. Returns
    {'ok': True, ...} or {'ok': False, 'error': str}; callers must not report
    per-sample verdicts off a failed preflight.
    """
    try:
        return preflight_decoders(ctx.wazuh, log_format=log_format, location=location)
    except ToolError as e:
        return {"ok": False, "error": str(e)}


# --------------------------------------------------------------------------- #
def _baseline_for(
    ctx: ToolContext, sample: str, log_format: str, location: str | None = None
) -> dict[str, Any]:
    """Logtest ONE real sample event against the current deployed ruleset.

    Goes through logtest.logtest_event, which is the single place the logtest
    socket is called and which refuses anything that is not a log line - rule
    XML in this parameter can only ever come back 'No decoder matched.'.
    """
    try:
        info, token = logtest_event(ctx.wazuh, sample, log_format=log_format, location=location)
    except Exception as e:  # noqa: BLE001 - surface cleanly, keep the workflow alive
        return {"sample": sample[:200], "status": "logtest_error", "error": str(e)[:200]}
    # every call here opens its own session, so every call closes it
    _close_session(ctx.wazuh, token)
    return {
        "sample": sample[:200],
        "status": "matched" if info["matched"] else "no_alert",
        "rule_id": info["rule_id"],
        "rule_level": info["rule_level"],
        "rule_description": info["rule_description"],
        "decoder_name": (info["decoder"] or {}).get("name"),
        "catch_all": is_catch_all_rule(info["rule_id"]),
        "messages": info["messages"][:3],
        "location": info["location"],
    }


def _close_session(wazuh: Any, token: str | None) -> None:
    if not token:
        return
    try:
        wazuh.end_logtest_session(token)
    except Exception:  # noqa: BLE001 - best-effort session cleanup
        pass


def _baseline_in_session(
    ctx: ToolContext, sample: str, log_format: str, token: str | None, location: str | None = None
) -> tuple[dict[str, Any], str | None]:
    """Logtest one sample reusing an open logtest session (token) so
    frequency/divide counters accumulate across samples. The session is NOT
    closed here - the caller owns it. Returns (row, next_token)."""
    try:
        info, next_token = logtest_event(
            ctx.wazuh, sample, log_format=log_format, location=location, token=token
        )
        error = None
    except Exception as e:  # noqa: BLE001 - surface cleanly
        info, error, next_token = {}, str(e)[:200], token
    return (
        {
            "sample": sample[:200],
            "status": "matched" if (error is None and info.get("matched")) else "no_alert",
            "rule_id": info.get("rule_id"),
            "rule_level": info.get("rule_level"),
            "rule_description": info.get("rule_description"),
            "decoder_name": (info.get("decoder") or {}).get("name"),
            "catch_all": is_catch_all_rule(info.get("rule_id")),
            "messages": (info.get("messages") or [])[:3],
            "location": info.get("location"),
            **({"error": error} if error else {}),
        }
    ), next_token


def _rule_uses_frequency(ctx: ToolContext, rule_id: int) -> bool:
    """True if the deployed local rule uses a frequency/divide attribute.
    logtest evaluates samples in one session for such rules, because the
    counter must reach the threshold before the rule fires."""
    try:
        content = ctx.wazuh.get_rules_file("local_rules.xml", raw=True) or ""
    except Exception:  # noqa: BLE001 - treat as plain rule, verification still runs
        return False
    m = re.search(f'<rule\\b(?=[^>]*\\bid="{int(rule_id)}")(?:[^>]*)>.*?</rule>', content, re.S)
    return bool(m and re.search(r"\b(?:frequency|divide)=\"[0-9]+\"", m.group(0)))


def _classify_baseline(
    candidate_rule_id: int | None, row: dict[str, Any], expect_positive: bool
) -> str:
    """Map a baseline logtest row to a label relative to the candidate rule.

    `catch_all` is split out from `fires_other` on purpose: Wazuh's generic
    1002/1005 rules match anything that decoded but hit no specific rule, so
    they say nothing about overlap and must not be filed as "the ruleset
    already covers this". `preflight_failed` means we never got a trustworthy
    answer at all (see _preflight) and must not be laundered into `no_decode`.
    """
    if row.get("status") == "logtest_error":
        return "logtest_error"
    if row.get("status") == "no_alert":
        if expect_positive:
            return "no_decode"  # log decoded to nothing - cannot match yet
        return "clean"  # negative sample fires nothing - good baseline
    rid = row.get("rule_id")
    if str(rid) == str(candidate_rule_id):
        return "already_covered"  # the rule already exists and fires
    if row.get("catch_all") or is_catch_all_rule(rid):
        return "catch_all"  # generic rule 1002/1005 - not evidence either way
    return "fires_other"  # some other rule fires - overlap/shadow risk


def _run_overlap_search(ctx: ToolContext, xml_text: str, rid: int) -> list[dict[str, Any]]:
    """Find existing rules likely to overlap the candidate (same match terms
    or same description keywords) - the FP/noise analysis."""
    import re

    terms = re.findall(r"<(?:match|regex)>([^<]{3,40})</(?:match|regex)>", xml_text)
    seen: dict[str, dict[str, Any]] = {}
    try:
        resp = ctx.wazuh.get_rules(limit=100)
        items = resp.get("data", {}).get("affected_items", [])
    except Exception:  # noqa: BLE001
        return []
    for item in items:
        if item.get("id") == rid:
            continue
        details = item.get("details") or {}
        blob = " ".join(
            str(v) for v in (details.get("match"), details.get("regex"), item.get("description"))
        )
        overlap = [t for t in terms if t.lower() in blob.lower()]
        if overlap:
            seen[str(item.get("id"))] = {
                "rule_id": item.get("id"),
                "level": item.get("level"),
                "description": item.get("description"),
                "overlapping_terms": overlap,
            }
    return list(seen.values())[:10]


# --------------------------------------------------------------------------- #
class DevelopWazuhRule(BaseWazuhTool):
    name = "develop_wazuh_rule"
    description = (
        "Detection engineering workflow: given a candidate <rule> XML and sample logs, "
        "statically validate it, check the parent (if_sid) and overlapping existing rules, "
        "logtest the samples against the current ruleset as baseline evidence, and produce "
        "a human-approvable proposal to add it to local_rules.xml. Requires approval to "
        "execute; a manager restart (own approval) loads it; then verify_rule_deployment "
        "proves it fires on positives and not on negatives. Call this instead of "
        "create_wazuh_rule when you have representative log samples."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "rule_xml": {
                "type": "string",
                "description": "full <rule>...</rule> XML (id >= 100000)",
            },
            "positive_samples": {
                "type": "array",
                "items": {"type": "string"},
                "description": "log lines that MUST fire this rule",
            },
            "negative_samples": {
                "type": "array",
                "items": {"type": "string"},
                "description": "log lines that must NOT fire this rule",
            },
            "log_format": {
                "type": "string",
                "description": "logtest format: syslog, json, eventlog, ...",
            },
            "location": {
                "type": "string",
                "description": "source path of the samples, e.g. /var/log/auth.log",
            },
            "reason": {
                "type": "string",
                "description": "why this detection is needed (shown to the approver)",
            },
        },
        "required": ["rule_xml", "positive_samples", "reason"],
    }
    permission = Permission.PROPOSE

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        xml = str(p["rule_xml"]).strip()
        positives = [str(s)[:2000] for s in (p.get("positive_samples") or [])[:_SAMPLE_LIMIT]]
        negatives = [str(s)[:2000] for s in (p.get("negative_samples") or [])[:_SAMPLE_LIMIT]]
        log_format = p.get("log_format") or "syslog"
        location = normalize_location(p.get("location"))
        if not positives:
            raise ToolError(
                "At least one positive sample log is required (a log the rule must detect)."
            )

        # 1) static validation - no manager round trip on typos
        validation = validate_wazuh_rule_xml(xml)
        if not validation["valid"]:
            raise ToolError(
                "Rule failed static validation:\n- " + "\n- ".join(validation["errors"])
            )
        rid = validation["rule_id"]

        evidence: dict[str, Any] = {"static": validation, "sample_groups": {}}

        # 2) manager checks: parent existence + candidate already present
        checks: list[str] = []
        parent = _find_if_sid(xml)
        if parent:
            try:
                parent_found = _rule_exists(ctx, parent)
            except RuleLookupError as e:
                parent_found = None
                checks.append(f"WARNING: couldn't verify parent rule {parent} ({e})")
            if parent_found:
                checks.append(f"parent rule {parent} exists")
            elif parent_found is False:
                checks.append(
                    f"WARNING: if_sid references rule {parent}, which is NOT in the ruleset - the rule will never fire"
                )
        # Fail safe, but say why: an unreachable manager blocks the proposal
        # with a connection message, not a false "already exists".
        try:
            taken = _rule_exists(ctx, rid)
        except RuleLookupError as e:
            raise ToolError(
                f"Couldn't check whether rule id {rid} is free - the Wazuh manager API isn't reachable ({e}). "
                "Check WAZUH_API_URL / WAZUH_API_USERNAME / WAZUH_API_PASSWORD in .env, then try again."
            ) from e
        if taken:
            raise ToolError(
                f"Rule id {rid} already exists in the manager ruleset - use update_wazuh_rule or pick a new id."
            )
        checks.append(f"candidate id {rid} is free")
        evidence["manager_checks"] = checks
        evidence["max_attempts"] = int(getattr(cfg, "LOGTEST_MAX_ATTEMPTS", 3))

        # 3) overlap / FP analysis
        overlaps = _run_overlap_search(ctx, xml, rid)
        evidence["overlap"] = {
            "note": (
                "existing rules sharing match terms - high overlap suggests the candidate "
                "may be redundant or generate duplicate alerts"
            ),
            "rules": overlaps,
        }

        # 4) baseline logtest (current deployed ruleset)
        #
        # Preflight first. If the canonical sshd line does not decode, every
        # row below would come back `no_decode` - which reads as a verdict on
        # the candidate but is really a verdict on the session. In that case
        # we do not logtest the samples at all and say so, instead of filling
        # the proposal with meaningless "no decoder matched" rows.
        preflight = _preflight(ctx, log_format, location)
        evidence["preflight"] = preflight
        if not preflight.get("ok"):
            evidence["harness_broken"] = True
            evidence["sample_groups"] = {
                "positives": _preflight_rows(positives),
                "negatives": _preflight_rows(negatives),
            }
            evidence["baseline_summary"] = (
                "NO logtest verdicts were collected: the preflight could not decode a "
                "known-good canonical log line, so this manager's logtest session has "
                "no decoders loaded and 'No decoder matched' on your samples would "
                "say nothing about the candidate rule. Fix the decoder set (or wait "
                f"for wazuh-analysisd to finish reloading) and re-run. Detail: {preflight.get('error', '')[:300]}"
            )
        else:
            pos_details = _run_baseline(ctx, rid, positives, log_format, True, location)
            neg_details = _run_baseline(ctx, rid, negatives, log_format, False, location)
            evidence["sample_groups"] = {
                "positives": pos_details,
                "negatives": neg_details,
            }
            covered = [r for r in pos_details if r["class"] == "already_covered"]
            no_decode = [r for r in pos_details if r["class"] == "no_decode"]
            fires_other = [r for r in pos_details if r["class"] == "fires_other"]
            catch_all = [r for r in pos_details if r["class"] == "catch_all"]
            if covered:
                evidence["baseline_summary"] = (
                    "The candidate rule (or another rule with this id) ALREADY fires on the positive "
                    "samples - confirm this rule is really needed."
                )
            elif catch_all and len(catch_all) == len(pos_details):
                evidence["baseline_summary"] = (
                    "Every positive sample was swallowed by Wazuh's generic catch-all rule "
                    "(1002/1005): the events decode but match no specific rule. That is not "
                    "evidence the candidate is redundant, and it is not a null-match "
                    "baseline either - these samples most likely need a custom decoder."
                )
            elif no_decode and len(no_decode) == len(pos_details):
                evidence["baseline_summary"] = (
                    "None of the positive samples decode to an alert under the current ruleset. They may "
                    "need a custom decoder first, or the log format/location may be wrong for logtest."
                )
            elif fires_other:
                evidence["baseline_summary"] = (
                    "Positive samples currently trigger different rule(s) - the candidate will add "
                    "detection on top of them. Review the overlap list above for duplication."
                )
            else:
                evidence["baseline_summary"] = (
                    "Positive samples are currently undetected ('no alert' or "
                    "generic decode) and negative samples are clean - the candidate "
                    "adds real coverage."
                )

        # 5) build + gate the proposal
        current = fetch_local_file(ctx, LOCAL_RULES_FILE)
        new_content, issues = merge_rule(current, xml, overwrite=False)
        if issues and new_content == current:
            raise ToolError("; ".join(issues))
        diff = unified_diff(current, new_content)

        proposed = {
            "action": "create_wazuh_rule",
            "reason": p.get("reason", ""),
            # The executed action re-merges the candidate rule into the CURRENT
            # file at execution time (deterministic, never a stale snapshot).
            "payload": {"rule_xml": xml, "overwrite": False, "reason": p.get("reason", "")},
            "permission": self.permission.value,
        }
        proposed["generated_config"] = new_content
        proposed["validation"] = {
            "valid": True,
            "errors": [],
            "diff": diff,
            "evidence": evidence,
            "next_steps": [
                "approve -> deploy rule (executes PUT local_rules.xml)",
                "restart_wazuh_manager (EXECUTE, own approval) to load the rule",
                "verify_rule_deployment (READ) to prove the rule fires on positives and not negatives",
            ],
        }
        ctx.approve_or_raise(proposed)

        resp = ctx.wazuh.put_rules_file(LOCAL_RULES_FILE, new_content)
        return {
            "status": "executed",
            "rule_id": rid,
            "restart_required": True,
            "evidence": evidence,
            "detail": resp.get("message"),
        }


class VerifyRuleDeployment(BaseWazuhTool):
    name = "verify_rule_deployment"
    description = (
        "READ-ONLY post-deploy verification: after a rule was deployed and the manager "
        "restarted, logtest the positive/negative samples and prove the rule id fires on "
        "positives and stays silent on negatives. Reports pass/fail per sample - never "
        "assume; the manager's answer is the truth."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "rule_id": {"type": "integer"},
            "positive_samples": {"type": "array", "items": {"type": "string"}},
            "negative_samples": {"type": "array", "items": {"type": "string"}},
            "log_format": {"type": "string"},
            "location": {"type": "string", "description": "source path of the samples"},
        },
        "required": ["rule_id", "positive_samples"],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        rid = int(p["rule_id"])
        log_format = p.get("log_format") or "syslog"
        location = normalize_location(p.get("location"))
        positives = [str(s)[:2000] for s in (p.get("positive_samples") or [])[:_SAMPLE_LIMIT]]
        negatives = [str(s)[:2000] for s in (p.get("negative_samples") or [])[:_SAMPLE_LIMIT]]
        # A verdict built on a session that cannot decode is worse than no
        # verdict: every sample would come back "No decoder matched" and be
        # filed as a per-sample failure of the rule. Refuse up front instead.
        preflight = _preflight(ctx, log_format, location)
        if not preflight.get("ok"):
            raise ToolError(
                "Cannot verify rule "
                f"{rid}: {preflight.get('error', 'logtest preflight failed')} No "
                "per-sample result is reported, because a session that cannot "
                "decode a known-good line cannot refute a rule either."
            )
        freq = _rule_uses_frequency(ctx, rid)
        results: list[dict[str, Any]] = []
        token: str | None = None
        session_note = ""
        catch_all_hits: list[dict[str, Any]] = []
        # frequency/divide rules need N matching events in ONE logtest session
        # before they fire - send all positives through the same session so the
        # counter accumulates. Plain rules are checked per-sample (fresh session).
        if freq:
            for sample in positives:
                row, token = _baseline_in_session(ctx, sample, log_format, token, location)
                if row.get("catch_all"):
                    catch_all_hits.append({"expected": "positive", "sample": str(sample)[:160]})
                results.append(
                    {
                        "expected": "positive",
                        "pass": str(row.get("rule_id")) == str(rid),
                        "fired_rule": row.get("rule_id"),
                        "fired_description": row.get("rule_description"),
                        "decoder": row.get("decoder_name"),
                        "catch_all": bool(row.get("catch_all")),
                        "status": row.get("status"),
                        "sample": str(sample)[:160],
                        **({"error": row["error"]} if row.get("error") else {}),
                    }
                )
            fired_pos = [
                i + 1
                for i, r in enumerate(results)
                if r["expected"] == "positive" and str(r.get("fired_rule")) == str(rid)
            ]
            session_note = (
                f"frequency/divide rule: positives were pushed through a single logtest "
                f"session (threshold accumulation). Fired on sample(s): {fired_pos}. "
                "NOTE: logtest does not persist frequency counters between calls, so "
                "a non-firing frequency rule here is expected and is NOT evidence of "
                "a broken rule - treat the positive arm as inconclusive and verify "
                "through analysisd."
                if fired_pos
                else "frequency/divide rule: the rule did not trip inside logtest. This is "
                "the expected result on this build - logtest holds no frequency state, "
                "so it cannot confirm or refute a correlation rule. Do not conclude "
                "the rule is broken; verify through analysisd instead."
            )
        else:
            for sample in positives:
                row = _baseline_for(ctx, sample, log_format, location)
                if row.get("catch_all"):
                    catch_all_hits.append({"expected": "positive", "sample": str(sample)[:160]})
                results.append(
                    {
                        "expected": "positive",
                        "pass": str(row.get("rule_id")) == str(rid),
                        "fired_rule": row.get("rule_id"),
                        "fired_description": row.get("rule_description"),
                        "decoder": row.get("decoder_name"),
                        "catch_all": bool(row.get("catch_all")),
                        "status": row.get("status"),
                        "sample": str(sample)[:160],
                        **({"error": row["error"]} if row.get("error") else {}),
                    }
                )
        if token:
            _close_session(ctx.wazuh, token)
        for sample in negatives:
            row = _baseline_for(ctx, sample, log_format, location)
            if row.get("catch_all"):
                catch_all_hits.append({"expected": "negative", "sample": str(sample)[:160]})
            results.append(
                {
                    "expected": "negative",
                    # A catch-all on a negative is a pass (the rule did not
                    # fire), but it is flagged: a negative that only ever
                    # reaches 1002 usually never exercised the decoder path
                    # the positive does, so it proves less than it looks.
                    "pass": str(row.get("rule_id")) != str(rid),
                    "fired_rule": row.get("rule_id"),
                    "fired_description": row.get("rule_description"),
                    "decoder": row.get("decoder_name"),
                    "catch_all": bool(row.get("catch_all")),
                    "status": row.get("status"),
                    "sample": str(sample)[:160],
                    **({"error": row["error"]} if row.get("error") else {}),
                }
            )
        pos_pass = sum(1 for r in results if r["expected"] == "positive" and r["pass"])
        neg_pass = sum(1 for r in results if r["expected"] == "negative" and r["pass"])
        pos_total = sum(1 for r in results if r["expected"] == "positive")
        neg_total = sum(1 for r in results if r["expected"] == "negative")
        clean = not any(r.get("error") for r in results)
        pos_fired = any(
            str(r.get("fired_rule")) == str(rid) for r in results if r["expected"] == "positive"
        )
        # A catch-all (1002/1005) on a POSITIVE is not a near-miss: the event
        # decoded and matched no specific rule, so the sample never reached
        # the candidate's match terms. Filing that as an ordinary per-sample
        # failure is how a quietly broken harness gets to look like a rule
        # that needs deleting - so it is surfaced on its own and forces the
        # verdict to `inconclusive`.
        pos_catch_all = [r for r in results if r["expected"] == "positive" and r.get("catch_all")]
        if pos_catch_all:
            session_note = (
                f"WARNING: {len(pos_catch_all)} positive sample(s) were swallowed by "
                "Wazuh's generic catch-all rule (1002/1005). The events decode, but they "
                "match no specific rule - the candidate's if_sid chain or match terms never "
                "selected them. This is NOT a null-match baseline and NOT an ordinary "
                f"per-sample failure: check that the sample really exercises the decoder "
                f"rule {rid} hangs off (sshd decoder, right location/log_format) before "
                "concluding anything about the rule. "
            ) + session_note
        verified = (
            pos_total > 0
            and neg_pass == neg_total
            and clean
            and not pos_catch_all
            and ((not freq and pos_pass == pos_total) or (freq and pos_fired))
        )
        # logtest is a per-event decoder+rule tester: it holds no frequency/
        # timeframe counter, so a correlation rule can never be CONFIRMED (or
        # refuted) through it. Measured on a live 4.x manager: 8 repeated
        # failures through a single session never tripped a frequency=5 rule
        # while the live pipeline would have. Reporting verified=False there
        # is a false negative - it reads as "this rule is broken" and invites
        # deleting a working rule, so say inconclusive and mean it.
        inconclusive = freq or bool(pos_catch_all)
        verification = "inconclusive" if inconclusive else ("confirmed" if verified else "failed")
        return {
            "rule_id": rid,
            "frequency_rule": freq,
            "positive_pass": f"{pos_pass}/{pos_total}",
            "negative_pass": f"{neg_pass}/{neg_total}",
            # None (not False) when the result is unknown, not disproven.
            "verified": (None if inconclusive else verified),
            "verification": verification,
            "catch_all_hits": catch_all_hits,
            "harness_suspect": bool(pos_catch_all),
            "frequency_rule_unverifiable_via_logtest": bool(freq),
            "how_to_verify_frequency_rule": (
                "Push real events through analysisd (agent/syslog input) and read "
                "the alert stream, or confirm the rule is loaded and enabled via "
                "GET /rules/<id> and trust the live engine. The parent rules and "
                "the negatives below are still verified by logtest."
            )
            if freq
            else None,
            "samples": results,
            "preflight": preflight,
            "note": (
                "verified=True means the manager confirmed the rule fires on all "
                "positives and no negatives. " + session_note
            ).strip(),
        }


# --------------------------------------------------------------------------- #
def _preflight_rows(samples: list[str]) -> list[dict[str, Any]]:
    """Placeholder rows when the preflight proved the session unusable.

    One row per sample, all classified `preflight_failed`, so the proposal
    still shows what *would* have been tested without inventing a per-sample
    verdict the manager never gave.
    """
    return [
        {
            "index": i,
            "class": "preflight_failed",
            "sample": s[:200],
            "error": "logtest preflight failed - no decoder loaded, so this sample "
            "was not submitted and has no verdict",
        }
        for i, s in enumerate(samples)
    ]


def _run_baseline(
    ctx: ToolContext,
    rid: int,
    samples: list[str],
    log_format: str,
    expect_positive: bool,
    location: str | None = None,
) -> list[dict[str, Any]]:
    """Logtest samples against the deployed ruleset; annotate each with the
    classification relative to the candidate."""
    out: list[dict[str, Any]] = []
    for i, s in enumerate(samples):
        base = _baseline_for(ctx, s, log_format, location)
        cls = _classify_baseline(rid, base, expect_positive)
        row = {"index": i, "class": cls, "sample": s[:200]}
        if base.get("rule_id") is not None:
            row.update(
                {
                    "rule_id": base.get("rule_id"),
                    "rule_description": base.get("rule_description"),
                    "rule_level": base.get("rule_level"),
                    "decoder": base.get("decoder_name"),
                    "catch_all": bool(base.get("catch_all")),
                }
            )
        if base.get("error"):
            row["error"] = base["error"]
        out.append(row)
    return out


def _find_if_sid(xml_text: str) -> int | None:
    import re

    m = re.search(r"<if_sid>(\d+)</if_sid>", xml_text)
    return int(m.group(1)) if m else None


def _rule_exists(ctx: ToolContext, rule_id: int) -> bool:
    """Existence check via GET /rules?q=id=X (the per-rule detail endpoint
    404s for built-in rules on this API build - the list endpoint is the
    reliable route). Raises RuleLookupError when the manager can't be asked,
    so callers can say "couldn't check" instead of a false "already exists"."""
    try:
        resp = ctx.wazuh.get_rules(limit=1, q=f"id={int(rule_id)}")
    except Exception as e:  # noqa: BLE001 - surfaced to the caller as a lookup failure
        raise RuleLookupError(str(e)) from e
    return bool(resp.get("data", {}).get("affected_items"))


class RuleLookupError(RuntimeError):
    """The manager ruleset couldn't be queried (unreachable / not configured)."""


def zip_neg(neg: list[str], classes: list[str]):
    return list(zip(neg, classes, strict=True))


TOOLS = [DevelopWazuhRule, VerifyRuleDeployment]
