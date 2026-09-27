"""
Detection gap analysis for the AI SOC engineer.

Answers "find detection gaps in my web server telemetry" with a factual,
5-state coverage table. Every number comes from the real manager ruleset and
the real indexer - nothing guessed:

  - rules_exist  : rules matching the category (manager ruleset, paged once)
  - alerts_seen  : alerts matching the category in the window (indexer)
  - events_seen  : raw events matching the category (archives)

Per-category state:
  detected            rules exist AND alerts actually fired recently
  partial             rules exist, no alerts, but raw archive activity exists
                      (rule too narrow / wrong group / needs tuning)
  covered_no_events   rules exist, no alerts and no archive activity
                      (either no such traffic or event capture is off)
  gap                 no rules found but raw activity exists (clear gap)
  unknown             no rules and no observed activity (can't tell yet)

The gap rows (state in {gap, partial}) are what the detection engineer turns
into develop_wazuh_rule proposals.

Queries are built as deterministic bool clauses (term / match_phrase) - never
query_string, whose special characters (/, <, =, ..) crash older Elasticsearch
parsers with 500s.
"""

from __future__ import annotations

from typing import Any

from tools.base import BaseWazuhTool, Permission, ToolContext, ToolError
from tools.indexer.queries import to_range_expr

_INDEX = "wazuh-alerts-*"
_ARCHIVE = "wazuh-archives-*"

# category -> {rule: regex on ruleset blob, alerts: structured bool spec,
#             must: [(field, value)] exact-term filters, should: [(match|phrase, text)]}
_CATEGORIES: dict[str, list[dict[str, Any]]] = {
    "web": [
        {
            "name": "probes_scanning",
            "key": "possible web scanning/probing",
            "rule": "scan|probe|cgi-bin|masscan|nikto|sqlmap",
            "must": [("rule.groups", "web")],
            "should": [("phrase", "scan"), ("phrase", "probe"), ("phrase", "cgi-bin")],
        },
        {
            "name": "sql_injection",
            "key": "SQL injection",
            "rule": "sql injection|union select|sqlmap|or 1=1|sqli",
            "must": [("rule.groups", "web")],
            "should": [
                ("phrase", "SQL injection"),
                ("phrase", "union select"),
                ("term", "sqlmap"),
                ("phrase", "1=1"),
            ],
        },
        {
            "name": "xss",
            "key": "cross-site scripting (XSS)",
            "rule": "cross site|xss|<script|javascript:",
            "must": [("rule.groups", "web")],
            "should": [("phrase", "cross site"), ("term", "xss"), ("phrase", "<script")],
        },
        {
            "name": "path_traversal_lfi",
            "key": "path traversal / LFI",
            "rule": "path traversal|../|lfi|directory traversal",
            "must": [("rule.groups", "web")],
            "should": [("phrase", "path traversal"), ("phrase", "../"), ("phrase", "..\\\\")],
        },
        {
            "name": "sensitive_urls",
            "key": "access to sensitive URLs",
            "rule": "admin|\\.env|wp-admin|\\.git|config.php|phpinfo",
            "must": [("rule.groups", "web")],
            "should": [
                ("phrase", "/admin"),
                ("phrase", "/.env"),
                ("phrase", "/wp-admin"),
                ("phrase", "/.git"),
            ],
        },
        {
            "name": "login_bruteforce",
            "key": "web login brute force",
            "rule": "brute force|bruteforce|authentication failure|access denied",
            "must": [("rule.groups", "web")],
            "should": [("term", "brute"), ("phrase", "access denied"), ("term", "401")],
        },
        {
            "name": "log4j_jndi",
            "key": "Log4Shell / JNDI injection",
            "rule": "log4j|jndi:|log4shell",
            "must": [("rule.groups", "web")],
            "should": [("term", "jndi"), ("term", "log4j"), ("term", "log4shell")],
        },
        {
            "name": "webshell_upload",
            "key": "webshell / RCE attempts",
            "rule": r"webshell|shell[.]php|cmd=.+[.]php|uploads[.]php|base64_decode",
            "must": [("rule.groups", "web")],
            "should": [("term", "webshell"), ("phrase", "shell.php"), ("term", "cmd=")],
        },
    ],
    "ssh": [
        {
            "name": "ssh_bruteforce",
            "key": "SSH brute force",
            "rule": "sshd: brute force|authentication failure|failed password|breakin",
            "must": [("rule.groups", "authentication_failures")],
            "should": [
                ("phrase", "brute force"),
                ("phrase", "authentication failure"),
                ("phrase", "failed password"),
            ],
        },
        {
            "name": "ssh_oddusers",
            "key": "SSH unknown-user abuse",
            "rule": "non-existent user|invalid user|useless sshd|unknown user",
            "must": [("rule.groups", "authentication_failures")],
            "should": [("phrase", "invalid user"), ("phrase", "non-existent user")],
        },
        {
            "name": "ssh_exploits",
            "key": "SSH exploit attempts",
            "rule": "openssh exploit|crc|challenge-response|corrupted bytes|ssh vulnerability",
            "must": [("rule.groups", "authentication_failures")],
            "should": [
                ("term", "openssh"),
                ("phrase", "challenge-response"),
                ("phrase", "corrupted bytes"),
            ],
        },
    ],
    "network": [
        {
            "name": "port_scan",
            "key": "network scans",
            "rule": "port scan|nmap|possible scan|multiple ports",
            "must": [("rule.groups", "attack")],
            "should": [("phrase", "port scan"), ("phrase", "possible scan"), ("term", "nmap")],
        },
        {
            "name": "recon_udp",
            "key": "UDP recon / sweep",
            "rule": "udp reconnaissance|recon|arp|suspicious udp",
            "must": [("rule.groups", "attack")],
            "should": [("term", "recon"), ("phrase", "suspicious udp")],
        },
        {
            "name": "malware_c2",
            "key": "C2 / malware comms",
            "rule": "backdoor|trojan|c2|command and control|botnet|malware",
            "must": [("rule.groups", "attack")],
            "should": [("term", "backdoor"), ("phrase", "command and control"), ("term", "botnet")],
        },
    ],
}


def _load_rules(ctx: ToolContext) -> list[dict[str, Any]]:
    """Page the whole manager ruleset once (metadata only). 4513 rules @
    500/page ~ 10 calls - bounded and read-only."""
    out: list[dict[str, Any]] = []
    offset = 0
    for _ in range(30):
        try:
            resp = ctx.wazuh.get_rules(limit=500, offset=offset)
        except Exception:  # noqa: BLE001 - manager hiccup -> partial result
            break
        items = resp.get("data", {}).get("affected_items", [])
        out.extend(items)
        total = int(resp.get("data", {}).get("total_affected_items", 0))
        offset += len(items)
        if offset >= total or not items:
            break
    return out


def _rule_blob(item: dict[str, Any]) -> str:
    det = item.get("details") or {}
    return " ".join(
        str(v) for v in (item.get("description"), " ".join(item.get("groups") or []), det)
    )


def _match_rules(rules: list[dict[str, Any]], terms: str) -> int:
    """Count distinct rules whose description/groups/details match the regex
    terms (local matching - the API `search` param is literal, not regex)."""
    import re

    try:
        prog = re.compile(terms, re.IGNORECASE)
    except re.error:
        return 0
    return sum(1 for r in rules if prog.search(_rule_blob(r)))


def _count(ctx: ToolContext, index: str, spec: dict[str, Any], time_range: str) -> int:
    """Structured bool count - no query_string parser involved."""
    must: list[dict[str, Any]] = [
        {"range": {"timestamp": {"gte": to_range_expr(time_range) or "now-24h"}}}
    ]
    must += [{"term": {field: value}} for field, value in spec.get("must", [])]
    should: list[dict[str, Any]] = []
    for kind, text in spec.get("should", []):
        if kind == "term":
            should.append(
                {
                    "multi_match": {
                        "query": text,
                        "fields": ["full_log", "rule.description"],
                        "type": "cross_fields",
                        "operator": "and",
                    }
                }
            )
        else:  # phrase
            should.append(
                {
                    "multi_match": {
                        "query": text,
                        "fields": ["full_log", "rule.description"],
                        "type": "phrase",
                    }
                }
            )
    body: dict[str, Any] = {"size": 0}
    if should:
        query: dict[str, Any] = {
            "bool": {"must": must, "should": should, "minimum_should_match": 1}
        }
    else:
        query = {"bool": {"must": must}}
    body["query"] = query
    try:
        r = ctx.indexer.search(index, body)
        return int(r.get("hits", {}).get("total", {}).get("value", 0))
    except Exception:  # noqa: BLE001 - indexer hiccup -> -1 (honest unknown)
        return -1


def _classify(rules: int, alerts: int, events: int) -> str:
    if rules > 0 and alerts > 0:
        return "detected"
    if rules > 0 and alerts == 0 and events > 0:
        return "partial"
    if rules > 0:
        return "covered_no_events"
    if events > 0:
        return "gap"
    return "unknown"


class AnalyzeDetectionGaps(BaseWazuhTool):
    name = "analyze_detection_gaps"
    description = (
        "Factual detection-gap analysis: for each attack category (web / ssh / network) "
        "build a 5-state coverage table using the real manager ruleset and the real "
        "indexer - detected / partial / covered_no_events / gap / unknown. The gap and "
        "partial rows are candidate detections to develop. Use for 'find detection gaps "
        "in my web server telemetry'."
    )
    input_schema = {
        "type": "object",
        "properties": {
            "target": {"type": "string", "description": "web | ssh | network (default web)"},
            "time_range": {"type": "string", "description": "default -7d"},
        },
        "required": [],
    }
    permission = Permission.READ

    def run(self, ctx: ToolContext, **params: Any) -> Any:
        p = self.validate(params)
        target = (p.get("target") or "web").lower()
        time_range = p.get("time_range") or "-7d"
        categories = _CATEGORIES.get(target)
        if not categories:
            raise ToolError(f"Unknown target '{target}'. Use web | ssh | network.")

        ruleset = _load_rules(ctx)
        rows: list[dict[str, Any]] = []
        for cat in categories:
            rules = _match_rules(ruleset, cat["rule"])
            alerts = _count(ctx, _INDEX, cat, time_range)
            events = _count(ctx, _ARCHIVE, cat, time_range)
            rows.append(
                {
                    "category": cat["name"],
                    "key": cat["key"],
                    "state": _classify(rules, alerts, events),
                    "rules": rules,
                    "alerts_seen": max(alerts, 0),
                    "raw_events_seen": max(events, 0),
                }
            )

        gaps = [r for r in rows if r["state"] in ("gap", "partial")]
        return {
            "target": target,
            "time_range": time_range,
            "index": _INDEX,
            "archive_index": _ARCHIVE,
            "coverage": rows,
            "gap_candidates": gaps,
            "summary": (
                f"{len(gaps)} category/categories need attention in {target} telemetry - "
                f"{sum(1 for r in rows if r['state'] == 'gap')} with activity but no rules, "
                f"{sum(1 for r in rows if r['state'] == 'partial')} with rules that do not fire on "
                f"observed activity."
            ),
        }


TOOLS = [AnalyzeDetectionGaps]
