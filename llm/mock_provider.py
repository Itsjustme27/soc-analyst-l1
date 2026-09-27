"""
Deterministic, fully-offline LLM provider.

Two uses:

1. Development / CI / demos with no API key at all:
       LLM_PROVIDER=mock   or   python main.py demo --provider mock
   The full pipeline (RAG retrieval -> enrichment -> structured verdict ->
   audit log) runs end to end with canned reasoning.

2. A minimal reference implementation for "how to add a provider" - read the
   LLMProvider interface in llm/base.py, then mirror the two methods here.

It does NOT reason. It replays a scripted triage per alert type and builds
the final verdict from tool results that actually appear in the conversation
history, so the transcript still shows the retrieval -> enrichment -> verdict
flow (and would break loudly if a real endpoint changed shape).
"""

from __future__ import annotations

import json
from typing import Any

import guard
from llm.base import LLMProvider, LLMResponse, ToolCall

ALERT_PREFIX = "New alert to triage:"


# --------------------------------------------------------------------------- #
# scripted answers for the two generative builder prompts (dashboard planner,
# rule drafter). Deterministic, key-free stand-ins for a real model so
# MOCK_MODE demos and the offline test suite exercise the real code paths.


def _mock_dashboard_plan(user_msg: str) -> dict[str, Any]:
    blob = (user_msg or "").lower()
    filters: list[dict[str, Any]] = []
    panels: list[dict[str, Any]] = []
    if "ssh" in blob or "login" in blob or "auth" in blob:
        filters.append({"field": "rule_group", "op": "match_phrase", "values": ["ssh"]})
        panels += [
            {"kind": "breakdown", "field": "src_ip", "vis": "pie"},
            {"kind": "breakdown", "field": "dst_ip", "vis": "bar"},
            {"kind": "breakdown", "field": "user", "vis": "bar"},
            {"kind": "breakdown", "field": "rule_level", "vis": "bar"},
        ]
    if "private" in blob:
        private = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        filters.append({"field": "src_ip", "op": "cidr", "values": private})
        filters.append({"field": "dst_ip", "op": "cidr", "values": private})
    if "web" in blob:
        filters.append({"field": "rule_group", "op": "match_phrase", "values": ["web"]})
        panels.append({"kind": "breakdown", "field": "src_ip", "vis": "pie"})
    panels.append({"kind": "breakdown", "field": "agent", "vis": "bar"})
    return {
        "title": "Mock Planned Dashboard",
        "filters": filters,
        "panels": panels,
        "notes": "Scripted mock plan (no model was called).",
    }


def _mock_rule_draft(user_msg: str) -> dict[str, Any]:
    blob = (user_msg or "").lower()
    rule_xml = (
        '<rule id="100250" level="10" frequency="5" timeframe="120">\n'
        "  <if_matched_sid>5760</if_matched_sid>\n"
        "  <description>Mock: repeated failed logins from one source (scripted draft)"
        "</description>\n"
        "  <group>authentication_failures,</group>\n"
        "</rule>"
    )
    positives = [
        "Nov 21 09:41:01 db01 sshd[2710]: Failed password for invalid user root from 10.10.4.22 port 44555 ssh2",
        "Nov 21 09:41:04 db01 sshd[2710]: Failed password for invalid user admin from 10.10.4.22 port 44561 ssh2",
        "Nov 21 09:41:09 db01 sshd[2710]: Failed password for invalid user oracle from 10.10.4.22 port 44570 ssh2",
    ]
    negatives: list[str] = []
    if "web" in blob or "http" in blob:
        rule_xml = (
            '<rule id="100251" level="12">\n'
            '  <match type="pcre2">"GET [^"]*" 40[0-9] </match>\n'
            "  <description>Mock: repeated HTTP 40x responses (scripted draft)</description>\n"
            "  <group>web,</group>\n"
            "</rule>"
        )
        positives = [
            'Nov 21 09:41:02 web01 nginx: 10.10.4.22 - - "GET /admin.php HTTP/1.1" 404 162 "-" "curl/8.4.0"',
            'Nov 21 09:41:05 web01 nginx: 10.10.4.22 - - "GET /.env HTTP/1.1" 404 162 "-" "curl/8.4.0"',
        ]
        negatives = [
            'Nov 21 09:41:09 web01 nginx: 10.10.4.30 - - "GET /health HTTP/1.1" 200 12 "-" "kube-probe/1.29"'
        ]
    return {
        "rule_xml": rule_xml,
        "positive_samples": positives,
        "negative_samples": negatives,
        "log_format": "syslog",
        "notes": "Scripted mock draft (no model was called).",
    }


# --------------------------------------------------------------------------- #
# conversation helpers


def _first_alert(messages: list[dict[str, Any]]) -> dict[str, Any] | None:
    for m in messages:
        content = m.get("content")
        if (
            m.get("role") == "user"
            and isinstance(content, str)
            and content.startswith(ALERT_PREFIX)
        ):
            try:
                return json.loads(guard.unwrap(content[len(ALERT_PREFIX) :].strip()))
            except json.JSONDecodeError:
                return {}
    return None


def _classify(alert: dict[str, Any]) -> str:
    blob = json.dumps(alert).lower()
    if any(k in blob for k in ("brute", "auth failure", "credential stuff", " login")):
        return "brute_force"
    if any(k in blob for k in ("malware", "beacon", "suspicious process", "powershell", "edr")):
        return "malware"
    if any(k in blob for k in ("phish", "email", "spf", "dkim")):
        return "phishing"
    return "general"


def _issued_tool_calls(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in messages:
        if m.get("role") == "assistant":
            out.extend(m.get("tool_calls") or [])
    return out


def _tool_results(messages: list[dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for m in messages:
        if m.get("role") == "tool":
            try:
                out[m["tool_call_id"]] = json.loads(guard.unwrap(m["content"]))
            except (KeyError, json.JSONDecodeError):
                out[m.get("tool_call_id", "")] = {"raw": m.get("content")}
    return out


# --------------------------------------------------------------------------- #
# provider


class MockProvider(LLMProvider):
    name = "mock"

    def _plan(self, alert_type: str, alert: dict[str, Any]) -> list[ToolCall]:
        if alert_type == "brute_force":
            return [
                ToolCall(
                    id="mock-1",
                    name="retrieve_playbook",
                    input={"query": "brute force credential stuff multiple auth failures"},
                ),  # noqa
                ToolCall(
                    id="mock-2",
                    name="retrieve_similar_cases",
                    input={"query": "brute force multiple auth failures then success"},
                ),  # noqa
                ToolCall(
                    id="mock-3",
                    name="retrieve_lessons",
                    input={"query": "brute force source ip reputation mfa fatigue service account"},
                ),  # noqa
                ToolCall(
                    id="mock-4",
                    name="search_related_events",
                    input={
                        "host": alert.get("host"),
                        "user": alert.get("user"),
                        "earliest": "-24h",
                    },
                ),  # noqa
            ]
        if alert_type == "malware":
            return [
                ToolCall(
                    id="mock-1",
                    name="retrieve_playbook",
                    input={"query": "malware detection c2 beacon edr"},
                ),
                ToolCall(
                    id="mock-2",
                    name="retrieve_similar_cases",
                    input={"query": "edr malware office macro spawning powershell base64"},
                ),
                ToolCall(
                    id="mock-3",
                    name="retrieve_lessons",
                    input={"query": "malware beacon suspicious parent process unknown hash"},
                ),
                ToolCall(
                    id="mock-4", name="get_host_info", input={"host_id": alert.get("host_id")}
                ),
                ToolCall(
                    id="mock-5",
                    name="get_process_tree",
                    input={"falcon_process_id": alert.get("falcon_process_id")},
                ),
                ToolCall(
                    id="mock-6",
                    name="get_detection_details",
                    input={"detection_id": alert.get("detection_id")},
                ),
                ToolCall(
                    id="mock-7",
                    name="get_host_alert_history",
                    input={"host_id": alert.get("host_id")},
                ),
            ]
        if alert_type == "phishing":
            return [
                ToolCall(
                    id="mock-1",
                    name="retrieve_playbook",
                    input={"query": "phishing user reported suspicious email spf dkim"},
                ),
                ToolCall(
                    id="mock-2",
                    name="retrieve_similar_cases",
                    input={"query": "phishing spoofed it support credentials link"},
                ),
                ToolCall(
                    id="mock-3",
                    name="retrieve_lessons",
                    input={"query": "phishing credential lure no click monitor"},
                ),
            ]
        return [
            ToolCall(id="mock-1", name="retrieve_playbook", input={"query": "general triage"}),
            ToolCall(
                id="mock-2", name="retrieve_similar_cases", input={"query": "similar past cases"}
            ),
            ToolCall(id="mock-3", name="retrieve_lessons", input={"query": "known noisy patterns"}),
        ]

    # ------------------------------------------------------------------ #
    def chat_text(self, *, system, messages, max_tokens) -> str:
        """Answer the two GENERATIVE builder prompts offline.

        The engineer console calls chat_text (no tools) to plan a dashboard from
        a free-text intent and to draft a rule from a request. Both expect a
        single JSON object. Scripted answers keep MOCK_MODE demos and the test
        suite working with no API key; anything else still returns the neutral
        no-op reply below."""
        system = system or ""
        last = ""
        for m in reversed(messages or []):
            if m.get("role") == "user":
                last = str(m.get("content") or "")
                break
        if "plan Wazuh security dashboards" in system:
            return json.dumps(_mock_dashboard_plan(last))
        if "You write Wazuh detection rules" in system:
            return json.dumps(_mock_rule_draft(last))
        return "[]"

    # ------------------------------------------------------------------ #
    def chat(self, *, system, messages, tools, max_tokens) -> LLMResponse:
        alert = _first_alert(messages)
        if alert is None:
            # Not an alert-triage prompt (e.g. lesson distillation) -> no-op.
            return LLMResponse(content="[]")

        alert_type = _classify(alert)
        plan = self._plan(alert_type, alert)
        issued = {tc["id"] for tc in _issued_tool_calls(messages)}

        for call in plan:
            if call.id not in issued:
                return LLMResponse(tool_calls=[call])
        return LLMResponse(tool_calls=[self._verdict(alert_type, alert, _tool_results(messages))])

    # ------------------------------------------------------------------ #
    def _verdict(self, alert_type: str, alert: dict[str, Any], results: dict[str, Any]) -> ToolCall:
        if alert_type == "brute_force":
            events = results.get("mock-4")
            if not isinstance(events, list):
                events = []
            successes = [e for e in events if str(e.get("result", "")).lower() == "success"]
            raw = alert.get("raw_fields", {})
            v = {
                "verdict": "true_positive",
                "confidence": 0.82,
                "recommended_action": "escalate_to_l2",
                "rationale": (
                    f"Brute force from source IP {alert.get('src_ip', 'unknown')} "
                    f"(AS {raw.get('source_asn', 'unknown')} - proxy/VPN hosting) followed by a "
                    "successful login with no MFA prompt. Per the brute-force playbook, successful "
                    "auth after failures is an account-compromise investigation: recommend password "
                    "reset + session revocation and escalate to L2 for a lateral-movement scope check."
                ),
                "evidence_used": [
                    "playbook: brute_force.md (success after failures => contain + escalate)",
                    f"splunk search_related_events: {len(events)} event(s), {len(successes)} "
                    f"success without MFA from {alert.get('src_ip')}",
                    f"alert raw_fields: source_asn={raw.get('source_asn')}, mfa_satisfied={raw.get('mfa_satisfied')}",
                ],
            }
            return ToolCall(id="mock-verdict", name="submit_verdict", input=v)

        if alert_type == "malware":
            tree = results.get("mock-5", {})
            det = results.get("mock-6", {})
            parent = (tree.get("parent") or {}).get("process_name", "unknown")
            hash_val = (tree or {}).get("file_hash_sha256", "unknown")
            v = {
                "verdict": "true_positive",
                "confidence": 0.9,
                "recommended_action": "isolate_host",
                "rationale": (
                    f"{parent} spawned powershell.exe with a base64-encoded command line (decodes to "
                    f"a download cradle), hash {hash_val} has unknown reputation, and the detection "
                    "was NOT prevented by EDR. Matches the malware playbook's contain criteria "
                    "(unusual Office -> PowerShell parent chain + unknown hash). Recommend host "
                    "isolation (dry-run) and L2 follow-up for persistence/IOC sweep."
                ),
                "evidence_used": [
                    "playbook: malware_beacon.md (Office spawns PowerShell + unknown hash => contain)",
                    f"crowdstrike get_process_tree: parent={parent}, -enc cradle, hash {hash_val} unknown",
                    f"crowdstrike get_detection_details: severity={det.get('severity')}, "
                    f"prevented={det.get('prevented')}",
                    "crowdstrike get_host_alert_history: first detection on host in window",
                ],
            }
            return ToolCall(id="mock-verdict", name="submit_verdict", input=v)

        if alert_type == "phishing":
            raw = alert.get("raw_fields", {})
            v = {
                "verdict": "true_positive",
                "confidence": 0.62,
                "recommended_action": "monitor",
                "rationale": (
                    f"Spoofed 'IT support' sender ({raw.get('sender')}) with SPF and DKIM both failing "
                    "and a credential-harvesting lure. Link was NOT clicked, so no credential entry or "
                    "execution yet - per the phishing playbook this is monitor: block the sender domain, "
                    "watch IDP logs, and escalate only if the user clicks or an anomalous login follows."
                ),
                "evidence_used": [
                    "playbook: phishing.md (no click, no anomalous login => monitor)",
                    f"alert raw_fields: spf={raw.get('spf')}, dkim={raw.get('dkim')}, "
                    f"link_clicked={raw.get('link_clicked')}",
                ],
            }
            return ToolCall(id="mock-verdict", name="submit_verdict", input=v)

        v = {
            "verdict": "escalate",
            "confidence": 0.5,
            "recommended_action": "escalate_to_l2",
            "rationale": "Mock provider has no scripted verdict for this alert type - escalating.",
            "evidence_used": [],
        }
        return ToolCall(id="mock-verdict", name="submit_verdict", input=v)
