"""
The L1 triage agent itself.

Pattern: a bounded tool-use loop (max_turns) where Claude decides which
enrichment/retrieval tools to call, then must emit a final structured verdict
as a tool call (`submit_verdict`). This keeps the output machine-parseable
for the ticketing system and audit log, instead of parsing free text.

Guardrails baked in here (not just in the connectors):
  - The agent can never call a containment action directly; it can only
    *recommend* one via submit_verdict.recommended_action. A separate,
    human-gated step (see main.py) decides whether to actually execute it.
  - Every tool call and its result is kept in the transcript that gets
    logged with the case - full audit trail.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from config import cfg
from connectors.siem import SIEMConnector, get_siem_connector
from llm import get_provider
from rag.knowledge_base import KnowledgeBase

if cfg.MOCK_MODE:
    from connectors.mock_connectors import MockCrowdStrikeConnector as CrowdStrikeConnector
else:
    from connectors.crowdstrike_connector import CrowdStrikeConnector


def _tool_input(tc: Any) -> dict[str, Any]:
    """LLM tool arguments must be a JSON *object*. A truncated/malformed
    arguments payload can arrive as a bool/list/str/None; normalize so a
    malformed submit_verdict can't crash the whole triage run."""
    raw = getattr(tc, "input", None)
    return raw if isinstance(raw, dict) else {}


MAX_TOOL_TURNS = 8

SYSTEM_PROMPT = """You are an L1 SOC triage analyst agent. You investigate one \
security alert at a time and must reach a verdict grounded in evidence you \
actually retrieved - never guess at facts you haven't looked up.

Process:
1. Read the alert. Retrieve the relevant playbook for this alert type first.
2. Retrieve similar historical cases - if a near-identical case was closed as \
a false positive before, weight that heavily.
3. Retrieve any "lessons" - these are notes written by past analyst \
corrections and take priority over your own general knowledge, since they \
capture this specific organization's environment quirks.
4. Use enrichment tools (host info, process tree, related events, detection \
details) as needed per the playbook's triage steps. Don't call tools you \
don't need.
5. When you have enough evidence, call submit_verdict with your conclusion. \
Cite which specific evidence drove the verdict in your rationale.

Be conservative: if evidence is ambiguous or incomplete, verdict should be \
"escalate" with confidence reflecting that ambiguity, not a forced guess. \
You never take containment actions yourself - you only recommend them."""

TOOLS = [
    {
        "name": "retrieve_playbook",
        "description": "Retrieve the relevant SOC playbook/SOP for this kind of alert.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "e.g. alert type or short description"}
            },
            "required": ["query"],
        },
    },
    {
        "name": "retrieve_similar_cases",
        "description": "Retrieve past closed cases similar to this alert, with their verdicts and reasoning.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "retrieve_lessons",
        "description": "Retrieve self-written lessons distilled from prior analyst corrections - environment-specific quirks and known-noisy patterns.",
        "input_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
        },
    },
    {
        "name": "search_related_events",
        "description": "SIEM: find other events for a given host/user in a time window - use to check for a broader pattern.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "user": {"type": "string"},
                "earliest": {"type": "string", "description": "time modifier, default -24h"},
            },
        },
    },
    {
        "name": "get_host_info",
        "description": "CrowdStrike: get host metadata (OS, criticality, owner, last seen).",
        "input_schema": {
            "type": "object",
            "properties": {"host_id": {"type": "string"}},
            "required": ["host_id"],
        },
    },
    {
        "name": "get_process_tree",
        "description": "CrowdStrike: get the process ancestry/children for the process that triggered the detection.",
        "input_schema": {
            "type": "object",
            "properties": {"falcon_process_id": {"type": "string"}},
            "required": ["falcon_process_id"],
        },
    },
    {
        "name": "get_detection_details",
        "description": "CrowdStrike: get full details of a specific detection by ID.",
        "input_schema": {
            "type": "object",
            "properties": {"detection_id": {"type": "string"}},
            "required": ["detection_id"],
        },
    },
    {
        "name": "get_host_alert_history",
        "description": "CrowdStrike: prior detections on this host - is it a known-noisy box.",
        "input_schema": {
            "type": "object",
            "properties": {"host_id": {"type": "string"}},
            "required": ["host_id"],
        },
    },
    {
        "name": "submit_verdict",
        "description": "Final answer. Call this exactly once, when you're done investigating.",
        "input_schema": {
            "type": "object",
            "properties": {
                "verdict": {
                    "type": "string",
                    "enum": ["false_positive", "true_positive", "escalate"],
                },
                "confidence": {"type": "number", "description": "0.0-1.0"},
                "recommended_action": {
                    "type": "string",
                    "enum": [
                        "close_no_action",
                        "monitor",
                        "isolate_host",
                        "disable_account",
                        "escalate_to_l2",
                    ],
                },
                "rationale": {
                    "type": "string",
                    "description": "Cite the specific evidence retrieved.",
                },
                "evidence_used": {"type": "array", "items": {"type": "string"}},
            },
            "required": [
                "verdict",
                "confidence",
                "recommended_action",
                "rationale",
                "evidence_used",
            ],
        },
    },
]


@dataclass
class TriageResult:
    verdict: str
    confidence: float
    recommended_action: str
    rationale: str
    evidence_used: list[str]
    transcript: list[dict[str, Any]] = field(default_factory=list)


def needs_human_review(
    result: TriageResult, rule_matches: list[dict[str, Any]] | None = None
) -> bool:
    """Single source of truth for the "does a human need to look at this"
    check - main.py, run.py, and dashboard.py's on-demand triage route all
    call this instead of each re-implementing the same three conditions."""
    rule_escalate = any(
        m.get("action", {}).get("escalate") for m in (rule_matches or []) if m.get("triggered")
    )
    return (
        result.verdict == "escalate"
        or result.confidence < cfg.AUTO_CLOSE_CONFIDENCE_THRESHOLD
        or result.recommended_action in ("isolate_host", "disable_account")
        or rule_escalate
    )


class TriageAgent:
    def __init__(self, provider: str | None = None, siem: SIEMConnector | None = None):
        """`provider` overrides the LLM_PROVIDER env var (e.g. mock/anthropic).

        `siem` injects a specific SIEM connector (any platform - Splunk,
        QRadar, Elastic, Sentinel, mock, or a dashboard-registered connection).
        When None, it resolves from MOCK_MODE / SIEM_PROVIDER in .env.
        """
        self.llm = get_provider(provider)
        self.kb = KnowledgeBase()
        self.siem = siem or self._default_siem()
        self.crowdstrike = CrowdStrikeConnector()

    @staticmethod
    def _default_siem() -> SIEMConnector:
        if cfg.MOCK_MODE:
            return get_siem_connector("mock", name="mock")
        return get_siem_connector(cfg.SIEM_PROVIDER)

    # ------------------------------------------------------------------ #
    def _execute_tool(self, name: str, tool_input: dict[str, Any]) -> Any:
        if name == "retrieve_playbook":
            return self.kb.query("playbooks", tool_input["query"])
        if name == "retrieve_similar_cases":
            return self.kb.query("cases", tool_input["query"])
        if name == "retrieve_lessons":
            return self.kb.query("lessons", tool_input["query"])
        if name == "search_related_events":
            return self.siem.search_related_events(
                host=tool_input.get("host"),
                user=tool_input.get("user"),
                earliest=tool_input.get("earliest", "-24h"),
            )
        if name == "get_host_info":
            return self.crowdstrike.get_host_info(tool_input["host_id"])
        if name == "get_process_tree":
            return self.crowdstrike.get_process_tree(tool_input["falcon_process_id"])
        if name == "get_detection_details":
            return self.crowdstrike.get_detection_details(tool_input["detection_id"])
        if name == "get_host_alert_history":
            return self.crowdstrike.get_host_alert_history(tool_input["host_id"])
        raise ValueError(f"unknown tool {name}")

    # ------------------------------------------------------------------ #
    def triage(self, alert: dict[str, Any]) -> TriageResult:
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": f"New alert to triage:\n\n{json.dumps(alert, indent=2)}"}
        ]
        transcript: list[dict[str, Any]] = []

        for _ in range(MAX_TOOL_TURNS):
            resp = self.llm.chat(
                system=SYSTEM_PROMPT,
                messages=messages,
                tools=TOOLS,
                max_tokens=2000,
            )
            messages.append(
                {
                    "role": "assistant",
                    "content": resp.content,
                    "tool_calls": [
                        {"id": tc.id, "name": tc.name, "input": _tool_input(tc)}
                        for tc in resp.tool_calls
                    ],
                }
            )

            if not resp.tool_calls:
                # Model didn't call a tool - nudge it, it must submit_verdict to finish.
                messages.append(
                    {
                        "role": "user",
                        "content": "Please call submit_verdict to finish, or call another tool if you need more evidence.",
                    }
                )
                continue

            tool_results: list[dict[str, Any]] = []
            for call in resp.tool_calls:
                call_input = _tool_input(call)
                transcript.append({"tool": call.name, "input": call_input})
                if call.name == "submit_verdict":
                    v = call_input
                    transcript.append({"final_verdict": v})
                    try:
                        verdict = v["verdict"]
                        confidence = float(v["confidence"])
                        action = v["recommended_action"]
                        rationale = v["rationale"]
                        evidence = v["evidence_used"]
                    except (KeyError, TypeError, ValueError) as e:
                        # Truncated/malformed verdict - never crash the run;
                        # tell the model and let it retry within the budget.
                        transcript.append(
                            {"tool_result": {"error": "malformed verdict", "detail": str(e)}}
                        )
                        tool_results.append(
                            {
                                "role": "tool",
                                "tool_call_id": call.id,
                                "content": json.dumps(
                                    {
                                        "error": "Malformed submit_verdict arguments - expected an object with "
                                        "verdict, confidence, recommended_action, rationale, evidence_used. "
                                        "Please retry.",
                                        "detail": str(e),
                                    },
                                    default=str,
                                ),
                            }
                        )
                        continue
                    return TriageResult(
                        verdict=verdict,
                        confidence=confidence,
                        recommended_action=action,
                        rationale=rationale,
                        evidence_used=evidence,
                        transcript=transcript,
                    )
                try:
                    result = self._execute_tool(call.name, call_input)
                except Exception as e:  # connector unreachable, bad id, etc.
                    result = {"error": str(e)}
                transcript.append({"tool_result": result})
                tool_results.append(
                    {
                        "role": "tool",
                        "tool_call_id": call.id,
                        "content": json.dumps(result, default=str),
                    }
                )
            messages.extend(tool_results)

        # Ran out of turns without a verdict - fail safe to escalate.
        return TriageResult(
            verdict="escalate",
            confidence=0.0,
            recommended_action="escalate_to_l2",
            rationale="Agent did not reach a verdict within the tool-call budget - escalating for manual review.",
            evidence_used=[],
            transcript=transcript,
        )
