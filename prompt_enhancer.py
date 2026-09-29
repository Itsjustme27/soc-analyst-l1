"""
Prompt enhancer - turn a short, free-text request into a normalized, validated
JSON spec before the agent sees it.

    "show me ssh brute force from 185.220.101.7 last 24h and make a rule for it"
        ->
    {"tasks": [{"type": "investigate", ...}, {"type": "create_rule", ...}],
     "entities": {"ips": ["185.220.101.7"], ...}, "time_range": "-24h",
     "ambiguities": [...], "needs_confirmation": true, "original": "..."}

Design (see docs/prompt_enhancer.md):

  * Hard facts come from CODE, never from the model: IPs, CIDRs, CVEs, MITRE
    technique ids, rule ids, ports, hashes, domains and the time range are
    extracted with patterns, so they can't be hallucinated or mistyped. If the
    model returns an IP the user never typed, it is discarded.
  * The model only does the fuzzy part - which task(s) the user wants and a
    short description of each - and its reply is validated against a closed
    schema (task types, fields, lengths). Anything outside it is dropped.
  * With no LLM, a failed call, or an unusable reply, a keyword classifier
    produces the tasks instead, so the enhancer never blocks a request.
  * The original text always travels with the spec; the agent is told the
    user's own words win on any conflict.
  * Only the user's text is ever sent to the model - never alert data or logs -
    so this adds no prompt-injection path.
  * Write-capable tasks (create_rule / create_dashboard) set
    `needs_confirmation`, so the UI/CLI can show "here's what I understood"
    before any work is done.
"""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

SCHEMA_VERSION = 1

TASK_TYPES: dict[str, str] = {
    "investigate": "investigate activity (an IP, host, user, alert or attack pattern)",
    "explain_alert": "explain why an alert/rule fired",
    "create_rule": "draft and propose a Wazuh detection rule",
    "create_dashboard": "design and propose a Wazuh dashboard",
    "detection_gaps": "find missing detection coverage",
    "question": "answer a general question (no Wazuh action needed)",
}
WRITE_TASKS = frozenset({"create_rule", "create_dashboard"})
MAX_TASKS = 4
MAX_TEXT = 300

# --------------------------------------------------------------------------- #
# Deterministic extraction
# --------------------------------------------------------------------------- #
_IPV4 = r"(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
_CIDR_RE = re.compile(rf"\b{_IPV4}/(?:3[0-2]|[12]?\d)\b")
_IP_RE = re.compile(rf"(?<![\d.]){_IPV4}(?![\d.]|/\d)")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_RULE_ID_RE = re.compile(r"\brule(?:\s*id)?\s*#?\s*(\d{3,6})\b", re.I)
_PORT_RE = re.compile(r"\bport\s*(\d{1,5})\b", re.I)
_HASH_RE = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
_DOMAIN_RE = re.compile(
    r"\b(?=[a-z0-9-]{1,63}\.)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|io|ru|cn|info|biz|xyz|top|co|uk|de|fr|local|internal|corp|lan)\b",
    re.I,
)
_USER_RE = re.compile(r"\b(?:user(?:name)?|account)\s+[\"']?([A-Za-z0-9._$\\-]{2,64})", re.I)
_HOST_RE = re.compile(
    r"\b(?:host(?:name)?|agent|server|endpoint|machine)\s+[\"']?([A-Za-z0-9._-]{2,64})", re.I
)
_NOT_NAMES = {
    "the",
    "a",
    "an",
    "is",
    "was",
    "that",
    "this",
    "with",
    "from",
    "for",
    "and",
    "to",
    "in",
    "on",
}

_UNIT = {
    "m": "m",
    "min": "m",
    "mins": "m",
    "minute": "m",
    "minutes": "m",
    "h": "h",
    "hr": "h",
    "hrs": "h",
    "hour": "h",
    "hours": "h",
    "d": "d",
    "day": "d",
    "days": "d",
    "w": "w",
    "week": "w",
    "weeks": "w",
}
_RANGE_RE = re.compile(
    r"\b(?:last|past|previous|in the last|over the last)\s+(\d{1,4})\s*"
    r"(m|mins?|minutes?|h|hrs?|hours?|d|days?|w|weeks?)\b",
    re.I,
)
_SHORT_RANGE_RE = re.compile(r"(?<![\w-])-?(\d{1,4})(m|h|d|w)\b", re.I)
_NAMED_RANGES = [
    (re.compile(r"\b(?:today|last\s+24\s*h(?:ours)?)\b", re.I), "-24h"),
    (re.compile(r"\byesterday\b", re.I), "-48h"),
    (re.compile(r"\b(?:this|last|past)\s+week\b", re.I), "-7d"),
    (re.compile(r"\b(?:this|last|past)\s+month\b", re.I), "-30d"),
    (re.compile(r"\b(?:last|past)\s+hour\b", re.I), "-1h"),
]


def _dedupe(items: list[str]) -> list[str]:
    seen, out = set(), []
    for x in items:
        k = x.lower()
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out


def extract_time_range(text: str) -> str | None:
    m = _RANGE_RE.search(text)
    if m:
        return f"-{int(m.group(1))}{_UNIT[m.group(2).lower()]}"
    for rx, value in _NAMED_RANGES:
        if rx.search(text):
            return value
    m = _SHORT_RANGE_RE.search(text)
    if m:
        return f"-{int(m.group(1))}{m.group(2).lower()}"
    return None


def extract_entities(text: str) -> dict[str, list[str]]:
    text = text or ""
    cidrs = _dedupe(_CIDR_RE.findall(text))
    ips = [ip for ip in _dedupe(_IP_RE.findall(text)) if _valid_ip(ip)]
    ports = _dedupe([p for p in _PORT_RE.findall(text) if 0 < int(p) <= 65535])
    users = _dedupe([u for u in _USER_RE.findall(text) if u.lower() not in _NOT_NAMES])
    hosts = _dedupe(
        [h for h in _HOST_RE.findall(text) if h.lower() not in _NOT_NAMES and not _valid_ip(h)]
    )
    return {
        "ips": ips,
        "cidrs": cidrs,
        "cves": _dedupe([c.upper() for c in _CVE_RE.findall(text)]),
        "mitre": _dedupe([t.upper() for t in _MITRE_RE.findall(text)]),
        "rule_ids": _dedupe(_RULE_ID_RE.findall(text)),
        "ports": ports,
        "hashes": _dedupe([h.lower() for h in _HASH_RE.findall(text)]),
        "domains": _dedupe([d.lower() for d in _DOMAIN_RE.findall(text) if not _valid_ip(d)]),
        "users": users,
        "hosts": hosts,
    }


def _valid_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Keyword classifier (no-LLM fallback)
# --------------------------------------------------------------------------- #
_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
    (
        "create_dashboard",
        re.compile(r"\b(dashboards?|visuali[sz](e|ation)s?|panels?|charts?)\b", re.I),
    ),
    (
        "create_rule",
        re.compile(
            r"\b(rule|detection|detect|alert on|decoder)\b.*\b(create|make|write|add|build|draft|new|propose)\b|"
            r"\b(create|make|write|add|build|draft|new|propose)\b.*\b(rule|detection|decoder)\b",
            re.I,
        ),
    ),
    ("detection_gaps", re.compile(r"\b(gaps?|coverage|blind ?spots?|missing detections?)\b", re.I)),
    (
        "explain_alert",
        re.compile(r"\b(why did|why was|explain)\b.*\b(alert|rule|fire|trigger)", re.I),
    ),
    (
        "investigate",
        re.compile(
            r"\b(investigate|look into|check|show|find|who|what happened|top|attack|attacking|"
            r"brute ?force|suspicious|activity|hunt|search)\b",
            re.I,
        ),
    ),
]


def classify_keywords(text: str, entities: dict[str, list[str]]) -> list[dict[str, Any]]:
    # Order tasks the way the user wrote them ("investigate X and make a rule"),
    # and leave description empty: the keyword path can't say more than the
    # type, and repeating the whole request per task is just noise. The agent
    # still gets the original text alongside the spec.
    found: list[tuple[int, str]] = []
    for ttype, rx in _KEYWORDS:
        m = rx.search(text or "")
        if m and not any(t == ttype for _, t in found):
            found.append((m.start(), ttype))
    tasks: list[dict[str, Any]] = [{"type": t, "description": ""} for _, t in sorted(found)]
    # "create a dashboard" also matches investigate words ("show"); keep the write
    # task and drop a redundant investigate only when nothing points at a target.
    has_target = any(
        entities.get(k) for k in ("ips", "hosts", "users", "cves", "rule_ids", "hashes", "domains")
    )
    if any(t["type"] in WRITE_TASKS for t in tasks) and not has_target:
        tasks = [t for t in tasks if t["type"] != "investigate"] or tasks
    if not tasks:
        tasks = [{"type": "investigate" if has_target else "question", "description": ""}]
    return tasks[:MAX_TASKS]


# --------------------------------------------------------------------------- #
# LLM classification (validated)
# --------------------------------------------------------------------------- #
_SYSTEM = (
    "You normalize requests sent to a SOC assistant for Wazuh. Split the request into "
    "tasks and describe each. Reply with ONE JSON object and nothing else:\n"
    '{"tasks": [{"type": "<type>", "description": "<what exactly to do, in plain words>", '
    '"details": {"<key>": "<value>"}}], "ambiguities": ["<assumption or missing detail>"], '
    '"clarifying_question": "<one question, or empty if the request is clear>"}\n'
    "Task types (use ONLY these): {types}\n"
    "Rules:\n- One task per distinct thing the user asked for; at most 4.\n"
    "- `details` holds short specifics you are sure of (e.g. threshold, focus, "
    "severity). Do not invent IPs, hosts, users, CVEs or ids.\n"
    "- Put every assumption you had to make in `ambiguities`.\n"
    "- Ask a clarifying question only if you genuinely cannot tell what they want.\n"
    "- JSON only, no prose, no markdown fence."
)
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.M)


def _clip(s: Any, n: int = MAX_TEXT) -> str:
    s = re.sub(r"\s+", " ", str(s or "")).strip()
    return s if len(s) <= n else s[: n - 1] + "…"


def _parse_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    c = _FENCE.sub("", str(text)).strip()
    a, b = c.find("{"), c.rfind("}")
    if a == -1 or b <= a:
        return None
    try:
        obj = json.loads(c[a : b + 1])
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


_IDENTIFIER_KEYS = ("ip", "host", "user", "cve", "hash", "domain", "rule_id", "technique")


def _sanitize_tasks(
    raw: Any, entities: dict[str, list[str]]
) -> tuple[list[dict[str, Any]], list[str]]:
    """Keep only known task types and short string details; drop any detail that
    names an identifier the user never typed (facts come from code)."""
    dropped: list[str] = []
    known_values = {v.lower() for vals in entities.values() for v in vals}
    out: list[dict[str, Any]] = []
    for t in raw if isinstance(raw, list) else []:
        if not isinstance(t, dict):
            continue
        ttype = str(t.get("type") or "").strip().lower()
        if ttype not in TASK_TYPES:
            dropped.append(f"unknown task type {ttype!r}")
            continue
        details: dict[str, str] = {}
        for k, v in (t.get("details") or {}).items() if isinstance(t.get("details"), dict) else []:
            k = _clip(k, 40).lower().replace(" ", "_")
            if isinstance(v, (list, tuple)):
                v = ", ".join(str(x) for x in v)
            v = _clip(v, 120)
            if not k or not v:
                continue
            if any(idk in k for idk in _IDENTIFIER_KEYS) and v.lower() not in known_values:
                dropped.append(f"detail {k}={v!r} names something not in the request")
                continue
            details[k] = v
        task = {"type": ttype, "description": _clip(t.get("description"))}
        if details:
            task["details"] = details
        out.append(task)
        if len(out) >= MAX_TASKS:
            break
    return out, dropped


def _classify_llm(text: str, llm: Any) -> tuple[dict[str, Any] | None, str | None]:
    system = _SYSTEM.replace("{types}", "; ".join(f"{k} = {v}" for k, v in TASK_TYPES.items()))
    try:
        reply = llm.chat_text(
            system=system, messages=[{"role": "user", "content": text}], max_tokens=700
        )
    except Exception as e:  # noqa: BLE001 - the enhancer must never block a request
        return None, f"LLM classification failed: {e}"
    obj = _parse_json(reply)
    if obj is None:
        return None, "LLM reply was not a JSON object"
    return obj, None


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def enhance(text: str, llm: Any = None, *, use_llm: bool = True) -> dict[str, Any]:
    """Normalize a request. Never raises; always returns a valid spec."""
    original = (text or "").strip()
    entities = extract_entities(original)
    time_range = extract_time_range(original)
    ambiguities: list[str] = []
    notes: list[str] = []
    clarify = ""
    source = "rules"
    tasks: list[dict[str, Any]] = []

    if use_llm and llm is not None and original:
        obj, err = _classify_llm(original, llm)
        if obj is not None:
            tasks, dropped = _sanitize_tasks(obj.get("tasks"), entities)
            notes.extend(dropped)
            ambiguities = [
                _clip(a, 200)
                for a in (obj.get("ambiguities") or [])
                if isinstance(a, str) and a.strip()
            ][:5]
            clarify = _clip(obj.get("clarifying_question") or "", 200)
            if tasks:
                source = "llm"
            else:
                notes.append("model returned no usable tasks - used keyword classification")
        else:
            notes.append(err or "LLM unavailable")
    if not tasks:
        tasks = classify_keywords(original, entities)

    if any(t["type"] in WRITE_TASKS for t in tasks) and time_range is None:
        ambiguities.append(
            "no time range given - the tools' defaults apply (usually the last 7 days)"
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "original": original,
        "tasks": tasks,
        "entities": {k: v for k, v in entities.items() if v},
        "time_range": time_range,
        "ambiguities": _dedupe(ambiguities),
        "clarifying_question": clarify,
        "needs_confirmation": any(t["type"] in WRITE_TASKS for t in tasks),
        "source": source,
        "notes": notes,
    }


def validate_spec(spec: Any) -> dict[str, Any]:
    """Re-validate a spec that came back from a client (the UI lets the user
    confirm or edit it). Facts are re-extracted from the original text, never
    trusted from the client."""
    if not isinstance(spec, dict) or not str(spec.get("original") or "").strip():
        raise ValueError("spec must be an object with a non-empty 'original'")
    original = str(spec["original"]).strip()
    entities = extract_entities(original)
    tasks, _ = _sanitize_tasks(spec.get("tasks"), entities)
    if not tasks:
        tasks = classify_keywords(original, entities)
    return {
        **enhance(original, use_llm=False),
        "tasks": tasks,
        "ambiguities": [
            _clip(a, 200) for a in (spec.get("ambiguities") or []) if isinstance(a, str)
        ][:5],
        "needs_confirmation": any(t["type"] in WRITE_TASKS for t in tasks),
        "source": "confirmed",
    }


def render_for_agent(spec: dict[str, Any]) -> str:
    """The block appended to the user's message for the agent."""
    payload = {k: spec.get(k) for k in ("tasks", "entities", "time_range", "ambiguities")}
    return (
        "\n\n[Structured request from the prompt enhancer - guidance only; the user's own "
        "words above take precedence on any conflict. Handle every task listed.]\n"
        "```json\n" + json.dumps(payload, indent=2) + "\n```"
    )


def summarize(spec: dict[str, Any]) -> list[str]:
    """Human-readable 'here's what I understood' lines."""
    lines = []
    for i, t in enumerate(spec.get("tasks") or [], 1):
        details = "; ".join(f"{k}: {v}" for k, v in (t.get("details") or {}).items())
        label = TASK_TYPES.get(t["type"], t["type"])
        label = label[:1].upper() + label[1:]  # not .capitalize(): keeps "Wazuh", "IP"
        desc = t.get("description") or ""
        lines.append(
            f"{i}. {label}" + (f": {desc}" if desc else "") + (f" ({details})" if details else "")
        )
    ents = spec.get("entities") or {}
    if ents:
        lines.append("Entities: " + "; ".join(f"{k}: {', '.join(v)}" for k, v in ents.items()))
    if spec.get("time_range"):
        lines.append(f"Time range: {spec['time_range']}")
    for a in spec.get("ambiguities") or []:
        lines.append(f"Assumption: {a}")
    if spec.get("clarifying_question"):
        lines.append(f"Question: {spec['clarifying_question']}")
    return lines


def attach(message: str, spec: dict[str, Any]) -> str:
    return message + render_for_agent(spec)
