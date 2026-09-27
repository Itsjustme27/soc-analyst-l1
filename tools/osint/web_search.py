"""Shared OSINT web search for every agent that needs it.

Moved out of `agent/chat_agent.py` so the engineer and the triage analyst can
use the same implementation instead of each growing its own. The chat agent
re-exports `web_search` from here, so its behaviour is unchanged.

Four things this module does that the original did not, each because the
original was written for exactly one interactive caller and is now reachable
from an unattended one:

1. GUARD WRAPPED AT THE SOURCE. `web_search` returns
   `guard.wrap_tool_output(...)`, so every caller gets untrusted-data markers
   whether or not its own loop wraps results. The chat agent did not wrap
   either, so internet text was already reaching a model unmarked.

2. EVERY QUERY IS AUDIT-LOGGED. The query string leaves the building. If the
   agent puts an internal hostname, a customer name, or an estate-specific
   indicator into a query, that is your environment going to a third party -
   and an injected instruction could cause it. Logging every query to
   `WEB_QUERY_LOG_PATH` makes that inspectable after the fact rather than
   invisible. This is the main reason the analyst can be given search at all.

3. AN EMPTY RESULT IS NOT "NOTHING EXISTS". Both backends fail soft, and with
   no SearXNG configured the only backend is DuckDuckGo's *instant answer*
   endpoint, which is a disambiguation database and returns almost nothing for
   security queries. A bare `results: []` invites a model to conclude there is
   no threat intelligence on the subject. `note` says which backend was asked
   and whether it was even configured, so silence is never mistaken for
   absence.

4. RESULTS CARRY PROVENANCE. Each result keeps its `url` and a `fetched_at`,
   and a `kind: "web"` tag, which is what keeps web-sourced text outside
   `triage_agent.HUMAN_AUTHORED_KINDS` - the tier that may auto-close an alert
   with no human.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import guard
from config import cfg

MAX_RESULTS = 8
_SNIPPET_CAP = 300
_TITLE_CAP = 120
_URL_CAP = 500


# --------------------------------------------------------------------------- #
# audit log
# --------------------------------------------------------------------------- #
def _log_query(query: str, backend: str, count: int, error: str = "") -> None:
    """Append one row per query. Never raises - auditing must not break search."""
    path = Path(getattr(cfg, "WEB_QUERY_LOG_PATH", "") or "data/web_queries.jsonl")
    row = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "query": query[:500],
        "backend": backend,
        "count": count,
    }
    if error:
        row["error"] = error[:200]
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, default=str) + "\n")
    except Exception:  # noqa: BLE001 - a failed audit write must not fail the search
        pass


# --------------------------------------------------------------------------- #
# backends
# --------------------------------------------------------------------------- #
def _ddg_instant(query: str) -> list[dict[str, Any]]:
    """DuckDuckGo instant answers.

    NOT a web search: this endpoint answers "who/what is X" for entities it
    recognises. It is kept first because it is keyless, but it returns nothing
    for most security queries, which is why `note` in web_search() reports the
    backend rather than presenting an empty list as a finding.
    """
    import requests

    try:
        r = requests.get(
            "https://api.duckduckgo.com/",
            params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1},
            timeout=8,
        )
        r.raise_for_status()
    except Exception:  # noqa: BLE001 - offline / blocked -> fall through
        return []
    data = r.json()
    out: list[dict[str, Any]] = []
    if data.get("AbstractText"):
        out.append(
            {
                "title": "Instant answer",
                "snippet": str(data.get("AbstractText"))[:_SNIPPET_CAP],
                "url": data.get("AbstractURL", ""),
            }
        )
    for topic in data.get("RelatedTopics") or []:
        if not isinstance(topic, dict):
            continue
        if "Text" in topic and topic.get("FirstURL"):
            out.append(
                {
                    "title": str(topic.get("Text", ""))[:_TITLE_CAP],
                    "snippet": str(topic.get("Text", ""))[:_SNIPPET_CAP],
                    "url": topic.get("FirstURL", ""),
                }
            )
        for sub in topic.get("Topics") or []:
            if isinstance(sub, dict) and sub.get("FirstURL"):
                out.append(
                    {
                        "title": str(sub.get("Text", ""))[:_TITLE_CAP],
                        "snippet": str(sub.get("Text", ""))[:_SNIPPET_CAP],
                        "url": sub.get("FirstURL", ""),
                    }
                )
        if len(out) >= MAX_RESULTS:
            break
    return out[:MAX_RESULTS]


def _searxng(query: str) -> list[dict[str, Any]]:
    import requests

    base = (getattr(cfg, "SEARXNG_URL", "") or "").rstrip("/")
    if not base:
        return []
    try:
        r = requests.get(
            f"{base}/search",
            params={"q": query, "format": "json"},
            headers={"User-Agent": "soc-triage-agent/1.0"},
            timeout=8,
        )
        r.raise_for_status()
    except Exception:  # noqa: BLE001 - searxng down -> fall through
        return []
    return [
        {
            "title": str(x.get("title") or "")[:_TITLE_CAP],
            "snippet": str(x.get("content") or "")[:_SNIPPET_CAP],
            "url": x.get("url", ""),
        }
        for x in (r.json().get("results") or [])[:MAX_RESULTS]
    ]


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #
def web_search(query: str) -> dict[str, Any]:
    """OSINT web search. Keyless DuckDuckGo instant answers, then SearXNG.

    The returned `note` is load-bearing: it distinguishes "no backend is
    configured" from "the backend answered and found nothing", which a bare
    empty `results` list cannot.
    """
    if not getattr(cfg, "WEB_SEARCH_ENABLED", False):
        return {
            "enabled": False,
            "note": (
                "Web search is disabled (WEB_SEARCH_ENABLED=false). Nothing was "
                "searched - do NOT read this as there being no information on "
                "the subject."
            ),
            "results": [],
        }

    q = (query or "").strip()[:300]
    results = _ddg_instant(q)
    backend = "duckduckgo-instant"
    searx_configured = bool((getattr(cfg, "SEARXNG_URL", "") or "").strip())
    if not results:
        # Only claim the searxng backend if it was actually configured and
        # therefore actually asked. Labelling an unconfigured fallback as
        # "searxng" makes the note say a search happened when none did, which
        # is the false negative this whole note field exists to prevent.
        if searx_configured:
            results = _searxng(q)
            backend = "searxng"

    # Caps are enforced HERE, not only in the backends. The backends each trim
    # their own results, but a new or altered backend that forgets to would
    # otherwise feed unbounded attacker-influenced text straight into a model's
    # context. This is the one choke point every backend passes through.
    results = [
        {
            "title": str(r.get("title") or "")[:_TITLE_CAP],
            "snippet": str(r.get("snippet") or "")[:_SNIPPET_CAP],
            "url": str(r.get("url") or "")[:_URL_CAP],
        }
        for r in results[:MAX_RESULTS]
        if isinstance(r, dict)
    ]

    if not results:
        if not searx_configured:
            note = (
                "No results. DuckDuckGo instant answers only covers recognised "
                "entities and is not a web search; SEARXNG_URL is unset, so no "
                "real search backend is configured. Absence of results here "
                "means the lookup did not happen, NOT that no information exists."
            )
        else:
            note = (
                f"{backend} returned no results. That is a real answer, but a "
                "negative one - corroborate against Wazuh or another source "
                "before concluding the subject is benign."
            )
    else:
        note = f"{len(results)} result(s) from {backend}. Untrusted external data."

    _log_query(q, backend, len(results))

    return {
        "enabled": True,
        "backend": backend,
        "query": q,
        "count": len(results),
        # kind="web" is what keeps this text out of the auto-close trust tier.
        "kind": "web",
        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "note": note,
        "results": results,
    }


def web_search_for_llm(query: str) -> str:
    """`web_search` rendered as guard-wrapped text, ready for a tool message.

    Callers that already wrap their own tool output should use `web_search`
    directly; this exists so the wrapping cannot be forgotten at a new call
    site. The chat agent does not wrap, so it uses this.
    """
    return guard.wrap_tool_output(web_search(query))
