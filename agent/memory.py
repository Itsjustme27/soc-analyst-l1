"""
The self-improvement loop, split into two deliberately separate steps:

  1. capture_feedback() - cheap, synchronous, called every time an analyst
     confirms or overrides the agent's verdict. Just appends to a JSONL log.
     No model call, no memory mutation - this is the raw training signal.

  2. distill_lessons() - run as a periodic batch job (e.g. nightly cron),
     NOT live during triage. Looks at recent corrections, asks Claude to
     find recurring patterns worth remembering, and writes them to the
     "lessons" RAG collection that the triage agent retrieves from.

Why split them: writing memory live, in the same loop that's making
decisions, lets a single noisy or wrong analyst correction immediately
corrupt future triage. Batching + review gives you a checkpoint to catch
that before it goes live. A human should spot-check distilled lessons
before this runs unattended (see review_pending_lessons in main.py).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from config import cfg
from llm import get_provider
from rag.knowledge_base import KnowledgeBase

DISTILL_SYSTEM_PROMPT = """You review a batch of SOC analyst corrections to an \
AI triage agent. Each record has the agent's original verdict and the \
analyst's corrected verdict + their reasoning.

Find recurring, generalizable patterns worth remembering for future triage \
- e.g. "alerts from rule X on subnet Y are consistently false positive \
because of a known scanner" or "the agent under-weights impossible-travel \
logins for service accounts."

Ignore one-off corrections that don't generalize. For each pattern found, \
write a short, specific lesson (2-4 sentences) an analyst could sanity-check \
in a few seconds. Output ONLY a JSON array of objects: \
[{"lesson": "...", "supporting_case_ids": ["..."]}, ...]. If nothing \
generalizes yet, output []."""


class MemoryStore:
    def __init__(self):
        self.kb = KnowledgeBase()
        self.feedback_path = Path(cfg.FEEDBACK_LOG_PATH)
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def capture_feedback(
        self,
        case_id: str,
        alert: dict[str, Any],
        agent_verdict: dict[str, Any],
        analyst_verdict: str,
        analyst_reasoning: str,
        analyst: str = "",
    ) -> None:
        record = {
            "case_id": case_id,
            "timestamp": time.time(),
            "alert": alert,
            "agent_verdict": agent_verdict,
            "analyst_verdict": analyst_verdict,
            "analyst_reasoning": analyst_reasoning,
            "analyst": analyst,
            "agreed": agent_verdict.get("verdict") == analyst_verdict,
        }
        with open(self.feedback_path, "a") as f:
            f.write(json.dumps(record, default=str) + "\n")

        # Also store the closed case itself into the "cases" RAG collection
        # immediately - future triage should be able to find "we saw this
        # exact pattern before" regardless of whether it generalizes into a
        # broader lesson.
        case_text = (
            f"Alert: {json.dumps(alert)}\n"
            f"Analyst verdict: {analyst_verdict}\n"
            f"Analyst reasoning: {analyst_reasoning}"
        )
        self.kb.add(
            "cases", case_text, {"case_id": case_id, "verdict": analyst_verdict}, doc_id=case_id
        )

    # ------------------------------------------------------------------ #
    def _load_recent_feedback(self, since_ts: float) -> list[dict[str, Any]]:
        if not self.feedback_path.exists():
            return []
        out = []
        with open(self.feedback_path) as f:
            for line in f:
                rec = json.loads(line)
                if rec["timestamp"] >= since_ts:
                    out.append(rec)
        return out

    def distill_lessons(self, since_ts: float = 0, min_records: int = 5) -> list[dict[str, Any]]:
        """Batch job: turn recent corrections into candidate lessons.
        Returns the candidates WITHOUT writing them - call
        approve_and_store_lesson() per item after human review."""
        records = self._load_recent_feedback(since_ts)
        # Focus the model's attention on disagreements - agreement is a weak signal.
        disagreements = [r for r in records if not r["agreed"]]
        if len(disagreements) < min_records:
            return []

        provider = get_provider()
        text = provider.chat_text(
            system=DISTILL_SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": json.dumps(disagreements, default=str, indent=2)}
            ],
            max_tokens=1500,
        )
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # model wrapped it in prose/markdown fences despite instructions
            start, end = text.find("["), text.rfind("]")
            return json.loads(text[start : end + 1]) if start != -1 else []

    def approve_and_store_lesson(
        self, lesson_text: str, metadata: dict[str, Any], approved_by: str = ""
    ) -> str:
        """Call this only after a human has reviewed the candidate lesson."""
        if approved_by:
            metadata = {**metadata, "approved_by": approved_by}
        return self.kb.add("lessons", lesson_text, metadata)
