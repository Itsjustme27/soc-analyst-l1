"""
Unit tests for agent.triage_agent.needs_human_review - the single shared
"does a human need to look at this" check now used by main.py, run.py, and
dashboard.py's on-demand triage route (previously duplicated three times).

Pure logic, no LLM/RAG/network needed.

Run: python -m unittest tests.test_triage_agent -v
"""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")


def _result(verdict="true_positive", confidence=0.95, action="monitor"):
    from agent.triage_agent import TriageResult

    return TriageResult(
        verdict=verdict,
        confidence=confidence,
        recommended_action=action,
        rationale="",
        evidence_used=[],
        transcript=[],
    )


class TestNeedsHumanReview(unittest.TestCase):
    def test_confident_low_stakes_verdict_does_not_need_review(self):
        from agent.triage_agent import needs_human_review

        self.assertFalse(needs_human_review(_result()))

    def test_escalate_verdict_always_needs_review(self):
        from agent.triage_agent import needs_human_review

        self.assertTrue(needs_human_review(_result(verdict="escalate", confidence=0.99)))

    def test_low_confidence_needs_review(self):
        from agent.triage_agent import cfg, needs_human_review

        below = cfg.AUTO_CLOSE_CONFIDENCE_THRESHOLD - 0.01
        self.assertTrue(needs_human_review(_result(confidence=below)))

    def test_destructive_action_needs_review_even_if_confident(self):
        from agent.triage_agent import needs_human_review

        self.assertTrue(needs_human_review(_result(action="isolate_host", confidence=0.99)))
        self.assertTrue(needs_human_review(_result(action="disable_account", confidence=0.99)))

    def test_no_rule_matches_defaults_safely(self):
        from agent.triage_agent import needs_human_review

        self.assertFalse(needs_human_review(_result(), rule_matches=None))
        self.assertFalse(needs_human_review(_result(), rule_matches=[]))

    def test_triggered_escalating_rule_forces_review(self):
        from agent.triage_agent import needs_human_review

        matches = [{"triggered": True, "action": {"escalate": True}}]
        self.assertTrue(needs_human_review(_result(confidence=0.99), matches))

    def test_matched_but_not_triggered_rule_does_not_force_review(self):
        # matched=True but triggered=False (e.g. threshold not yet reached)
        # should NOT force review on its own.
        from agent.triage_agent import needs_human_review

        matches = [{"matched": True, "triggered": False, "action": {"escalate": True}}]
        self.assertFalse(needs_human_review(_result(confidence=0.99), matches))

    def test_triggered_non_escalating_rule_does_not_force_review(self):
        from agent.triage_agent import needs_human_review

        matches = [{"triggered": True, "action": {"tag": "fyi", "escalate": False}}]
        self.assertFalse(needs_human_review(_result(confidence=0.99), matches))


class TestTriageAgentEndToEnd(unittest.TestCase):
    """Full TriageAgent.triage() loop - mock LLM, mock SIEM, and a REAL
    KnowledgeBase (using the offline hashing embedding, so this needs no
    network and no downloaded model - see rag/embeddings.py). This is the
    coverage gap flagged earlier: nothing previously exercised the actual
    tool-use loop with retrieval wired in, only the mock LLM provider in
    isolation (test_providers.py) or pure unit tests of needs_human_review."""

    def setUp(self):
        from config import cfg

        self._orig_chroma_path = cfg.CHROMA_DB_PATH
        self.tmp_chroma = tempfile.mkdtemp(prefix="kb-test-")
        cfg.CHROMA_DB_PATH = self.tmp_chroma

    def tearDown(self):
        from config import cfg

        cfg.CHROMA_DB_PATH = self._orig_chroma_path
        shutil.rmtree(self.tmp_chroma, ignore_errors=True)

    def _seed_playbooks(self):
        from rag.knowledge_base import KnowledgeBase

        kb = KnowledgeBase()
        kb.add(
            "playbooks",
            "Brute force login playbook: check MFA status and source ASN reputation before escalating.",
            {"source": "brute_force.md"},
            doc_id="brute_force",
        )
        kb.add(
            "playbooks",
            "Malware detection playbook: pull the process tree and check host alert history.",
            {"source": "malware.md"},
            doc_id="malware",
        )

    def test_brute_force_alert_reaches_a_verdict_via_real_kb(self):
        self._seed_playbooks()
        from agent.triage_agent import TriageAgent
        from connectors.siem import get_siem_connector

        agent = TriageAgent(provider="mock", siem=get_siem_connector("mock", name="mock"))
        alert = {
            "alert_id": "SPLK-TEST-1",
            "rule_name": "Brute Force - Multiple Auth Failures Then Success",
            "severity": "high",
            "description": "12 failed logins then a successful login for jsmith from 185.220.101.7",
            "user": "jsmith",
            "src_ip": "185.220.101.7",
            "raw_fields": {"failed_count": 12, "mfa_satisfied": False},
        }
        result = agent.triage(alert)
        self.assertIn(result.verdict, ("false_positive", "true_positive", "escalate"))
        self.assertTrue(0.0 <= result.confidence <= 1.0)
        self.assertTrue(len(result.transcript) > 0)
        # the mock provider's scripted brute-force path always calls
        # retrieve_playbook before submitting a verdict - confirm that tool
        # call actually round-tripped through the real KnowledgeBase.
        tool_calls = [t["tool"] for t in result.transcript if "tool" in t]
        self.assertIn("retrieve_playbook", tool_calls)

    def test_malware_alert_reaches_a_verdict_via_real_kb(self):
        self._seed_playbooks()
        from agent.triage_agent import TriageAgent
        from connectors.siem import get_siem_connector

        agent = TriageAgent(provider="mock", siem=get_siem_connector("mock", name="mock"))
        alert = {
            "alert_id": "SPLK-TEST-2",
            "rule_name": "EDR Malware Detection - Suspicious Process",
            "severity": "critical",
            "description": "powershell.exe spawned by WINWORD.EXE with base64-encoded command line",
            "host": "WKS-TEST-01",
            "host_id": "mock-host-id",
            "detection_id": "mock-detection-id",
            "falcon_process_id": "mock-process-id",
        }
        result = agent.triage(alert)
        self.assertIn(result.verdict, ("false_positive", "true_positive", "escalate"))

    def test_empty_knowledge_base_does_not_crash_triage(self):
        # No playbooks/cases/lessons seeded at all - retrieval should just
        # come back empty, not error, and the agent should still finish.
        from agent.triage_agent import TriageAgent
        from connectors.siem import get_siem_connector

        agent = TriageAgent(provider="mock", siem=get_siem_connector("mock", name="mock"))
        result = agent.triage(
            {
                "alert_id": "SPLK-TEST-3",
                "rule_name": "Generic alert",
                "severity": "low",
                "description": "something happened",
            }
        )
        self.assertIsNotNone(result.verdict)


if __name__ == "__main__":
    unittest.main()
