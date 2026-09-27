"""
Approval Center hardening - each test reproduces an attack or failure mode
from the security review and asserts it's now refused.

Run: python -m unittest tests.test_approvals -v
"""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

import approvals  # noqa: E402
import permissions  # noqa: E402
from config import cfg  # noqa: E402
from tools.base import Permission  # noqa: E402


class _TempStore(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="approvals-test-")
        self.path = str(Path(self.dir) / "approvals.json")
        self._orig = {
            k: getattr(cfg, k)
            for k in (
                "APPROVAL_EXPIRY_SECONDS",
                "APPROVAL_EXECUTION_WINDOW_SECONDS",
                "APPROVAL_BLOCK_SELF_APPROVAL",
                "APPROVAL_EXECUTE_MIN_APPROVERS",
                "APPROVAL_PROPOSE_MIN_APPROVERS",
                "APPROVALS_PATH",
            )
        }

    def tearDown(self):
        for k, v in self._orig.items():
            setattr(cfg, k, v)
        import shutil

        shutil.rmtree(self.dir, ignore_errors=True)

    def propose(self, action="create_wazuh_rule", permission="propose", user="alice"):
        return approvals.create_proposal(
            action=action,
            reason="r",
            payload={"x": 1},
            permission=permission,
            user=user,
            path=self.path,
        )


class TestLifecycle(_TempStore):
    def test_approve_then_claim_then_finish(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        claimed = approvals.claim_for_execution(p["id"], "bob", path=self.path)
        self.assertEqual(claimed["status"], "executing")
        done = approvals.finish_execution(p["id"], ok=True, path=self.path)
        self.assertEqual(done["status"], "executed")

    def test_replay_after_execution_is_refused(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        approvals.claim_for_execution(p["id"], "bob", path=self.path)
        approvals.finish_execution(p["id"], ok=True, path=self.path)
        with self.assertRaises(ValueError):
            approvals.claim_for_execution(p["id"], "bob", path=self.path)

    def test_failed_execution_is_terminal(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        approvals.claim_for_execution(p["id"], "bob", path=self.path)
        out = approvals.finish_execution(p["id"], ok=False, error="boom", path=self.path)
        self.assertEqual(out["status"], "failed")
        self.assertEqual(out["execution_error"], "boom")
        with self.assertRaises(ValueError):
            approvals.claim_for_execution(p["id"], "bob", path=self.path)

    def test_pending_cannot_be_claimed(self):
        p = self.propose()
        with self.assertRaises(ValueError):
            approvals.claim_for_execution(p["id"], "bob", path=self.path)

    def test_concurrent_claims_only_one_wins(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        wins, losses = [], []

        def worker():
            try:
                approvals.claim_for_execution(p["id"], "bob", path=self.path)
                wins.append(1)
            except ValueError:
                losses.append(1)

        threads = [threading.Thread(target=worker) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(len(wins), 1)
        self.assertEqual(len(losses), 11)

    def test_saves_are_atomic_no_temp_files_left(self):
        for _ in range(5):
            self.propose()
        leftovers = [f for f in os.listdir(self.dir) if f.endswith(".tmp")]
        self.assertEqual(leftovers, [])
        self.assertEqual(len(approvals.list_proposals(path=self.path)), 5)


class TestExpiry(_TempStore):
    def test_stale_pending_cannot_be_approved_even_without_a_list_call(self):
        cfg.APPROVAL_EXPIRY_SECONDS = 60
        p = self.propose()
        with mock.patch("approvals._now", return_value=time.time() + 120):
            with self.assertRaises(ValueError) as cm:
                approvals.approve(p["id"], "bob", path=self.path)
        self.assertIn("expired", str(cm.exception))

    def test_approved_but_not_executed_in_window_expires(self):
        cfg.APPROVAL_EXECUTION_WINDOW_SECONDS = 60
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        with mock.patch("approvals._now", return_value=time.time() + 120):
            with self.assertRaises(ValueError):
                approvals.claim_for_execution(p["id"], "bob", path=self.path)
        self.assertEqual(approvals.get_proposal(p["id"], path=self.path)["status"], "expired")

    def test_execution_window_zero_means_no_limit(self):
        cfg.APPROVAL_EXECUTION_WINDOW_SECONDS = 0
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        with mock.patch("approvals._now", return_value=time.time() + 10**6):
            approvals.claim_for_execution(p["id"], "bob", path=self.path)


class TestSeparationOfDuties(_TempStore):
    def test_verified_self_approval_is_blocked(self):
        p = self.propose(user="alice")
        with self.assertRaises(approvals.ApprovalPolicyError):
            approvals.approve(p["id"], "alice", path=self.path, identity_verified=True)

    def test_self_approval_block_can_be_disabled(self):
        cfg.APPROVAL_BLOCK_SELF_APPROVAL = False
        p = self.propose(user="alice")
        out = approvals.approve(p["id"], "alice", path=self.path, identity_verified=True)
        self.assertEqual(out["status"], "approved")

    def test_same_approver_counts_once(self):
        cfg.APPROVAL_PROPOSE_MIN_APPROVERS = 2
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        with self.assertRaises(approvals.ApprovalPolicyError):
            approvals.approve(p["id"], "bob", path=self.path)

    def test_execute_level_needs_two_distinct_approvers_when_configured(self):
        cfg.APPROVAL_EXECUTE_MIN_APPROVERS = 2
        p = self.propose(action="delete_wazuh_rule", permission="execute")
        self.assertEqual(p["required_approvers"], 2)
        first = approvals.approve(p["id"], "bob", path=self.path)
        self.assertEqual(first["status"], "pending")
        second = approvals.approve(p["id"], "carol", path=self.path)
        self.assertEqual(second["status"], "approved")

    def test_policy_tightened_after_creation_still_applies(self):
        p = self.propose(action="delete_wazuh_rule", permission="execute")
        cfg.APPROVAL_EXECUTE_MIN_APPROVERS = 2
        out = approvals.approve(p["id"], "bob", path=self.path)
        self.assertEqual(out["status"], "pending")


class TestEffectiveLevel(_TempStore):
    def test_proposal_cannot_downgrade_a_delete_to_propose(self):
        p = self.propose(action="delete_wazuh_rule", permission="propose")
        self.assertEqual(p["permission"], "execute")

    def test_high_risk_name_escalates_unknown_actions(self):
        self.assertIs(permissions.effective_level("block_ip_range"), Permission.EXECUTE)
        self.assertIs(permissions.effective_level("purge_everything", "read"), Permission.EXECUTE)

    def test_unknown_action_is_never_read(self):
        self.assertIs(permissions.effective_level("mystery_tool"), Permission.PROPOSE)

    def test_check_can_run_uses_confirmed(self):
        from tools.base import PermissionDenied

        with self.assertRaises(PermissionDenied):
            permissions.check_can_run(
                "execute", "delete_wazuh_rule", approved=True, confirmed=False
            )
        permissions.check_can_run("execute", "delete_wazuh_rule", approved=True, confirmed=True)
        with self.assertRaises(PermissionDenied):
            permissions.check_can_run("propose", "create_wazuh_rule", approved=False)

    def test_check_can_run_ignores_a_weaker_claimed_level(self):
        from tools.base import PermissionDenied

        with self.assertRaises(PermissionDenied):
            permissions.check_can_run("read", "delete_wazuh_rule", approved=True, confirmed=False)


class TestToolGate(unittest.TestCase):
    def test_non_approved_record_cannot_unlock_a_write(self):
        from tools.base import PermissionDenied, ToolContext

        for status in ("pending", "rejected", "expired", "executed", None):
            ctx = ToolContext(
                wazuh=None,
                indexer=None,
                approval={"id": "x", "action": "create_wazuh_rule", "status": status},
            )
            with self.assertRaises(PermissionDenied, msg=str(status)):
                ctx.approve_or_raise({"action": "create_wazuh_rule"})


class TestDashboardRoutes(_TempStore):
    def setUp(self):
        super().setUp()
        from dashboard import app

        app.config["TESTING"] = True
        self.client = app.test_client()
        cfg.APPROVALS_PATH = self.path
        self._orig_auth = (cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS)
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = "", "alice:tokA,bob:tokB"

    def tearDown(self):
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = self._orig_auth
        super().tearDown()

    def post(self, url, token, json=None):
        return self.client.post(url, json=json or {}, headers={"Authorization": f"Bearer {token}"})

    def test_unknown_token_is_401(self):
        self.assertEqual(
            self.client.get("/api/proposals", headers={"Authorization": "Bearer nope"}).status_code,
            401,
        )

    def test_client_supplied_by_is_ignored_for_verified_users(self):
        p = self.propose(user="alice")
        r = self.post(f"/api/proposals/{p['id']}/approve", "tokB", {"by": "the-ciso"})
        self.assertEqual(r.status_code, 200, r.get_json())
        stored = approvals.get_proposal(p["id"], path=self.path)
        self.assertEqual(stored["approvals"][0]["by"], "bob")
        self.assertTrue(stored["approvals"][0]["verified"])

    def test_proposer_cannot_self_approve_via_route(self):
        p = self.propose(user="alice")
        r = self.post(f"/api/proposals/{p['id']}/approve", "tokA", {"by": "someone-else"})
        self.assertEqual(r.status_code, 403)

    @mock.patch("tools.registry.execute", return_value={"status": "ok"})
    def test_execute_replay_via_route_is_409(self, reg):
        p = self.propose(user="alice")
        self.assertEqual(self.post(f"/api/proposals/{p['id']}/approve", "tokB").status_code, 200)
        first = self.post(f"/api/proposals/{p['id']}/execute", "tokB")
        self.assertEqual(first.status_code, 200, first.get_json())
        self.assertTrue(first.get_json()["ok"])
        replay = self.post(f"/api/proposals/{p['id']}/execute", "tokB")
        self.assertEqual(replay.status_code, 409)
        self.assertEqual(reg.call_count, 1)

    @mock.patch("tools.registry.execute", return_value={"status": "ok"})
    def test_execute_level_requires_confirm_via_route(self, reg):
        p = self.propose(action="delete_wazuh_rule", permission="propose", user="alice")
        self.post(f"/api/proposals/{p['id']}/approve", "tokB")
        r = self.post(f"/api/proposals/{p['id']}/execute", "tokB")
        self.assertEqual(r.status_code, 400)
        reg.assert_not_called()
        ok = self.post(f"/api/proposals/{p['id']}/execute", "tokB", {"confirm": True})
        self.assertTrue(ok.get_json()["ok"])


class TestAuthDisabledApproval(_TempStore):
    """Regression cover for the bug that made the Approval Center unusable.

    _verified_approver() used to return None whenever DASHBOARD_TOKEN and
    DASHBOARD_USERS were both unset - the DEFAULT config - because _token_ok()
    short-circuits to False and _token_user() to None. Every read route stayed
    open (the before_request gate also no-ops when auth is off), so the page
    loaded and the proposal rendered, but approve/reject/execute 401'd
    unconditionally: no token can satisfy a check that no token can configure.
    These tests pin the local-trust fallback in place.
    """

    def setUp(self):
        super().setUp()
        from dashboard import app

        app.config["TESTING"] = True
        self.client = app.test_client()
        cfg.APPROVALS_PATH = self.path
        self._orig_auth = (cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS)
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = "", ""  # the default: auth OFF

    def tearDown(self):
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = self._orig_auth
        super().tearDown()

    def test_approve_works_with_no_token_configured(self):
        p = self.propose(user="alice")
        r = self.client.post(f"/api/proposals/{p['id']}/approve", json={"by": "whoever"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["proposal"]["status"], "approved")

    def test_local_trust_approval_is_recorded_unverified(self):
        p = self.propose(user="alice")
        self.client.post(f"/api/proposals/{p['id']}/approve", json={})
        stored = approvals.get_proposal(p["id"], path=self.path)
        self.assertEqual(stored["approvals"][0]["verified"], False)
        self.assertEqual(stored["approvals"][0]["by"], "local-user")

    def test_reject_works_with_no_token_configured(self):
        p = self.propose(user="alice")
        r = self.client.post(f"/api/proposals/{p['id']}/reject", json={"reason": "dup"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertEqual(r.get_json()["proposal"]["status"], "rejected")

    @mock.patch("tools.registry.execute", return_value={"status": "ok"})
    def test_execute_works_with_no_token_configured(self, reg):
        p = self.propose(user="alice")
        self.assertEqual(
            self.client.post(f"/api/proposals/{p['id']}/approve", json={}).status_code, 200
        )
        r = self.client.post(f"/api/proposals/{p['id']}/execute", json={})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertTrue(r.get_json()["ok"])
        reg.assert_called_once()

    def test_reads_still_work(self):
        self.assertEqual(self.client.get("/api/proposals").status_code, 200)
        self.assertEqual(self.client.get("/api/rules").status_code, 200)

    def test_unknown_proposal_is_still_404_not_401(self):
        r = self.client.post("/api/proposals/appr-nope/approve", json={})
        self.assertEqual(r.status_code, 404, r.get_json())


class TestAuthConfiguredStillEnforced(_TempStore):
    """The other half: the fallback must NOT open a hole when auth IS on."""

    def setUp(self):
        super().setUp()
        from dashboard import app

        app.config["TESTING"] = True
        self.client = app.test_client()
        cfg.APPROVALS_PATH = self.path
        self._orig_auth = (cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS)
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = "", "alice:tokA,bob:tokB"

    def tearDown(self):
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = self._orig_auth
        super().tearDown()

    def test_wrong_token_is_401_with_token_hint(self):
        p = self.propose(user="alice")
        r = self.client.post(
            f"/api/proposals/{p['id']}/approve", json={}, headers={"Authorization": "Bearer nope"}
        )
        self.assertEqual(r.status_code, 401)
        # must NOT claim auth is disabled - that is the confusing half of the old bug
        self.assertNotIn("auth is disabled", r.get_json()["error"])

    def test_no_token_at_all_is_401(self):
        p = self.propose(user="alice")
        self.assertEqual(
            self.client.post(f"/api/proposals/{p['id']}/approve", json={}).status_code, 401
        )


class TestRoles(_TempStore):
    """F3: DASHBOARD_USERS gains an optional role so a token is not a skeleton key."""

    def setUp(self):
        super().setUp()
        from dashboard import app

        app.config["TESTING"] = True
        self.client = app.test_client()
        cfg.APPROVALS_PATH = self.path
        self._orig_auth = (cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS)
        # an entry with no explicit role stays an admin (back-compat)
        cfg.DASHBOARD_TOKEN = ""
        cfg.DASHBOARD_USERS = "alice:tokA:admin,bob:tokB:approver,carol:tokC:viewer"

    def tearDown(self):
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = self._orig_auth
        super().tearDown()

    def post_as(self, token, url, json=None):
        return self.client.post(url, json=json or {}, headers={"Authorization": f"Bearer {token}"})

    def test_viewer_cannot_create_rules(self):
        r = self.post_as("tokC", "/api/rules", {"name": "x"})
        self.assertEqual(r.status_code, 403, r.get_json())
        self.assertIn("viewer", r.get_json()["error"])

    def test_approver_cannot_create_rules_but_can_approve(self):
        p = self.propose(user="alice")
        self.assertEqual(self.post_as("tokB", f"/api/proposals/{p['id']}/approve").status_code, 200)
        r = self.post_as("tokB", "/api/rules", {"name": "x"})
        self.assertEqual(r.status_code, 403, r.get_json())

    def test_viewer_cannot_run_tools(self):
        r = self.post_as("tokC", "/api/engineer/tool", {"tool": "get_wazuh_rules"})
        self.assertEqual(r.status_code, 403, r.get_json())

    def test_admin_role_omitted_defaults_to_admin(self):
        from dashboard import _token_user

        with mock.patch("dashboard._supplied_token", return_value="tokA"):
            self.assertEqual(_token_user(), ("alice", "admin"))

    def test_viewer_can_still_read(self):
        self.assertEqual(
            self.client.get("/api/rules", headers={"Authorization": "Bearer tokC"}).status_code, 200
        )

    def test_unknown_role_falls_back_to_admin_not_bypass(self):
        from dashboard import _token_user

        cfg.DASHBOARD_USERS = "dave:tokD:superuser"
        with mock.patch("dashboard._supplied_token", return_value="tokD"):
            self.assertEqual(_token_user(), ("dave", "admin"))


class TestCancelTransition(_TempStore):
    """An approved proposal used to be a permanent executable grant: the only
    exit from `approved` was execution, and `reject` refused anything that was
    not pending. cancel() is the missing withdrawal."""

    def test_cancel_pending(self):
        p = self.propose()
        out = approvals.cancel(p["id"], "bob", "not needed", path=self.path)
        self.assertEqual(out["status"], "cancelled")
        self.assertEqual(out["cancelled_by"], "bob")
        self.assertEqual(out["cancel_reason"], "not needed")
        self.assertIn("cancelled_at", out)

    def test_cancel_approved_is_the_point(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        out = approvals.cancel(p["id"], "bob", "superseded by a newer proposal", path=self.path)
        self.assertEqual(out["status"], "cancelled")

    def test_cancelled_proposal_cannot_be_claimed_or_executed(self):
        """The whole point of withdrawing it: the grant is dead, not just
        relabelled."""
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        approvals.cancel(p["id"], "bob", "withdrawn", path=self.path)
        with self.assertRaises(ValueError):
            approvals.claim_for_execution(p["id"], "bob", path=self.path)

    def test_cancelled_proposal_cannot_be_approved_again(self):
        p = self.propose()
        approvals.cancel(p["id"], "bob", path=self.path)
        with self.assertRaises(ValueError):
            approvals.approve(p["id"], "bob", path=self.path)

    def test_terminal_states_refuse_cancel(self):
        """History is immutable: a proposal that already ran is a record of
        what happened, not something to rewrite."""
        for terminal in ("executed", "failed", "expired", "rejected"):
            p = self.propose()
            if terminal == "executed":
                approvals.approve(p["id"], "bob", path=self.path)
                approvals.claim_for_execution(p["id"], "bob", path=self.path)
                approvals.finish_execution(p["id"], ok=True, path=self.path)
            elif terminal == "failed":
                approvals.approve(p["id"], "bob", path=self.path)
                approvals.claim_for_execution(p["id"], "bob", path=self.path)
                approvals.finish_execution(p["id"], ok=False, error="x", path=self.path)
            elif terminal == "expired":
                with mock.patch.object(approvals, "_now", return_value=approvals._now() + 10**7):
                    approvals.list_proposals(path=self.path)
            elif terminal == "rejected":
                approvals.reject(p["id"], "bob", path=self.path)
            self.assertEqual(approvals.get_proposal(p["id"], path=self.path)["status"], terminal)
            with self.assertRaises(ValueError):
                approvals.cancel(p["id"], "bob", path=self.path)

    def test_executing_refuses_cancel(self):
        """Never race the executor: mid-flight is not cancellable."""
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        approvals.claim_for_execution(p["id"], "bob", path=self.path)
        with self.assertRaises(ValueError):
            approvals.cancel(p["id"], "bob", path=self.path)

    def test_double_cancel_refused(self):
        p = self.propose()
        approvals.cancel(p["id"], "bob", path=self.path)
        with self.assertRaises(ValueError):
            approvals.cancel(p["id"], "bob", path=self.path)

    def test_public_view_exposes_the_withdrawal(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        approvals.cancel(p["id"], "carol", "wrong payload", path=self.path)
        v = approvals.public_view(approvals.get_proposal(p["id"], path=self.path))
        self.assertEqual(v["status"], "cancelled")
        self.assertEqual(v["cancelled_by"], "carol")
        self.assertEqual(v["cancel_reason"], "wrong payload")


class TestProposalRouteRoles(_TempStore):
    """The proposal routes are the privileged surface. They used to check only
    that a token was valid, never that it was powerful enough, so a `viewer`
    could approve and then execute - the exact escalation the roles exist to
    prevent."""

    def setUp(self):
        super().setUp()
        from dashboard import app

        app.config["TESTING"] = True
        self.client = app.test_client()
        cfg.APPROVALS_PATH = self.path
        self._orig_auth = (cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS)
        cfg.DASHBOARD_TOKEN = ""
        cfg.DASHBOARD_USERS = "bob:tokB:approver,carol:tokC:viewer"

    def tearDown(self):
        cfg.DASHBOARD_TOKEN, cfg.DASHBOARD_USERS = self._orig_auth
        super().tearDown()

    def post_as(self, token, url, payload=None):
        return self.client.post(
            url, json=payload or {}, headers={"Authorization": f"Bearer {token}"}
        )

    def test_viewer_cannot_approve(self):
        p = self.propose()
        r = self.post_as("tokC", f"/api/proposals/{p['id']}/approve")
        self.assertEqual(r.status_code, 403, r.get_json())
        self.assertEqual(approvals.get_proposal(p["id"], path=self.path)["status"], "pending")

    def test_viewer_cannot_reject(self):
        p = self.propose()
        r = self.post_as("tokC", f"/api/proposals/{p['id']}/reject")
        self.assertEqual(r.status_code, 403, r.get_json())
        self.assertEqual(approvals.get_proposal(p["id"], path=self.path)["status"], "pending")

    def test_viewer_cannot_cancel(self):
        p = self.propose()
        r = self.post_as("tokC", f"/api/proposals/{p['id']}/cancel", {"reason": "no"})
        self.assertEqual(r.status_code, 403, r.get_json())
        self.assertEqual(approvals.get_proposal(p["id"], path=self.path)["status"], "pending")

    def test_viewer_cannot_execute(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        r = self.post_as("tokC", f"/api/proposals/{p['id']}/execute", {"confirm": True})
        self.assertEqual(r.status_code, 403, r.get_json())
        self.assertEqual(approvals.get_proposal(p["id"], path=self.path)["status"], "approved")

    def test_approver_can_approve_and_cancel(self):
        p = self.propose()
        self.assertEqual(self.post_as("tokB", f"/api/proposals/{p['id']}/approve").status_code, 200)
        r = self.post_as("tokB", f"/api/proposals/{p['id']}/cancel", {"reason": "changed my mind"})
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()["proposal"]
        self.assertEqual(body["status"], "cancelled")
        self.assertEqual(body["cancel_reason"], "changed my mind")

    def test_cancel_route_rejects_terminal_proposal_with_409(self):
        p = self.propose()
        approvals.approve(p["id"], "bob", path=self.path)
        approvals.claim_for_execution(p["id"], "bob", path=self.path)
        approvals.finish_execution(p["id"], ok=True, path=self.path)
        r = self.post_as("tokB", f"/api/proposals/{p['id']}/cancel")
        self.assertEqual(r.status_code, 409, r.get_json())

    def test_cancel_unknown_proposal_is_404(self):
        r = self.post_as("tokB", "/api/proposals/appr-does-not-exist/cancel")
        self.assertEqual(r.status_code, 404, r.get_json())


if __name__ == "__main__":
    unittest.main()
