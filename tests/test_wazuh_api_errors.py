"""
The manager reports a semantically-rejected write with HTTP 200 and an error in
the BODY. Before raise_for_inbody_error() existed, api_client.request() only
raised on HTTP >= 400, so those came back as successes.

The concrete incident: create_wazuh_rule uploaded a local_rules.xml the manager
rejected with code 1113 ("XML syntax error"). The tool returned
{"status": "executed", "detail": "Could not upload rule"} - with the failure
sitting unread in the same dict - approval_executor marked the proposal
executed, the audit log recorded execution_status="success", and because
claim_for_execution() is single-use the proposal could never be retried.

Run: python -m unittest tests.test_wazuh_api_errors -v
"""

from __future__ import annotations

import os
import unittest

os.environ.setdefault("MOCK_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "mock")

from tools.api_client import WazuhAPIError, raise_for_inbody_error  # noqa: E402

# Verbatim shape returned by PUT /rules/files/local_rules.xml on rejection.
REJECTED = {
    "data": {
        "affected_items": [],
        "total_affected_items": 0,
        "total_failed_items": 1,
        "failed_items": [
            {
                "error": {
                    "code": 1113,
                    "message": "XML syntax error",
                    "remediation": "Please, ensure file content has correct XML",
                },
                "id": ["etc/rules/local_rules.xml"],
            },
        ],
    },
    "message": "Could not upload rule",
    "error": 1,
}

ACCEPTED = {
    "data": {
        "affected_items": ["etc/rules/local_rules.xml"],
        "total_affected_items": 1,
        "total_failed_items": 0,
        "failed_items": [],
    },
    "message": "Rule was successfully uploaded",
    "error": 0,
}


class TestRaiseForInbodyError(unittest.TestCase):
    def test_rejected_upload_raises(self):
        with self.assertRaises(WazuhAPIError) as cm:
            raise_for_inbody_error(REJECTED, "Upload of rules file 'local_rules.xml'")
        self.assertIn("1113", str(cm.exception))
        self.assertIn("XML syntax error", str(cm.exception))
        self.assertIn("local_rules.xml", str(cm.exception))

    def test_accepted_upload_passes_through_untouched(self):
        self.assertIs(raise_for_inbody_error(ACCEPTED, "x"), ACCEPTED)

    def test_error_zero_with_no_failures_is_success(self):
        # Some endpoints omit `error` entirely on success.
        resp = {"data": {"affected_items": ["x"]}}
        self.assertIs(raise_for_inbody_error(resp, "x"), resp)

    def test_failed_items_alone_triggers_even_if_counter_absent(self):
        resp = {
            "data": {"failed_items": REJECTED["data"]["failed_items"]},
            "message": "Could not upload rule",
        }
        with self.assertRaises(WazuhAPIError):
            raise_for_inbody_error(resp, "x")

    def test_error_flag_alone_triggers_even_without_detail(self):
        with self.assertRaises(WazuhAPIError) as cm:
            raise_for_inbody_error({"error": 1, "message": "nope"}, "x")
        self.assertIn("nope", str(cm.exception))

    def test_non_dict_response_is_passed_through(self):
        self.assertEqual(raise_for_inbody_error("raw", "x"), "raw")
        self.assertIsNone(raise_for_inbody_error(None, "x"))

    def test_status_is_200_so_callers_can_tell_this_apart_from_http_failure(self):
        with self.assertRaises(WazuhAPIError) as cm:
            raise_for_inbody_error(REJECTED, "x")
        self.assertEqual(cm.exception.status, 200)


class TestWriteHelpersEnforceIt(unittest.TestCase):
    """The guard must be wired into the write helpers, not just available."""

    def _api(self, resp):
        from tools.api_client import WazuhManagerAPI

        api = WazuhManagerAPI.__new__(WazuhManagerAPI)  # bypass __init__/auth
        api.put = lambda *a, **k: resp
        api.post = lambda *a, **k: resp
        api.delete = lambda *a, **k: resp
        return api

    def test_put_rules_file_raises_on_rejection(self):
        with self.assertRaises(WazuhAPIError):
            self._api(REJECTED).put_rules_file("local_rules.xml", "<group/>")

    def test_put_decoders_file_raises_on_rejection(self):
        with self.assertRaises(WazuhAPIError):
            self._api(REJECTED).put_decoders_file("local_decoder.xml", "<decoder/>")

    def test_delete_rule_raises_on_rejection(self):
        with self.assertRaises(WazuhAPIError):
            self._api(REJECTED).delete_rule(200001)

    def test_put_rules_file_returns_on_success(self):
        self.assertEqual(self._api(ACCEPTED).put_rules_file("local_rules.xml", "x"), ACCEPTED)


if __name__ == "__main__":
    unittest.main()
