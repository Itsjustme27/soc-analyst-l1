"""
Drop-in replacements used when MOCK_MODE=true.

- MockSiemConnector is the multi-SIEM mock provider - see connectors.siem.mock.
  It returns canned alerts and event history instead of hitting a live SIEM.
- MockCrowdStrikeConnector stubs the EDR enrichment side.
"""

from __future__ import annotations

from typing import Any


class MockCrowdStrikeConnector:
    def get_detection_details(self, detection_id: str) -> dict[str, Any]:
        return {
            "detection_id": detection_id,
            "severity": "critical",
            "tactic": "Execution",
            "technique": "Command and Scripting Interpreter: PowerShell",
            "prevented": False,
        }

    def get_host_info(self, host_id: str) -> dict[str, Any]:
        return {
            "host_id": host_id,
            "hostname": "WKS-FIN-0231",
            "os": "Windows 11",
            "criticality": "standard-workstation",
            "owner": "afinance-dept",
            "last_seen": "2026-09-23T09:02:00Z",
        }

    def get_process_tree(self, falcon_process_id: str) -> dict[str, Any]:
        return {
            "process_id": falcon_process_id,
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc JABjAGwAaQBlAG4AdAAgAD0A...(base64, decodes to a download cradle)",
            "parent": {
                "process_name": "WINWORD.EXE",
                "command_line": 'WINWORD.EXE /n "Invoice_2691.docm"',
            },
            "children": [],
            "file_hash_sha256": "3fa1c2...mockhash...9e21",
            "hash_reputation": "unknown - not previously seen in VT",
        }

    def get_host_alert_history(self, host_id: str) -> list[dict[str, Any]]:
        return []  # first detection on this host in the window

    def isolate_host(self, host_id: str, reason: str) -> dict[str, Any]:
        return {"dry_run": True, "action": "isolate_host", "host_id": host_id, "reason": reason}
