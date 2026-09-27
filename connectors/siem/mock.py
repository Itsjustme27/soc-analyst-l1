"""
Mock SIEM connector.

A drop-in SIEMConnector provider that returns canned alerts instead of hitting
a real API. Used when MOCK_MODE=true or SIEM_PROVIDER=mock, so you can test
the agent, the RAG / self-improvement loop, and the dashboard's provider
management before wiring real credentials.

Each mock provider instance can carry a distinct name, so the dashboard can
demo *multiple* SIEM connections side by side (e.g. "Mock Splunk" vs
"Mock Sentinel") without any real endpoints.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from config import cfg
from connectors.siem.base import SIEMConnector, resolve_cfg

BASE_ALERTS = [
    {
        "alert_id": "SPLK-10231",
        "rule_id": "R-10231",
        "rule_name": "Brute Force - Multiple Auth Failures Then Success",
        "severity": "high",
        "description": "12 failed logins followed by 1 successful login for user jsmith@corp.local from IP 185.220.101.7",
        "user": "jsmith",
        "host": None,
        "src_ip": "185.220.101.7",
        "raw_fields": {
            "failed_count": 12,
            "success": True,
            "mfa_satisfied": False,
            "source_asn": "AS9009 (known VPN/proxy hosting provider)",
        },
    },
    {
        "alert_id": "SPLK-10245",
        "rule_id": "R-10245",
        "rule_name": "EDR Malware Detection - Suspicious Process",
        "severity": "critical",
        "description": "CrowdStrike flagged powershell.exe spawned by WINWORD.EXE with base64-encoded command line on host WKS-FIN-0231",
        "user": None,
        "host": "WKS-FIN-0231",
        "src_ip": None,
        "raw_fields": {
            "parent_process": "WINWORD.EXE",
            "child_process": "powershell.exe",
            "command_line_snippet": "-enc JAB...(truncated)",
            "prevented": False,
        },
    },
    {
        "alert_id": "SPLK-10250",
        "rule_id": "R-10250",
        "rule_name": "Phishing - User Reported Suspicious Email",
        "severity": "medium",
        "description": "User reported an email claiming to be from IT support asking to verify credentials via a link",
        "user": "agarcia",
        "host": None,
        "src_ip": None,
        "raw_fields": {
            "sender": "it-support@corp-secure-login.net",
            "spf": "fail",
            "dkim": "fail",
            "link_clicked": False,
        },
    },
]


class MockSiemConnector(SIEMConnector):
    platform = "mock"

    def __init__(self, name: str = "mock", config: dict[str, Any] | None = None):
        super().__init__(name=name, config=config)
        alerts_file = (
            resolve_cfg(config, "alerts_file", cfg.MOCK_SIEM_ALERTS_FILE)
            or "seed_data/mock_alerts.json"
        )
        self._alerts = self._load_alerts(alerts_file)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _load_alerts(alerts_file: str) -> list[dict[str, Any]]:
        path = Path(alerts_file)
        if path.exists():
            try:
                return json.loads(path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return BASE_ALERTS

    def get_new_alerts(self) -> list[dict[str, Any]]:
        # Give each mock provider a distinctive id prefix so alerts from
        # multiple demo providers don't collide in the dashboard.
        prefix = "".join(ch for ch in self.name if ch.isalnum())[:12].upper() or "MOCK"
        out = []
        for a in self._alerts:
            copy = dict(a)
            copy["raw_fields"] = dict(a.get("raw_fields", {}))
            copy["alert_id"] = f"{prefix}-{a.get('alert_id', 'MOCK-1')}"
            copy["rule_id"] = a.get("rule_id")  # None when a custom seed file omits it
            out.append(copy)
        return out

    def search_related_events(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest: str = "-24h",
        index: str = "*",
    ) -> list[dict[str, Any]]:
        if user == "jsmith":
            return [
                {
                    "_time": "2026-09-22T03:14:00Z",
                    "event": "VPN login attempt",
                    "src_ip": "185.220.101.7",
                    "result": "failure",
                },
                {
                    "_time": "2026-09-22T03:15:00Z",
                    "event": "VPN login attempt",
                    "src_ip": "185.220.101.7",
                    "result": "failure",
                },
                {
                    "_time": "2026-09-22T03:21:00Z",
                    "event": "O365 login",
                    "src_ip": "185.220.101.7",
                    "result": "success",
                    "mfa": "not_prompted",
                },
            ]
        return []

    def close_notable(self, event_id: str, status: str, comment: str) -> None:
        print(f"[MOCK] would close {self.platform} notable {event_id} as {status}: {comment}")

    def _ping(self) -> str:
        return f"Mock SIEM '{self.name}' OK (no live endpoint)"
