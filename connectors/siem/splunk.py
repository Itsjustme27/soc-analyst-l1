"""
Splunk connector (via Splunk REST API / ES notable events).

Endpoints used:
  POST {host}/services/search/jobs                (create search job)
  GET  {host}/services/search/jobs/{sid}/results   (poll for results)
  GET  {host}/services/server/info                 (health check)
"""

from __future__ import annotations

import time
from typing import Any

import requests

from config import cfg
from connectors.siem.base import SIEMConnector, resolve_bool_cfg, resolve_cfg


class SplunkConnector(SIEMConnector):
    platform = "splunk"

    def __init__(self, name: str = "default", config: dict[str, Any] | None = None):
        super().__init__(name=name, config=config)
        self.host = resolve_cfg(config, "host", cfg.SPLUNK_HOST).rstrip("/")
        self.token = resolve_cfg(config, "token", cfg.SPLUNK_TOKEN)
        self.verify = resolve_bool_cfg(config, "verify_ssl", cfg.SPLUNK_VERIFY_SSL)
        self.search = resolve_cfg(config, "search", cfg.SPLUNK_SEARCH)
        self.headers = {"Authorization": f"Bearer {self.token}"}

    # ------------------------------------------------------------------ #
    def _run_search(self, spl: str, max_wait_s: int = 30) -> list[dict[str, Any]]:
        """Blocking helper: submit a search job and return results as dicts."""
        create = requests.post(
            f"{self.host}/services/search/jobs",
            headers=self.headers,
            data={"search": spl, "output_mode": "json"},
            verify=self.verify,
            timeout=15,
        )
        create.raise_for_status()
        sid = create.json()["sid"]

        waited = 0
        while waited < max_wait_s:
            status = requests.get(
                f"{self.host}/services/search/jobs/{sid}",
                headers=self.headers,
                params={"output_mode": "json"},
                verify=self.verify,
                timeout=15,
            )
            status.raise_for_status()
            if status.json()["entry"][0]["content"]["isDone"]:
                break
            time.sleep(1)
            waited += 1

        results = requests.get(
            f"{self.host}/services/search/jobs/{sid}/results",
            headers=self.headers,
            params={"output_mode": "json", "count": 0},
            verify=self.verify,
            timeout=15,
        )
        results.raise_for_status()
        return results.json().get("results", [])

    # ------------------------------------------------------------------ #
    def get_new_alerts(self) -> list[dict[str, Any]]:
        """Pull new notable events per the configured search."""
        rows = self._run_search(self.search)
        return [self._normalize(r) for r in rows]

    def search_related_events(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest: str = "-24h",
        index: str = "*",
    ) -> list[dict[str, Any]]:
        """Correlation lookup: other events for this host/user in a time window."""
        filters = []
        if host:
            filters.append(f'(host="{host}" OR dest="{host}" OR src="{host}")')
        if user:
            filters.append(f'(user="{user}")')
        filt = " ".join(filters) if filters else ""
        spl = f"search index={index} earliest={earliest} {filt} | head 50"
        return self._run_search(spl)

    def close_notable(self, event_id: str, status: str, comment: str) -> None:
        """Write the agent's verdict back into Splunk ES as a notable update."""
        requests.post(
            f"{self.host}/services/notable_update",
            headers=self.headers,
            data={"ruleUIDs": event_id, "status": status, "comment": comment},
            verify=self.verify,
            timeout=15,
        ).raise_for_status()

    # ------------------------------------------------------------------ #
    def _ping(self) -> str:
        r = requests.get(
            f"{self.host}/services/server/info",
            headers=self.headers,
            params={"output_mode": "json"},
            verify=self.verify,
            timeout=10,
        )
        r.raise_for_status()
        return f"Splunk {self.host} auth OK"

    @staticmethod
    def _normalize(row: dict[str, Any]) -> dict[str, Any]:
        """Map Splunk result fields onto the common alert shape."""
        alert_id = (
            row.get("event_id") or row.get("rule_id") or row.get("_key") or row.get("_cd") or ""
        )
        return {
            "alert_id": str(alert_id),
            "rule_id": row.get("rule_id"),
            "rule_name": row.get("rule_name") or row.get("name") or "Splunk notable",
            "severity": row.get("severity") or row.get("urgency") or "unknown",
            "description": row.get("description") or row.get("_raw", ""),
            "host": row.get("host") or row.get("dest") or row.get("src"),
            "user": row.get("user"),
            "src_ip": row.get("src_ip") or row.get("src"),
            "raw_fields": row,
        }
