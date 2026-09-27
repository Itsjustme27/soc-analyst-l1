"""
IBM QRadar connector (Ariel search API).

Endpoints used:
  POST {host}/api/ariel/searches              (create an Ariel search job)
  GET  {host}/api/ariel/searches/{id}          (poll status)
  GET  {host}/api/ariel/searches/{id}/results  (get event rows)
  GET  {host}/api/ariel/databases              (health check)

Auth: QRadar API token in the ``SEC`` header.
"""
from __future__ import annotations
import re
import time
import requests
from typing import Any

from config import cfg
from connectors.siem.base import SIEMConnector, resolve_cfg, resolve_bool_cfg

# Default: every event in the last hour. Users should point QRADAR_SEARCH at a
# query that surfaces *alerts* (e.g. QRadar offense/rule events + custom rules).
DEFAULT_SEARCH = "SELECT * FROM events LAST 1 HOUR"

# Conservative allowlist for values interpolated into Ariel query strings.
_ARIEL_SAFE = re.compile(r"^[A-Za-z0-9@._:\-/\s\[\]()%=\+]+$")


def _ariel_literal(value: str) -> str:
    """A literal for safe interpolation into an Ariel WHERE clause (B608).

    Fail-closed: quotes, comment markers and semicolons are refused outright
    and only a conservative character set is allowed, so alert-derived
    host/user values can never break out of the filter band."""
    v = str(value or "").strip()
    if not v:
        return v
    if "'" in v or '"' in v or "--" in v or ";" in v:
        raise ValueError("refusing QRadar filter with quote/comment metacharacters")
    if not _ARIEL_SAFE.match(v):
        raise ValueError("refusing QRadar filter with unsupported characters")
    return v


class QRadarConnector(SIEMConnector):
    platform = "qradar"

    def __init__(self, name: str = "default", config: dict[str, Any] | None = None):
        super().__init__(name=name, config=config)
        self.host = resolve_cfg(config, "host", cfg.QRADAR_HOST).rstrip("/")
        self.token = resolve_cfg(config, "token", cfg.QRADAR_TOKEN)
        self.verify = resolve_bool_cfg(config, "verify_ssl", cfg.QRADAR_VERIFY_SSL)
        self.search = resolve_cfg(config, "search", cfg.QRADAR_SEARCH) or DEFAULT_SEARCH

    # ------------------------------------------------------------------ #
    def _headers(self) -> dict[str, str]:
        return {"SEC": self.token, "Accept": "application/json"}

    def _run_ariel(self, query: str, max_wait_s: int = 30) -> list[dict[str, Any]]:
        """Blocking helper: submit an Ariel query and return result events."""
        create = requests.post(
            f"{self.host}/api/ariel/searches",
            headers=self._headers(),
            data={"query_expression": query},
            verify=self.verify,
            timeout=15,
        )
        create.raise_for_status()
        search_id = create.json()["search_id"]

        waited = 0
        while waited < max_wait_s:
            status = requests.get(
                f"{self.host}/api/ariel/searches/{search_id}",
                headers=self._headers(),
                verify=self.verify,
                timeout=15,
            )
            status.raise_for_status()
            if status.json().get("status") == "COMPLETED":
                break
            time.sleep(1)
            waited += 1

        results = requests.get(
            f"{self.host}/api/ariel/searches/{search_id}/results",
            headers=self._headers(),
            verify=self.verify,
            timeout=20,
        )
        results.raise_for_status()
        return results.json().get("events", [])

    # ------------------------------------------------------------------ #
    def get_new_alerts(self) -> list[dict[str, Any]]:
        rows = self._run_ariel(self.search)
        return [self._normalize(r) for r in rows]

    def search_related_events(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest: str = "-24h",
        index: str = "*",
    ) -> list[dict[str, Any]]:
        where = ["1=1"]
        if host:
            h = _ariel_literal(host)
            where.append(f"(sourceIP='{h}' OR destinationIP='{h}' OR hostname='{h}')")
        if user:
            where.append(f"userName='{_ariel_literal(user)}'")
        # nosec B608 - the only dynamic input here is `where`, composed purely
        # of _ariel_literal()-validated values (tested in test_siem.py)
        query = f"SELECT * FROM events WHERE {' AND '.join(where)} LAST 24 HOURS | LIMIT 50"  # nosec B608
        return self._run_ariel(query)

    def close_notable(self, event_id: str, status: str, comment: str) -> None:
        """Map a verdict to a QRadar offense status update."""
        requests.post(
            f"{self.host}/api/siem/offenses/{int(event_id)}",
            headers=self._headers(),
            data={"status": status.upper(), "description": comment},
            verify=self.verify,
            timeout=15,
        ).raise_for_status()

    # ------------------------------------------------------------------ #
    def _ping(self) -> str:
        r = requests.get(
            f"{self.host}/api/ariel/databases",
            headers=self._headers(),
            verify=self.verify,
            timeout=10,
        )
        r.raise_for_status()
        return f"QRadar {self.host} auth OK"

    @staticmethod
    def _normalize(row: dict[str, Any]) -> dict[str, Any]:
        alert_id = row.get("eventID") or row.get("startTime") or row.get("endTime") or ""
        return {
            "alert_id": str(alert_id),
            "rule_id": None,
            "rule_name": row.get("name") or row.get("category") or "QRadar event",
            "severity": str(row.get("severity", "unknown")),
            "description": row.get("description") or row.get("message", ""),
            "host": row.get("hostname") or row.get("destinationIP") or row.get("sourceIP"),
            "user": row.get("userName"),
            "src_ip": row.get("sourceIP") or row.get("identityIP"),
            "raw_fields": row,
        }