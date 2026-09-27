"""
Microsoft Sentinel connector (Log Analytics query REST API).

Endpoints used:
  POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token   (get bearer token)
  POST https://api.loganalytics.io/v1/workspaces/{workspace}/query    (run KQL)

Auth: Azure AD app registration with client-credentials grant, scoped to
``https://api.loganalytics.io/.default``. The app needs Log Analytics Reader
on the workspace (or Sentinel Reader for SecurityAlert tables).

Alerts are read from the configured KQL query (default: recent SecurityAlert
records) and mapped from SecurityAlert columns.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from config import cfg
from connectors.siem.base import SIEMConnector, resolve_cfg

TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
QUERY_URL = "https://api.loganalytics.io/v1/workspaces/{workspace_id}/query"

DEFAULT_QUERY = (
    "SecurityAlert | where TimeGenerated > ago(1h) "
    "| project SystemAlertId, AlertName, Severity, Description, "
    "CompromisedEntity, SourceIPAddress, UserName, HostName, TimeGenerated "
    "| order by TimeGenerated desc | take 20"
)


class SentinelConnector(SIEMConnector):
    platform = "sentinel"

    def __init__(self, name: str = "default", config: dict[str, Any] | None = None):
        super().__init__(name=name, config=config)
        self.tenant_id = resolve_cfg(config, "tenant_id", cfg.SENTINEL_TENANT_ID)
        self.client_id = resolve_cfg(config, "client_id", cfg.SENTINEL_CLIENT_ID)
        self.client_secret = resolve_cfg(config, "client_secret", cfg.SENTINEL_CLIENT_SECRET)
        self.workspace_id = resolve_cfg(config, "workspace_id", cfg.SENTINEL_WORKSPACE_ID)
        self.query = resolve_cfg(config, "query", cfg.SENTINEL_QUERY) or DEFAULT_QUERY
        self._token: str | None = None
        self._token_expiry: float = 0

    # ------------------------------------------------------------------ #
    def _auth_token(self) -> str:
        if self._token and time.time() < self._token_expiry:
            return self._token
        r = requests.post(
            TOKEN_URL.format(tenant=self.tenant_id),
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "https://api.loganalytics.io/.default",
            },
            timeout=20,
        )
        r.raise_for_status()
        body = r.json()
        self._token = body["access_token"]
        self._token_expiry = time.time() + int(body.get("expires_in", 3600)) - 60
        return self._token

    def _run_query(self, kql: str) -> list[dict[str, Any]]:
        r = requests.post(
            QUERY_URL.format(workspace_id=self.workspace_id),
            headers={
                "Authorization": f"Bearer {self._auth_token()}",
                "Content-Type": "application/json",
            },
            json={"query": kql},
            timeout=40,
        )
        r.raise_for_status()
        tables = r.json().get("tables", [])
        if not tables:
            return []
        cols = [c["name"] for c in tables[0].get("columns", [])]
        return [dict(zip(cols, row, strict=True)) for row in tables[0].get("rows", [])]

    # ------------------------------------------------------------------ #
    def get_new_alerts(self) -> list[dict[str, Any]]:
        return [self._normalize(r) for r in self._run_query(self.query)]

    def search_related_events(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest: str = "-24h",
        index: str = "*",
    ) -> list[dict[str, Any]]:
        clauses = []
        if host:
            clauses.append(f"HostName == '{host}' or CompromisedEntity == '{host}'")
        if user:
            clauses.append(f"UserName == '{user}'")
        where = f" | where {' or '.join(clauses)}" if clauses else ""
        kql = f"SecurityAlert | where TimeGenerated > ago(1d){where} | take 50"
        return [self._normalize(r) for r in self._run_query(kql)]

    def close_notable(self, event_id: str, status: str, comment: str) -> None:
        """Sentinel has no direct 'close alert' REST endpoint - alert closure is
        done in the portal or via the Microsoft Graph security API. Appending
        the verdict here would require a write-capable integration; this is a
        documented no-op so the agent loop never crashes on it."""
        raise NotImplementedError(
            "Sentinel alert closure requires the Microsoft Graph security API "
            "(graph.microsoft.com /security/alerts/v2) - not wired in this connector."
        )

    # ------------------------------------------------------------------ #
    def _ping(self) -> str:
        # Cheapest authenticated check: run a 1-row constant query.
        self._run_query("let n = range x from 1 to 1 step 1; n | count")
        return f"Sentinel workspace {self.workspace_id} auth OK"

    @staticmethod
    def _normalize(row: dict[str, Any]) -> dict[str, Any]:
        return {
            "alert_id": str(row.get("SystemAlertId") or row.get("AlertName") or ""),
            "rule_id": None,
            "rule_name": row.get("AlertName") or "Sentinel alert",
            "severity": str(row.get("Severity", "unknown")),
            "description": row.get("Description") or row.get("AlertType", ""),
            "host": row.get("HostName") or row.get("CompromisedEntity"),
            "user": row.get("UserName") or row.get("AccountName"),
            "src_ip": row.get("SourceIPAddress"),
            "raw_fields": row,
        }
