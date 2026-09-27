"""
Indexer (OpenSearch) client for the AI SOC engineer.

Wraps the existing connectors.siem.wazuh.WazuhConnector rather than re-spelling
its HTTP code: the engineer reads alerts/events/schema through the exact same
host/auth/verify path the rest of the application uses. Adds the schema
inspection (`_field_caps`) and aggregation helpers the dashboard engineer and
the gap analyzer need.

Everything here is read-only. Writes to the indexer (dashboard saved objects)
live in tools/dashboard/ and go through approval gates.
"""

from __future__ import annotations

from typing import Any

from connectors.siem.wazuh import WazuhConnector
from tools.api_client import WazuhAPIError


class IndexerClient:
    def __init__(self, connector: WazuhConnector | None = None):
        self.connector = connector or WazuhConnector(name="engine")

    # ------------------------------------------------------------------ #
    def search(self, index: str, body: dict[str, Any]) -> dict[str, Any]:
        """Raw OpenSearch `_search` against an index (full response incl.
        aggregations)."""
        try:
            return self.connector.search(index, body)
        except WazuhAPIError:
            raise
        except Exception as e:  # requests errors etc. -> normalized tool error
            raise WazuhAPIError(f"Indexer search failed: {e}") from e

    def hits(self, index: str, body: dict[str, Any]) -> list[dict[str, Any]]:
        resp = self.search(index, body)
        out = []
        for h in resp.get("hits", {}).get("hits", []):
            src = h.get("_source") or {}
            src = {**src, "_id": h.get("_id", "")}
            out.append(src)
        return out

    # ------------------------------------------------------------------ #
    def field_caps(self, index: str = "wazuh-alerts-*") -> dict[str, str]:
        """Field name -> type mapping for the index, via _field_caps (handy
        for the dashboard engineer to pick real fields, and for the gap
        analyzer to see what telemetry actually exists)."""
        r = self.connector.post_field_caps_search(self._field_caps_body(), index)
        caps = r.get("fields", {})
        return {name: (list(info.keys())[0] if info else "unknown") for name, info in caps.items()}

    def _field_caps_body(self) -> dict[str, Any]:
        return {
            "index_filter": {"match_all": {}},
            "fields": ["*"],
            "include_unmapped": False,
        }

    # ------------------------------------------------------------------ #
    def count(self, index: str, query: dict[str, Any] | None = None) -> int:
        r = self.search(index, {"size": 0, "query": query or {"match_all": {}}})
        return int(r.get("hits", {}).get("total", {}).get("value", 0))

    # ------------------------------------------------------------------ #
    def recent_docs(self, index: str, size: int = 20) -> list[dict[str, Any]]:
        return self.hits(
            index,
            {
                "size": min(size, 200),
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"match_all": {}},
            },
        )

    def query_count(self, index: str, body: dict[str, Any]) -> int:
        """Result count for an arbitrary search body - used to validate that a
        generated OpenSearch query (dashboard engineer) matches data."""
        check = {**body, "size": 0}
        r = self.search(index, check)
        return int(r.get("hits", {}).get("total", {}).get("value", 0))

    def ping(self) -> str:
        return self.connector.test_connection().get("detail", "")
