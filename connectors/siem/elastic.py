"""
Elastic Security connector (Elasticsearch _search API).

Endpoints used:
  GET/POST {host}/{index}/_search      (query alert documents)
  POST     {host}/{index}/_update/{id} (close/annotate an alert)
  GET      {host}/                     (cluster info - health check)

Auth: API key header ``Authorization: ApiKey <key>``.
Alerts are read from the configured index (defaults to the Elastic Security
signals index ``.siem-signals-*``) and mapped from ``kibana.alert.*`` fields.
"""

from __future__ import annotations

from typing import Any

import requests

from config import cfg
from connectors.siem.base import SIEMConnector, resolve_bool_cfg, resolve_cfg

DEFAULT_INDEX = ".siem-signals-*"
DEFAULT_QUERY_SIZE = 20


class ElasticConnector(SIEMConnector):
    platform = "elastic"

    def __init__(self, name: str = "default", config: dict[str, Any] | None = None):
        super().__init__(name=name, config=config)
        self.host = resolve_cfg(config, "host", cfg.ELASTIC_HOST).rstrip("/")
        self.api_key = resolve_cfg(config, "api_key", cfg.ELASTIC_API_KEY)
        self.index = resolve_cfg(config, "index", cfg.ELASTIC_INDEX) or DEFAULT_INDEX
        self.verify = resolve_bool_cfg(config, "verify_ssl", cfg.ELASTIC_VERIFY_SSL)
        self.headers = {
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/json",
        }

    # ------------------------------------------------------------------ #
    def _search(self, body: dict[str, Any]) -> list[dict[str, Any]]:
        r = requests.post(
            f"{self.host}/{self.index}/_search",
            headers=self.headers,
            json=body,
            verify=self.verify,
            timeout=20,
        )
        r.raise_for_status()
        return r.json().get("hits", {}).get("hits", [])

    # ------------------------------------------------------------------ #
    def get_new_alerts(self) -> list[dict[str, Any]]:
        hits = self._search(
            {
                "size": DEFAULT_QUERY_SIZE,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {
                    "bool": {
                        "must": [{"exists": {"field": "kibana.alert.rule.name"}}],
                        "filter": [{"terms": {"kibana.alert.status": ["open", "acknowledged"]}}],
                    }
                },
            }
        )
        return [self._normalize(h["_source"], h["_id"]) for h in hits]

    def search_related_events(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest: str = "-24h",
        index: str = "*",
    ) -> list[dict[str, Any]]:
        should: list[dict[str, Any]] = []
        if host:
            should.append({"term": {"host.name": host}})
            should.append({"term": {"source.ip": host}})
        if user:
            should.append({"term": {"user.name": user}})
        query = {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-1d"}}}]}}
        if should:
            query["bool"]["should"] = should
            query["bool"]["minimum_should_match"] = 1
        hits = self._search(
            {
                "size": 50,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": query,
            }
        )
        return [self._normalize(h["_source"], h["_id"]) for h in hits]

    def close_notable(self, event_id: str, status: str, comment: str) -> None:
        """Annotate the alert doc - e.g. mark it closed with the agent's note."""
        r = requests.post(
            f"{self.host}/{self.index}/_update/{event_id}",
            headers=self.headers,
            json={
                "doc": {
                    "kibana.alert.status": status,
                    "soc_agent_note": comment,
                    "soc_agent_closed_at": requests.utils.default_headers().get("Date", ""),
                }
            },
            verify=self.verify,
            timeout=15,
        )
        r.raise_for_status()

    # ------------------------------------------------------------------ #
    def _ping(self) -> str:
        r = requests.get(self.host, headers=self.headers, verify=self.verify, timeout=10)
        r.raise_for_status()
        name = (r.json() or {}).get("cluster_name", "")
        return f"Elastic cluster {name} auth OK"

    @staticmethod
    def _normalize(src: dict[str, Any], doc_id: str) -> dict[str, Any]:
        host = src.get("host") or {}
        user = src.get("user") or {}
        source = src.get("source") or {}
        return {
            "alert_id": src.get("kibana.alert.uuid") or doc_id,
            "rule_id": src.get("kibana.alert.rule.uuid"),
            "rule_name": src.get("kibana.alert.rule.name") or "Elastic alert",
            "severity": str(src.get("kibana.alert.severity", "unknown")),
            "description": src.get("message") or src.get("kibana.alert.rule.description", ""),
            "host": (host.get("name") if isinstance(host, dict) else None) or src.get("host.name"),
            "user": (user.get("name") if isinstance(user, dict) else None) or src.get("user.name"),
            "src_ip": (source.get("ip") if isinstance(source, dict) else None)
            or src.get("source.ip"),
            "raw_fields": src,
        }
