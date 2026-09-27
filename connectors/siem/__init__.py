"""
SIEM connector registry - the multi-SIEM layer.

    SIEM_PROVIDER=splunk|qradar|elastic|sentinel|wazuh|mock   (env, default: splunk)

  - splunk   : Splunk REST API / ES notable events
  - qradar   : IBM QRadar Ariel search API
  - elastic  : Elastic Security (.siem-signals-*)
  - sentinel : Microsoft Sentinel (Log Analytics KQL API)
  - wazuh    : Wazuh indexer / OpenSearch API (wazuh-alerts-*)
  - mock     : deterministic offline provider - no creds, for dev/CI/demos

To add another platform: implement connectors.siem.base.SIEMConnector, drop
the file in this package, register it in SIEM_PLATFORMS below, and add its
config fields to PLATFORM_FIELDS (used by the dashboard's "Add provider"
form). Nothing else changes.

The dashboard stores extra connections in data/siem_providers.json (see
siem_providers.py); each stored provider is instantiated with its own config,
so you can connect to many instances of the same platform at once.
"""

from __future__ import annotations

from typing import Any

from config import cfg
from connectors.siem.base import SIEMConnector
from connectors.siem.elastic import ElasticConnector
from connectors.siem.mock import MockSiemConnector
from connectors.siem.qradar import QRadarConnector
from connectors.siem.sentinel import SentinelConnector
from connectors.siem.splunk import SplunkConnector
from connectors.siem.wazuh import WazuhConnector

SIEM_PLATFORMS: dict[str, type[SIEMConnector]] = {
    "splunk": SplunkConnector,
    "qradar": QRadarConnector,
    "elastic": ElasticConnector,
    "sentinel": SentinelConnector,
    "wazuh": WazuhConnector,
    "mock": MockSiemConnector,
}

# How the dashboard renders each platform and which config fields its connector
# accepts. `secret: True` fields are rendered as password inputs and never
# echoed back to the UI.
PLATFORM_FIELDS: dict[str, dict[str, Any]] = {
    "splunk": {
        "label": "Splunk",
        "description": "Splunk Enterprise / Splunk ES notable events",
        "fields": [
            {
                "key": "host",
                "label": "Host URL",
                "placeholder": "https://splunk.corp.local:8089",
                "required": True,
                "secret": False,
            },
            {
                "key": "token",
                "label": "Bearer token",
                "placeholder": "HEC or auth token",
                "required": True,
                "secret": True,
            },
            {
                "key": "verify_ssl",
                "label": "Verify SSL",
                "type": "boolean",
                "default": True,
                "required": False,
                "secret": False,
            },
            {
                "key": "search",
                "label": "Alert search",
                "placeholder": "search index=notable status=new | head 20",
                "required": False,
                "secret": False,
            },
        ],
    },
    "qradar": {
        "label": "IBM QRadar",
        "description": "IBM QRadar Ariel search API",
        "fields": [
            {
                "key": "host",
                "label": "Host URL",
                "placeholder": "https://qradar.corp.local",
                "required": True,
                "secret": False,
            },
            {
                "key": "token",
                "label": "API token (SEC)",
                "placeholder": "QRadar API token",
                "required": True,
                "secret": True,
            },
            {
                "key": "verify_ssl",
                "label": "Verify SSL",
                "type": "boolean",
                "default": True,
                "required": False,
                "secret": False,
            },
            {
                "key": "search",
                "label": "Ariel query (alerts)",
                "placeholder": "SELECT * FROM events LAST 1 HOUR",
                "required": False,
                "secret": False,
            },
        ],
    },
    "elastic": {
        "label": "Elastic Security",
        "description": "Elasticsearch / Elastic Security signals",
        "fields": [
            {
                "key": "host",
                "label": "Cluster URL",
                "placeholder": "https://elastic.corp.local:9200",
                "required": True,
                "secret": False,
            },
            {
                "key": "api_key",
                "label": "API key",
                "placeholder": "Base64 API key",
                "required": True,
                "secret": True,
            },
            {
                "key": "index",
                "label": "Alerts index",
                "placeholder": ".siem-signals-*",
                "required": False,
                "secret": False,
            },
            {
                "key": "verify_ssl",
                "label": "Verify SSL",
                "type": "boolean",
                "default": True,
                "required": False,
                "secret": False,
            },
        ],
    },
    "sentinel": {
        "label": "Microsoft Sentinel",
        "description": "Microsoft Sentinel via Log Analytics",
        "fields": [
            {
                "key": "tenant_id",
                "label": "Azure tenant ID",
                "placeholder": "00000000-0000-0000-0000-000000000000",
                "required": True,
                "secret": False,
            },
            {
                "key": "client_id",
                "label": "App (client) ID",
                "placeholder": "00000000-0000-0000-0000-000000000000",
                "required": True,
                "secret": False,
            },
            {
                "key": "client_secret",
                "label": "Client secret",
                "placeholder": "App registration secret",
                "required": True,
                "secret": True,
            },
            {
                "key": "workspace_id",
                "label": "Log Analytics workspace ID",
                "placeholder": "00000000-0000-0000-0000-000000000000",
                "required": True,
                "secret": False,
            },
            {
                "key": "query",
                "label": "KQL query (alerts)",
                "placeholder": "SecurityAlert | where TimeGenerated > ago(1h) | take 20",
                "required": False,
                "secret": False,
            },
        ],
    },
    "wazuh": {
        "label": "Wazuh",
        "description": "Wazuh indexer (OpenSearch) - wazuh-alerts-*",
        "fields": [
            {
                "key": "host",
                "label": "Indexer URL",
                "placeholder": "https://localhost:9200",
                "required": True,
                "secret": False,
            },
            {
                "key": "username",
                "label": "Username",
                "placeholder": "admin",
                "required": False,
                "secret": False,
            },
            {
                "key": "password",
                "label": "Password",
                "placeholder": "admin",
                "required": False,
                "secret": True,
            },
            {
                "key": "index",
                "label": "Alerts index",
                "placeholder": "wazuh-alerts-*",
                "required": False,
                "secret": False,
            },
            {
                "key": "verify_ssl",
                "label": "Verify SSL",
                "type": "boolean",
                "default": False,
                "required": False,
                "secret": False,
            },
            {
                "key": "ca_cert",
                "label": "CA cert path",
                "placeholder": "wazuh/config/wazuh_indexer_ssl_certs/root-ca.pem",
                "required": False,
                "secret": False,
            },
        ],
    },
    "mock": {
        "label": "Mock SIEM",
        "description": "Offline canned-alert provider (no credentials)",
        "fields": [],
    },
}


def get_siem_connector(
    platform: str | None = None,
    name: str = "default",
    config: dict[str, Any] | None = None,
) -> SIEMConnector:
    """Return a SIEMConnector. `platform` overrides the SIEM_PROVIDER env var."""
    key = (platform or cfg.SIEM_PROVIDER).strip().lower()
    try:
        cls = SIEM_PLATFORMS[key]
    except KeyError:
        raise ValueError(
            f"Unknown SIEM platform '{key}'. Available: "
            f"{', '.join(sorted(SIEM_PLATFORMS))} (set SIEM_PROVIDER in .env)"
        ) from None
    return cls(name=name, config=config)


def list_siem_platforms() -> list[str]:
    return sorted(SIEM_PLATFORMS)


__all__ = [
    "SIEMConnector",
    "SIEM_PLATFORMS",
    "PLATFORM_FIELDS",
    "get_siem_connector",
    "list_siem_platforms",
]
