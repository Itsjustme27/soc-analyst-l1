"""
AI SOC engineer - typed tool layer for Wazuh.

Package layout:

    api_client.py      Wazuh manager REST API client (rules/decoders/agents/
                       logtest/status/config). JWT auth, typed methods.
    indexer.py         Indexer (OpenSearch) client - wraps the existing
                       connectors.siem.wazuh.WazuhConnector so the engineer
                       reads alerts/events/schema through the same HTTP path
                       the rest of the app uses (no second raw client).
    base.py            Permission levels, ToolContext, BaseWazuhTool.
    wazuh/             Read/propose/execute tools for manager surfaces
                       (alerts live on the indexer - see indexer/).
    indexer/           Schema inspection + search/query tools over the indexer.
    dashboard/         OpenSearch Dashboards saved-objects tools (best-effort).
    registry.py        Builds the canonical TOOLS list for the LLM and the
                       dispatch table; runs every call through permission
                       gates + the audit log.
"""

from tools.api_client import (
    WazuhAPIError,
    WazuhAPINotConfigured,
    WazuhAuthError,
    WazuhManagerAPI,
)
from tools.base import (
    ApprovalRequired,
    Permission,
    PermissionDenied,
    ToolContext,
    ToolError,
    ToolParamError,
)
from tools.indexer_client import IndexerClient

__all__ = [
    "Permission",
    "PermissionDenied",
    "ToolContext",
    "ToolError",
    "ToolParamError",
    "ApprovalRequired",
    "WazuhAPIError",
    "WazuhAPINotConfigured",
    "WazuhAuthError",
    "WazuhManagerAPI",
    "IndexerClient",
]
