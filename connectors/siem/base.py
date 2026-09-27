"""
Common interface for SIEM connectors.

Every SIEM platform (Splunk, QRadar, Elastic, Sentinel, ...) implements this
interface so the triage agent and the dashboard can treat them uniformly:

  get_new_alerts()        -> alerts to triage (normalized dicts)
  search_related_events() -> correlation lookup (exposed to the LLM as a tool)
  close_notable()         -> write a verdict/status back to the SIEM
  test_connection()       -> lightweight reachability/auth check (dashboard)

Each connector takes an optional ``config`` dict that overrides the matching
``.env`` value, so a provider registered in the dashboard can point at any
host/tenant without touching ``.env``.

Alerts are normalized to a common shape so downstream code (agent, RAG,
dashboard) never sees platform-specific fields:

    {alert_id, rule_id, rule_name, severity, description, host, user, src_ip, raw_fields}
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from typing import Any


def resolve_cfg(config: dict[str, Any] | None, key: str, default: str = "") -> str:
    """Prefer an explicit per-provider config value, fall back to the default."""
    if config:
        val = config.get(key)
        if val not in (None, ""):
            return str(val)
    return default


def resolve_bool_cfg(config: dict[str, Any] | None, key: str, default: bool = True) -> bool:
    """Same as resolve_cfg but for boolean-ish values."""
    if config:
        val = config.get(key)
        if val is not None and str(val).strip().lower() not in ("", "none", "null"):
            return str(val).strip().lower() in ("1", "true", "yes", "on")
    return default


class SIEMConnector(ABC):
    """Abstract SIEM provider. Subclass per platform."""

    platform: str = "generic"

    def __init__(self, name: str = "default", config: dict[str, Any] | None = None):
        self.name = name
        self.config = config or {}

    @abstractmethod
    def get_new_alerts(self) -> list[dict[str, Any]]:
        """Return alerts ready for triage, normalized to the common alert shape."""

    @abstractmethod
    def search_related_events(
        self,
        host: str | None = None,
        user: str | None = None,
        earliest: str = "-24h",
        index: str = "*",
    ) -> list[dict[str, Any]]:
        """Correlation lookup: other events for this host/user in a time window.
        Exposed to the LLM as a tool - it decides when to call it."""

    @abstractmethod
    def close_notable(self, event_id: str, status: str, comment: str) -> None:
        """Write the agent's verdict/status back to the SIEM.

        DRY_RUN_ACTIONS gates this at the agent layer, not here - this method
        always performs the write when called."""

    # ------------------------------------------------------------------ #
    def test_connection(self) -> dict[str, Any]:
        """Lightweight reachability/auth check for the dashboard."""
        start = time.monotonic()
        try:
            detail = self._ping()
            return {
                "ok": True,
                "latency_ms": int((time.monotonic() - start) * 1000),
                "detail": detail or f"{self.name} ({self.platform}) reachable",
            }
        except Exception as e:  # noqa: BLE001 - surface any failure to the UI
            return {
                "ok": False,
                "latency_ms": int((time.monotonic() - start) * 1000),
                "detail": str(e),
            }

    def _ping(self) -> str:
        """One cheap authenticated request. Raise on failure, return detail text."""
        raise NotImplementedError
