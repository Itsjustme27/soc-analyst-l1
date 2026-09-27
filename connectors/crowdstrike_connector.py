"""
Thin wrapper around the CrowdStrike Falcon API (OAuth2 client-credentials).
Provides enrichment (host info, process tree, detection details) and one
containment action (host isolation) that is gated by DRY_RUN_ACTIONS.

Docs: https://falconpy.io / https://www.falconpy.io/Service-Collections/
"""

from __future__ import annotations

import time
from typing import Any

import requests

from config import cfg


class CrowdStrikeConnector:
    def __init__(self):
        self.base = cfg.FALCON_BASE_URL.rstrip("/")
        self._token: str | None = None
        self._token_expiry: float = 0

    # ------------------------------------------------------------------ #
    def _auth_headers(self) -> dict[str, str]:
        if not self._token or time.time() >= self._token_expiry:
            resp = requests.post(
                f"{self.base}/oauth2/token",
                data={
                    "client_id": cfg.FALCON_CLIENT_ID,
                    "client_secret": cfg.FALCON_CLIENT_SECRET,
                },
                timeout=15,
            )
            resp.raise_for_status()
            body = resp.json()
            self._token = body["access_token"]
            self._token_expiry = time.time() + body.get("expires_in", 1700) - 60
        return {"Authorization": f"Bearer {self._token}"}

    # ------------------------------------------------------------------ #
    def get_detection_details(self, detection_id: str) -> dict[str, Any]:
        r = requests.post(
            f"{self.base}/detects/entities/summaries/GET/v1",
            headers=self._auth_headers(),
            json={"ids": [detection_id]},
            timeout=15,
        )
        r.raise_for_status()
        resources = r.json().get("resources", [])
        return resources[0] if resources else {}

    def get_host_info(self, host_id: str) -> dict[str, Any]:
        r = requests.get(
            f"{self.base}/devices/entities/devices/v2",
            headers=self._auth_headers(),
            params={"ids": host_id},
            timeout=15,
        )
        r.raise_for_status()
        resources = r.json().get("resources", [])
        return resources[0] if resources else {}

    def get_process_tree(self, falcon_process_id: str) -> dict[str, Any]:
        """Ancestor/child processes for a given detection's triggering process -
        this is usually the single most useful enrichment for L1 triage."""
        r = requests.get(
            f"{self.base}/processes/entities/processes/v1",
            headers=self._auth_headers(),
            params={"ids": falcon_process_id},
            timeout=15,
        )
        r.raise_for_status()
        resources = r.json().get("resources", [])
        return resources[0] if resources else {}

    def get_host_alert_history(self, host_id: str) -> list[dict[str, Any]]:
        """Prior detections on this host - useful for 'is this box known-noisy'."""
        r = requests.get(
            f"{self.base}/detects/queries/detects/v1",
            headers=self._auth_headers(),
            params={"filter": f"device.device_id:'{host_id}'", "limit": 25},
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("resources", [])

    # ------------------------------------------------------------------ #
    def isolate_host(self, host_id: str, reason: str) -> dict[str, Any]:
        """Containment action. Real API call is skipped when DRY_RUN_ACTIONS
        is set - the agent logs the recommendation instead of executing it.
        This is an L1 agent; network containment should require human sign-off
        until the agent's precision is proven over time."""
        if cfg.DRY_RUN_ACTIONS:
            return {
                "dry_run": True,
                "action": "isolate_host",
                "host_id": host_id,
                "reason": reason,
                "note": "DRY_RUN_ACTIONS=true - no action taken, recommendation logged only.",
            }
        r = requests.post(
            f"{self.base}/devices/entities/devices-actions/v2",
            headers=self._auth_headers(),
            params={"action_name": "contain"},
            json={"ids": [host_id]},
            timeout=15,
        )
        r.raise_for_status()
        return r.json()
