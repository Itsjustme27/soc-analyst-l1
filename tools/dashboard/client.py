"""
Wazuh dashboard (OpenSearch Dashboards) saved-objects HTTP client.

Separate host from the manager API and the indexer - the Dashboards server
serves the saved-objects API (default https://localhost:443, admin/admin in
the bundled docker stack). Best-effort by design: every call either returns a
2xx payload or raises ToolError with the real dashboards-server message; the
engineer never claims a dashboard was created unless the server said so.

Auth: OpenSearch Dashboards 2.x (Wazuh dashboard 4.x) requires a session
login - plain HTTP Basic auth is rejected with 401.  This client performs a
POST /auth/login handshake (cookie + osd-xsrf), re-logins once on a 401, and
falls back through credential sources (dedicated dashboard creds -> indexer
creds -> admin/admin) so a stale credential pair never bricks deployment.
Credentials are never logged; only the username that authenticated is
returned in debug info.
"""

from __future__ import annotations

import threading
from typing import Any

import requests

from config import cfg
from tools.base import ToolError

_SESSION = requests.Session()
_LOGIN_LOCK = threading.Lock()
_LOGGED_IN_USER: str | None = None


def _base_url() -> str:
    return (cfg.WAZUH_DASHBOARD_URL or "https://localhost:443").rstrip("/")


def _credential_sources() -> list[tuple[str, str]]:
    """Ordered (username, password) candidates for the dashboard session."""
    pairs: list[tuple[str, str | None]] = [
        (cfg.WAZUH_DASHBOARD_USERNAME, cfg.WAZUH_DASHBOARD_PASSWORD),
        (cfg.WAZUH_USERNAME, cfg.WAZUH_PASSWORD),
        ("admin", "admin"),
    ]
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for user, pwd in pairs:
        if not user:
            continue
        key = (user, pwd or "")
        if key in seen:
            continue
        seen.add(key)
        out.append((user, pwd or ""))
    return out


def _login() -> None:
    """Establish a session cookie for the dashboards server. Raises ToolError
    if every credential source is rejected (error message never contains
    passwords)."""
    global _LOGGED_IN_USER
    url = _base_url()
    last_status = 0
    for user, pwd in _credential_sources():
        try:
            r = _SESSION.post(
                f"{url}/auth/login",
                json={"username": user, "password": pwd},
                headers={"osd-xsrf": "true"},
                verify=cfg.WAZUH_DASHBOARD_VERIFY_SSL,
                timeout=cfg.TOOL_QUERY_TIMEOUT,
            )
        except requests.RequestException as e:
            raise ToolError(f"OpenSearch Dashboards login unreachable ({url}): {e}") from e
        last_status = r.status_code
        if r.status_code < 400:
            _LOGGED_IN_USER = user
            return
    raise ToolError(
        f"Dashboards login failed for all credential sources "
        f"(last status {last_status}). Check WAZUH_DASHBOARD_* / WAZUH_* "
        f"credentials in .env."
    )


def _ensure_session() -> None:
    if _LOGGED_IN_USER is None:
        with _LOGIN_LOCK:
            if _LOGGED_IN_USER is None:
                _login()


def dashboards_request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    body: Any = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Authenticated saved-objects request against the Wazuh dashboard.

    Returns the 2xx JSON payload or raises ToolError. Re-logins once after a
    401 (session may have expired) before giving up."""
    url = _base_url()
    _ensure_session()
    headers = {"osd-xsrf": "true"}
    timeout = timeout or cfg.TOOL_QUERY_TIMEOUT
    for attempt in range(2):
        try:
            r = _SESSION.request(
                method,
                f"{url}{path}",
                params=params,
                json=body,
                headers=headers,
                verify=cfg.WAZUH_DASHBOARD_VERIFY_SSL,
                timeout=timeout,
            )
        except requests.RequestException as e:
            raise ToolError(f"OpenSearch Dashboards unreachable ({url}): {e}") from e
        if r.status_code == 401 and attempt == 0:
            _login()  # session expired -> one re-login then retry
            continue
        break
    try:
        payload = r.json()
    except ValueError:
        payload = {"raw": r.text[:400]}
    if r.status_code >= 400:
        msg = payload.get("message") or payload.get("error") or payload.get("raw") or payload
        raise ToolError(f"Dashboards API {method} {path} -> {r.status_code}: {msg}")
    return payload
