"""
Wazuh manager REST API client (port 55000 by default).

This is the API surface for rules, decoders, agents, manager/cluster status,
manager configuration, and the logtest tool. It is deliberately separate from
the indexer client (tools/indexer.py / connectors.siem.wazuh.WazuhConnector),
which reads *alerts* out of OpenSearch.

Auth flow (Wazuh 4.x):

    POST /security/user/authenticate      (HTTP Basic auth)
        -> {"data": {"token": "<JWT>"}}

The JWT is then sent as `Authorization: Bearer <token>` on every call and is
refreshed automatically when a call comes back 401. Credentials come from
WAZUH_API_URL / WAZUH_API_USERNAME / WAZUH_API_PASSWORD (.env). Like the
indexer connector, this client refuses to use the empty-password default
against a non-local host, so a misconfigured .env fails loudly instead of
silently sending Basic auth with an empty password.

All methods raise WazuhAPIError on any non-2xx response; Wazuh's
{"error": N, "message": "..."} payload (or its title/detail shape) is folded
into the exception so callers can show the real reason to the user.
"""

from __future__ import annotations

import time
from typing import Any

import requests

from config import cfg


class WazuhAPIError(RuntimeError):
    """Any non-2xx / malformed response from the manager API."""

    def __init__(
        self, message: str, status: int | None = None, code: Any = None, detail: Any = None
    ):
        super().__init__(message)
        self.status = status
        self.code = code
        self.detail = detail


class WazuhAPINotConfigured(WazuhAPIError):
    """Manager API credentials are missing entirely."""


class WazuhAuthError(WazuhAPIError):
    """Authentication failed (bad user/password, token rejected twice)."""


def _looks_local(host: str) -> bool:
    # loopback markers, not a bind host (see connectors/siem/wazuh.py)
    return any(marker in host for marker in ("localhost", "127.0.0.1", "0.0.0.0", "::1"))  # nosec B104


def raise_for_inbody_error(resp: dict[str, Any], what: str) -> dict[str, Any]:
    """Raise when a manager response reports failure INSIDE a 200 body.

    The Wazuh API answers a semantically-rejected write with HTTP 200 and
    {"error": 1, "message": "Could not upload rule", "data": {"total_failed_items": 1,
    "failed_items": [{"error": {"code": 1113, ...}}]}}. request() only raises on
    HTTP >= 400, so without this check every one of those was returned as a
    success: create_wazuh_rule reported {"status": "executed"} with
    "detail": "Could not upload rule" sitting unread in the same dict, and
    approval_executor then marked the proposal executed and audited
    execution_status="success" for a write that never happened. Because
    claim_for_execution() is single-use, that proposal could never be retried.

    Returns resp unchanged when the write actually succeeded.
    """
    if not isinstance(resp, dict):
        return resp
    data = resp.get("data")
    data = data if isinstance(data, dict) else {}
    failed = data.get("total_failed_items") or 0
    has_failed = bool(failed) or bool(data.get("failed_items"))
    reported_error = resp.get("error") not in (None, 0, False, "")
    if not (has_failed or reported_error):
        return resp
    reasons = []
    for item in data.get("failed_items") or []:
        if not isinstance(item, dict):
            continue
        err = item.get("error") or {}
        code = err.get("code")
        msg = err.get("message") or "write rejected"
        target = ", ".join(item.get("id") or []) or "target"
        reasons.append(f"{target}: {msg} (code {code})" if code else f"{target}: {msg}")
    detail = "; ".join(reasons) or str(resp.get("message") or "no detail")
    raise WazuhAPIError(
        f"{what} failed: {detail} (message: {resp.get('message') or 'n/a'})",
        status=200,
        code=resp.get("error") or (reasons and reasons[0]) or None,
        detail=data.get("failed_items") or resp.get("message"),
    )


def _err_from_payload(payload: dict[str, Any], status: int) -> str:
    if isinstance(payload, dict):
        if payload.get("message"):
            return f"{payload.get('message')} (error {payload.get('error')})"
        if payload.get("detail"):
            return str(payload["detail"])
        if payload.get("title"):
            return f"{payload.get('title')}: {payload.get('detail', '')}".strip()
    return f"HTTP {status}"


class WazuhManagerAPI:
    """Typed client for the Wazuh manager REST API.

    Thread-safety: one instance per request/agent session. The token cache is
    per-instance.
    """

    def __init__(
        self,
        url: str | None = None,
        username: str | None = None,
        password: str | None = None,
        verify: bool | None = None,
        ca_cert: str | None = None,
        timeout: float | None = None,
    ):
        self.base_url = (url or cfg.WAZUH_API_URL).rstrip("/")
        self.username = username or cfg.WAZUH_API_USERNAME
        self.password = cfg.WAZUH_API_PASSWORD if password is None else password
        if not self.password and not cfg.MOCK_MODE and not _looks_local(self.base_url):
            raise WazuhAPINotConfigured(
                f"Wazuh manager API '{self.base_url}' isn't local, but no "
                "WAZUH_API_PASSWORD is set - refusing to authenticate with an "
                "empty password. Set WAZUH_API_PASSWORD in .env "
                "(see wazuh/docker-compose.yml for the wazuh-wui user)."
            )
        self.verify: Any = ca_cert or cfg.WAZUH_API_CA_CERT
        if not self.verify:
            self.verify = cfg.WAZUH_API_VERIFY_SSL if verify is None else verify
        self.timeout = timeout or cfg.TOOL_QUERY_TIMEOUT
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self._session = requests.Session()

    # ------------------------------------------------------------------ #
    # auth
    # ------------------------------------------------------------------ #
    def _authenticate(self) -> str:
        if not self.password:
            raise WazuhAPINotConfigured(
                "WAZUH_API_PASSWORD is not set - cannot authenticate to the manager API."
            )
        try:
            r = self._session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=requests.auth.HTTPBasicAuth(self.username, self.password),
                timeout=self.timeout,
                verify=self.verify,
            )
        except requests.RequestException as e:
            raise WazuhAPIError(f"Manager API unreachable: {e}") from e
        try:
            payload = r.json()
        except ValueError:
            payload = {}
        if r.status_code != 200 or not isinstance(payload, dict):
            raise WazuhAuthError(
                f"Wazuh manager API authentication failed ({r.status_code}): "
                f"{_err_from_payload(payload, r.status_code)}"
            )
        token = (payload.get("data") or {}).get("token")
        if not token:
            raise WazuhAuthError("Manager API returned no token.")
        # Wazuh returns token expiration in seconds; default to a short cache.
        expires_in = (payload.get("data") or {}).get("expires_in") or 900
        self._token = str(token)
        self._token_expiry = time.time() + int(expires_in) - 30
        return self._token

    def _headers(self) -> dict[str, str]:
        if not self._token or time.time() >= self._token_expiry:
            self._authenticate()
        return {"Authorization": f"Bearer {self._token}"}

    # ------------------------------------------------------------------ #
    # low-level request
    # ------------------------------------------------------------------ #
    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
        body_content_type: str | None = None,
        raw_text: bool = False,
    ) -> dict[str, Any]:
        """One authenticated request. Retries auth once on 401. Raises
        WazuhAPIError on any non-2xx. `raw_text=True` returns the response
        body as-is (used by /rules/files/<file>?raw=true which streams the
        file, not JSON)."""
        url = f"{self.base_url}{path}"
        for attempt in (0, 1):
            headers = {"Authorization": f"Bearer {self._token or self._authenticate()}"}
            if body_content_type:
                headers["Content-Type"] = body_content_type
            try:
                if body_content_type == "application/json":
                    r = self._session.request(
                        method,
                        url,
                        params=params,
                        json=body,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify,
                    )
                else:
                    r = self._session.request(
                        method,
                        url,
                        params=params,
                        data=body,
                        headers=headers,
                        timeout=self.timeout,
                        verify=self.verify,
                    )
            except requests.RequestException as e:
                raise WazuhAPIError(f"Manager API request failed: {e}") from e
            if r.status_code == 401 and attempt == 0:
                self._token = None
                continue
            if r.status_code >= 400:
                try:
                    payload = r.json()
                except ValueError:
                    payload = {}
                raise WazuhAPIError(
                    _err_from_payload(payload, r.status_code),
                    status=r.status_code,
                    code=(payload or {}).get("error") if isinstance(payload, dict) else None,
                    detail=(payload or {}).get("detail")
                    or ((payload or {}).get("failed_items") if isinstance(payload, dict) else None),
                )
            if raw_text:
                return {"data": r.text}
            try:
                payload = r.json()
            except ValueError:
                payload = {}
            if not isinstance(payload, dict):
                return {"data": payload}
            return payload
        raise WazuhAuthError("Manager API authentication failed twice.")

    def get(
        self, path: str, params: dict[str, Any] | None = None, raw_text: bool = False
    ) -> dict[str, Any]:
        return self.request("GET", path, params=params, raw_text=raw_text)

    def put(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
        body_content_type: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "PUT", path, params=params, body=body, body_content_type=body_content_type
        )

    def post(
        self,
        path: str,
        params: dict[str, Any] | None = None,
        body: Any = None,
        body_content_type: str | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST", path, params=params, body=body, body_content_type=body_content_type
        )

    def delete(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        return self.request("DELETE", path, params=params)

    # ------------------------------------------------------------------ #
    # rules
    # ------------------------------------------------------------------ #
    def get_rules(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        group: str | None = None,
        level: int | None = None,
        filename: str | None = None,
        status: str | None = None,
        sort: str | None = None,
        q: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        for key, val in (
            ("search", search),
            ("group", group),
            ("level", level),
            ("filename", filename),
            ("status", status),
            ("sort", sort),
            ("q", q),
        ):
            if val is not None:
                params[key] = val
        return self.get("/rules", params=params)

    def get_rule(self, rule_id: int | str) -> dict[str, Any]:
        """GET /rules/{id}. This API build (4.14) does not expose the per-rule
        detail endpoint for built-in rules (404), so fall back to the list
        endpoint filtered by exact id - same data, different route."""
        try:
            resp = self.get(f"/rules/{rule_id}")
            if resp.get("data", {}).get("total_affected_items", 0):
                return resp
            raise WazuhAPIError("no rule returned")
        except Exception:  # noqa: BLE001 - fall back below for any failure
            pass
        return self.get("/rules", params={"q": f"id={int(rule_id)}", "limit": 1, "offset": 0})

    def create_rule(self, rule_xml: str, overwrite: bool = False) -> dict[str, Any]:
        """POST /rules - NOT available on this API build (4.14 removed per-rule
        POST in favour of file management via put_rules_file). Kept for
        compatibility with builds that still expose it."""
        resp = self.post(
            "/rules",
            params={"overwrite": overwrite},
            body=rule_xml,
            body_content_type="application/xml",
        )
        return raise_for_inbody_error(resp, "Create rule")

    def update_rule(
        self, rule_id: int | str, rule_xml: str, overwrite: bool = True, purge: bool = False
    ) -> dict[str, Any]:
        resp = self.put(
            f"/rules/{rule_id}",
            params={"overwrite": overwrite, "purge": purge},
            body=rule_xml,
            body_content_type="application/xml",
        )
        return raise_for_inbody_error(resp, f"Update rule {rule_id}")

    def delete_rule(self, rule_id: int | str, purge: bool = False) -> dict[str, Any]:
        resp = self.delete(f"/rules/{rule_id}", params={"purge": purge})
        return raise_for_inbody_error(resp, f"Delete rule {rule_id}")

    # -- ruleset file management (the 4.14 way to add/modify/remove rules) --
    def get_rules_file(self, filename: str = "local_rules.xml", raw: bool = True) -> str:
        resp = self.get(f"/rules/files/{filename}", params={"raw": raw}, raw_text=raw)
        if raw:
            return str(resp.get("data", ""))
        return resp.get("data", {}).get("affected_items", [])

    def put_rules_file(self, filename: str, content: str, overwrite: bool = True) -> dict[str, Any]:
        resp = self.put(
            f"/rules/files/{filename}",
            params={"overwrite": overwrite},
            body=content,
            body_content_type="application/octet-stream",
        )
        return raise_for_inbody_error(resp, f"Upload of rules file '{filename}'")

    # ------------------------------------------------------------------ #
    # decoders
    # ------------------------------------------------------------------ #
    def get_decoders(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        filename: str | None = None,
        status: str | None = None,
        parents: bool = False,
        sort: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset, "parents": parents}
        for key, val in (
            ("search", search),
            ("filename", filename),
            ("status", status),
            ("sort", sort),
        ):
            if val is not None:
                params[key] = val
        return self.get("/decoders", params=params)

    # -- decoder file management (the 4.14 way to add/modify/remove decoders) --
    def get_decoders_file(self, filename: str = "local_decoder.xml", raw: bool = True) -> str:
        resp = self.get(f"/decoders/files/{filename}", params={"raw": raw}, raw_text=raw)
        return str(resp.get("data", "")) if raw else resp.get("data", {}).get("affected_items", [])

    def put_decoders_file(
        self, filename: str, content: str, overwrite: bool = True
    ) -> dict[str, Any]:
        resp = self.put(
            f"/decoders/files/{filename}",
            params={"overwrite": overwrite},
            body=content,
            body_content_type="application/octet-stream",
        )
        return raise_for_inbody_error(resp, f"Upload of decoders file '{filename}'")

    # ------------------------------------------------------------------ #
    # agents
    # ------------------------------------------------------------------ #
    def get_agents(
        self,
        limit: int = 50,
        offset: int = 0,
        search: str | None = None,
        status: str | None = None,
        group: str | None = None,
        platform: str | None = None,
        version: str | None = None,
        agents_list: str | None = None,
        select: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "offset": offset}
        for key, val in (
            ("search", search),
            ("status", status),
            ("group", group),
            ("platform", platform),
            ("version", version),
            ("agents_list", agents_list),
            ("select", select),
        ):
            if val is not None:
                params[key] = val
        return self.get("/agents", params=params)

    def get_agent(self, agent_id: str) -> dict[str, Any]:
        """Agent detail - this API build has no /agents/{id} route, so detail
        comes back through /agents?agents_list=<id>&select=..."""
        return self.get("/agents", params={"agents_list": agent_id})

    # ------------------------------------------------------------------ #
    # manager / cluster / config
    # ------------------------------------------------------------------ #
    def get_manager_status(self) -> dict[str, Any]:
        return self.get("/manager/status")

    def get_cluster_status(self) -> dict[str, Any]:
        return self.get("/cluster/status")

    def get_manager_configuration(
        self, section: str, field: str | None = None, component: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"section": section}
        if field:
            params["field"] = field
        if component:
            params["component"] = component
        return self.get("/manager/configuration", params=params)

    def restart_manager(self) -> dict[str, Any]:
        # Same reason the rule/decoder writes are guarded: the manager answers
        # a refused restart with HTTP 200 and error:1 in the body, which used to
        # be reported as a successful restart. A restart is exactly when you
        # need to know it did not happen.
        return raise_for_inbody_error(self.put("/manager/restart"), "Manager restart")

    # ------------------------------------------------------------------ #
    # logtest (rule/decoder testing on the manager)
    # ------------------------------------------------------------------ #
    def run_logtest(
        self,
        log: str,
        log_format: str | None = None,
        location: str | None = None,
        token: str | None = None,
    ) -> dict[str, Any]:
        """PUT /logtest. Wazuh 4.7+ calls the payload field `event`;
        `log_format`/`location` are required. `log` MUST be one real log line.

        logtest evaluates the *deployed* ruleset against an event - it is not a
        rule validator. A candidate rule has to be loaded into the ruleset
        first (see tools/wazuh/logtest.py::TestWazuhRule); rule XML in `event`
        can only ever come back 'No decoder matched.', so it is refused here at
        the transport boundary rather than sent and misread as a verdict.
        """
        # nosec B314 - no XML parsing here; the guard below only *rejects* XML.
        from tools.wazuh.xmlio import NotALogEventError, ensure_real_event

        try:
            event = ensure_real_event(log, field="log")
        except NotALogEventError as e:
            raise WazuhAPIError(str(e)) from e
        body: dict[str, Any] = {
            "event": event,
            "log_format": log_format or "syslog",
            # `location` is "<component>-><path>" and selects the decoder, so it
            # must be qualified; the default is the manager's own auth.log,
            # which is what the canonical sshd preflight sample comes from.
            "location": location or "master->/var/log/auth.log",
        }
        if token:
            body["token"] = token
        return self.put("/logtest", body=body, body_content_type="application/json")

    def end_logtest_session(self, token: str) -> dict[str, Any]:
        return self.delete(f"/logtest/sessions/{token}")
