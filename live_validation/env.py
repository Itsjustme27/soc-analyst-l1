"""Live environment wrapper: clients, the application's propose/execute gates,
and preflight availability checks.

Execution semantics replicate the dashboard's Approval Center implementation
exactly (see dashboard.py `api_proposal_execute`): an approved proposal carries
the exact action + payload, and tools.registry.execute re-runs the real tool
with that stored payload - no LLM, no display blob, no re-derivation.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

import requests  # module-level so hermetic tests can patch live_validation.env.requests

from config import cfg
from tools.base import ToolContext


class LiveEnv:
    """Bundles live clients + options for one validation run.

    `wazuh`, `indexer` and `dashboards` are injectable so hermetic tests can
    substitute fake clients; defaults are the real connectors.
    """

    def __init__(
        self,
        *,
        wazuh: Any = None,
        indexer: Any = None,
        dashboards: Callable[..., dict[str, Any]] | None = None,
        approvals_path: str | Path | None = None,
        audit_path: str | Path | None = None,
        by: str = "phase14-validator",
        auto_approve: bool = False,
        confirm_execute: bool = False,
        cleanup: bool = True,
    ) -> None:
        from tools.api_client import WazuhManagerAPI
        from tools.indexer_client import IndexerClient

        self.wazuh = wazuh if wazuh is not None else WazuhManagerAPI()
        self.indexer = indexer if indexer is not None else IndexerClient()
        self.dashboards = dashboards  # default wired lazily in dashboards_call()
        self.approvals_path = approvals_path
        self.audit_path = audit_path
        self.by = by
        self.auto_approve = auto_approve
        self.confirm_execute = confirm_execute
        self.cleanup = cleanup
        # artifacts the scenarios have created (for cleanup)
        self.created_rules: list[int] = []
        self.created_dashboards: list[str] = []
        self.created_proposals: list[str] = []
        self.rule_file = "local_rules.xml"
        self._kb: Any = None

    # ------------------------------------------------------------------ #
    def tool_ctx(self, user: str | None = None, agent: str = "phase14-validator") -> ToolContext:
        return ToolContext(wazuh=self.wazuh, indexer=self.indexer,
                           user=user or self.by, agent=agent)

    def approve(self, proposal: dict[str, Any], by: str | None = None) -> dict[str, Any]:
        import approvals
        return approvals.approve(proposal["id"], by or self.by, path=self.approvals_path)

    def propose(self, tool_name: str, params: dict[str, Any],
                agent: str = "phase14-validator") -> dict[str, Any]:
        """Run one tool through the standard gate. Write tools yield an
        approval_required outcome whose proposal is persisted."""
        from tools.registry import execute as run_tool
        ctx = self.tool_ctx(agent=agent)
        outcome = run_tool(ctx, tool_name, params, silent=False)
        return outcome

    def execute_approved(self, proposal: dict[str, Any]) -> dict[str, Any]:
        """Deterministic execution of an approved proposal (mirrors the
        dashboard execute endpoint). EXECUTE-level actions require the
        `confirm` flag on top of approval."""
        import approvals
        from tools.registry import execute as run_tool

        p = approvals.get_proposal(proposal["id"], path=self.approvals_path)
        if not p:
            return {"ok": False, "error": f"Proposal {proposal['id']} not found."}
        if p.get("status") != "approved":
            return {"ok": False,
                    "error": f"Proposal {proposal['id']} is not approved (status: {p.get('status')})."}
        if p.get("permission") == "execute" and not self.confirm_execute:
            return {"ok": False,
                    "error": "EXECUTE-level action: requires an explicit confirmation "
                             "on top of the approval (set confirm_execute)."}

        ctx = self.tool_ctx(user=self.by, agent="approval_executor")
        ctx.approval = p
        try:
            result = run_tool(ctx, p.get("action", ""), p.get("payload") or {}, silent=True)
        except Exception as e:  # noqa: BLE001 - tool failure surfaces with its audit row
            return {"ok": False, "error": str(e)}
        if isinstance(result, dict) and result.get("status") == "error":
            return {"ok": False, "error": result.get("error", "execution failed"),
                    "result": result}
        return {"ok": True, "result": result}

    # ------------------------------------------------------------------ #
    def dashboards_call(self, method: str, path: str, **kw: Any) -> dict[str, Any]:
        fn = self.dashboards
        if fn is None:
            from tools.dashboard.client import dashboards_request
            fn = dashboards_request
        return fn(method, path, **kw)

    def rag_counts(self) -> dict[str, int]:
        if self._kb is None:
            from rag.knowledge_base import KnowledgeBase
            self._kb = KnowledgeBase()
        return dict(self._kb.counts())

    def rag_retrieve(self, query: str, top_k: int = 3, collection: str = "wazuh_docs") -> list[dict[str, Any]]:
        if self._kb is None:
            from rag.knowledge_base import KnowledgeBase
            self._kb = KnowledgeBase()
        return list(self._kb.query(collection, query, n_results=top_k))

    def approvals_count(self, status: str | None = None) -> int:
        import approvals
        return len(approvals.list_proposals(status, path=self.approvals_path))

    def audit_count(self) -> int:
        p = Path(self.audit_path or getattr(cfg, "AUDIT_LOG_PATH", "data/audit_log.jsonl"))
        if not p.exists():
            return 0
        return sum(1 for _ in p.open())

    def audit_rows(self, limit: int | None = None) -> list[dict[str, Any]]:
        p = Path(self.audit_path or getattr(cfg, "AUDIT_LOG_PATH", "data/audit_log.jsonl"))
        if not p.exists():
            return []
        rows = [json.loads(line) for line in p.open() if line.strip()]
        return rows if limit is None else rows[-limit:]

    # ------------------------------------------------------------------ #
    def delete_by_query(self, index: str = "wazuh-alerts-*",
                        query: dict[str, Any] | None = None) -> dict[str, Any]:
        """Dev-environment cleanup op: POST /{index}/_delete_by_query.

        Deliberately NOT an application tool - the IndexerClient is read-only
        and destructive indexer writes belong only to the validation harness
        (unique-marker cleanup of synthetic data)."""
        conn = self.indexer.connector
        url = f"{conn.host.rstrip('/')}/{index}/_delete_by_query?refresh=true"
        r = requests.post(url, auth=conn.auth, verify=conn.verify,  # nosec B113 - timeout= on continuation line
                          json={"query": query or {"match_all": {}}},
                          timeout=getattr(cfg, "TOOL_QUERY_TIMEOUT", 15))
        if r.status_code >= 400:
            raise RuntimeError(f"delete_by_query {index} -> {r.status_code}: "
                               f"{r.text[:200]}")
        return r.json()

    # ------------------------------------------------------------------ #
    # dev-stack setup/cleanup (docker-exec; NOT application tools). These
    # exist because the stock single-node stack only listens on 1514/tcp
    # (secure) - the streamed syslog workflow needs a UDP 514 syslog input.
    # ------------------------------------------------------------------ #
    def docker_exec(self, cmd: list[str], *, container: str | None = None) -> str:
        container = container or getattr(cfg, "WAZUH_MANAGER_CONTAINER", "single-node_wazuh.manager_1")
        proc = subprocess.run(["docker", "exec", container] + cmd,
                              capture_output=True, text=True, timeout=60)
        proc.check_returncode()
        return proc.stdout

    def _syslog_remote_block(self, container: str | None = None) -> str:
        """Build the syslog <remote> block for this stack. Wazuh 4.x disables
        the syslog server unless <allowed-ips> is present (remoted logs 1501).
        Datagrams forwarded by docker-proxy appear with the bridge gateway as
        source IP, so allow the container gateway(s) + loopback."""
        gw = "127.0.0.1"
        try:
            cname = container or getattr(cfg, "WAZUH_MANAGER_CONTAINER",
                                         "single-node_wazuh.manager_1")
            proc = subprocess.run(
                ["docker", "inspect", cname, "-f",
                 "{{range .NetworkSettings.Networks}}{{.Gateway}} {{end}}"],
                capture_output=True, text=True, timeout=60)
            gws = [g for g in (proc.stdout or "").strip().split() if g and g != "127.0.0.1"]
            if gws:
                gw = ",".join(gws)
        except Exception:  # noqa: BLE001 - fall back to loopback
            pass
        # Wazuh's <allowed-ips> accepts ONE ip/network per element (error 1237
        # on comma lists), so emit one element per allowed host.
        allowed = "".join(f"    <allowed-ips>{ip}</allowed-ips>\n"
                          for ip in ["127.0.0.1", *gw.split(",")])
        return (f"\n  <remote>\n    <connection>syslog</connection>\n    <port>514</port>\n"
                f"    <protocol>udp</protocol>\n{allowed}  </remote>\n")

    def has_syslog_514(self, container: str | None = None) -> bool:
        try:
            cfg_text = self.docker_exec(["cat", "/var/ossec/etc/ossec.conf"], container=container)
        except Exception:  # noqa: BLE001 - docker not available in hermetic tests
            return False
        return ("<connection>syslog</connection>" in cfg_text
                and "<port>514</port>" in cfg_text)

    def ensure_syslog_514(self, container: str | None = None) -> tuple[bool, str]:
        """Idempotently add the UDP 514 syslog <remote> block to ossec.conf.
        Returns (changed, detail). No restart here - callers restart via the
        approved EXECUTE path. Reverted by remove_syslog_514()."""
        if self.has_syslog_514(container):
            return False, "syslog 514 listener already configured"
        block = self._syslog_remote_block(container)
        script = (
            "import pathlib, sys;"
            "p = pathlib.Path('/var/ossec/etc/ossec.conf'); t = p.read_text();"
            "marker = '</ossec_config>';"
            "assert '<connection>syslog</connection>' not in t, 'syslog remote already present';"
            "idx = t.index(marker);"
            "p.write_text(t[:idx] + sys.argv[1] + t[idx:])"
        )
        self.docker_exec(["python3", "-c", script, block], container=container)
        if not self.has_syslog_514(container):
            raise RuntimeError("ossec.conf edit did not take effect")
        return True, "added UDP 514 syslog <remote> block to ossec.conf"

    def remove_syslog_514(self, container: str | None = None) -> tuple[bool, str]:
        """Idempotently remove the UDP 514 syslog <remote> block (cleanup)."""
        if not self.has_syslog_514(container):
            return False, "no syslog 514 block present"
        script = (
            "import pathlib, re; p = pathlib.Path('/var/ossec/etc/ossec.conf');"
            "t = p.read_text();"
            "t2 = re.sub(r'\\s*<remote>\\s*<connection>syslog</connection>\\s*"
            "<port>514</port>\\s*<protocol>udp</protocol>\\s*"
            "(?:(?:<allowed-ips>[^<]+</allowed-ips>\\s*)+)?</remote>', '', t);"
            "assert t2 != t, 'syslog block regex failed'; p.write_text(t2)"
        )
        self.docker_exec(["python3", "-c", script], container=container)
        if self.has_syslog_514(container):
            raise RuntimeError("ossec.conf removal did not take effect")
        return True, "removed UDP 514 syslog <remote> block from ossec.conf"

    # ------------------------------------------------------------------ #
    # preflight - the CLI refuses to run scenarios before this passes
    # ------------------------------------------------------------------ #
    def preflight(self) -> list[str]:
        """Return a list of problems (empty == ready). Never raises."""
        problems: list[str] = []
        # manager API
        try:
            tok = self.wazuh._authenticate()
            if not tok:
                problems.append("manager API returned an empty token")
        except Exception as e:  # noqa: BLE001
            problems.append(f"manager API auth failed: {type(e).__name__}: {str(e)[:120]}")
        # manager readiness (core daemons)
        try:
            st = self.wazuh.get_manager_status()
            daemons = ((st.get("data") or {}).get("affected_items") or [{}])[0]
            core = ["wazuh-analysisd", "wazuh-db", "wazuh-remoted",
                    "wazuh-authd", "wazuh-modulesd", "wazuh-apid"]
            down = [d for d in core if daemons.get(d) != "running"]
            if down:
                problems.append(f"manager core daemons not running: {', '.join(down)}")
        except Exception as e:  # noqa: BLE001
            problems.append(f"manager status failed: {type(e).__name__}: {str(e)[:120]}")
        # indexer
        try:
            resp = self.indexer.search("wazuh-alerts-*", {"size": 0})
            if not isinstance(resp, dict):
                problems.append("indexer search returned a non-JSON response")
        except Exception as e:  # noqa: BLE001
            problems.append(f"indexer search failed: {type(e).__name__}: {str(e)[:120]}")
        # dashboards
        try:
            r = self.dashboards_call("GET", "/api/saved_objects/_find",
                                     params={"type": "dashboard", "per_page": 1})
            if not isinstance(r, dict):
                problems.append("dashboards API returned a non-JSON response")
        except Exception as e:  # noqa: BLE001
            problems.append(f"dashboards API failed: {type(e).__name__}: {str(e)[:120]}")
        return problems

    # ------------------------------------------------------------------ #
    def wait_for_manager(self, timeout_s: float = 600.0, poll_s: float = 10.0) -> bool:
        """Block until the manager API reports core daemons running."""
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                st = self.wazuh.get_manager_status()
                daemons = ((st.get("data") or {}).get("affected_items") or [{}])[0]
                if all(daemons.get(d) == "running"
                       for d in ("wazuh-analysisd", "wazuh-db", "wazuh-remoted",
                                 "wazuh-authd", "wazuh-modulesd", "wazuh-apid")):
                    return True
            except Exception:  # noqa: BLE001 - transient during restart
                pass
            time.sleep(poll_s)
        return False

    def wait_for_logtest(self, timeout_s: float = 300.0, poll_s: float = 5.0,
                         probe_log: str | None = None) -> bool:
        """Block until wazuh-analysisd's logtest engine accepts events. After a
        manager restart the API reports daemons 'running' before logtest can
        evaluate - probe until the 'daemons not ready' error goes away."""
        probe_log = probe_log or ("Oct 24 06:00:00 testhost sshd[1000]: Accepted password "
                                  "for phase14-probe from 203.0.113.200 port 22 ssh2")
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            try:
                row = self.wazuh.run_logtest(probe_log, "syslog") or {}
                blob = str(row).lower()
                if ("not running or not yet available" not in blob
                        and "not ready yet" not in blob):
                    return True
            except Exception:  # noqa: BLE001 - still warming up
                pass
            time.sleep(poll_s)
        return False

    def wait_for_rule(self, rule_id: int, timeout_s: float = 300.0,
                      poll_s: float = 10.0) -> tuple[bool, str]:
        """Retry until the manager serves the rule (transient 'daemons not
        ready' errors must not fail verification). Returns (found, last_error)."""
        deadline = time.time() + timeout_s
        last_err = ""
        while time.time() < deadline:
            try:
                again = self.wazuh.get_rule(rule_id) or {}
                if bool((again.get("data") or {}).get("affected_items")):
                    return True, ""
            except Exception as e:  # noqa: BLE001 - transient during restart
                last_err = str(e)[:200]
            time.sleep(poll_s)
        return False, last_err