"""CLI entry for live validation.

The harness is intentionally separate from the unit suite (which must remain
runnable offline): it requires an explicit --live flag, refuses to run when
MOCK_MODE is on, verifies credentials + API availability before doing
anything, and only deploys/restarts when --auto-approve is passed (with
EXECUTE-level confirmations implicit in env.confirm_execute).
"""
from __future__ import annotations

import argparse
import sys
from typing import Any

from config import cfg

SCENARIO_ORDER = [
    "env_baseline",
    "detection_ssh_rule",
    "streamed_ssh_alert",
    "investigation_ip",
    "investigation_web",
    "investigation_existing_alert",
    "security_tool_args",
    "security_query_safety",
    "security_approval_bypass",
    "security_prompt_injection",
    "dashboard_workflow",
    "detection_gaps",
]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="live_validation",
        description="PHASE 14 live validation - requires a live Wazuh dev "
                    "environment. Never run automatically with the unit suite.",
    )
    p.add_argument("--live", action="store_true",
                   help="explicitly confirm a live Wazuh environment is intended")
    p.add_argument("--scenario", default="all",
                   help="scenario name or comma-separated list (default: all)")
    p.add_argument("--auto-approve", action="store_true",
                   help="for validation runs: approve the harness's own proposals and "
                        "execute them (deploy rules/dashboards, restart manager). Without "
                        "this flag workflows stop at the approval gate (N/A for env_baseline)")
    p.add_argument("--confirm-execute", action="store_true",
                   help="confirm EXECUTE-level actions (delete/restart) on top of approval")
    p.add_argument("--out", default="data/phase14_evidence.json",
                   help="evidence JSON output path")
    p.add_argument("--cleanup", action="store_true",
                   help="remove test artifacts after the run (rules/dashboards/proposals)")
    p.add_argument("--opts", default="",
                   help="scenario options as key=value,key2=value2 (e.g. test_ip=203.0.113.77)")
    p.add_argument("--approvals-path", default=None, help="approval store path (dev/testing)")
    p.add_argument("--audit-path", default=None, help="audit log path (dev/testing)")
    p.add_argument("--syslog-listener-setup", action="store_true",
                   help="dev-stack setup: add UDP 514 syslog <remote> to ossec.conf "
                        "(needed for streamed_ssh_alert) and restart the manager")
    p.add_argument("--syslog-listener-remove", action="store_true",
                   help="dev-stack cleanup: remove the UDP 514 syslog <remote> block "
                        "from ossec.conf and restart the manager")
    p.add_argument("--cleanup-rule-ids", default="",
                   help="extra rule ids to remove during --cleanup (comma-separated) - "
                        "for test rules deployed by earlier validation runs whose ids "
                        "this run did not create")
    p.add_argument("--cleanup-dashboard-ids", default="",
                   help="extra dashboard ids to remove during --cleanup "
                        "(comma-separated) - for dashboards created by earlier "
                        "validation runs this process did not create")
    p.add_argument("--reset-stores", action="store_true",
                   help="admin/dev-environment op: restore the approval + audit stores "
                        "to the PHASE 14 baseline snapshot, keeping phase evidence "
                        "copies next to them (.phase14.*)")
    p.add_argument("--snapshot-approvals", default="/tmp/opencode/phase14_backup/approvals_pre_phase14.json",  # nosec B108 - operator-overridable argparse default for the pre-approved scratch dir
                   help="approvals snapshot to restore (default: pre-PHASE-14 baseline)")
    p.add_argument("--snapshot-audit", default="/tmp/opencode/phase14_backup/audit_log_pre_phase14.jsonl",  # nosec B108 - operator-overridable argparse default for the pre-approved scratch dir
                   help="audit log snapshot to restore (default: pre-PHASE-14 baseline)")
    return p


def _parse_opts(raw: str) -> dict[str, Any]:
    opts: dict[str, Any] = {}
    for pair in raw.split(","):
        if not pair:
            continue
        if "=" not in pair:
            opts[pair] = True
            continue
        k, v = pair.split("=", 1)
        opts[k] = v
    return opts


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print("=" * 72)
    print("PHASE 14 LIVE VALIDATION - requires a live Wazuh development environment")
    print("=" * 72)
    if not args.live:
        print("REFUSING: pass --live to confirm you intend a live run "
              "(this harness never runs with the unit suite).")
        return 2
    if getattr(cfg, "MOCK_MODE", False):
        print("REFUSING: MOCK_MODE is on - live validation needs real connectors.")
        return 2
    if cfg.WAZUH_API_PASSWORD is None or cfg.WAZUH_USERNAME is None:
        print("REFUSING: missing WAZUH_* credentials in .env.")
        return 2

    from live_validation.env import LiveEnv
    from live_validation.evidence import EvidenceLog
    from live_validation import scenarios as scen

    opts = _parse_opts(args.opts)
    env = LiveEnv(
        approvals_path=args.approvals_path,
        audit_path=args.audit_path,
        by="phase14-validator",
        auto_approve=args.auto_approve,
        confirm_execute=args.confirm_execute or args.auto_approve,
        cleanup=args.cleanup,
    )

    # preflight
    print("\n[preflight] checking credentials + API availability ...")
    problems = env.preflight()
    if problems:
        print("PREFLIGHT FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("preflight OK (manager API, manager status, indexer, dashboards)")

    # dev-stack listener setup (UDP 514 syslog) - docker-exec admin ops
    if args.syslog_listener_setup:
        changed, detail = env.ensure_syslog_514()
        print(f"\n[syslog-listener] {detail}")
        env.docker_exec(["/var/ossec/bin/wazuh-control", "restart"])
        print("[syslog-listener] manager restarted (docker wazuh-control); waiting for readiness...")
        if not env.wait_for_manager(timeout_s=300) or not env.wait_for_logtest(timeout_s=300):
            print("[syslog-listener] FAILED: manager not ready after listener setup")
            return 1
        print("[syslog-listener] ready; UDP 514 syslog input active")

    if args.syslog_listener_remove:
        changed, detail = env.remove_syslog_514()
        print(f"\n[syslog-listener] {detail}")
        env.docker_exec(["/var/ossec/bin/wazuh-control", "restart"])
        print("[syslog-listener] manager restarted; waiting for readiness...")
        if not env.wait_for_manager(timeout_s=300) or not env.wait_for_logtest(timeout_s=300):
            print("[syslog-listener] FAILED: manager not ready after listener removal")
            return 1
        print("[syslog-listener] ready; UDP 514 syslog input removed")

    # choose scenarios
    if args.scenario == "all":
        names = [s for s in SCENARIO_ORDER if s in scen.SCENARIOS]
    else:
        names = [n.strip() for n in args.scenario.split(",") if n.strip()]
    unknown = [n for n in names if n not in scen.SCENARIOS]
    if unknown:
        print(f"ERROR: unknown scenario(s): {unknown}")
        return 2
    for n in names:
        reg = scen.SCENARIOS[n]
        if reg["requires_auto_approve"] and not args.auto_approve:
            print(f"NOTE: scenario '{n}' will stop at the approval gate "
                  "(pass --auto-approve to also deploy/verify).")

    log = EvidenceLog()
    for name in names:
        print(f"\n--- scenario: {name} ---")
        try:
            slog = scen.run_scenario(env, name, opts)
        except Exception as e:  # noqa: BLE001 - scenario crash is a failed run
            log.step(name, "scenario-crash", "live_validation.scenarios", "error", False,
                     detail=f"{type(e).__name__}: {str(e)[:300]}")
            continue
        for item in slog.items:
            log.add(item)
        st = log.scenario_status(name)
        print(f"  {st['status']} ({st['passed']}/{st['total']} steps passed)")
        for f in st["failures"]:
            print(f"    FAIL {f['tool']} [{f['step']}]: {f['detail']}")

    print("\n" + "=" * 72)
    print("VALIDATION MATRIX")
    print(log.matrix())
    print("=" * 72)

    if args.cleanup:
        print("\n[cleanup] removing PHASE 14 test artifacts ...")
        from live_validation.cleanup import (reject_leftover_proposals, cleanup_rules,
                                             cleanup_dashboards, cleanup_syslog_listener)
        n = reject_leftover_proposals(env)
        print(f"  rejected {n} leftover pending proposals")
        for rid_s in (args.cleanup_rule_ids or "").split(","):
            rid_s = rid_s.strip()
            if rid_s.isdigit() and int(rid_s) not in env.created_rules:
                env.created_rules.append(int(rid_s))
        for did_s in (args.cleanup_dashboard_ids or "").split(","):
            did_s = did_s.strip()
            if did_s and did_s not in env.created_dashboards:
                env.created_dashboards.append(did_s)
        cleanup_dashboards(env, log)
        cleanup_rules(env, log)
        cleanup_syslog_listener(env, log)
        if args.reset_stores:
            from live_validation.cleanup import reset_stores
            out = reset_stores(
                env,
                args.approvals_path or cfg.APPROVALS_PATH,
                args.audit_path or cfg.AUDIT_LOG_PATH,
                args.snapshot_approvals, args.snapshot_audit,
            )
            for k, v in out.items():
                print(f"  {k}: {v}")
        print("  cleanup done (see evidence for per-artifact results)")

    if args.out:
        log.to_json(args.out)
        print(f"\nevidence written to {args.out}")

    ok = log.all_pass()
    print("\nRESULT:", "ALL SCENARIOS PASS" if ok else "SCENARIO FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())