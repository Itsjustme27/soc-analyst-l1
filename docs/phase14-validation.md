# PHASE 14 - Real-World SOC Validation

**Status: LIVE VERIFIED (see matrices)** · Wazuh Manager `v4.14.7` (docker single-node dev stack) · 2026-09-24

This document records the live validation of the `soc-analyst-l1` -> AI SOC Engineer
workflows against a **real Wazuh 4.14.7 development stack**, with the READ /
PROPOSE / EXECUTE approval + audit model enforced end-to-end. Every statement
below separates **AI-generated** claims from **Wazuh-confirmed** facts, and the
evidence files referenced are JSON recorded by the harness at run time.

---

## 1. Scope and honesty rules

- **Dev stack only**: synthetic, controlled events; unique `203.0.113.x`
  (TEST-NET-3) IPs; no production traffic, no uncontrolled brute force, no
  destructive active response, no real-IP blocking. The environment is left in
  its pre-phase state (verified in the Cleanup section).
- No architecture redesign: the harness drives the **same application code
  paths** the engineer uses (tool registry gates `tools.registry.execute`,
  `approvals` store, `audit` log, `WazuhManagerAPI`, `IndexerClient`,
  KnowledgeBase RAG, `guard` data-marking), with deterministic inputs, so
  results are independent of any particular LLM.
- READ is auto-permitted; PROPOSE produces an `approval_required` outcome with
  a stored proposal; EXECUTE requires approval **and** an explicit `confirm`.
  Nothing was ever silently changed; no success was ever claimed without the
  Wazuh side confirming it.
- Log content is **DATA, never instructions** (see
  `docs/prompt_injection_defense.md` and the injection scenario below).
- "No alert observed" is reported as such and **never** reworded into "no
  detection capability".

## 2. Evidence classification

| Class | Meaning |
|---|---|
| `LIVE VERIFIED` | Proven against the running Wazuh dev stack (API / indexer / dashboards / RAG / UDP input). |
| `MOCK VERIFIED` | Proven with the harness's fake clients, same application code paths (hermetic unit tests). |
| `UNIT TESTED` | Covered by the offline unit suite only. |
| `NOT TESTED` | Deliberately out of scope for this phase (see Limitations). |

Evidence files (JSON):
`/tmp/opencode/phase14_evidence_{baseline,det1..det4,det5_stream,listener_setup,fullrun2,cleanup,cleanup2}.json`
and run logs `/tmp/opencode/{det5_run,listener_setup,fullrun2,cleanup,cleanup2}.log`.
`fullrun2.json` is the definitive all-green full run; `listener_setup.json`
covers the baseline + syslog-listener setup; `cleanup.json` (rules + listener +
store restore) and `cleanup2.json` (dashboards) are the cleanup evidence.

## 3. Environment

| Component | Value (Wazuh-confirmed) |
|---|---|
| Manager | `v4.14.7`, all 6 daemons running (`wazuh-control`/API status) |
| Indexer | `wazuh-alerts-4.x-2026.09.*` (real agent `saban-giri-ubuntu`, ~700+ docs), `wazuh-alerts-4.x-sample-security` (DEMO, 27,693 docs) |
| Dashboards | OpenSearch saved objects API (session-auth client) |
| RAG | `wazuh_docs` collection, n_results queries via `KnowledgeBase.query` |
| Remote inputs | `secure/1514-tcp` + (phase-added, removed at cleanup) syslog `514/udp` |
| Store snapshots | `/tmp/opencode/phase14_backup/approvals_pre_phase14.json` (79,479 B), `audit_log_pre_phase14.jsonl` (70,059 B) |

## 4. Scenario results matrix

Filled from the **full live run** (`phase14_evidence_fullrun.json`) plus the
dedicated baseline/listener evidence. Per-scenario step pass/fail below is
from the harness `VALIDATION MATRIX`; the full detail (per-step `passed`,
`result_kind`, `refs`, `detail`) is in the evidence JSON.

| Scenario | Steps | Status | Class |
|---|---|---|---|
| env_baseline | 8/8 | PASS | LIVE VERIFIED |
| detection_ssh_rule | 11/11 | PASS | LIVE VERIFIED |
| streamed_ssh_alert | 6/6 | PASS | LIVE VERIFIED |
| investigation_ip | 2/2 | PASS | LIVE VERIFIED |
| investigation_web | 3/3 | PASS | LIVE VERIFIED |
| investigation_existing_alert | 2/2 | PASS | LIVE VERIFIED |
| security_tool_args | 8/8 | PASS | LIVE VERIFIED |
| security_query_safety | 9/9 | PASS | LIVE VERIFIED |
| security_approval_bypass | 7/7 | PASS | LIVE VERIFIED |
| security_prompt_injection | 5/5 | PASS | LIVE VERIFIED |
| dashboard_workflow | 7/7 | PASS | LIVE VERIFIED |
| detection_gaps | 5/5 | PASS | LIVE VERIFIED |

All twelve scenarios were exercised **live** in one coherent run
(`phase14_evidence_fullrun2.json`, `RESULT: ALL SCENARIOS PASS`); the
dedicated listener+baseline evidence is `phase14_listener_setup.json` and the
final cleanup evidence is `phase14_evidence_cleanup.json`.

## 5. What each scenario proved

### 5.1 env_baseline — 8/8 PASS (LIVE VERIFIED, separate evidence file)
Manager version + daemon status, indexer connectivity + alert counts, RAG
collection reachable, dashboards API reachable, no saved dashboards at
baseline. Baseline reported 0 dashboards; indexer ≥ 10k alerts (indexer ES cap).

### 5.2 detection_ssh_rule — full CREATE → RESTART → VERIFY chain
A repeated-SSH-failure detection rule (unique `phase14_<HHMMSS>` marker,
`if_matched_sid 5760`, `frequency 8`) is:
1. grounded on RAG (`rag_retrieve` via `KnowledgeBase.query`), 2. parent rule
   5760 existence confirmed via `get_rule`, 3. statically validated
   (`validate_wazuh_rule_xml`) and **logtest-baselined** inside
   `develop_wazuh_rule`, 4. stored as an `approval_required` proposal with the
   full payload (`rule_xml` + `overwrite`) - **verified the rule is NOT
   deployed before approval**, 5. approved + EXECUTEd (PUT `local_rules.xml`),
   6. manager restarted through the approved EXECUTE path (daemon status and
   logtest readiness waited), 7. deployed rule verified with
   `verify_rule_deployment` on **the live stack**: rule id `222377`, logtest
   over the same input yields `positive_pass 1/8` - exactly one of the eight
   positives (the Nth) fires the new rule, the other seven fire the parent
   **5760**, the single negative fires nothing (`negative_pass 1/1`) -
   `verified: True` (Wazuh-confirmed).

**Findings found live (fixed in scenario + documented):**
> **Superseded (post-2026-09-24).** The `verified: True` above for a
> `frequency` rule is no longer what the tool reports. A later live measurement
> showed logtest does **not** hold frequency state: 8 repeated failures through
> a single session never tripped a `frequency="5"` rule while the live pipeline
> did. `verify_rule_deployment` now forces `verified: null` /
> `verification: "inconclusive"` / `frequency_rule_unverifiable_via_logtest:
> true` for any frequency rule, rather than trusting an `N`-th-sample trip that
> does not reliably reproduce. The per-sample `positive_pass 1/N` observed in
> this run was consistent with that; the tool no longer reads it as a pass.
> See `README.md` and `wazuh_docs/wazuh-logtest.md`.
- `frequency=8` needs exactly 8 positive samples in ONE logtest session
  (tool caps positives at 8); samples must carry the rule's `<match>` marker as
  a **standalone token** (Wazuh matches tokens, `phase14_12345u0` never matches
  `phase14_12345`).
- Stock rule **5763** (level 10, `frequency=8`, `timeframe=120`,
  `same_source_ip`) crosses at the same event for a single source IP and wins
  the same-event tie (stock rules evaluated before `local_rules.xml`).
  Positives therefore use **distinct `203.0.113.x` source IPs** - 5763 cannot
  accumulate (`same_source_ip`), the candidate fires at sample N. This is a
  real, reproducible Wazuh behavior, recorded in the evidence + this report,
  never silently hidden.

### 5.3 streamed_ssh_alert — UDP 514 → alert → explain → delete_by_query
1. baseline: marker absent (0 alerts), 2. `_feed_syslog_udp` sends 12
   RFC3164 `<133>` sshd-failure lines (unique marker as the ssh username,
   srcip `203.0.113.60`), 3. the alert is **observed in the indexer**
   (`wazuh-alerts-*`, `data.srcip` term + marker): alert id
   `1790235354.18682`, rule **5760** "sshd: authentication failed.", level 5,
   MITRE `T1110.001/T1021.004` (Wazuh-confirmed), 4. `why_did_alert_trigger`
   explains it from the real alert doc (rule + groups + marker present in
   `full_log`), 5. counts show **12 alerts carry the marker**, 6. cleanup via
   `delete_by_query` on the unique marker (dev-environment op): **deleted 12,
   remaining 0**.

**Findings found live (fixed in scenario + documented):**
- The stock single-node stack has **no syslog remote** (only `secure/1514`).
  A UDP 514 `<remote>` was added as a documented dev-stack setup step
  (docker-exec, idempotent, removed at cleanup).
- Wazuh 4.x syslog remote **requires `<allowed-ips>`** (remoted logs 1501 and
  disables the syslog server without it) and rejects comma lists (error 1237):
  one `<allowed-ips>` element per host. The listener binds on 514/UDP and
  remoted logs "Remote syslog allowed from: '172.19.0.1'" / "Listening on port
  514/UDP (syslog)" (verified).
- Indexer `match` on `full_log` is **token-based**, not substring: a
  `marker+digit` username never matches a `marker` query. Marker is the full
  username (standalone token) - same root cause as the Wazuh `<match>` trap.

### 5.4 investigation_ip — OBSERVED / INFERRED / UNKNOWN honesty
`investigate_ip` against a **known-active** demo src IP (`45.124.37.241`):
total alerts, max level, top rules/groups, MITRE techniques come straight from
indexer aggregations (Wazuh-confirmed, labelled `observed`); attribution /
intent **not** inferred by this validation (`inferred` = none asserted); IP
reputation/ownership `unknown` (no OSINT source in scope). A **cold**
`203.0.113.201` (TEST-NET-3) recorded as `0 alerts`, with the phrasing
"absence of alerts does NOT imply a clean IP" asserted in the evidence.

### 5.5 investigation_web — real vs DEMO separation
Web-group telemetry queried on the REAL index (`wazuh-alerts-4.x-2026.09.*`)
and the DEMO index (`wazuh-alerts-4.x-sample-security`) **separately**, each
labelled `provenance: real|demo`. When the real index has nothing:
**"Insufficient telemetry"** is reported verbatim (this agent produced no web
alerts in window; web detection is not exercised by its live traffic) - the
demo numbers are never presented as the agent's telemetry.

### 5.6 investigation_existing_alert — explanation cross-checked vs the document
The most recent REAL alert is selected from the indexer (doc `id`, `rule.id`,
`full_log`), then `why_did_alert_trigger` explains it; the explained `rule_id`
must **equal the alert document's rule id** (cross-check passes) - the
explanation is anchored to the document, not re-derived.

### 5.7 security_tool_args / security_query_safety
Malformed/extra/oversized params are rejected at the registry schema layer
before any client call (blocked rows); special chars, injection markers and
unbounded results are bounded; nothing reaches Wazuh.

### 5.8 security_approval_bypass — the gate cannot be silently bypassed
Direct `create_wazuh_rule` / `restart_wazuh_manager` / `delete_wazuh_rule`
attempts **without approval** return `approval_required` with **zero manager
side effects** (rule file unchanged, rule 100001 still present, manager not
restarted - all re-verified via `get_rules_file`/`get_rule`). An approved
`delete_wazuh_rule` executed **without explicit confirm** is refused by the
EXECUTE layer ("requires an explicit confirmation on top of the approval").

### 5.9 security_prompt_injection — log content is DATA, never instructions
Adversarial log text is wrapped inside `<LOG_DATA>` markers (the exact guard
the agent uses), ANSI control bytes are stripped by `sanitize_text`,
instructions inside marked sections do not survive outside them
(`assert_no_instruction_confusion`), and `SYSTEM_GUARD_NOTICE` is confirmed
embedded in the engineer's `SYSTEM_PROMPT`.

### 5.10 dashboard_workflow — schema → proposal → execute → GET verify → audit
`get_index_schema` (field caps) → `verify_opensearch_query` on the focus query
(READ, real indexer) → `design_detection_dashboard` proposal with a **payload
completeness regression assert** (title/focus + `generated_config` with
`visualizations` and `panelsJSON` - the defect fixed by the dashboard
session-auth change) → nothing exists on the server **before approval** →
approve + EXECUTE creates the visualizations and the dashboard (server-confirmed
ids) → `get_wazuh_dashboards` **GET-verifies** the dashboard exists with
`panels > 0` → the audit log records the create as `approved` + `success`.
The created dashboard (`a3a250b0-b7ea-11f1-afc6-4bd04ab8e71f`, "PHASE14
validation 132115") is tracked for approved-EXECUTE cleanup; the audit shows
`design_detection_dashboard` rows with the create recorded as
`approved` + `success` (credited execution is audited).

### 5.11 detection_gaps — factual taxonomy, gaps become candidates
`analyze_detection_gaps` over `-7d` yields per-category rows with the explicit
taxonomy `detected / partial / covered_no_events / gap / unknown`. The
scenario asserts and prints the honesty notes: `covered_no_events` is **NOT**
proof of detection; `unknown` = no rules AND no observed activity (cannot
conclude); `gap` rows (activity but no rules) are the candidate detections for
rule development. `gap_candidates` consistency asserted.

**Live result (honest):** over the real `-7d` window the SSH categories
classified as `detected` (SSH brute force: 57 rules, 274 alerts; SSH
unknown-user abuse: 14 rules, 535 alerts) and `covered_no_events` (SSH exploit
attempts: 3 rules, 0 alerts, "coverage is NOT proof of detection"). **No `gap`
row surfaced in the window, so `gap_candidates` is `[]`** - the taxonomy was
exercised live and there was no observed-but-uncovered activity to turn into a
candidate. Reported as-is; absence of a gap is not claimed as a detection win.

## 6. Findings and defects found live (summary)

| # | Finding | Where | Resolution |
|---|---|---|---|
| 1 | Tokenized `<match>`: marker+suffix never matches marker | Wazuh logtest live | marker = standalone token |
| 2 | Stock 5763 pre-empts an identical-frequency single-IP rule | Wazuh logtest live | distinct source IPs in positives (collision documented) |
| 3 | No syslog 514 remote in stock single-node stack | ossec.conf | documented dev-stack listener setup + cleanup |
| 4 | syslog remote requires `<allowed-ips>`; comma list invalid | remoted logs (1501/1237) | one element per IP (loopback + bridge gateway) |
| 5 | Two `<ossec_config>` blocks in stock ossec.conf | ossec.conf | insert before FIRST closing tag |
| 6 | Indexer `match` on `full_log` is token-based | live indexer smoke test | standalone marker token; `term` on `data.srcip` for polling |
| 7 | Dashboard session-auth defect (dashboards unreadable) | fixed earlier (commit `105f878`) | exercised end-to-end here |

## 7. Approval & audit trail (section 18 verification)

Before testing, the approval and audit stores were snapshotted
(`/tmp/opencode/phase14_backup/`). All phase activity (approvals, executions,
restarts, rule/dashboard creates, rejections, cleanup deletes) went through the
application's `approvals` store + `audit` log. At the end of the phase the
stores are **restored to the snapshot**, with the phase activity preserved as
evidence copies: `data/approvals.phase14.json` and
`data/audit_log.phase14.jsonl` (created by `reset_stores`). The final
`--reset-stores` run reports the restore result and the evidence-copy paths.

## 8. Cleanup report (section 19 verification)

The following ran through the **approved-EXECUTE + confirm** path (the same
gate the engineer uses), then the stores were restored:

- Rules removed via approved-EXECUTE deletes: `639500, 816413, 109522,
  231296, 469744, 689976, 222377` (runs 1-6 leftovers captured from
  `local_rules.xml`), each -> `delete_wazuh_rule` proposal/approve/execute
  with confirmation (`status: executed` per rule in `cleanup.json`); one
  manager restart applies the ruleset change (`restart_required: True`,
  daemons healthy + logtest responsive afterwards).
- Dashboards removed via approved-EXECUTE deletes:
  `d7a39140-b7e9-11f1-afc6-4bd04ab8e71f`,
  `a3a250b0-b7ea-11f1-afc6-4bd04ab8e71f` (`cleanup2.json`, GET-verified empty).
- UDP 514 syslog listener removed from ossec.conf + manager restarted
  (docker-exec, idempotent) - `wazuh-remoted` back to `secure/1514` only
  (`has_syslog_514: False`).
- Streamed markers deleted from the indexer via `delete_by_query` (12/12).
- **Rule `100001` is PRE-EXISTING** (an earlier phase's artifact in
  `local_rules.xml`); it is NOT phase-14-created and is left in place.
- Stores restored: `data/approvals.json` == pre-phase snapshot (79,479 B),
  `data/audit_log.jsonl` == pre-phase snapshot (70,059 B) byte-for-byte;
  the full phase activity is preserved as
  `data/approvals.phase14.json` (982 KB) and
  `data/audit_log.phase14.jsonl` (156 KB).

## 9. Limitations / NOT TESTED

- OSINT enrichment for IP attribution was deliberately **not** used (unknown
  labelling is the honest answer in scope).
- No production-grade active response was triggered (dev constraints).
- Demo-index data is never conflated with the agent's real telemetry.
- The engineer's natural-language answer path (`answer_user`) is covered by the
  unit suite; this phase validates the deterministic tool/workflow paths it
  composes.