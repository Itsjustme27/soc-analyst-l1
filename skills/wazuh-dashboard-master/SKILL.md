---
name: wazuh-dashboard-master
description: The five Wazuh dashboard pillars - reporting (metrics/digest), alerting (rule creation), anomaly detection (CrowdStrike + detection gaps), maps (geo-IP), notifications (action.notify). Use for any Wazuh dashboard, report, digest, rule, alert, anomaly, coverage, geo/map, or notify request.
version: 1.0.0
---
# Wazuh dashboard master

The console's five dashboard pillars. Route the request, then follow that
pillar's section. Each pillar names the module that owns it and the agent
tool that reaches it - those are different things, and mixing them up is the
most common failure here.

## Routing

| User asks for | Pillar | Owned by | Agent reaches it via |
|---|---|---|---|
| a report, metrics, daily/weekly digest, "how many alerts" | Reporting | `metrics.py`, `digest.py` | `compute_metrics()` / `build_digest_text()` |
| a rule, an alert, "notify me on X", tune detection | Alerting | `rules.py` + `local_rules.xml` | `create_wazuh_rule`, `update_wazuh_rule`, `develop_wazuh_rule` |
| anomalies, what am I missing, coverage | Anomaly detection | `connectors/crowdstrike_connector.py`, `tools/gaps/` | `analyze_detection_gaps` |
| where attackers are, a map, geo view | Maps | investigate engine | `top_attacking_ips`, `investigate_ip` |
| get this to Slack/Teams/webhook | Notifications | `notify.py`, `action.notify` | set the field when creating the rule |

If a request spans pillars, do the read-only pillar first (Reporting /
Anomaly / Maps), then propose the write (Alerting), then state the
Notification routing it needs. Never reorder to put a write first.

## 1. Reporting - metrics.py, digest.py

`metrics.py::compute_metrics()` is the single source of dashboard numbers. It
is read-only and stateless over `data/triage_log.jsonl` (plus
`data/feedback_log.jsonl` for the analyst-agreement rate) - it re-reads on
every call, so there is no cache to invalidate. Use it for any "how many / how
often / what broke" question about triage activity. CLI: `python metrics.py`
prints the same dict as JSON.

`digest.py` turns those aggregates into the periodic text report:
`build_digest_text(period)` renders it, `send_digest(period, target=...)`
delivers it through `notify.py`'s webhook. CLI:
`python digest.py --period {daily,weekly,all} [--target '#soc-daily'] [--dry-run]`.

`--dry-run` first. Never send a digest on the first attempt - confirm the text
reads correctly before it goes to a real channel.

Quote the numbers exactly as returned. Do not recompute, round differently, or
re-derive a percentage the module already gave you.

## 2. Alerting - rules.py, staged into local_rules.xml

Rule *definitions* live in `local_rules.xml` on the manager, not in `rules.py`.
`rules.py` is the local saved-rule store (its own `list` / `export` / `import` /
`backtest` CLI) and is what normalises the `action` block.

There is **no tool called `put_rules_file`**. `put_rules_file(filename, content,
overwrite=True)` is a method on the Wazuh manager client
(`tools/api_client.py`) that the rule tools call *internally* to stage a
merged rules file. To change alerting, call the tool that wraps it:

- `create_wazuh_rule(rule_xml, overwrite, reason)` - new rule.
- `update_wazuh_rule(rule_id, rule_xml, reason)` - change an existing one.
- `develop_wazuh_rule(...)` - full workflow: validate, pre-flight, logtest baseline.
- `delete_wazuh_rule` - EXECUTE, not PROPOSE.

Every one of these is a **proposal**, never a direct write: they raise the
approval gate, merge into `local_rules.xml`, and show the operator the exact
diff. Report the proposal id and the diff; do not claim the rule is live.
Loading it needs a manager restart, which is a separate EXECUTE approval.

Rule anatomy and frequency/if_matched_sid constraints are in the
`wazuh-rule-authoring` skill - read it before drafting any XML.

## 3. Anomaly detection - CrowdStrike enrichment, tools/gaps/ for coverage

Two different questions, two different sources. Do not substitute one for the
other.

**"Is this host/process suspicious?"** (enrichment) -
`connectors/crowdstrike_connector.py::CrowdStrikeConnector` wraps the Falcon
API (OAuth2 client-credentials) and returns host info, process tree, and
detection details. It is used by the triage agent during enrichment, and is
**not** an agent tool you can call directly. It also exposes one containment
action, host isolation, which is gated by `DRY_RUN_ACTIONS` - that gate is
deliberate; never work around it or claim an isolation happened.

**"What am I not detecting?"** (coverage) - `analyze_detection_gaps(target,
time_range)`, backed by `tools/gaps/detection_gaps.py`. `target` is
`web | ssh | network` (default `web`), `time_range` defaults to `-7d`. It
returns a 5-state table per category, every number from the real ruleset,
indexer, and archives:

| state | meaning |
|---|---|
| `detected` | rules exist **and** alerts actually fired recently |
| `partial` | rules exist, no alerts, but raw archive activity exists - rule too narrow, wrong group, needs tuning |
| `covered_no_events` | rules exist, no alerts and no archive activity - no such traffic, or event capture is off |
| `gap` | no rules found but raw activity exists - clear gap |
| `unknown` | no rules and no observed activity - cannot tell yet |

Only `gap` and `partial` are actionable findings. Turn those into
`develop_wazuh_rule` proposals. Do not invent a state, and do not present
`covered_no_events` as a gap - it is usually just quiet traffic.

## 4. Maps - investigate engine (geo-IP)

Handles "where are the attacks coming from", attacker-origin and map questions.
Use the investigate engine to get the *IP* picture, then geo-enrich only if the
indexer actually carries geo fields.

1. `top_attacking_ips(group, time_range, size)` - ranks source IPs by alert
   volume with max level, first/last seen, rule groups, top rules, and agents.
2. `investigate_ip(ip, time_range)` - one IP deep-dive: alert volume, rule
   groups/rules fired, destinations and ports, a 3-hourly timeline, and MITRE
   techniques, plus raw sample events from the archives.

Summarise as a ranked table of origin IPs, and describe geography **only** if
geo fields exist.

**There is no geo-IP code in this repo.** No GeoIP lookup, no country/lat/long
resolution - the engine aggregates raw IPs (`data.srcip`, `data.dstip`,
`data.dstport`) and nothing else. A live index can carry `data.src_country` /
`data.src_city` / `data.src_latitude` style fields, but only when the operator
has enabled the Wazuh GeoIP framework and geo-enabled decoders manager-side.
Verify before you rely on them - `get_index_schema` or a `search_wazuh_index`
probe - and if they are absent, say geo enrichment is unavailable and give the
IP distribution. Never guess a country from an IP, and never present a list of
invented coordinates as a map.

## 5. Notifications - notify.py, action.notify

`notify.py` is deliberately one generic webhook, not per-platform
integrations: `send_notification(text, target, extra)` POSTs a Slack-compatible
`{"text": ...}` body to `NOTIFY_WEBHOOK_URL`, which Slack, Mattermost, and most
Teams/Discord generic-webhook connectors accept as-is. Every send is appended to
`data/notifications.jsonl` regardless, so there is a local audit trail even with
no webhook configured.

Per-rule channel routing is the rule's job, not the transport's: set
`action.notify` on the rule. `notify_rule_matches(alert, rule_matches)` fires
**one notification per triggered rule whose `action.notify` is non-empty**, and
includes `action.tag` in the text. An empty or missing `action.notify` means
that rule is deliberately silent.

So whenever you create or update a rule that is meant to reach a human, set
`action.notify` in the rule's `action` block at creation time (with
`action.tag` for routing context). Setting it later is easy to forget, and a
correctly-firing rule that notifies nobody is a silent failure - call this out
explicitly in your summary.

The gate is on the triage path, not the rule: `main.py`, `run.py`, and
`dashboard.py` call `notify_rule_matches`. Creating a rule does not by itself
deliver anything until an alert fires through one of those.

## Rules of engagement

- Propose, never assert. Rule writes, manager restarts, and host isolation are
  approval-gated; report the proposal id and the diff, then wait.
- Numbers come from the module, verbatim.
- The digest/`--dry-run` first, then send.
- `DRY_RUN_ACTIONS` and the approval gate are deliberate. Do not route around
  them to be more helpful.

## Gotchas

- **`--period daily` can report zero activity when alerts really were triaged.**
  Period filtering only counts `triage_log.jsonl` entries carrying a real `ts`;
  today that is only `run.py`'s watch-loop entries - `main.py` and the dashboard
  write on-demand entries without one. Use `--period all` to see everything, and
  say which period you used.
- **A firing rule is not a notifying rule.** `action.notify` empty = silent by
  design.
- **`covered_no_events` is not a gap**, and `unknown` is not a clean bill of
  health - it means the data cannot tell you.
- **No `put_rules_file` tool exists**; use the rule tools that wrap it.
- **No geo-IP support exists**; verify fields before summarising geography.
- Prefer `retrieve_wazuh_docs` to recall the ingested ruleset snapshot
  (fast, offline) before hitting the manager for rule lookups.
