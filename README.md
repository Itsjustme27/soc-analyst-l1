# SOC L1 Triage Agent

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
[![Python 3.11-3.13](https://img.shields.io/badge/Python-3.11_|_3.12_|_3.13-blue.svg)](#setup)
[![CI](https://github.com/sabangiri7/soc-analyst-l1/actions/workflows/ci.yml/badge.svg)](https://github.com/sabangiri7/soc-analyst-l1/actions/workflows/ci.yml)
[![CodeQL](https://github.com/sabangiri7/soc-analyst-l1/actions/workflows/codeql.yml/badge.svg)](https://github.com/sabangiri7/soc-analyst-l1/actions/workflows/codeql.yml)
[![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**An agentic L1 SOC analyst that triages alerts from any major SIEM, enriches with CrowdStrike, cites its reasoning, and learns from analyst corrections — all running on your own machine.**

> **Reuse notice:** this repository is licensed MIT, but the maintainer requires
> **written permission for any reuse** beyond this project (forks, derivatives,
> commercial use). See [License & reuse](#license--reuse) at the bottom.

---

## 🛡️ AI SOC Engineer for Wazuh (agentic detection engineer)

This repo also ships an **AI SOC Engineer** — a conversational detection /
investigation / dashboard engineer for Wazuh built on the same bounded
tool-use loop, driving a typed tool layer behind a
**READ / PROPOSE / EXECUTE** approval model (`agent/soc_engineer.py`,
`tools/registry.py`):

| Prompt | Flow |
|---|---|
| «Investigate the top attacking IPs against my web servers in the last 24 hours» | indexer aggregation → per-IP deep dive → alert explain |
| «Create a Wazuh rule detecting repeated SSH failures» | validate → pre-flight → logtest baseline → **proposal** |
| «Create a dashboard for web server attacks» | indexer schema → panel plan → query verification → **proposal** |
| «Find detection gaps in my web server telemetry» | 5-state coverage table → gap candidates |

**Safety model (enforced in code, not prompts):** READ tools (search, list,
status, logtest, RAG) run immediately. CREATE/MODIFY tools (rules, decoders,
dashboards) only *plan* — the tool raises `ApprovalRequired` and the
validated proposal lands in the dashboard's **Approval Center**
(`GET /api/proposals`). DELETE/RESTART/DISABLE need approval **and** an
explicit confirmation. Approved execution is a deterministic re-run of the
stored payload (no LLM in the execution step) and success is only claimed
when the Wazuh API confirms it. Every tool call is audited to
`data/audit_log.jsonl`, and tool results are wrapped as **UNTRUSTED DATA** —
attacker-controlled log content can never become instructions.

```bash
python dashboard.py                     # open http://127.0.0.1:5001
#   💬 post /api/engineer/chat          # chat with the engineer
#   🛠️ /api/proposals panel            # review + approve + execute proposals
python scripts_engineer_cli.py          # the same engineer, as a terminal agent (REPL)
python scripts_ingest_wazuh_docs.py     # seed the engineering reference (RAG)
python scripts_ingest_wazuh_rules.py    # snapshot the live ruleset into the RAG (READ-only)
```

The engineer can also snapshot the manager's live ruleset into its local RAG
(`ingest_wazuh_rules`, READ-only — pulls and upserts rules into the
`wazuh_docs` collection as `kind=wazuh-rule`, prunes stale ids, and never
modifies the manager), either from the agent itself or as a batch job via
`scripts_ingest_wazuh_rules.py`. See `wazuh_docs/wazuh-rules.md`.

Full reference in [`docs/`](docs/): [`permissions.md`](docs/permissions.md)
(approval model), [`architecture.md`](docs/architecture.md),
[`golden_workflows.md`](docs/golden_workflows.md),
[`approval_center.md`](docs/approval_center.md),
[`rule_engineering.md`](docs/rule_engineering.md),
[`dashboard_engineering.md`](docs/dashboard_engineering.md),
[`detection_gaps.md`](docs/detection_gaps.md),
[`prompt_injection_defense.md`](docs/prompt_injection_defense.md),
[`rag_knowledge_base.md`](docs/rag_knowledge_base.md), the live
validation report [`phase14-validation.md`](docs/phase14-validation.md), and
the terminal-agent handbook [`wazuh_docs/cli.md`](wazuh_docs/cli.md).

---

## Run the engineer as a terminal agent (CLI)

The same SOC Engineer is available as a terminal agent — **one agent, two
faces**: the dashboard chat + Approval Center, and `scripts_engineer_cli.py`,
which reuses the exact bounded tool-use loop, the READ / PROPOSE / EXECUTE
gate, the approvals store, and the audit trail:

```bash
python scripts_engineer_cli.py                          # interactive REPL (/help)
python scripts_engineer_cli.py -m "analyze rule 100001" # one-shot
python scripts_engineer_cli.py -m "…" --json            # machine-readable JSON
python scripts_engineer_cli.py --session ssh --resume   # persisted, resumable sessions
```

Everything runs from the terminal:

- **Skills** — activate packs with `--with-skill <name>` or `/use <name>`;
  install a pack folder like a coding agent (`--add-skill /path`,
  `/add-skill <path>`); scaffold a starter template (`--new-skill <name>`);
  or turn on contextual auto-activation (`--auto-skills`,
  `/auto-skills on|off`) and the CLI pulls up to 3 relevant skills per turn by
  keyword match. Skills are markdown packs in `skills/` injected into the
  system prompt inside `<SKILL role='instruction'>` markers — trusted operator
  instructions, never sourced from Wazuh data.
- **Approvals** — full in-terminal parity with the dashboard's Approval
  Center: `/proposals`, `/proposals <id>` (diff + validation evidence),
  `/approve <id>`, `/reject <id> [reason]`, `/execute <id> --confirm` (for
  EXECUTE-level), plus a `N approval(s) pending` banner after every turn. The
  terminal identifies you as the local operator (`--user`, with
  `identity_verified=False`); use the dashboard center for token-verified
  remote approvers.
- **Ops** — `/status` shows live manager daemon status, `/audit` tails the
  audit log, and `--list-skills` / `--list-proposals` / `--list-sessions`
  give quick machine-readable views.

Exit codes: `0` ok, `1` usage/data error, `2` LLM outage or tool-budget
exhaustion (JSON mode still emits a payload so pipelines can tell them apart).
Full reference: `wazuh_docs/cli.md`.

---

## What it does

Point it at alerts from **Splunk, IBM QRadar, Elastic Security, Microsoft Sentinel, Wazuh, or a mock**. The agent:

1. **Retrieves** your playbooks and past cases from a local RAG store (ChromaDB).
2. **Enriches** with SIEM correlation and CrowdStrike host/process/detection data.
3. **Produces a structured verdict** — verdict, confidence, recommended action, rationale, and cited evidence.
4. **Logs everything** to `data/triage_log.jsonl` for audit.
5. **Improves over time** through a human-gated feedback loop that turns analyst corrections into permanent memory.

Only outbound calls are to your chosen LLM API (Anthropic / OpenAI-compatible / Google / FreeLLMAPI), your SIEM(s), your CrowdStrike tenant, and a one-time small embedding-model download for the local RAG store. See [Offline/air-gapped RAG](#offlineair-gapped-rag) if even that isn't an option. A small web dashboard (`dashboard.py`) lets you connect to and manage multiple SIEM providers at once; its Metrics panel loads Chart.js from a CDN (`cdnjs.cloudflare.com`), the one part of the dashboard itself that isn't fully self-contained.

---

## Architecture

```
Alert from any SIEM ──▶ TriageAgent (Claude, tool-use loop)
                         │
         ┌───────────────┼────────────────────┐
         ▼               ▼                    ▼
    RAG retrieval   Enrichment tools     submit_verdict
    (playbooks,     (SIEM correlation,   (structured JSON:
    cases, lessons)  CrowdStrike host/    verdict, confidence,
    ChromaDB, local  process/detection)   action, rationale,
                                          evidence cited)
                         │
                         ▼
               data/triage_log.jsonl (audit trail)
                         │
                         ▼
               feedback_cli.py review   ◀── analyst confirms/corrects
                         │
                         ▼
               MemoryStore.capture_feedback
                  - logs raw feedback
                  - stores closed case → RAG 'cases' collection (immediate)
                         │
                         ▼ (batch, e.g. nightly)
               feedback_cli.py distill
                  - Claude looks for recurring patterns in corrections
                  - proposes "lessons"
                  - YOU approve each one  ◀── human checkpoint
                         │
                         ▼
               RAG 'lessons' collection
               (retrieved by the agent on future triage)
```

### Why the self-improvement loop is split in two

Writing memory **live**, in the same loop that's making decisions, lets one noisy or wrong correction immediately corrupt future triage. Batching corrections and requiring a human to approve each distilled "lesson" before it goes live is the checkpoint that catches that before it does damage.

---

## ⚠️ Guardrails — read before pointing this at production

| Guardrail | Detail |
|---|---|
| **The agent never executes containment actions.** | `isolate_host` and similar always go through `DRY_RUN_ACTIONS=true` by default. The agent can only *recommend* isolation/account-disable, logged for a human to execute manually. Only flip this once you trust the agent's precision on your environment — and even then, start with reversible actions. |
| **Low-confidence and destructive-action verdicts always route to a human.** | See the `needs_human_review` logic in `main.py`. Don't remove this without a lot of production data behind you. |
| **Full audit trail.** | Every tool call and result is logged with each case in `data/triage_log.jsonl`, tied to the alert ID. |
| **Self-improvement never writes to memory unattended.** | `distill_lessons` only *proposes*; a human approves via `feedback_cli.py distill`. |

---

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env
```

### 1. Try it in mock mode first (no real Splunk/CrowdStrike needed)

Edit `.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...   # required, real key
MOCK_MODE=true
```

Ingest the seed playbooks into the local RAG store (one-time; downloads a small local embedding model on first run — see [Offline/air-gapped RAG](#offlineair-gapped-rag) if that download isn't possible):

```bash
python scripts_ingest_seed.py
```

Run the agent against the three sample alerts in `seed_data/mock_alerts.json`:

```bash
python main.py demo
```

You'll see each alert triaged with a verdict, confidence, recommended action, and cited rationale, logged to `data/triage_log.jsonl`.

### No API key yet? Use the offline **mock** provider

The LLM backend is pluggable (see [LLM providers](#llm-providers-bring-your-own) below). For a fully-offline demo with no API key at all, use the deterministic mock LLM (dev/CI/reference example):

```bash
python main.py demo --provider mock
# or set LLM_PROVIDER=mock in .env
```

It drives the real agent loop — RAG retrieval → enrichment → structured verdict → audit log — with scripted reasoning per alert type, so you can exercise the whole architecture before wiring credentials.

---

## LLM providers (bring your own)

The triage reasoning runs on a pluggable LLM layer in `llm/`:

| `LLM_PROVIDER` | Backend | Env vars |
|---|---|---|
| `anthropic` *(default)* | Claude | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` |
| `openai` | Any OpenAI-compatible `/chat/completions` endpoint: OpenAI, OpenRouter, Ollama, vLLM, LM Studio, DeepSeek, … | `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENAI_MODEL` |
| `google` | Gemini | `GOOGLE_API_KEY`, `GOOGLE_MODEL` |
| `freellmapi` | FreeLLMAPI gateway — one unified key for dozens of free LLM providers (https://freellmapi.co) | `FREELLMAPI_API_KEY`, `FREELLMAPI_BASE_URL`, `FREELLMAPI_MODEL` |
| `mock` | Deterministic offline script (no key) | — |

Any `*_MODEL` you leave unset falls back to `AGENT_MODEL`. You can override the provider per run without touching `.env`:

```bash
python main.py demo --provider openai
python feedback_cli.py distill                 # uses LLM_PROVIDER from .env
```

**Using FreeLLMAPI's unified key:** run the FreeLLMAPI gateway (self-hosted, defaults to `http://localhost:3001/v1`), paste your provider keys into its dashboard once, copy your unified `freellmapi-...` key, then:

```env
LLM_PROVIDER=freellmapi
FREELLMAPI_API_KEY=freellmapi-your-unified-key
# FREELLMAPI_BASE_URL=http://localhost:3001/v1   (default)
# FREELLMAPI_MODEL=auto                           (default - the gateway routes)
```

`model: "auto"` lets the gateway pick the best available model and fail over across providers automatically. Tool calling (used by the triage loop) is supported over the same OpenAI-compatible surface, and each response's `X-Routed-Via` header is printed so you can see which upstream actually served the call.

**Adding a new LLM provider:** implement `llm/base.LLMProvider` (one method — `chat(system, messages, tools, max_tokens)` returning `LLMResponse` with `content` + `tool_calls`), then register it in `_PROVIDERS` in `llm/__init__.py`. Tool definitions are in one canonical shape (`{name, description, input_schema}`); each provider translates that and the normalized message format (see `llm/base.py` docstring) to its own wire format. `llm/mock_provider.py` is the smallest working example; `llm/freellmapi_provider.py` is the smallest useful one (subclass of the OpenAI-compatible provider).

---

## 2. Review and correct verdicts (closes the feedback loop)

```bash
python feedback_cli.py review
python feedback_cli.py review --analyst jsmith    # or set ANALYST_NAME in .env
```

Walks through cases flagged `needs_human_review`, asks you to confirm or correct each verdict. Every response is immediately stored into the RAG `cases` collection, so a near-identical future alert can retrieve it.

`--analyst` (or the `ANALYST_NAME` env var, or an interactive prompt if neither is set) tags every correction with who made it — this is a single free-text name recorded in `data/feedback_log.jsonl`, not an account system (see [Dashboard auth](#dashboard-auth) for why this project doesn't do full multi-user auth). `metrics.py`'s `analyst_agreement` breaks agreement rate down per analyst once more than one has reviewed cases.

## 3. Distill lessons from accumulated corrections (run periodically)

```bash
python feedback_cli.py distill
python feedback_cli.py distill --analyst jsmith
```

Looks for recurring patterns across your corrections (needs a handful of disagreements to find something generalizable — this won't produce much after only 2–3 reviews). Proposes short "lessons"; **you approve each one** before it's written to memory. `--analyst` records who approved it in the lesson's `approved_by` metadata.

## 4. Go live against your SIEM(s) + CrowdStrike

Fill in the rest of `.env`, pick your default SIEM platform with `SIEM_PROVIDER` (`splunk | qradar | elastic | sentinel | wazuh | mock`), and set the matching credentials:

```env
MOCK_MODE=false
SIEM_PROVIDER=splunk
SPLUNK_HOST=https://splunk.yourcorp.local:8089
SPLUNK_TOKEN=...
SPLUNK_SEARCH=search index=notable status=new | head 20
FALCON_CLIENT_ID=...
FALCON_CLIENT_SECRET=...
```

```bash
python main.py live
```

Point this at a cron/scheduler to run periodically. **Keep `DRY_RUN_ACTIONS=true`** until you've reviewed enough cases to trust the agent's precision on your specific environment.

## 5. Connect multiple SIEMs with the dashboard

`dashboard.py` is a small web UI for managing SIEM connections — add any number of providers across platforms, test them, pull their alerts, and run the triage agent on them:

```bash
pip install -r requirements.txt   # includes flask
python dashboard.py                # open http://127.0.0.1:5001
```

From the dashboard you can:

- **Signal-room console UI** — a single self-contained page
  (`templates/index.html`: warm monochrome palette, Geist + JetBrains Mono,
  1px hairlines, pastel severity badges, no emojis/gradients) with the
  engineer chat, Approval Center, and every panel below.
- **Add a provider** — name + platform (Splunk / IBM QRadar / Elastic Security / Microsoft Sentinel / Wazuh / Mock) + connection details. Stored in `data/siem_providers.json`; env-seeded connections (from `.env`) are always listed too and can't be accidentally deleted.
- **Test** — lightweight reachability + auth check per connection.
- **Alerts** — pull the latest alerts from any provider (normalized to the same shape the agent expects).
- **Run triage** — triage that provider's newest alerts with the agent; each verdict is written to `data/triage_log.jsonl` tagged with the provider.

To run the agent against a specific connection from the CLI:

```bash
python main.py live --siem env-qradar        # a dashboard/env provider id
python main.py live --siem wazuh             # any platform (uses its .env creds)
```

Wazuh ships as a ready-made docker-compose stack in `wazuh/` (manager + indexer + dashboard, official 6.0.0 images) — see `wazuh/README.md`. Once it's up, point the wazuh provider at the indexer (`WAZUH_HOST=https://localhost:9200`, default `admin/admin`) and the agent reads alerts straight from the `wazuh-alerts-*` index.

See `connectors/siem/` for how a new platform plugs in (Splunk, QRadar, Elastic, Sentinel, and Wazuh are implemented; each is just a class implementing `SIEMConnector`).

---

## Stay on it through the night: `run.py`

`run.py` is the single entrypoint that runs the actual SOC analyst against your live Wazuh stack in a long-running watch loop — exactly the process you leave running overnight from the dashboard and shut off from the dashboard when you're done:

```bash
python run.py                       # watch mode - polls SIEM on an interval
python run.py --interval 120        # tune the poll cadence (seconds)
python run.py --exit-after 50       # stop cleanly after 50 poll cycles
python run.py --siem wazuh          # pin which dashboard provider to watch
python run.py --provider mock       # offline LLM for dev/CI (no key)
```

- **Graceful shutdown** — `Ctrl+C`, `SIGTERM`, the dashboard's *Stop agent* button, or creating the stop file (`data/agent_stop.txt`). All exit `0` so cron/systemd see a clean stop.
- **Heartbeat** — each cycle appends to `data/agent_heartbeat.json` with `status` / `cycle` / last-triggered alert id and timestamp, so the dashboard shows "running / last seen Ns ago" without you SSH'ing in.
- **Audit trail** — every verdict is appended to `data/triage_log.jsonl` (same JSONL the dashboard history panel reads).
- **Resilient** — a single bad alert never kills the watch; the SIEM pull and the per-alert triage are each wrapped so one failure logs and continues.

---

## Chat with the agent (conversational SOC assistant)

The dashboard has a chat panel backed by `agent/chat_agent.py` — same bounded tool-use loop as triage, but conversational. Ask it things like:

> «what's the status of alert SPLK-10231?»   *(get_alert_status)*
> «show me jsmith's recent events»            *(get_user_details / search_related_events)*
> «add 185.220.101.7 to the watchlist»        *(R/W lookup tables)*
> «close SPLK-10245 as a false positive»      *(R/W alerts via close_notable)*
> «list my SIEM providers / add Splunk»       *(R/W dashboard providers)*
> «what do we know about the MOB malware?»    *(web search / OSINT)*
> «what's 8.8.8.8's reputation?»              *(web search)*

It reads/writes the same stores the dashboard manages (alerts, providers, lookup tables) and writes the full transcript to `data/chat_log.jsonl` for the audit trail. You can also run it as a REPL:

```bash
python run.py chat      # or: python -c "from agent.chat_agent import ChatAgent; ..."
```

---

## Lookup tables (R/W, JSON-backed)

`lookup_tables.py` gives you persistent allowlists / watchlists / threat-intel stores, editable from the dashboard and from the chat agent:

- `list/read/create/upsert/delete_lookup_table`, `upsert_lookup_entry`, `search_lookup`. Tables live in `data/lookup_tables.json` (gitignored).

## Alert rules (local correlation, before the LLM ever sees the alert)

`rules.py` gives you **deterministic, zero-cost pre-filtering/correlation** evaluated against every alert right after it's pulled from the SIEM and before `TriageAgent` spends any tool calls on it — the same role a SIEM's own correlation search plays, but running locally so it never depends on LLM availability.

A rule is a condition tree (`field/op/value`, combined `all`/`any`) plus an optional threshold (e.g. "5 matching alerts for the same `src_ip` within 15 minutes", counted in `data/rule_state.json` across polls) and an action (`tag`, `escalate`, `notify`). Conditions can reference a lookup table via `op: "in_lookup"`, so watchlists you build from the dashboard/chat agent feed straight into rules. A triggered rule with `escalate: true` forces `needs_human_review`, same as a low-confidence LLM verdict — see the `rule_matches` field `main.py` / `run.py` / the dashboard's triage route all now write into `data/triage_log.jsonl`.

CRUD: `list/read/create/update/delete_rule`; evaluate with `evaluate_all` (persists threshold state) or `evaluate_rule(..., dry_run=True)` (doesn't — used by the dashboard's "test rule" action). Manage rules from the dashboard's 🧩 **Alert Rules** panel, or directly against `data/rules.json`.

### Rule import/export

Share a baseline rule set across environments the same way `seed_data/playbooks/` shares SOPs — `seed_data/rules/baseline_rules.json` is a starter set:

```bash
python rules.py export --out my-rules.json     # portable JSON - no id/created/updated
python rules.py import seed_data/rules/baseline_rules.json
python rules.py import my-rules.json --overwrite   # update existing rules with matching names in place
```

Rules match across an import **by name** (ids won't line up between environments); by default a name collision is skipped, leaving the existing rule untouched — pass `--overwrite` to update it in place instead. The dashboard's 🧩 Alert Rules panel has matching **Export all as JSON** / **Import from file…** buttons (`GET /api/rules/export`, `POST /api/rules/import`).

### Rule backtesting

Before enabling a rule live, see how often it would have fired historically:

```bash
python rules.py list
python rules.py backtest rule-3c42ccde06 --limit 200
```

`rules.backtest_rule()` dry-runs the rule against `data/triage_log.jsonl` — it **never touches the real threshold-window state**, so trying a rule out doesn't perturb its actual counters. Only `run.py`'s watch-loop entries carry a real timestamp (`"ts"`); `main.py` / the dashboard's on-demand entries don't, so threshold windows during a backtest fall back to treating consecutive matched alerts as one second apart where no `"ts"` is available — enough to see the rough shape ("this would have fired ~14 times"), not to reproduce exact historical timing. The dashboard's 🧩 Alert Rules panel has a **Backtest** button per rule that calls the same thing via `POST /api/rules/<id>/backtest`.

## Notifications (`rules.py` `action.notify`)

`notify.py` fires when a triggered rule's `action.notify` field (see [Alert rules](#alert-rules-local-correlation-before-the-llm-ever-sees-the-alert) above) is set to something non-empty. It POSTs a Slack-incoming-webhook-compatible `{"text": "..."}` body to `NOTIFY_WEBHOOK_URL` (works as-is for Slack, Mattermost, and most "generic webhook" Teams/Discord connectors); with no webhook configured it still logs every notification locally to `data/notifications.jsonl`, so there's an audit trail from day one. A broken or unreachable webhook never blocks or kills a triage run — `send_notification()` catches its own errors and always returns a result dict rather than raising.

## Case/incident grouping

`cases.py` clusters alerts from `data/triage_log.jsonl` by shared host or user within a time window (default 30 minutes), so a flurry of related alerts shows up as **one case** instead of unconnected rows. Two alerts link when they share a non-empty host **OR** user (not necessarily both) and fall within the window; a chain (A-B share a host, B-C share a user) merges into one case via union-find even when A and C share nothing directly. Read-only like `metrics.py` — this is just a different view over the same log, nothing is written.

```bash
python cases.py                                 # default 30-minute window
python cases.py --window-minutes 60 --min-alerts 2   # only show actual clusters
```

The dashboard's 🗂️ **Cases** panel calls the same thing via `GET /api/cases` (query params: `window_minutes`, `limit`, `min_alerts`) — it's on-demand (click *Load cases*) rather than loading automatically, since grouping is O(n²) over however many log entries you scan.

## Metrics

`GET /api/metrics` (`metrics.py`) aggregates `data/triage_log.jsonl` into:

- verdict counts by day
- a confidence-score histogram
- the overall `needs_human_review` rate
- alert volume and needs-review rate per SIEM provider
- which rules trigger most often alongside their true-positive rate (how often a rule's trigger actually lined up with a `true_positive` verdict)
- and, once you've run `feedback_cli.py review` a few times, the analyst-agreement rate from `data/feedback_log.jsonl`

Nothing here is cached or persisted; it's always a live read of the current logs. The dashboard's 📊 **Metrics** panel renders this with Chart.js.

## Scheduled digest reports

`digest.py` builds a periodic summary from `metrics.py`'s aggregates (verdict totals, needs-review rate, top triggered rules, per-provider breakdown, and notable host/user clusters from `cases.py`) and sends it through `notify.py`'s webhook — point cron/a scheduler at it:

```bash
python digest.py --period daily --dry-run          # print without sending
python digest.py --period daily --target "#soc-daily"
python digest.py --period weekly
```

Like the rest of the timestamp-dependent tooling in this project (`cases.py`, `rules.py`'s backtest, `metrics.py`), period filtering (`daily`/`weekly`) only counts log entries that carry a real `"ts"` field — today, only `run.py`'s watch-loop entries do. If you're only running `main.py` / the dashboard's on-demand triage, use `--period all` to see everything regardless of timestamp; the digest text says so explicitly when a period comes back empty for this reason.

## Log rotation

`triage_log.jsonl`, `chat_log.jsonl`, `notifications.jsonl`, and `feedback_log.jsonl` are all append-only and grow forever otherwise — none of the writers rotate on their own. Run this periodically (cron, or by hand):

```bash
python log_rotation.py                                    # default: rotate anything >100MB or >30 days old
python log_rotation.py --max-bytes 50000000 --max-age-days 14
python log_rotation.py --prune-archives-older-than-days 365  # also delete old .jsonl.gz archives
```

A rotated log is gzip-compressed to `data/archive/<name>.jsonl.gz` and the original file is truncated to empty (not deleted — every writer assumes the file exists). Pruning archives is opt-in and separate from rotation itself — nothing is ever deleted unless you ask for it.

## Offline/air-gapped RAG

By default `rag/knowledge_base.py` downloads a small sentence-transformer model the first time it's used (needs internet; everything after that is fully offline). If that download isn't an option — air-gapped deployment, locked-down CI, no network at all — set:

```env
KB_EMBEDDING_MODE=hashing
```

This switches to a deterministic, dependency-free bag-of-words embedding (`rag/embeddings.py`) — no download, no model file, no network, ever. Retrieval quality is **noticeably worse** (it only picks up literal shared words between texts, with no notion of meaning), so use it only when you can't use the default. `MOCK_MODE=true` selects this automatically, which is how the test suite exercises the full `TriageAgent` tool-use loop (playbook retrieval included) without needing network access.

A Chroma collection's embedding function is fixed at creation time in its on-disk data; if `CHROMA_DB_PATH` already has data created under a different mode, `KnowledgeBase` falls back to whatever's actually persisted there rather than erroring, so flipping `MOCK_MODE` on an existing data directory degrades gracefully instead of crashing.

## Web search (OSINT, no API key required)

The `web_search` tool queries DuckDuckGo instant-answer first, falls back to SearXNG (`SEARXNG_URL`), and returns a graceful offline result when neither is reachable — no API key, never blocks triage. Set `WEB_SEARCH_ENABLED=false` to disable entirely.

## LLM resilience: retry with backoff

Every LLM provider (`llm/openai_compat_provider.py` and everything that subclasses it, incl. FreeLLMAPI) retries transient `429` / `5xx` / network failures with exponential backoff + jitter instead of aborting a whole batch — so a free-gateway rate limit never kills your overnight run:

```env
LLM_MAX_RETRIES=5            # attempts after the first (0 disables retry)
LLM_RETRY_BACKOFF_BASE=1.5   # backoff multiplier between attempts
LLM_RETRY_BACKOFF_MAX=30     # cap on each backoff step (seconds)
```

---

## File guide

| File | Purpose |
|---|---|
| `agent/triage_agent.py` | Core tool-use loop — the actual triage reasoning |
| `agent/memory.py` | Feedback capture + lesson distillation (self-improvement) |
| `rag/knowledge_base.py` | ChromaDB wrapper: playbooks / cases / lessons / wazuh_docs collections |
| `connectors/siem/` | Pluggable SIEM layer: `base.py` (interface) + splunk / qradar / elastic / sentinel / wazuh / mock providers, selected by `SIEM_PROVIDER` |
| `wazuh/` | Docker-compose Wazuh 6.0 stack (manager + indexer + dashboard) the wazuh connector reads from |
| `connectors/crowdstrike_connector.py` | Real CrowdStrike Falcon API calls (EDR enrichment, independent of which SIEM feeds alerts) |
| `connectors/mock_connectors.py` | Canned responses for `MOCK_MODE=true` testing |
| `siem_providers.py` | JSON-backed store of SIEM provider connections; merges env-seeded + dashboard-added providers |
| `rules.py` | Local alert-rules engine: condition/threshold evaluation + CRUD + backtesting, backed by `data/rules.json` and `data/rule_state.json` |
| `notify.py` | Outbound webhook notifications for `rules.py` `action.notify`, logged to `data/notifications.jsonl` regardless of whether a webhook is configured |
| `metrics.py` | Read-only aggregate metrics over `data/triage_log.jsonl` (+ analyst agreement from `data/feedback_log.jsonl`) for the dashboard's Metrics panel |
| `cases.py` | Read-only clustering of `data/triage_log.jsonl` alerts by shared host/user within a time window, for the dashboard's Cases panel |
| `digest.py` | Periodic summary (built from `metrics.py`/`cases.py`) sent via `notify.py` — the piece a scheduler/cron calls |
| `log_rotation.py` | Size/age-based rotation + gzip archiving for the project's JSONL logs (triage_log, chat_log, notifications, feedback_log) |
| `rag/embeddings.py` | Deterministic offline embedding fallback (`KB_EMBEDDING_MODE=hashing`) for `rag/knowledge_base.py` — no download, no network |
| `dashboard.py` | Flask dashboard — add/test/review multiple SIEM connections, view alerts, run triage |
| `templates/index.html` | Dashboard UI (single self-contained page) |
| `llm/` | Pluggable LLM backend: `base.py` (interface) + anthropic / openai-compatible / google / freellmapi / mock providers, selected by `LLM_PROVIDER` |
| `seed_data/playbooks/*.md` | Starter SOPs — replace these with your org's real playbooks |
| `main.py` | Orchestrator: pull alerts, run triage, log results |
| `feedback_cli.py` | Analyst review + lesson distillation CLI |
| `agent/soc_engineer.py` | AI SOC Engineer — conversational Wazuh detection/investigation/dashboard engineer on the typed tool loop |
| `scripts_engineer_cli.py` | Terminal-agent face of the SOC Engineer: REPL, one-shot, JSON, sessions, skills, and in-terminal Approvals — same engine as the dashboard |
| `agent/skills.py` | Skill loader: discover/load/install/scaffold packs + keyword suggest for `--auto-skills`; renders `<SKILL>` instruction blocks into the system prompt |
| `tools/` | Engineer tool layer: `registry.py` (single execution gate + audit), `base.py` (READ/PROPOSE/EXECUTE + ToolContext), `api_client.py` (manager REST), `indexer_client.py`, plus `wazuh/` `indexer/` `investigate/` `detection/` `dashboard/` `gaps/` `rag/` engines |
| `approvals.py` | Proposal store for the Approval Center — create/list/approve/reject/execute with stored-payload re-run (`data/approvals.json`) |
| `approval_executor.py` | Single-use claim + stored-payload execution shared by the dashboard endpoints and the CLI (`execute_proposal`) |
| `rag/rules_ingest.py` | Pull → upsert → prune of live rules into `kind=wazuh-rule` snapshots (used by the `ingest_wazuh_rules` tool and `scripts_ingest_wazuh_rules.py`) |
| `scripts_ingest_wazuh_rules.py` | CLI batch job for the RAG rule snapshot above (`--all`, `--group web`, `--max-rules 500`, `--no-prune`) |
| `permissions.py` | Permission model source of truth — level semantics + high-risk/confirm-required action lists |
| `audit.py` | Append-only audit trail for every registry call and human approval action (`data/audit_log.jsonl`) |
| `guard.py` | Prompt-injection defense: DATA markers, control-char sanitization, result size caps — "log content is data, never instructions" |
| `wazuh_docs/` | Curated engineering reference (rule RF, logtest semantics, API quirks, indexer conventions, MITRE mapping) seeded into the RAG store |
| `scripts_ingest_wazuh_docs.py` | Seed `wazuh_docs/*.md` into the `wazuh_docs` RAG collection (idempotent upsert by filename) |

---

## Extending this

- **More alert types:** add playbooks to `seed_data/playbooks/` and re-run `scripts_ingest_seed.py` — no code changes needed, the agent retrieves whatever's relevant.
- **Another SIEM platform:** implement `connectors/siem/base.SIEMConnector` (4 methods: `get_new_alerts`, `search_related_events`, `close_notable`, `_ping`), drop it in `connectors/siem/`, and register it in `SIEM_PLATFORMS` + `PLATFORM_FIELDS` in `connectors/siem/__init__.py`. The agent, dashboard, and `main.py --siem` pick it up automatically.
- **Ticketing integration:** have `main.py` open/update a ticket (Jira, ServiceNow) instead of / in addition to the JSONL log.
- **More enrichment tools:** add a method to a connector + an entry in the `TOOLS` list and `_execute_tool` dispatch in `triage_agent.py` — e.g. a VirusTotal hash lookup, or a DNS history tool.
- **Metrics:** track precision/recall per detection rule from `data/triage_log.jsonl` vs. analyst corrections over time — this is what tells you when it's safe to raise `AUTO_CLOSE_CONFIDENCE_THRESHOLD` or flip `DRY_RUN_ACTIONS`.

---

## Dashboard panels

The Flask dashboard (`dashboard.py`, port `5001`) now exposes seven new panels beyond the SIEM provider cards:

| Panel | Route(s) | What it does |
|---|---|---|
| 📊 **Metrics** | `GET /api/metrics` | Verdict counts by day, a confidence histogram, needs-review rate overall and per provider, and top triggered rules with their true-positive rate, rendered with Chart.js. See [Metrics](#metrics). |
| 🗂️ **Cases** | `GET /api/cases` | Alerts clustered by shared host/user within a time window, on-demand. See [Case/incident grouping](#caseincident-grouping). |
| 💬 **SOC Chat Assistant** | `POST /api/chat`, `GET /api/chat/history` | A conversational L1 analyst that can answer questions about alerts, look up user/host enrichment, manage lookup tables, and optionally connect to a SIEM for live alert context. Every exchange is appended to `data/chat_log.jsonl` for audit. |
| 📋 **Lookup Tables** | `GET/POST /api/lookup-tables`, `GET/DELETE /api/lookup-tables/<id>`, `POST/DELETE /api/lookup-tables/<id>/entries/<key>` | Full CRUD for threat-intel / watchlist stores backed by `data/lookup_tables.json`. The chat agent calls these same primitives via its `write_lookup_table` tool. |
| 🧩 **Alert Rules** | `GET/POST /api/rules`, `GET/PATCH/DELETE /api/rules/<id>`, `POST /api/rules/<id>/test`, `POST /api/rules/<id>/backtest`, `POST /api/rules/preview`, `GET/POST /api/rules/export\|import`, `GET /api/rules/ops` | A rule builder (condition rows + optional threshold/grouping + tag/escalate/notify action) backed by `data/rules.json`, with dry-run "test against a sample alert", "backtest against history", and JSON export/import actions. Test/backtest never touch the real threshold counters in `data/rule_state.json`. Rules run automatically before every triage — see [Alert rules](#alert-rules-local-correlation-before-the-llm-ever-sees-the-alert). |
| 🤖 **Overnight Watcher** | `GET/POST /api/agent`, `POST /api/agent/start\|stop` | Controls `run.py`'s overnight triage loop. Start spawns `python run.py` in a detached session and writes an initial heartbeat; stop writes the stop-file kill switch (`data/agent_stop.txt`) and best-effort SIGTERMs the watcher PID. Status reports running/stopped, last heartbeat age, current cycle count, and whether the stop file is present. Poll every 2–5 s from the UI. |
| 🛠️ **AI Engineer + Approval Center** | `POST /api/engineer/chat`, `GET /api/proposals`, `POST /api/proposals/<id>/approve\|reject\|execute` | Chat with the AI SOC Engineer (Wazuh detection/investigation/dashboard work). Every rule/dashboard/delete/restart proposal is persisted in `data/approvals.json` and listed here — review the generated config + validation evidence, then approve, reject, or execute. EXECUTE-level proposals (delete/restart/disable) require an explicit confirmation checkbox alongside approval. Human actions are audited with `permission="human"`. The **same proposals are operable from the terminal agent** (`scripts_engineer_cli.py`: `/proposals`, `/approve`, `/reject`, `/execute`). |

---

## Dashboard auth

Every route above is **open by default** (fine for strictly local use on `127.0.0.1`). Set `DASHBOARD_TOKEN` in `.env` **before binding `--host` to anything else** — every route (including ones that write to the SIEM, start/stop the overnight watcher, and CRUD lookup tables/rules) is otherwise unauthenticated. With a token set, open the dashboard once as `http://<host>:5001/?token=<token>`; the page reads it off the URL, stores it in `sessionStorage`, strips it from the address bar, and attaches it as `Authorization: Bearer` on every API call from then on. The token is also accepted directly as `?token=...` on any API request (e.g. for `curl`).

### `DASHBOARD_USERS` — verified identities, separation of duties, and roles

`DASHBOARD_USERS="user:token[:role],..."` maps a Bearer token to a **verified** identity. The Approval Center then ignores any client-supplied `by` field and blocks a proposer from approving their own proposal.

Each entry takes an optional third field, the **role**:

| Role | Can do |
|---|---|
| `viewer` | read-only |
| `approver` | reads + the Approval Center (`approve`/`reject`/`cancel`/`execute`) + `POST /api/engineer/tool` |
| `admin` | everything, incl. rules / lookup-table / provider CRUD and watcher start/stop/kill |

An entry **without** a role is an `admin`, so pre-existing configs keep exactly the access they had. An unrecognised role name also falls back to `admin` rather than silently locking someone out.

```bash
DASHBOARD_USERS=alice:tok_alice:admin,bob:tok_bob:approver,carol:tok_carol:viewer
```

Roles only bite once auth is configured. With auth **off** (the default) every request is a local-trust `admin` identity — the Approval Center works out of the box and approvals are recorded with `"verified": false`. That is deliberate and matches `scripts_engineer_cli.py`, which calls `approvals.approve()` with no token at all; separation of duties switches on the moment `DASHBOARD_USERS` is set.

### Withdrawing an approval: `POST /api/proposals/<id>/cancel`

`reject` only works on `pending`. That used to leave an **approved** proposal as a permanent executable grant — the only exit from `approved` was execution — so a reviewer could not take back a yes when the payload was wrong, a newer proposal superseded it, or it was simply abandoned.

`cancel` withdraws a `pending` **or** `approved` proposal and records who/when/why. It refuses terminal states (`executed`, `failed`, `expired`, `rejected`, `cancelled`) — history is not rewritten — and refuses `executing`, so it can never race the executor. Once cancelled the proposal can no longer be approved or claimed.

### Which routes can reach Wazuh or a SIEM

Only `POST /api/proposals/<id>/execute` does, via the permission-gated tools in `tools/` — `local_rules.xml` is written exclusively through `put_rules_file`, which no HTTP route calls directly. The dashboard's CRUD routes manage purely local app config and cannot bypass that gate:

- `/api/rules` + `/api/rules/import` → `data/rules.json`, the pre-triage filter store (`rules.py` imports nothing but stdlib + config)
- `/api/lookup-tables` → `data/lookup_tables.json`
- `/api/providers` → `data/siem_providers.json`

All of them are role-gated and now write to the audit log (`tool="dashboard_ui"`), so a rule edited straight through the UI shows up in `/api/audit` instead of vanishing.

## Verifying a deployed Wazuh rule — and the logtest trap

`verify_rule_deployment` logtests your positive/negative samples. It works for ordinary rules, but **it cannot confirm or refute a frequency/timeframe correlation rule**, and the tool now says so instead of guessing.

`logtest` is a per-event decoder + rule tester. It holds no frequency counter: the `frequency`/`timeframe` state lives in analysisd's live event pipeline. Measured on a live 4.x manager — 8 repeated `Failed password` events pushed through a *single* logtest session never tripped a `frequency="5"` rule, while the live engine would have. So for a correlation rule the result is:

```json
{ "verified": null, "verification": "inconclusive",
  "frequency_rule_unverifiable_via_logtest": true,
  "negative_pass": "4/4" }
```

`verified` is `null`, **not** `false` — unknown, not disproven. Reading that as a failure is how you end up deleting a working rule. What logtest *does* still prove for a correlation rule is real signal:

- the **parent** rules fire (e.g. `5710`/`5760` for SSH auth failures), which proves decoding and the `if_matched_sid` wiring;
- the **negatives** stay silent, which proves the rule is not over-matching.

To confirm the correlation itself, push real events through analysisd (agent or syslog input) and read the alert stream, or check the rule is loaded and enabled with `GET /rules/<id>` and trust the live engine.

Two related gotchas this toolchain hit for real:

- **`<if_matched_sid>` and `<same_source_ip/>` must be child elements** on a Wazuh 4.x build. The attribute form (`if_matched_sid="5710,5760" same_source_ip="yes"`) is rejected by the manager with `1113: XML syntax error`.
- **Wazuh already ships an SSH brute-force rule.** `5763` (*"sshd: brute force trying to get access to the system"*) fires on repeated `Failed password` from one source IP. A custom rule is a deliberate threshold/scope choice and will overlap with it — check the stock rule before tuning your own, and expect duplicate alerts if both match.

## License & reuse

The repository is licensed under the **MIT License** (see `LICENSE`). **In
addition** to the MIT terms, the maintainer requires **written permission
for any reuse** of this code:

- public forks published outside this project,
- derivative products or services built on it,
- inclusion in other repositories or commercial offerings.

If you want to build on this code, contact the maintainer first (open an
issue or reach out directly). Unapproved reuse will be treated as a
violation of this policy. Contributing back fixes or improvements to this
repository is always welcome — see `CONTRIBUTING.md`.

## Security

- The dashboard is **auth-less by default** and treats every request as
  local-trust admin. That is safe only while bound to `127.0.0.1`. Set
  `DASHBOARD_TOKEN` (and optionally per-user `DASHBOARD_USERS`) **before**
  binding `--host` to anything else — see `.env.example`.
- The AI SOC Engineer operates behind a READ/PROPOSE/EXECUTE approval model;
  every tool call is audited and tool results are untrusted data.
- Report vulnerabilities per `SECURITY.md` (private, never a public issue).
- The 2026-09-27 security audit — findings, fixes, residual risk — lives in
  [`docs/AUDIT-2026-09-27.md`](docs/AUDIT-2026-09-27.md).
