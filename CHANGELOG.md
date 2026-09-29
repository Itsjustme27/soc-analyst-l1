# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are tagged `v<version>` on `main`; the `release.yml` workflow turns
the tag + `VERSION` + this file's latest section into a GitHub release.

## [Unreleased]

### Added

- Second, co-existing system-prompt set selected by `PROMPT_PROFILE`
  (`agent/prompt_profile.py`). `default` keeps the original compact briefs and is
  unchanged in behaviour; `detailed` adds the longer, more explicit **SOC L1
  Analyst** brief (mission, ordered workflow, hard rules, judgment guidelines,
  output style) and **SOC Engineer** brief (platform responsibilities,
  non-negotiable safety principles, how-to-work). The analyst brief is split along
  the seam the code already uses: the unattended half (which calls
  `submit_verdict`) is on the triage loop, the "Chat mode" half on the chat loop.
  Both sets are always present in the code — the profile only selects which one is
  sent, so switching is a one-line env change and not a code revert. An
  unrecognised value falls back to `default` rather than erroring at import.
- `tests/test_prompt_profiles.py` (18 tests): profile resolution, guard-notice and
  `answer_user` retention in both sets, and that the detailed analyst brief names
  only values the `submit_verdict` schema accepts.

### Changed

- The detailed analyst brief's field-level values were aligned to the
  `submit_verdict` JSON Schema, which the authored text did not match. As written
  it would have produced invalid tool calls: `verdict` `benign` and
  `needs_investigation` are not in the schema enum or in `metrics.VALID_VERDICTS`
  (`false_positive` / `true_positive` / `escalate`); `recommended_action` is
  `close_no_action` / `monitor` / `isolate_host` / `disable_account` /
  `escalate_to_l2`; the field is `evidence_used`, not `evidence_cited`; and
  `needs_human_review` is computed in code rather than set by the model. The
  brief's prose, ordering and safety rules are otherwise unchanged.
- `test_the_engineer_is_pointed_at_the_designing_tool` now skips when the detailed
  profile is active. The Wazuh tool-level routing it asserts
  (`design_detection_dashboard` / `` `intent` `` / `ALREADY exist`) is specific to
  the default engineer brief; the detailed one is a platform-level brief. Under
  the default profile the assertion still runs unchanged.

- Terminal UI for the CLI (`cli/terminal.py`, `cli/completion.py`, optional
  `requirements-cli.txt`): tab completion with descriptions for commands and live arguments
  (skills, MCP servers/tools, proposal ids, SIEM connections, platforms, LLM backends, agents),
  `@skill` mentions for one turn, persistent history with suggestions, a status bar, Shift+Tab
  mode switch and Alt+Enter newlines. Falls back to readline or plain input; `--plain` forces it.

- Prompt enhancer (`prompt_enhancer.py`, `POST /api/enhance`): free-text requests become a
  validated JSON spec (tasks, entities, time range, assumptions) before the agent sees them.
  Facts are extracted by code, the LLM only classifies tasks, and a keyword classifier takes
  over when it can't. Write requests show "here's what I understood" first (dashboard AI
  engineer and CLI). Settings: `PROMPT_ENHANCER`, `PROMPT_ENHANCER_LLM`; CLI `--no-enhance`,
  `/enhance on|off`. See `docs/prompt_enhancer.md`.

### Fixed

- `.mcp.json` was committed again, auto-starting the test fixture server (whose tool returns an
  injection payload) for every CLI user, while the README's `cp .mcp.json.example .mcp.json`
  step failed because the example file didn't exist. It ships as `.mcp.json.example` and
  `.mcp.json` is git-ignored.

- Dashboard requests no longer come back as the generic default dashboard. The engineer was
  told to hand-build dashboards with `create_wazuh_dashboard` (which only assembles existing
  visualizations), agents that omitted `intent` got the fixed template, and a planner failure
  silently substituted it. Now: the engineer uses `design_detection_dashboard` with the request
  as `intent`; a missing `intent` is taken from a descriptive `reason`; a planner failure is a
  clear error and nothing is proposed.
- The dashboard planner can express far more requests: URLs, HTTP status, source countries,
  ports, MITRE technique/tactic/ID, Windows event IDs/processes, file-integrity paths,
  source/target users and vulnerabilities (each still offered only if the field exists in the
  index), with aliases such as "status" and "mitre". Panel titles no longer read
  "Alert volume - general" or "Unique Top source IPs".
- Rule builder reports an unreachable manager instead of a false "rule id already exists";
  an unconfigured indexer names `WAZUH_HOST` instead of a raw `requests` URL error.
- Watchlist: adding an entry right after creating a table works (the name is no longer cleared).
- Clean clones/CI: the `*.log` ignore rule no longer hides the logtest fixture;
  `.env.example` documents `PREVIEW_DIR` and `WEB_QUERY_LOG_PATH`.

### Added

- **Intent-driven builders.** Both builder UIs were template machines.
  `design_detection_dashboard` took `focus` as a closed enum
  (`web|ssh|network|general`) and ignored free text, so "ssh failed login from
  private to private ip" produced the same seven generic panels as any other
  request — the request itself was parked in the proposal's `reason` field. The
  Rule builder demanded hand-written XML plus samples, leaving one hardcoded SSH
  "Starter rule" as the only way in.
  - `design_detection_dashboard` now takes an optional free-text `intent`. The
    model chooses a title, filter clauses and panels from a **closed**
    vocabulary (`tools/dashboard/planner.py`); the code maps those to real index
    fields, drops anything absent from the live `field_caps` schema, renders the
    aggs, and the caller still verifies every panel query against the real
    indexer. The model never emits OpenSearch DSL and never names a field. With
    no `intent`, the old preset path is unchanged.
  - New READ tool `draft_wazuh_rule` (`tools/detection/drafter.py`): plain
    language → candidate `<rule>` XML + realistic positive samples, filled into
    the form for review. Negatives are optional — an empty list is a truthful
    answer, and `develop_wazuh_rule` never required one. It self-checks with the
    same `validate_wazuh_rule_xml` the propose step uses, so a doomed draft is
    flagged before you click anything. It proposes nothing and writes nothing.
  - `ToolContext.llm` / `ToolContext.get_llm()` — an injection seam for the two
    generative tools, so tests stub the model instead of calling one.
  - An intent filter that matches 0 alerts is a **validation error** rather than
    a proposal for seven empty panels.
  - `guard.wrap_log_data()` (nonce-matched wrapper for raw alert content) and
    `guard.unwrap()` (payload back out, for code — never for the model), plus
    case- and whitespace-insensitive forged-marker defanging.

### Fixed

- **Builder validation errors no longer surface as "Internal server error."**
  `registry.execute()` runs PROPOSE tools in a dry-run to collect their
  proposal, and their own validation (static rule checks, "rule id already
  exists", "needs a positive sample") raises `ToolError` from *inside* that
  dry-run. Only `ApprovalRequired` and `PermissionDenied` were caught, so the
  `ToolError` escaped and became an opaque HTTP 500. It is now caught and
  returned as `{"status": "error", "error": <the real message>}`.
- **Panel filters were silently dropped from created dashboards.**
  `osd_objects._filters()` understood only `term` and `range`, so a
  `match_phrase`, `terms`, or a `bool.should` of CIDR ranges vanished from the
  saved visualization — the evidence panel showed correct filtered counts while
  the created dashboard rendered *every* alert. All clause kinds now
  round-trip, and an unrecognised one is emitted as a custom filter rather than
  dropped.
- `tests/test_dashboard_panels.py` no longer deletes the developer's real
  `data/triage_log.jsonl` / `data/chat_log.jsonl` in `setUpClass`/`tearDownClass`;
  it points `cfg` at throwaway files and restores them. `data/` is gitignored, so
  that was unrecoverable.

First formal release candidate (`VERSION` = 1.0.0). Everything below is
new since the informal

### Fixed
- **Approved proposals could not be executed at all.** The duplicate-title guard
  shipped as a create-time check, which made the failure self-fulfilling: the
  dashboard an approval described already existed because an earlier execution
  had made it, so the guard refused the replay, and since the proposal stayed
  `approved` it could never succeed. All four outstanding approvals were stuck.
  The guard now belongs to the *propose* path only — `preview.duplicate_veto`
  stands down when `ctx.approval` is set, which is the one signal that an
  operator already decided. Proposing a repeat is still refused, which is where
  the re-creation loop actually lived.
- **A dashboard title could be an entire request sentence.** One proposal was
  approved with the title `"Build a real-time general threat dashboard that
  aggregates, normalizes, and visualizes security threat feeds…"` — 216
  characters, 28 words, JSON quotes attached. Unreadable in the dashboard list,
  and it defeated duplicate detection, since two requests differing by a word
  were two different dashboards. `preview.check_title` now rejects a
  request-shaped title while *proposing* (so the model retries with a real name)
  and `preview.derive_title` shortens it while *replaying* an approval, rather
  than stranding a decision the operator already made. The two paths differ for
  the same reason as the guard above: proposing is where the mistake is cheap to
  fix, and executing is too late to be picky.
- **A numeric `histogram` was translated to `date_histogram`** in the preview,
  which is not an empty panel but an HTTP 400 — `interval` on a histogram is a
  number of field units, and sending it to `date_histogram` makes the indexer
  try to parse it as a date span. A CVSS score distribution is what exposed it.
- **A visState agg whose `schema` is the aggregation type instead of Wazuh's
  metric/segment split** saves without complaint and then renders blank,
  because nothing tells the dashboard the series is a scalar. The preview now
  infers the split from the agg type when `schema` says neither, so it reports
  the cause rather than the symptom.
- **A saved object could be created, be schema-valid, and still be dead** — an
  index-pattern reference pointing at the pattern's *title* while the pattern
  itself had a uuid id. Every panel renders empty with no error logged
  anywhere. `engine._unresolved_data_refs` now resolves each created
  visualization's data reference and reports the dashboard as
  `executed_with_issues` rather than silently shipping it.

### Added
- **Threat-intelligence provider** (`tools/dashboard/threatintel.py`, new) — the
  provider the approved work needed, built over data Wazuh already indexes
  rather than an external feed. The engineer was being asked for CVEs, CVSS
  scores, severity trends and attacker behaviour and kept producing an
  alert-volume dashboard, because `design_detection_dashboard` only reads
  `wazuh-alerts-*` while the Vulnerability Detector writes
  `wazuh-states-vulnerabilities-*` and the alert stream carries the MITRE
  fields. The data was in the indexer the whole time; nothing queried it.
  - 11 panels over the combined pattern `wazuh-alerts-*,wazuh-states-vulnerabilities-*`:
    exposure metrics, CVSS distribution, severity breakdown, top CVEs, most
    affected packages, scoring source, publication timeline, and ATT&CK
    tactics/techniques. Every aggregation was executed against a live indexer
    before being written down.
  - Three data facts shape the plan, each measured rather than assumed:
    `-1.0` CVSS and the literal severity `"-"` are placeholders for "no score
    assigned" and cover 34% of the documents, so the CVSS panels filter to rated
    and the severity panel keeps an explicit `Unrated` slice instead of
    dropping a third of the estate; `detected_at` falls entirely within one
    month because the detector ran a single scan, so the trend panel uses
    `published_at` and says so in its title; and there is **no geo and no IOC
    data at all** on this deployment, so those panels are not built. They are
    reported in `UNSUPPORTED` with what each would need — an empty chart is
    ambiguous, and an operator cannot otherwise tell "no attacks from anywhere"
    from "never collected".
  - `ensure_index_pattern()` is an idempotent get-or-create for the combined
    data view, so re-running does not leave duplicate data views behind.
  - New tool `design_threat_intel_dashboard` (PROPOSE) registers alongside
    `design_detection_dashboard` and is previewable from the engineer's
    Dashboard Preview tab via the new **Source** selector.
- **Chat messages render Markdown** (`static/md.js`) rather than as escaped
  pre-formatted text, so a proposed dashboard's tables and lists are readable
  instead of showing their own source punctuation. `hrefKind` refuses
  `javascript:`, `data:`, `vbscript:`, `file:`, bare-relative and
  protocol-relative `//host` hrefs, marks only genuinely external links with
  `target="_blank" rel="noopener noreferrer"`, and falls back to escaped text
  rather than raw HTML.
- **Dashboard preview + duplicate guard** — the engineer no longer re-creates the
  same dashboard, and a proposed dashboard can be *seen* before it is approved.
  - `tools/dashboard/preview.py` (new) runs each panel's real `visState` aggs
    against the live indexer and draws them with matplotlib (Agg) in the same
    2-column `24x15` `gridData` geometry `osd_objects.build_panels()` assigns,
    so the PNG is a scale model of the dashboard rather than a mock-up. Panels
    are consumed from `engine._panel_plan()` — the same plan the create tool
    builds — so preview and creation cannot drift. Reports a per-panel status
    (`ok` / `empty` / `error`); one failing panel never blanks the rest, because
    a silently dropped panel would let an operator approve a dashboard with a
    hole in it. Resolves `interval: "auto"` to a concrete interval, which the
    live indexer rejects with HTTP 400 otherwise.
  - `create_wazuh_dashboard` and `design_detection_dashboard` now **refuse a
    repeated title** (normalised, so `Web Attacks` == `web-attacks`), checked
    before any panel or indexer work. The saved-objects API accepts duplicate
    ids silently, which is how copies accumulated. A listing failure never
    blocks a create.
  - New **Dashboard preview** sub-tab in the AI Engineer view, plus
    `POST /api/engineer/dashboard/preview` and
    `GET /api/engineer/dashboard/preview/<token>.png` (gated at `approver`).
    PNGs are addressed by an opaque random token, never a caller-supplied name,
    and the directory is pruned to the newest 40. The image is blob-fetched so
    the bearer token stays out of URLs and access logs.
  - `matplotlib` added to `requirements.txt`; it is imported lazily, so a host
    without it still runs everything else and gets one clear install hint.
  - 58 tests in `tests/test_dashboard_preview.py`.
- **`wazuh-dashboard-master` skill pack** (`skills/wazuh-dashboard-master/`) —
  routes Wazuh dashboard work across its five pillars: reporting
  (`metrics.py`/`digest.py`), alerting (`rules.py` staged into
  `local_rules.xml`), anomaly detection (CrowdStrike enrichment +
  `analyze_detection_gaps`), maps (investigate engine), and notifications
  (`notify.py` + `action.notify`). Auto-activates via `suggest_skills`
  (`agent/skills.py`) — it surfaces in the top 3 for requests naming any
  pillar. Two corrections are baked in so the agent does not invent
  capabilities: there is **no `put_rules_file` tool** (it is a client method
  the rule tools wrap) and there is **no geo-IP support** in this repo.
  Covered by 10 tests in `tests/test_skills.py::TestWazuhDashboardMasterPack`.

### Security
- **Audit & hardening pass (2026-09-27)** — see `docs/AUDIT-2026-09-27.md`:
  - Dashboard bearer/shared-token checks now compare in constant time
    (`hmac.compare_digest`).
  - QRadar Ariel `search_related_events` now builds filters from fail-closed,
    allowlisted literals (quote/comment metacharacters refused) — no more raw
    interpolation of alert-derived host/user values.
  - Wazuh rule/decoder XML parsing rejects `<!DOCTYPE` / `<!ENTITY`
    declarations everywhere (`tools/wazuh/xmlio.safe_fromstring`) — XXE guard
    without new dependencies.
  - Hashing-fallback embeddings mark their MD5 as non-security
    (`usedforsecurity=False`).
  - MCP config now warns when a `${VAR}` referenced in `.mcp.json` is not set
    (previously substituted an empty string silently).
- **PR #1 review fixes (2026-09-27)** — verified by the PR's own CI/CodeQL on the new head:
  - Python 3.11 compatibility: the engineer CLI `find_tools` event line no longer puts a
    `\u2026` escape inside an f-string expression (a `SyntaxError` on 3.11); a portable
    pre-3.12 f-string gate (`scripts/check_py311_syntax.py`) now runs on every CI matrix.
  - Dashboard watcher spawn (`POST /api/agent/start`, `POST /api/agents/start`) validates
    `--siem` selectors fail-closed against the same allowlist `run.py` resolves (provider ids +
    platform names); the `Popen` argv is a fully static, fixed list and the validated selector +
    sanitized `agent_id` are delivered to the watcher via its environment (`SOC_WATCHER_*`),
    `shell=False` explicit (CodeQL "Uncontrolled command line").
  - Dashboard API no longer echoes exception internals to clients: unexpected exceptions return
    a generic message and the full traceback goes to the server log only, backed by a global
    error handler returning a generic JSON 500 (CodeQL "Information exposure through an
    exception").
- `9c271b3` — role-gate the proposal routes, allow withdrawing an approval
  (approver role + verified identity on the Approval Center; cancellable
  pending/approved proposals).

### Added
- `test_wazuh_rule` tool (`tools/wazuh/logtest.py`): test ONE candidate `<rule>`
  against ONE real sample log line. It validates the XML statically, then stages
  the rule into `local_rules.xml` (`PUT /rules/files/local_rules.xml`, PROPOSE +
  approval-gated), then makes exactly **one** logtest call with the real event and
  reports which rule fired, at what level, and whether that is the candidate. It
  returns `restart_required: true` rather than smuggling a manager restart into a
  PROPOSE tool.
- Decoder preflight (`tools/wazuh/logtest.py::preflight_decoders`): every
  logtest-backed tool now submits one known-good canonical line
  (`tests/fixtures/sample_events/sshd_failed_auth.log`) and requires it to decode
  **and** fire stock rule `5716` before any candidate-rule result is trusted.
  A session with no decoders loaded fails even a perfect sample, so a failed
  preflight is surfaced as "logtest session has no decoders loaded" with no
  per-sample verdicts, instead of filing every sample as `no_decode`.
- Event guard `tools/wazuh/xmlio.py::looks_like_xml` / `ensure_real_event` /
  `NotALogEventError`: refuses rule XML in any logtest `event` field, at the tool
  layer *and* at the `WazuhManagerAPI.run_logtest` transport boundary.
- `tests/fixtures/sample_events/sshd_failed_auth.log` (+ `README.md`): the
  canonical sample event as a real fixture, lifted out of the inline XML comment
  in Wazuh's stock `local_rules.xml`, so a sample event can never again be
  confused with a line of a rules file.
- `tools/wazuh/logtest.py::logtest_event` is now the single place the logtest
  socket is called; the module docstring documents the request shape and why
  rule XML in `event` can only ever answer "No decoder matched.".
- CI (`ci.yml`): tests on Python 3.11–3.13 under `MOCK_MODE`, `ruff`, `bandit`
  (medium+), coverage `--fail-under=70`, config/env drift check, import smoke.
- Nightly CodeQL (`codeql.yml`), weekly Dependabot (`dependabot.yml`), and a
  tag-triggered release workflow (`release.yml`).
- Contributor-facing surface: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  `SECURITY.md`, `CODEOWNERS`, issue templates, PR template, `.editorconfig`,
  `.gitattributes`, pre-commit config.

### Changed
- `pyproject.toml` (ruff + coverage config) added; lint gate is now `ruff`
  (honors `# noqa` — pyflakes' one false positive is an intentional
  availability-probe import).
- `.env.example` synced with `config.py` (16 previously undocumented keys,
  dead `AGENT_EXIT_AFTER` removed).
- Bandit findings dropped from 1 High / 15 Medium → 0 High / 0 Medium; the
  remaining flagged spots are documented false positives with `nosec` +
  justification.
- Test suite grew 572 → 619 (all offline, `MOCK_MODE=true`), including
  `TestLogtestHarness` — 16 tests that pin the logtest contract: rule XML can
  never reach `event` at any layer, a failed preflight is surfaced rather than
  laundered into `no_decode` rows, a staged candidate's own id must fire (not
  the `1002` catch-all) from a single real sample event, and the socket is
  called once per test case rather than once per line.

### Fixed
- **Rule XML was being fed to the logtest socket as a log event.** The
  rule-validation path submitted raw `<rule>` markup — a whole
  `local_rules.xml`, or line by line — in logtest's `event` field, so every
  line came back `No decoder matched.`, including literal tags like
  `<if_sid>5716</if_sid>`. That answer is about the harness, not the rule, and
  it looked exactly like a manager verdict. `event` now always carries one real
  log line, and rule XML is refused at every boundary; a candidate rule is
  loaded into the ruleset logtest evaluates and then tested with one real
  sample event.
- **A decoder-less logtest session silently produced garbage.** When the
  session has no decoders loaded, a perfectly good sample fails to decode too,
  and the run filed every sample as `no_decode` — a statement about the
  harness wearing the costume of a statement about the rule. The preflight above
  now stops the run and says so; `verify_rule_deployment` raises instead of
  reporting a verdict it cannot support.
- **Rule `1002`/`1005` (the generic catch-all) was reported as an ordinary
  "some other rule fired" result.** On a *positive* sample it means the sample
  never reached the candidate's match terms — usually the manager was never
  restarted after the upload. It is now reported loudly as `catch_all`, forces
  `verification: "inconclusive"` with `verified: null` and `harness_suspect:
  true`, and is split out of the `fires_other` classification so it can no
  longer be read as "the ruleset already covers this".
- **Staging a rule into `local_rules.xml` could silently corrupt it.** The
  read-modify-write re-serialiser dropped attributes on any element with
  children (so `<rule id="100001" level="5">` was written back as a bare
  `<rule>`) and dropped the root `<group name="local,...">` wrapper entirely.
  Both fixed in `tools/wazuh/local_rules.py::_indent` / `_serialize_file`.
- `api_client.run_logtest` defaulted `location` to a path unrelated to its
  sample; it now defaults to `master->/var/log/auth.log`, the source of the
  canonical preflight line.
- `sample_events_from_xml_comment` harvested prose comments (`<!-- Local
  rules -->`) as if they were log events; it now requires an explicit sample
  label.
- Bandit B324/B608/B314/B113/B104/B108 findings per `docs/AUDIT-2026-09-27.md`.

### Removed
- Dead configuration `AGENT_EXIT_AFTER` from `.env.example`.

---

Prior work (informal history, no formal releases): the repo accumulated
multi-SIEM triage, the CrowdStrike enrichment, RAG memory + feedback loop,
the web dashboard with Approval Center, the agentic AI SOC Engineer for Wazuh
(READ/PROPOSE/EXECUTE model), the terminal CLI/MCP/sub-agent surface, and the
watcher — see `git log` for the full commit history.