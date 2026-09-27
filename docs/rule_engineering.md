# Rule engineering

The detection surface: authoring, validation, deployment, and post-deploy
verification against a Wazuh manager. Grounded in live-verified 4.14 behavior
(see `wazuh_docs/wazuh-rules.md` and `wazuh_docs/wazuh-logtest.md` — both are
seeded into the RAG store).

## draft_wazuh_rule (READ) — generating the draft

`draft_wazuh_rule(intent, log_format, parent_rule_id, log_sample)`

Drafting is deliberately split from proposing:

    draft_wazuh_rule        (READ)     generate — writes nothing, proposes nothing
    develop_wazuh_rule      (PROPOSE)  validate + propose

The model returns a candidate `<rule>` element plus realistic positive log
samples. The result is meant to be **read and edited by a human** before it
reaches `develop_wazuh_rule`, so a hallucinated rule can never become a
pending approval on its own.

- **Negatives are optional.** A request like "detect X" has no natural
  near-miss log, and an invented one just teaches the model to pad. An empty
  list is a truthful answer; `develop_wazuh_rule` only ever required one
  positive sample.
- **Self-check.** Whatever it generates is run through the same
  `validate_wazuh_rule_xml` the propose step uses, and the verdict travels
  back with the draft — so the UI can say "this will be rejected" before you
  click anything. (The `frequency` ⇒ `if_matched_sid` rule in step 1 below is
  exactly the kind of thing this catches.)
- Samples are flattened to one line each and de-duplicated: a sample is a log
  event, and logtest submits one event per call.
- A missing `rule_xml` or an empty positive list is a `ToolError`, not a
  half-filled draft.

## develop_wazuh_rule (PROPOSE)

`develop_wazuh_rule(rule_xml, positive_samples, negative_samples, log_format, reason)`:

1. **Static validation** — `tools/wazuh/validation.py`:
   - required attributes: `id` (>= 100000 for local rules) and `level`
     (0–15); `description` child required.
   - `frequency` / `timeframe` / `divide` **must be rule attributes** —
     child elements are rejected with a corrective error (the manager itself
     errors "Invalid option 'frequency' for rule").
   - a `frequency`/`divide` rule must reference its parent via
     `<if_matched_sid>…</if_matched_sid>` (`<if_sid>` fails the manager with
     "Invalid use of frequency/context options. Missing if_matched on rule").
     The canonical SSH-failure parent is rule **5760**.
2. **Pre-flight** — the proposed id is free (`get_rules(q=id=…)`), the parent
   rule exists, and the proposed XML doesn't overlap existing rules.
3. **Decoder preflight** — one known-good canonical line
   (`tests/fixtures/sample_events/sshd_failed_auth.log`) is submitted and must
   decode **and** fire stock rule `5716`. A session with no decoders loaded
   fails even a perfect sample, so without this check every row below would be
   filed as `no_decode` — a statement about the harness wearing the costume of
   a statement about the rule. On failure the proposal carries
   `harness_broken: true`, every sample row is classed `preflight_failed`
   (submitted zero times), and `baseline_summary` says no verdicts were
   collected.
4. **Logtest baseline** — positives/negatives are each submitted once, as real
   log events, and classified (`already_covered` / `catch_all` / `no_decode` /
   `fires_other` / `clean`). Rule XML is never an `event`: structure is
   answered by the parser in step 1, behaviour only by the manager.
5. **Proposal** — `{action: create_wazuh_rule, payload: {rule_xml, overwrite:
   false, reason}, generated_config: <merged local_rules.xml diff>, …}`.

Execution (approved) merges the rule into `local_rules.xml`, PUTs it
(octet-stream), and reports the manager's "Rule was successfully uploaded"
message. A manager **restart** (separate approval) is needed before rules
load — `RestartWazuhManager`.

## test_wazuh_rule (PROPOSE)

`test_wazuh_rule(rule_xml, sample_event, reason)`: the one rule + one real log
line case, for when you want the fired rule id before or right after a
restart. Static XML validation → decoder preflight → stage into
`local_rules.xml` (approval-gated `PUT`) → **exactly one** logtest call with the
real event.

`event` is a log line, always. A `<rule>` block or a line of one is refused by
`tools/wazuh/xmlio.py::ensure_real_event` before any round trip — the manager's
only possible answer would be "No decoder matched.", for every line, which is
indistinguishable from a real verdict. `status` is one of `tested` / `catch_all`
/ `no_decode` / `not_matched` / `no_alert`; **only `tested`** is a statement
about whether the rule works — the rest each carry an `error` saying why no
verdict was produced. After staging it also returns `restart_required: true` and
the explicit `next_steps` (a restart is EXECUTE with its own approval, so it is
not smuggled into this PROPOSE tool).

## verify_rule_deployment (READ)

`verify_rule_deployment(rule_id, positive_samples, negative_samples)`:

- **decoder preflight first.** A verdict built on a session that cannot decode
  is worse than no verdict — it would blame the rule for the harness. It raises
  instead.
- plain rules: every positive must fire the new id; negatives must fire
  something else.
- **frequency rules: inconclusive, always.** logtest holds no frequency
  counter — that state lives in analysisd's pipeline, and 8 repeated failures
  through a *single* logtest session never tripped a `frequency=5` rule on a
  live 4.x manager. So `verified` is `null` (unknown, **not** `false`) and
  `frequency_rule_unverifiable_via_logtest: true`. What logtest still proves
  here is real: the parent fires (decoding + `if_matched_sid` wiring), and the
  negatives stay silent (not over-matching).
- negatives run in their own fresh session and must never fire the new id.
- **rule 1002/1005 on a positive forces `inconclusive`** (`harness_suspect:
  true`, `catch_all_hits: [...]`). The generic catch-all matches anything that
  decoded but hit no specific rule, so the sample never reached the candidate's
  match terms — the usual cause is a manager that was never restarted after the
  upload. Filing that as an ordinary per-sample failure is how a working rule
  gets deleted.

## Rule lifecycle (CRUD)

`CreateWazuhRule` / `UpdateWazuhRule` / `DeleteWazuhRule` follow the same
payload round-trip (stored payload → deterministic execution →
API-confirmed result). Delete is EXECUTE: requires approval + `confirm`, and
only reports success after the manager confirms the rule is gone.

## Gotchas (all live-verified)

- `GET /manager/info` returns 200 while daemons restart — readiness is
  `GET /manager/status` with all core daemons (wazuh-analysisd, wazuh-db,
  wazuh-remoted, wazuh-authd, wazuh-modulesd, wazuh-apid) == "running".
  wazuh-agentlessd / csyslogd / integratord / maild may legitimately be
  stopped.
- Rules PUT as octet-stream; a missing `local_rules.xml` on a fresh manager
  reads as "not found" → treat as empty.
- Never run `query_string`-style indexer filters (see
  `docs/dashboard_engineering.md` / `wazuh_docs/wazuh-indexer.md`).