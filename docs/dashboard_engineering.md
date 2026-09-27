# Dashboard engineering

How `design_detection_dashboard(title, intent, focus, description, time_range,
reason)` turns **"create a dashboard for web server attacks"** into an
evidence-backed, human-approvable bundle (PROPOSE), and how approved
execution creates it for real.

## Two planning modes

**`intent` (free text, preferred).** The request is planned by the model,
then rendered and verified by the code — see `tools/dashboard/planner.py`.
The split is deliberate:

| Contributed by the model | Contributed by the code |
| --- | --- |
| a title | the mapping from semantic key → real index field |
| filter clauses over a **closed** field/operator vocabulary | the OpenSearch DSL and the agg payloads |
| which panels, from `count` / `trend` / `breakdown` / `unique` | dropping anything `field_caps` doesn't have, and verifying every query |

The model never names a field or an operator, so it cannot smuggle in a
query the index cannot run. A clause naming an unknown key, an unknown
operator, or a field absent from the live schema is **dropped and reported**,
not passed through. "private source to private destination" becomes two
`cidr` clauses, each rendered as an OR of `range` filters on the ip field.

If *every* filter the model proposed is unusable, the plan fails rather than
silently degrading to a generic dashboard that ignores what you asked for. If
the model is unreachable or returns junk, the tool falls back to the `focus`
template and records `planner_fallback` in the evidence — the UI shows that
the panels are generic, so a fallback is never passed off as a plan.

**`focus` (preset, legacy).** With no `intent`, the fixed per-focus template
is used exactly as before: alert volume, alert trend, top source IPs, top
rule groups, top rules, level distribution, top agents.

## Planning (no writes)

1. **Schema** — `field_caps` on the indexer tells the engine which fields
   exist (`data.srcip`, `agent.name`, `rule.groups`, `rule.level`, …). A
   schema read failure aborts the design ("Cannot read indexer schema …") —
   no guessing.
2. **Panel plan** — from the planner (intent mode) or the fixed template
   (preset mode). Panels referencing missing fields are dropped, not
   fabricated, and the shape is padded back out so a dashboard is never just
   two lone panels.
3. **Evidence** — every panel's OpenSearch query is run against the real
   indexer (`size: 0` count) and reported `valid` / degraded. A panel whose
   query fails to match is flagged in the proposal's validation, never hidden.
   An intent filter that matches **0** alerts is a validation error: seven
   empty panels must not be proposed as if they were fine.
4. **Bundle** — agg-based `visState` per visualization + `panelsJSON` grid,
   proposed with `{action: design_detection_dashboard, payload: <the tool's
   own input params>, generated_config, validation}`. `payload` includes
   `intent`, so an approved execution replans identically.

Every filter clause round-trips into the saved visualization's
`searchSourceJSON` (`osd_objects._filters`). An unrecognised clause kind is
emitted as a custom filter rather than dropped — a filter that silently
stops applying is worse than one that renders imperfectly.

`_find_index_pattern` discovers the Wazuh alert index-pattern id
best-effort and falls back to the conventional `wazuh-alerts-*` id.

## Execution (approved only)

The stored payload re-runs the design workflow, then writes via the
OpenSearch Dashboards saved-objects API (`POST /api/saved_objects/
visualization` then `…/dashboard`):

- each visualization is created and its real id captured;
- real ids are mapped into the grid (rows that failed to create are skipped
  — the dashboard is built from what actually exists);
- the dashboard is created and the result reports only
  server-confirmed ids (visualizations, dashboard id, panels created).

The dashboards server is best-effort by design: the engine never claims a
dashboard exists unless the API returned the saved object.

## Query rules (shared with every engine)

- structured bool clauses only (`term` / `terms` / `match` / `match_phrase`
  / `range` / `date_histogram`);
- no `query_string`-style filters (7.10.2 500s on `/`, `<`, `=`, `..`);
- count verification with `"size": 0` reading `hits.total.value`;
- `wazuh-alerts-*` for triggered alerts, `wazuh-archives-*` for raw activity.