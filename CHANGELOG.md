# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases are tagged `v<version>` on `main`; the `release.yml` workflow turns
the tag + `VERSION` + this file's latest section into a GitHub release.

## [Unreleased]

First formal release candidate (`VERSION` = 1.0.0). Everything below is
new since the informal

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
    platform names); `shell=False` is now explicit (CodeQL "Uncontrolled command line").
  - Dashboard API no longer echoes exception internals to clients: unexpected exceptions return
    a generic message and the full traceback goes to the server log only, backed by a global
    error handler returning a generic JSON 500 (CodeQL "Information exposure through an
    exception").
- `9c271b3` — role-gate the proposal routes, allow withdrawing an approval
  (approver role + verified identity on the Approval Center; cancellable
  pending/approved proposals).

### Added
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
- Test suite grew 572 → 591 (all offline, `MOCK_MODE=true`).

### Fixed
- Bandit B324/B608/B314/B113/B104/B108 findings per `docs/AUDIT-2026-09-27.md`.

### Removed
- Dead configuration `AGENT_EXIT_AFTER` from `.env.example`.

---

Prior work (informal history, no formal releases): the repo accumulated
multi-SIEM triage, the CrowdStrike enrichment, RAG memory + feedback loop,
the web dashboard with Approval Center, the agentic AI SOC Engineer for Wazuh
(READ/PROPOSE/EXECUTE model), the terminal CLI/MCP/sub-agent surface, and the
watcher — see `git log` for the full commit history.