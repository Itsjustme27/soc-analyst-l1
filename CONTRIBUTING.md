# Contributing to SOC L1 Triage Agent

Thanks for considering a contribution. This is a safety-critical codebase —
the code drives READ/PROPOSE/EXECUTE-gated operations against live SIEMs and
Wazuh — so the bar is "small, test-backed, human-reviewable diffs". Nothing
lands on `main` except through a reviewed PR; there is no direct push.

## Ground rules

1. **No secrets, ever.** Re-scan `git diff` before pushing. `.env`,
   `.env.*` (except `.env.example`), `data/*`, snapshots, and venvs are
   gitignored.
2. **Every behavior change ships a regression test.** The suite runs
   fully offline: `MOCK_MODE=true python -m unittest discover -s tests -p "test_*.py"`.
   A fix without a test will be sent back.
3. **One logical change per commit**, Conventional Commits
   (`fix(sec): …`, `feat(cli): …`, `docs: …`, `chore: …`).
4. **Lint & security gates must stay green:**
   ```bash
   ruff check agent cli connectors llm rag tools *.py     # pyflakes-clean, noqa-honoring
   bandit -q -lll -r agent cli connectors llm rag tools   # no High/Medium
   venv/bin/python -m coverage run -m unittest discover -s tests -p "test_*.py" && \
     venv/bin/python -m coverage report                  # coverage not decreased
   ```
5. **Runtime dependencies don't change casually.** `requirements.txt` is a
   deliberate, minimal, loose-range surface. Adding or pinning a dependency
   requires justification **and** a license check in the PR body (all
   current deps are MIT/Apache-2.0/BSD-compatible).
6. **Authz / approval / permission changes** are extra-scrutinized:
   - state the new gate in the PR description (what requires what, and what
     the residual risk is);
   - append a finding + fix + residual-risk entry to
     `docs/AUDIT-2026-09-27.md` — even for trivial fixes.
7. **No force-push to `main`**; rebase-before-merge is fine on feature
   branches, and the release flow is tag-based (`v*` → `release.yml`), never
   a direct push.

## Development setup

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt
venv/bin/pip install ruff coverage bandit radon pre-commit   # dev-only, venv-only
venv/bin/pre-commit install                                  # optional
MOCK_MODE=true venv/bin/python -m unittest discover -s tests -p "test_*.py"
```

## Where things live

| Area | Entry points |
|---|---|
| Alert triage agent | `agent/triage_agent.py`, `agent/chat_agent.py` |
| AI SOC Engineer (Wazuh) | `agent/soc_engineer.py`, `tools/registry.py`, `tools/wazuh/*` |
| Permission model | `permissions.py`, `approvals.py`, `approval_executor.py` |
| Dashboard + Approval Center | `dashboard.py`, `agent_control.py` |
| Terminal CLI / MCP / sub-agents | `cli/*`, `scripts_engineer_cli.py` |
| SIEM connectors | `connectors/siem/*`, `tools/indexer.py` |

## Reuse & licensing

The repository is licensed **MIT** (see `LICENSE`), **but** the maintainer
requires **written permission for any reuse** of this code outside this
project — including forks, derivative products, and inclusion in other
repositories or commercial offerings. If you want to build on this code,
open an issue or contact the maintainer first; do not assume the MIT grant
alone covers your use. Unapproved reuse will be treated as a violation.