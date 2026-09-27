## Description

Closes #[issue]

<!-- What does this PR do and why? Keep it human-reviewable: no force-pushes,
no secret commits, runtime requirements.txt unchanged unless a dep proved
necessary (and then: justify + license-check in the PR body). -->

## Type of change

- [ ] 🐛 Bug fix (non-breaking)
- [ ] ✨ Feature (non-breaking)
- [ ] 🔒 Security fix (non-breaking)
- [ ] ⚠️ Breaking change (public API / config surface) — needs justification
- [ ] 📚 Docs / repo hygiene

## Testing (mandatory)

- [ ] Added/extended regression test(s) for every behavior change
- [ ] Ran the full suite: `MOCK_MODE=true python -m unittest discover -s tests -p "test_*.py"`
  - Result: `Ran N tests` — pass/fail count
- [ ] `ruff check` clean
- [ ] `bandit -r agent cli connectors llm rag tools` — no new High/Medium
- [ ] Coverage not decreased (see CI report)

## Security notes

<!-- Authz-relevant change? Approval lifecycle / permission model / token
handling? State it here, including residual risk. Dashboard findings also go
into docs/AUDIT-2026-09-27.md regardless of severity. -->

## Checklist

- [ ] No secrets / credentials committed (checked `git diff` output)
- [ ] Commit messages follow Conventional Commits
- [ ] CHANGELOG entry added (Unreleased section)
- [ ] `.env.example` still in sync with `config.py`