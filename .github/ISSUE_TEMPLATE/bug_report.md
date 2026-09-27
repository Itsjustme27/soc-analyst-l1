---
name: Bug report
about: Something is broken or misbehaving
title: "[bug] "
labels: bug
assignees: ""
---

## Environment

- OS: <!-- e.g. Ubuntu 24.04, Windows 11 -->
- Python: `python --version`
- Repo: local main vs. tag (`git describe --tags`)

## What happened

<!-- Paste the error output or describe the misbehavior. -->

## What I expected

## Reproduction

Minimal steps to reproduce. If a config value or env var is involved, redact
secrets and say which SIEM / provider mode (`MOCK_MODE=true` strongly
preferred — the whole suite runs offline).

```
MOCK_MODE=true python -m unittest tests.test_... -v
```

## Relevant logs

<!-- Trim to the relevant lines; redact API keys/tokens. -->

## Code pointers

<!-- If you know where: file:line. -->

## Security relevance

- [ ] This involves auth / approvals / permissions / secret handling
  (if so, also drop a note in `docs/AUDIT-2026-09-27.md` per repo policy)