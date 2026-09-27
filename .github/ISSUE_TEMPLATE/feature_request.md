---
name: Feature request
about: Suggest a capability for the SOC L1 agent / AI SOC Engineer / CLI
title: "[feature] "
labels: enhancement
assignees: ""
---

## Problem to solve

<!-- What can't the operator do today? -->

## Proposed behavior

## Safety implications (important for this repo)

The tool layer runs READ/PROPOSE/EXECUTE-gated operations against a SIEM and
Wazuh. A feature that touches:

- which tools exist or what they may do (`tools/`, `permissions.py`)
- approval / execution semantics (`approvals.py`, `approval_executor.py`)
- dashboard auth / roles (`dashboard.py`, `config.py`)
- new runtime dependencies (`requirements.txt` changes need justification +
  license check in the PR)

must describe exactly where the new write/approval gate sits and what
residual risk remains.

## Sketch / alternatives

## Do you want to implement it?

- [ ] Yes, I'll open a PR (read `CONTRIBUTING.md` first — tests mandatory)