# Security Policy

## Supported versions

Only the latest release (`main` + the newest `v*` tag) receives security
fixes. The project has a single-repo, PR-gated release model — there are no
LTS branches.

## Reporting a vulnerability

**Do not open a public issue for a security bug.** Instead:

- Email the maintainer or open a **private** vulnerability report
  (`Security` tab → *Report a vulnerability*) with:
  - affected file:line (best effort)
  - a minimal, redacted reproduction
  - impact sketch (what an attacker can do)
- Expect an acknowledgement within 72h.
- Coordination: if it's a live/known-exploitable vuln, we agree a disclosure
  date before you publish anything.

You will be credited in the advisory / changelog unless you prefer anonymity.

## What this repo treats as security-relevant

Anything that touches:

- `dashboard.py` auth (tokens, roles, per-user identities) and approval routes
- `approvals.py` / `approval_executor.py` (proposal lifecycle, single-use
  claims, quorum)
- `permissions.py` / `tools/registry.py` / `guard.py` (the READ/PROPOSE/
  EXECUTE model, prompt-injection defense)
- `cli/` (MCP server permissioning, sub-agent delegation, secret handling)
- any code that parses operator/LLM-supplied content (XML, queries, rules)
- secret/key handling anywhere

Dashboard authz findings are additionally tracked in
`docs/AUDIT-2026-09-27.md` per repo policy, even for trivial fixes.

## Security posture notes (what we already know)

- Auth is **off by default** (documented local-trust posture). Set
  `DASHBOARD_TOKEN` / `DASHBOARD_USERS` before binding to anything other
  than `127.0.0.1`.
- Tool results are treated as **UNTRUSTED DATA** — never instructions.
- No `eval`/`exec`/`pickle` on untrusted input anywhere in app code.
- CI runs `bandit` (medium+) and nightly CodeQL. Residual risks are
  documented in `docs/AUDIT-2026-09-27.md`.