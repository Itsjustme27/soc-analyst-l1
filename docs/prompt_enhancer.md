# Prompt enhancer

A short request becomes a normalized, validated JSON spec before the agent sees it
(`prompt_enhancer.py`). Used by the dashboard's AI engineer and analyst chat, and by the
terminal agent (`scripts_engineer_cli.py`).

```
"show me ssh brute force from 185.220.101.7 last 24h and make a rule for it"
  ->
{"tasks": [{"type": "investigate", ...}, {"type": "create_rule", ...}],
 "entities": {"ips": ["185.220.101.7"]}, "time_range": "-24h",
 "ambiguities": [...], "needs_confirmation": true, "original": "..."}
```

## How it works

| Part | Done by | Why |
|---|---|---|
| IPs, CIDRs, CVEs, MITRE ids, rule ids, ports, hashes, domains, users/hosts, time range | **code** (patterns) | facts can't be hallucinated or mistyped |
| Which task(s) the user wants + a short description of each | **LLM** (optional) | the fuzzy part |
| Validation | **code** | only known task types; details that name an identifier the user never typed are dropped |
| Fallback | **code** (keywords) | no LLM, a failed call or an unusable reply never blocks a request |

Task types: `investigate`, `explain_alert`, `create_rule`, `create_dashboard`,
`detection_gaps`, `question`. At most 4 tasks, in the order the user wrote them.

The agent receives the user's original words **plus** the spec, and is told the words win
on any conflict. Only the user's text is sent to the model - never alert data or logs - so
this adds no prompt-injection path.

## "Here's what I understood"

Requests with a write task (`create_rule`, `create_dashboard`) - or where the model asks a
clarifying question - are shown back before any work is done:

- **Dashboard (AI engineer):** a card with **Run it** / **Edit request**.
- **CLI:** `[Enter] run it  [e] edit request  [c] cancel`. One-shot (`-m`) and `--json` runs
  attach the spec without asking.

Everything else goes straight through with the spec attached.

A spec the browser sends back is re-validated server-side: facts are re-extracted from the
original text, and a spec whose original doesn't match the message is ignored.

## Settings

| Setting | Default | Effect |
|---|---|---|
| `PROMPT_ENHANCER` | `true` | off = requests go to the agent exactly as typed |
| `PROMPT_ENHANCER_LLM` | `true` | off = keyword classification only (no extra model call) |

CLI: `--no-enhance`, or `/enhance on|off` in the REPL.

## Cost

With the LLM on, one small extra model call per request (only the user's text, max ~700
output tokens). Extraction and the keyword fallback are free.
