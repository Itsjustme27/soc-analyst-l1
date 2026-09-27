# Sample log events

Real log lines used as logtest input. These are **events**, never rule XML.

`logtest` is a per-event decoder+rule tester: the request body carries
`{"log_format": ..., "location": "master->/var/log/auth.log", "event": "<one of these>"}`.
Putting a `<rule>`/`<if_sid>` fragment in `event` can only ever come back
`No decoder matched.` — that is a harness bug, not a manager answer.

| file | what it exercises |
|---|---|
| `sshd_failed_auth.log` | canonical sshd failed-password line. Decodes via the `sshd` decoder and fires the stock base rule **5716** ("sshd: authentication failed."). This is the line `tools/wazuh/logtest.py::preflight_decoders` asserts on before any candidate-rule result is trusted. |

A candidate rule that chains `if_sid: 5716` must fire its own id (>= 100000) on
this line once it is loaded into the ruleset. Rule **1002** (the generic
"Log collection" catch-all) firing instead means the candidate never matched —
see `tools/wazuh/logtest.py::is_catch_all_rule`.
