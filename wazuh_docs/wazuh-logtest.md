# Wazuh logtest analysis workflow

How runtime verification of a new rule works, and the exact semantics of the
logtest API - ground truth for the `verify_rule_deployment` and
`test_wazuh_rule` tools.

## The request shape (get this wrong and everything after is noise)

logtest is a per-EVENT decoder+rule tester. There are two ways to reach it and
they take the same JSON body:

- unix socket: `/var/ossec/queue/sockets/logtest`
- manager REST: `PUT /logtest` (it is a PUT; `POST` is not the documented verb)

```json
{
  "log_format": "syslog",
  "location":   "master->/var/log/auth.log",
  "event":      "Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2",
  "token":      "<session token from the previous call; omit on the first>"
}
```

Three fields carry all the meaning, and all three change the answer:

- **`event` is ONE real log line.** Nothing else. A `<rule>` block, a
  `local_rules.xml` file, a single line of one, `<if_sid>5716</if_sid>` - none
  of these are log events. The manager can only answer them all with
  `No decoder matched.`, so a harness that sweeps a rules file through `event`
  produces a stream of identical fake verdicts that look exactly like a real
  result. `tools/wazuh/xmlio.py::ensure_real_event` refuses rule XML at every
  boundary that feeds `event`; the canonical sample line lives in
  `tests/fixtures/sample_events/sshd_failed_auth.log`.
- **`log_format`** picks the decoder family: `syslog`, `json`, `eventlog`, ...
  A syslog line submitted as `json` never decodes.
- **`location`** is `<component>-><path>` and *selects the decoder*. A bare
  `/var/log/auth.log` is qualified to `master->/var/log/auth.log`. Getting the
  component wrong is a second, quieter way to make a perfect log line come back
  "No decoder matched.".

**logtest evaluates the deployed ruleset, not a rule definition.** To test a
candidate rule you must load it into the ruleset first (merge into
`local_rules.xml`, `PUT /rules/files/local_rules.xml`, restart the manager) and
then submit a real sample log. A rule that only exists in the conversation can
never fire, no matter what you send. `test_wazuh_rule` does exactly this:
validate the XML statically, stage the rule, then make **one** logtest call with
one real event.

## Logtest session

- The first call (no `token`) starts a session and returns a `token`. Later
  calls pass it back to keep the same session.
- Close sessions with `DELETE /logtest/sessions/{token}` when done.
- A fresh session is a clean slate.

## Decoder preflight (do this before you trust any answer)

"No decoder matched" is only *meaningful* when the session actually has the
default decoders loaded (sshd, syslog, json, ...). If it does not, a perfectly
good sample log fails to decode too, and every result is silently garbage.

So: submit one known-good canonical line first and require it to decode **and**
fire its stock base rule.

- canonical line: `Dec 10 01:02:02 host sshd[1234]: Failed none for root from 1.1.1.1 port 1066 ssh2`
- stock base rule: **5716** "sshd: authentication failed."
- fixture: `tests/fixtures/sample_events/sshd_failed_auth.log`

`tools/wazuh/logtest.py::preflight_decoders` does this and raises a clear
"logtest session has no decoders loaded" error on failure. Callers must then
report **no** per-sample verdicts - filing every sample as `no_decode` is a
statement about the harness wearing the costume of a statement about the rule.
The same applies when the canonical line decodes but fires something *other*
than 5716: this is not the standard ruleset, so an `if_sid: 5716` chain cannot
be judged here at all.

## Rule 1002 is the catch-all, not a null match

**1002** ("Log collection: &lt;location&gt;", and 1005 for json) matches anything
that decoded but reached no specific rule. A sample landing on 1002 is
information: the decoder ran, the event was understood, and no rule selected
it.

- On a **negative** sample: the candidate correctly did not fire. Still a pass,
  but flag it - a negative that only ever reaches 1002 probably never exercised
  the decoder path the positive does, so it proves less than it looks.
- On a **positive** sample: the candidate's `if_sid` chain or match terms never
  selected the event. This is **not** a per-sample failure of the rule, it is a
  broken harness or an unloaded rule - report the verdict as
  `inconclusive` (never `failed`), because a `failed` reads as "this rule is
  broken" and invites deleting a working rule.
- When you stage a candidate and it comes back 1002, the usual cause is that the
  manager has not been restarted since the upload, so the new rule is not loaded
  yet. Say that; do not dress it up as a rule-behaviour result.

## Frequency rules cannot be confirmed through logtest

A `frequency`/`divide` rule only fires once its counter crosses the threshold
inside a session, and logtest does not persist that state the way analysisd
does. Measured on a live 4.x manager: 8 repeated failures through a single
session never tripped a `frequency=5` rule while the live pipeline did.

So a frequency rule's positive arm is **inconclusive** through logtest, by
construction. The parent rules and the negatives are still verified (the
negatives prove the rule does not over-fire), but never report
`verified=False` for "the frequency threshold was not reached in logtest" -
that is a false negative. Verify frequency rules by pushing real events through
analysisd and reading the alert stream, or by confirming the rule is loaded and
enabled via `GET /rules/{id}`.

## Response shape

The API answers with an `output` object containing the matched `rule` (id,
level, description, groups) and the matched `decoder` (name). Wazuh 4.7+ also
returns a top-level `alert` boolean, which is authoritative for "did anything
match". Older builds answer `{alerts: [...]}` instead. A sample that matched
nothing returns an empty `rule` and a falsy `decoder`. Treat the manager's
answer as the only source of truth when verifying.

## Practical notes

- If a sample fires rule 5715 "sshd: authentication succeeded." that is the
  SUCCESS event - a positive sample firing it means the log line decodes as a
  success, not a failure.
- Rule 5716 "sshd: authentication failed." is the base rule the canonical
  sample fires, and the natural `if_sid` parent for a custom sshd auth rule.
- "no_decode" means the log line did not decode - the sample is useless for
  verification and should be replaced with a realistic line the decoder
  actually processes. But check the preflight first: if the preflight itself
  failed, `no_decode` is a harness verdict, not a sample verdict.
- Sessions hold no useful cross-call state beyond the token, so prefer one
  fresh session per event and close it. Threading a token through a loop of
  unrelated samples only creates the illusion of accumulation.
