# 0027 — Where security events go, and what happens when that breaks

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

The shard emits sixty-four events through one named `Log` source, and `README.md` catalogues them.
`blueprints/0025-maturity-validation-results.md` (OPS-02, very high, targeted at M4) attempted the
scenario from a consumer project and found two things.

**There was no typed sink.** A `Log::Backend` bound to `kemal_identity.*` receives everything, so
the scenario is *possible* — but every field arrives in a loosely-typed bag. An adapter matches on
message strings and reads keys by name, a rename is a silent breakage, and nothing says which
fields it may rely on. The pass condition is "A typed event sink is injectable".

**And a sink that raises had two failure modes, both bad.** Measured, with a backend that throws
the way a SIEM does when its queue is full:

| `Log` dispatch | What happened |
|---|---|
| `:direct` | The exception left `Passwords::Authenticator#authenticate`. Every login became a 500 |
| `:async` | `authenticate` returned, but the dispatcher fiber died with `Unhandled exception in spawn` — and **the audit trail went quiet with nothing said** |

No security bypass in either: nobody is authenticated by a broken sink. But for a security library
the second row is the serious one, and neither was documented.

## Decisions

### 1. The correlation fields are typed; the rest is not

```crystal
struct SecurityEvent
  getter name : String
  getter severity : ::Log::Severity
  getter at : Time
  getter subject : String?      # who
  getter credential : String?   # which credential proved it
  getter tenant : String?
  getter ip : String?
  getter reason : String?       # why, for the events that carry one
  getter data : Hash(String, String)   # everything else, verbatim
end
```

What a SIEM correlates on is a short, stable list, and those are getters — a rename becomes a
compile error at every consumer. The event-specific remainder stays in `data`, because typing
forty event shapes would freeze forty things to gain nothing an adapter reads.

`alarming?` answers whether the severity is `warn` or above, which is the shard's own convention
for "an operator should see this".

Nothing here can carry credential material: every field is a `String?` the shard populated
deliberately, and the emitting call sites never had a secret to pass. A spec asserts a submitted
password and the login that was typed appear nowhere in a delivered event.

### 2. A bridge, not sixty-four extra calls

`EventBridge` is a `Log::Backend` that translates each entry into a `SecurityEvent` and hands it
to the sink. `KemalIdentity.event_sink = sink` installs it.

Adding a sink call beside each of the sixty-four `Log` emissions would be sixty-four chances to
drop a field, and two things to keep in step forever. One place that knows which keys are
correlation fields is smaller and cannot drift from the `Log` output — because it *is* the `Log`
output.

The existing logging is untouched. An application that wants both keeps both.

### 3. The field names were normalised first, because they were not consistent

Reading the emissions to write the bridge is what found it: `subject:` in twenty-eight places and
`account:` in four, both meaning the account id; `session:` for what `authz.denied` already called
`credential:`.

A bridge could have papered over that with aliases. Renaming at the source is better — the `Log`
output an operator greps is now consistent too — so `authz.*` events now say `subject:`, and
`session.revoked` and `session.ended` say `credential:`, which is what a session id is now that
`CredentialRef` exists.

**Amended in v0.8.2: this sweep was incomplete, and nothing was testing it.** `session.started`,
`api_token.issued` and `api_token.revoked` kept their own field names, so the three events that
*mint or kill* a credential were the three leaving `SecurityEvent#credential` nil — with the id in
the `data` bag instead, and `api_token.issued` calling it `token:`, which reads as though the
secret itself were in the log line. Found by reading a validation app's output
(`blueprints/0025`, TOK-02), not by a spec: the whole suite stayed green through the original
rename because no example asserted the convention. One now does, in
`spec/security/event_sink_spec.cr`, naming four events and the id each must carry.

### 4. A failing sink is counted, not silenced and not fatal

```crystal
def write(entry : ::Log::Entry) : Nil
  event = translate(entry)      # this shard's code: a bug here should be loud

  begin
    @sink.record(event)
  rescue Exception
    @failures += 1
  end
end
```

Three deliberate choices in that shape.

**Translation is outside the rescue.** A bug in the shard's own code should not be counted as
somebody else's sink failing.

**`rescue Exception`, named rather than bare.** `src/CLAUDE.md` bans a blanket rescue and the ban
is right; this is not the exception to it. What is being caught is third-party code, everything
raisable in Crystal is an `Exception`, so naming it is exhaustive rather than blanket. The hygiene
spec enforces the ban and this passes it honestly.

**Nothing is logged from in here.** Reporting a logging failure through the logger the sink is
attached to is how a backend recurses into itself. `#failures` is the report, and it is the thing
to alarm on: a broken SIEM feed shows up as a rising number rather than as an absence noticed
weeks later.

The bridge dispatches `:async`, so a slow sink does not sit on the request fiber — which is safe
only because of the isolation above, since an unhandled exception on the dispatcher fiber is what
killed the trail in the measurement.

### 5. `Log` remains the fallback, and that is the answer to "cannot bypass security"

A broken sink loses the SIEM feed and nothing else. The security decision was made and recorded
through `Log` before the bridge ran, so the operator's existing log pipeline is unaffected — the
audit trail does not go quiet, only its copy does, and the counter says so.

## Consequences

**Measured from the consumer project, after:**

| Attempt | Result |
|---|---|
| implement `SecurityEventSink`, read `event.subject` as a getter | works |
| a dead SIEM during a login | login refused on the credential, `InvalidCredential` — not on the sink |
| a dead SIEM across two events | `bridge.failures == 2` |
| a healthy sink beside a broken one | keeps receiving |

**Breaking for anyone reading the log field names.** `authz.*` events say `subject` rather than
`account`; `session.revoked` and `session.ended` say `credential` rather than `session`. A log
pipeline keyed on the old names needs updating.

**Not versioned.** The pass condition asks that "event names and required fields are versioned",
and they are catalogued rather than versioned — a rename is a compile error for a consumer reading
`SecurityEvent`'s getters, but the names in `data` and the event names themselves are documented
strings. Recording that as the remaining gap rather than inventing a scheme for it.

**Documentation owed.** The `README.md` event catalogue needs the sink, the two normalised field
names, and `#failures` as the thing to alarm on. Not written here: that file is being edited
elsewhere.

One more item is owed to that same file, recorded here because this is where the list started:
the credential-precedence section an earlier commit added is gone from the current README, and
now lives in `docs/04-kemal-integration.md`.

The fail-open ownership example this list used to name is **no longer there** — the README rewrite
removed the section entirely. The guidance moved to `docs/02-security-model.md`, and
`examples/ownership/app.cr` now carries the fail-closed version with the wrong line quoted beside
it, which is a better home than either.
