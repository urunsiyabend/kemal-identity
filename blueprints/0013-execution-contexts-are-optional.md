# 0013 — Execution contexts are optional, and the Crystal floor is 1.12

## Status

Accepted, 2026-08-26. Implemented in `src/kemal_identity/passwords/hashing_executor.cr`.

Supersedes the Crystal floor recorded in `docs/00-scope.md` on 2026-08-25, which was 1.21.0.

## Context

The first measurement put the Crystal floor at **1.21.0**. One class caused it:
`HashingExecutor` uses `Fiber::ExecutionContext::Parallel`, which is the default concurrency
model from 1.21 and available earlier only behind `-Dexecution_context`. Crystal 1.20 could not
compile the shard at all.

1.21 was three months old at the time. A floor that new rules out most deployments, and it was
set by a performance optimisation rather than by anything the authentication logic needs.

## Decision

The executor is compiled conditionally, and **refuses to run inline unless told to**.

```crystal
{% if Fiber.has_constant?("ExecutionContext") %}
  # real dispatch onto a dedicated Parallel context
{% else %}
  # constructor raises ConfigurationError unless allow_inline: true
{% end %}
```

A feature check, not a version comparison: an application building on 1.20 with
`-Dexecution_context` gets the real dispatcher, which a version test would have denied it.

### Refusing beats degrading

The tempting shape is a silent fallback — no execution contexts, so run the hash on the calling
fiber and say nothing. That is the wrong default and it is worth being explicit about why.

The executor exists for one measured property: at 50 concurrent logins, unrelated-request p99
latency is **1.17 ms** with dispatch and **2,176 ms** without. An application that configures
`HashingExecutor` has asked for that property. Silently handing back an object that does not
provide it means the protection disappears on an older compiler with nothing in the logs, in
the types, or on screen to say so.

So the constructor raises, and names the three ways out:

```
KemalIdentity::ConfigurationError: HashingExecutor needs execution contexts, which this
Crystal (1.20.0) does not provide. Upgrade to Crystal 1.21, build with -Dexecution_context,
or pass allow_inline: true to hash on the request fiber and accept that a burst of logins
will slow unrelated requests.
```

`allow_inline: true` is the deliberate opt-out — named for what it does, one grep away in
review, and impossible to arrive at by accident. Same shape as `allow_insecure` on the cookie
configuration, and for the same reason. `#dispatching?` reports which mode an instance is in.

## The measured floor

With the executor guarded, the suite was run downwards under Docker against real PostgreSQL:

| Crystal | Result |
|---|---|
| 1.21.0 | 739 examples green |
| 1.20, 1.18, 1.16, 1.14, 1.13, 1.12, 1.10, 1.8, 1.6, 1.4 | 740 examples green |
| 1.3.0 | fails — `can't infer the type of instance variable '@limit' of Kemal::ParamParser::LimitedBodyIO` |

The example count differs by one because the executor's spec asserts different things in each
mode: dispatching on 1.21, refusing-without-opt-out below it.

### A green suite was not the floor, and CI caught it

That table says 1.4. The floor is **1.12**, and the gap between the two is the useful part of
this record.

`crystal spec` never compiles `Kemal.run` — the spec application drives Kemal's handler chain
in memory through spec-kemal and never starts a server. The example does. On Crystal 1.11 and
below, `Kemal.run` fails with `undefined method 'on_terminate' for Process.class`:
`Process.on_terminate` arrived in Crystal 1.12, and Kemal 1.13 uses it.

So on 1.4 through 1.11 the suite is green and **no actual application compiles**. The floor is
where a real application works, not where the tests happen to.

The local measurement ran only `crystal spec`, so it reported 1.4 and the tag was cut on that
basis. CI ran the example build as well and failed on exactly that step, before the release was
final; the tag was withdrawn and re-cut at 1.12. CI now builds the example and the benchmarks on
**every** matrix entry, so a floor can no longer be established by the test suite alone — which
is the third time in this project that a test convenience tried to set the supported floor.

`docs/00-scope.md`'s rule is "lower until the suite fails, then set the floor one minor above".
Read literally against `crystal spec` it gives 1.4; read against what an application needs it
gives **1.12**. The second reading is the one that means anything. CI runs 1.21.0, 1.14.0 and
1.12.0.

Formatting and linting run on the main line only: `crystal tool format` changes its output
between releases, so checking it on an old compiler tests the compiler rather than the code.

## Two floors invented by the test suite, removed

Both were cases of a test convenience deciding what the library supports.

**`WaitGroup`** arrived in Crystal 1.13 and was used by five concurrency specs and the
benchmark. It set the floor
at 1.13 while the library itself needed nothing of the sort. Replaced with
`spec/support/fiber_join.cr`, a buffered-channel barrier that works on every supported version.
The concurrency specs were re-verified afterwards against the read-then-write mutation from
`blueprints/0011-action-token-atomicity.md` — they still catch it, three runs out of three,
which mattered because the swap touched the exact machinery those specs rely on.

**`query`** is a Kemal 1.13 route DSL used by the integration spec, and it had the same effect
on the Kemal floor. Now compiled only where `HTTP_METHODS` contains the verb.

The general rule: **when the suite fails on an old version, find out whether the library or the
test failed.** Twice out of three times here, it was the test.

## Consequences

- The floor drops from 1.21.0 to 1.12.0, and 1.21.0, 1.14.0 and 1.12.0 are tested on every push.
- Applications below 1.21 get all the authentication behaviour and must decide explicitly about
  the hashing executor. The README says so under Requirements rather than in a footnote.
- CI builds the example and the benchmarks on every matrix entry, not only on the main line.
- `examples/browser_session/app.cr` shows the conditional wiring, so the trade-off appears in
  the code somebody copies.
