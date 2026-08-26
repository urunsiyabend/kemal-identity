# 0013 — Execution contexts are optional, and the Crystal floor is 1.4

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

Two things worth noting. The failure at 1.3.0 is **inside Kemal**, not this shard, so 1.4.0 is
where a dependency stops us rather than where our own code does. And the example count differs
by one because the executor's spec asserts different things in each mode — dispatching on 1.21,
refusing-without-opt-out below it.

`docs/00-scope.md`'s rule is "lower until the suite fails, then set the floor one minor above",
which gives **1.4.0**. CI runs 1.21.0, 1.14.0 and 1.4.0, so the floor is a tested claim.

Formatting and linting run on the main line only: `crystal tool format` changes its output
between releases, so checking it on an old compiler tests the compiler rather than the code.

## Two floors invented by the test suite, removed

Both were cases of a test convenience deciding what the library supports.

**`WaitGroup`** arrived in Crystal 1.13 and was used by five concurrency specs. It set the floor
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

- The floor drops from 1.21.0 to 1.4.0, and every release in between is tested.
- Applications below 1.21 get all the authentication behaviour and must decide explicitly about
  the hashing executor. The README says so under Requirements rather than in a footnote.
- `examples/browser_session/app.cr` shows the conditional wiring, so the trade-off appears in
  the code somebody copies.
