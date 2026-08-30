# 0023 — What a rate limiter says when its store is gone

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

`RateLimiter#consume` returns a `Verdict`, and a `Verdict` had two states: allowed, or denied
with a `retry_after`. A limiter backed by shared storage has a third thing to say — *the store
did not answer* — and no way to say it. Its options were all lies:

| What it can return | What happens |
|---|---|
| `Verdict.allow` | Rate limiting silently turns off, under exactly the conditions an attacker can provoke |
| `Verdict.deny(…)` | The login endpoint closes for everybody: a self-inflicted outage |
| raise | `Passwords::Authenticator` does not rescue it and `ErrorHandler` does not catch it, so it surfaces as a 500 |

All three are decisions the adapter makes on the application's behalf, and none of them is
right everywhere. OPS-01 in `blueprints/maturity-validation-scenarios.md` is very high and
targeted at M4, and it asks for exactly this: "storage failure has an explicit
fail-open/fail-closed policy **chosen per endpoint**".

`Verdict` is the return type of a method v1.0 freezes, so a third state added afterwards would
break every exhaustive `case` over it. This is the deadline.

## Prior art

The ecosystem agrees on the shape of the trade-off and on where the line sits.

Laravel's `RateLimiter` facade documents `attempt`, `tooManyAttempts`, `increment`,
`availableIn` and `clear`, and configures which cache store backs it — and says **nothing at
all** about what happens when that store is unreachable. The gap is the norm rather than an
oversight in this shard alone.

Operational writing on distributed limiters is more direct, and consistent: rate limits on
general traffic should fail open so that a cache blip does not take an API down, while
**authentication must fail closed**, because allowing a request you could not meter is the
bypass the limiter existed to prevent. Both directions have real failure modes: failing closed
during an outage takes the service down for legitimate users, and failing open sends every
request downstream at the exact moment the store fell over — often *because* of load.

Which is why the choice is the application's and has to be made per endpoint, not once.

## Decisions

### 1. `Verdict` gains a third state

```crystal
Verdict.allow
Verdict.deny(retry_after)
Verdict.unavailable
```

`#unavailable?` distinguishes it. `retry_after` is deliberately absent from it: there is no
honest number to give when the limiter does not know what has already been spent.

### 2. An unavailable verdict reads as `allowed? == false`

The state is new, so some code will not know about it — a consumer's own service, a call site
added later, a branch somebody forgets. That code asks `verdict.allowed?` and nothing else.

Answering `true` there would make forgetting fail *open*: rate limiting off, silently, in the
one place nobody looked. Answering `false` makes forgetting fail closed. Neither is free, and
the direction to be wrong in is the one that refuses.

### 3. `consume` and `reset` must not raise for a storage failure

Stated on the contract, because an adapter that raises takes the choice away from everybody:
an exception is neither policy, and it arrives as a 500 rather than as either answer.

`reset` has no return value and therefore no way to report. It does not need one: a reset that
does not happen leaves somebody throttled slightly longer than they earned, which is not worth
failing a successful login over.

### 4. The shard's own call sites fail closed

Five of them, and every one is an authentication path: a login, a password reset request, and
three ways of proving a second factor. Running any of them unmetered is what an attacker gets
by overwhelming whatever stores the counts — the cheapest way to disable rate limiting is to
break the thing rate limiting depends on.

The password reset path declines **silently**, as every other outcome of that endpoint does. An
endpoint that answered differently when the limiter was down would be an account oracle with
extra steps.

### 5. Per-endpoint choice is a wrapper, not a setting

```crystal
class FailOpenRateLimiter < RateLimiter
  def consume(key : String) : Verdict
    verdict = @inner.consume(key)
    return verdict unless verdict.unavailable?

    Log.warn &.emit("rate_limiter.failing_open")
    Verdict.allow
  end
end
```

A flag on the limiter would settle the question once for the whole application, which is the
thing OPS-01 says is not good enough. A wrapper settles it once per limiter — and every service
already takes its own, so *per endpoint* falls out of wiring that exists rather than out of a
new parameter on five constructors.

It converts only the unavailable case. A genuine denial still denies, or the wrapper would be
an off switch rather than an outage policy.

Opt-in, and the default is fail-closed, because of decision 4: silence is the wrong answer on
all five of this shard's own paths. It is also inert for the default `NullRateLimiter`, which
has no store to lose — this only reaches an application that deliberately installed a
shared-store limiter, which is the same application that has an opinion about the trade-off.

### 6. `FailureReason::RateLimiterUnavailable`, not `RateLimited`

The two mean opposite things to whoever reads the trail. `RateLimited` is the limiter working:
somebody had their share. `RateLimiterUnavailable` is the limiter *broken*, which is an
operations incident and is frequently the first half of an attack. A run of the second deserves
a page; a run of the first does not.

The same argument `FailureReason` already makes for keeping `InvalidClaim` apart from
`InvalidCredential`, and the same constraint applies: `FailureReason` reaches `Failed`, which
reaches `Outcome`, which v1.0 freezes. Adding the member later would break exhaustive matches.

Invisible in the response, like every other reason. The client is told the same thing either
way.

## Consequences

**No frozen signature moved.** `RateLimiter#consume` and `#reset` keep their shapes; `Verdict`
gained a state and a predicate; `FailureReason` gained a member. All additive, and all before
the freeze rather than after it.

**No existing deployment changes behaviour.** `NullRateLimiter` and `FixedWindowRateLimiter`
never return `unavailable` — one has no store and the other's store is the process. Only an
adapter written to report the new state can produce it.

**An adapter written before v0.8 keeps its old failure mode.** It compiles unchanged, and if it
returns `allow` on an outage it still fails open. Nothing forces an existing adapter to adopt
this; what changes is that it now *can*, and that the contract says it should. The shared
contract suite cannot test it — a store failure is not triggerable through the public contract
— so this one is documentation and a `Verdict` constructor rather than an enforced invariant.
That asymmetry is worth naming: `blueprints/0021` could make the equivalent hazard fail loudly
because the state was observable through the contract, and here it is not.

**Left open:** whether the shard should ship a `Verdict.unavailable`-producing reference
adapter — a Redis limiter — so the state has an in-repository user. Today nothing in `src/`
returns it, which is the same "unexercised contract" objection `blueprints/0021` decision 7
raised against an empty scopes field. The difference is that this state has no schema and no
second half waiting on it: `FailOpenRateLimiter` exercises the conversion, and the specs
exercise all five call sites through a double. A driver-shaped adapter would drag a Redis
dependency into a shard that has just finished removing its database drivers, so it stays out.
