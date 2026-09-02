# 0029 — What throttles a second factor, and what a throttle cannot do

**Status:** accepted
**Date:** 2026-09-02
**Milestone:** v0.11

## Context

A consumer running the shipped configuration — `FixedWindowRateLimiter.new(limit: 12, window:
5.minutes)` — asked why a rate-limited TOTP submission renders the same "code was not accepted"
as a wrong one, and what other systems do. Answering the second half properly meant reading six
of them, and that reading found three things wrong with this shard rather than with the
question.

The measurements are in `blueprints/0025-maturity-validation-results.md` (MFA-01 and MFA-04,
re-measured); `tools/validation/mfa_throttle_spec.cr` is the attempt. What follows is why the
fixes take the shape they do.

### What the others actually do

Four distinct architectures, each verified from primary sources rather than recalled:

**Counter on the authenticator's row, exponential.** django-otp's `ThrottlingMixin` adds
`throttling_failure_count` and `throttling_failure_timestamp` as **columns on the device
model**, with `delay_required = throttle_factor × 2^(failure_count − 1)` and `throttle_reset()`
on success. The factor is configured per device *type* — `OTP_TOTP_THROTTLE_FACTOR`,
`OTP_STATIC_THROTTLE_FACTOR`. privacyIDEA is the same family: its failcount is per token, and
"all failcounter of all of their tokens will be reset" on success is an *opt-in* policy, which
only makes sense if they are separate by default.

The consequence worth stealing: a recovery-code device is a **different row**, so it has its own
bucket without anybody designing that. The cost is that an attacker can spread guesses across N
devices for N× the budget.

**Counter on the account's row, ending in a lock.** Devise's `:lockable` adds `failed_attempts`,
`locked_at` and `unlock_token` to the user, locks at `maximum_attempts`, unlocks by `:time` or
`:email`, and applies to `valid_for_authentication?` — every attempt, not only passwords. Its
`paranoid` mode suppresses the `:locked` message, which is the enumeration argument again.

Keycloak keeps `numFailures`, `lastFailure` and `failedLoginNotBefore` per user, with Wait
Increment, Quick Login Check, Max Wait, Failure Reset Time and an optional permanent lockout —
an increasing wait with a ceiling, not a flat window. And OTP failures feed the **same** counter
as passwords; from `OTPFormAuthenticator`:

```java
context.getEvent().user(userModel).error(Errors.INVALID_USER_CREDENTIALS);
context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challengeResponse);
```

`INVALID_USER_CREDENTIALS` is what the brute-force detector listens for.

**Bucket on the pair (address, account).** Auth0 counts failures "from a single IP address to a
single user identifier", default ten, and blocks that address for that account — cleared after
30 days, by an admin, by an unblock link, or by a password change. The property this buys: an
attacker cannot lock the real owner out, because the block lands on the attacker's address. The
cost: a botnet gets a fresh budget per address, which is why Auth0 runs a second, address-only
mechanism beside it.

**Bucket per endpoint, per address.** Supabase GoTrue gives the MFA challenge/verify endpoints
their own limit — 15 per hour, keyed by IP, answered with `429` — separate from `/verify` (360)
and `/token` (1800). Best protection for the service, weakest per-account guarantee.

### What the specifications require

NIST SP 800-63B is the only normative source here, and it is normative:

> the verifier **SHALL** limit consecutive failed authentication attempts using a specific
> authenticator on a single subscriber account to no more than 100 by disabling that
> authenticator.

It also lists, as a mitigation for locking out honest users, *"requiring the claimant to wait
after a failed attempt for a period of time that increases as the subscriber account approaches
its maximum allowance"* — the django-otp/Keycloak curve, named.

OWASP's Authentication Cheat Sheet is generic-message guidance for the **login** step
(`Login failed; Invalid user ID or password`, and revealing that an account "exists, is locked,
or is disabled" as a discrepancy factor). It says nothing about lockout wording and nothing about
OTP attempt limits.

## Decisions

### 1. The quota key carries the flow

It was `mfa:<account_id>` for verification, confirmation and recovery alike. Measured
consequence: twelve wrong TOTP codes left a **valid recovery code** refused as `RateLimited` and
a replacement factor unconfirmable. The credential that exists for "my phone is gone" was
unavailable in exactly that situation.

Now `<prefix>:<flow>:<account_id>`, with three flows, separated by **what is being guessed**:

| Flow | Credential | What the throttle is for |
|---|---|---|
| `code` | six digits, three counters accepted with `drift: 1` | the security control |
| `confirm` | six digits of a factor the caller just enrolled and whose secret they hold | the endpoint |
| `recovery` | 43 characters from a CSPRNG | the endpoint |

Separating them raises the total attempts an account can absorb, and that is the right trade
because the three are not equally guessable. Throttling a 43-character secret protects nothing
about the secret; throttling six digits is the whole defence.

`recovery_rate_limiter:` gives recovery a different *limit* as well as a different key. It
defaults to the same limiter, so the key separation alone is the fix and needs no configuration.

### 2. An attempt may carry its source address

`verify`, `confirm` and `redeem_recovery_code` take `ip : String? = nil` and consume an account
key **and** an address key, which is what `Passwords::Authenticator#quota_keys` has done since
v0.1. The asymmetry was the sharpest finding: the shard already knew to do this one step
earlier in the same login.

Every key is consumed rather than stopping at the first denial — otherwise an attacker who has
exhausted the account bucket could hammer from any number of addresses for free — and the
refusal reports the **longest** `retry_after` among those that denied, because telling a client
to come back sooner than the strictest bucket allows is telling it to be refused again.

**Not Auth0's `(address, account)` pair.** Keeping the account dimension means an attacker can
still lock the owner out; the pair would prevent that but hand a botnet a budget per address.
The account dimension is the one that bounds a distributed attack on one account, which is the
threat a second factor exists for. Recorded as a deliberate choice rather than an oversight, and
revisitable with `Verdict` already carrying everything a smarter policy would need.

`ip` is nilable throughout because an application driving these services from a CLI or a job has
no address, and inventing one is worse than the missing dimension.

### 3. A lifetime bound lives on the factor, because a limiter cannot hold one

`MFA::Factor` gains `consecutive_failures`, `last_failure_at` and `disabled_at`;
`MFA::Repository` gains `record_failure`, `clear_failures` and `disable_factor`;
`MFA::Service.new(max_consecutive_failures:)` enforces the bound and disables the factor.

A rate limiter cannot do this job, for three reasons that are all true of the shipped one: it is
keyed by account rather than by authenticator, which is what NIST names; it is a window that
resets, so there is no lifetime at all; and by default it lives in one process's memory, so the
count is not even shared. Measured, with the consumer's own configuration: **103,680 attempts
allowed in thirty days, no factor ever disabled** — about a 27% chance of guessing a six-digit
code with three counters accepted. After the bound: **100 attempts, ~0.03%**, factor disabled.

Where the state lives is django-otp's answer, and for its reason: the count belongs on the row
because that is the only place it is per authenticator, durable, and shared between processes.

**A wrong code counts against every usable factor it was offered to.** `verify` tries each, so
each saw a failed attempt. That is the literal reading of "consecutive failed attempts using a
specific authenticator", and the alternative — counting one — would let somebody with two
factors absorb twice the guesses.

**A disabled factor is not a deleted one.** `disabled_at` is a flag; `Factor#usable?` is what the
verification path and `enrolled?` now ask, and a disabled factor stays visible to
`factors()` because the person has to be told which device stopped working. Re-enabling is
deliberately not on the contract: what a deployment does about it is policy, and the two answers
it already has are `remove` plus a fresh enrolment.

**`max_consecutive_failures` defaults to `nil`, which does not meet the SHALL.** Deliberate, and
the trade is stated here rather than left implicit: a deployment upgrading into this release may
have factors carrying hundreds of accumulated typos from years of ordinary use, and switching
the bound on by default would disable those people's authenticators at once — a self-inflicted
outage on the credential that guards everything else. So it is opt-in, documented, and named in
the release notes as something new deployments should set.

### 4. An escalating limiter ships, and is not the bound

`ExponentialBackoffRateLimiter` is django-otp's curve: `factor × 2^(n−1)`, capped at
`max_delay`, one second and one hour by default. NIST names this shape as the mitigation for the
lockout a flat limit causes, and it is strictly kinder to honest users than a flat window — two
fat-fingered codes cost a second, a machine is at hours within a dozen attempts.

It does **not** replace decision 3: the delay grows without ever refusing outright, so the two
are meant to be used together. This one makes guessing slow; that one makes it stop.

A refused attempt is **not** counted, so a client in a retry loop cannot push its own next
window out exponentially and the `retry_after` it was handed stays true.

### 5. The shared limiter contract described one strategy, and was split

`it_behaves_like_a_rate_limiter` could not be run against the new limiter, because every example
in it is about a *window*: "allows `limit` attempts", "allows again once the window has passed",
and a concurrency example expecting exactly `limit` of `limit × 2` parallel attempts to pass.

That is a contract telling the next adapter author to implement the wrong thing — the mirror
image of DEV-02's complaint. So `it_behaves_like_a_rate_limiter_of_any_strategy` now holds what
every limiter owes its caller whatever curve it uses: it eventually refuses, a refusal carries
an honest `retry_after` and an allowance carries none, keys are independent, `reset` clears one
key and is idempotent, and no update is lost under concurrent consumers. Both shipped limiters
run it; the window suite runs only for the window.

## Consequences

**Breaking for a third-party `MFA::Repository`:** three new abstract methods and three new
columns. Same call as TOK-08's `expire` — taken before the v1.0 freeze rather than after it,
with the shared contract carrying eleven new examples so the rule arrives as a failing spec.

**Two migrations**, `20260902090000_add_auth_mfa_failure_counters.sql`, additive with defaults,
so an old binary keeps working against the new schema during a rollout (OPS-08's property,
untested as ever).

**The quota keys changed shape**, so counters in a shared store are orphaned by the deploy.
Harmless: they expire, and the worst case is one window of forgiven attempts.

**What this does not fix.** The shipped limiters are still per process, so a replicated
deployment multiplies every budget by the number of processes — measured at 2.2× with six
workers in OPS-01, and the answer is still a shared store behind the contract. The *lifetime*
bound is now immune to that, because it lives on the row; the per-window budget is not.

**What an application still owes its users:** telling them apart. `Failed#retry_after` is
populated for `RateLimited` precisely so a response can say when to come back, and
`RateLimiterUnavailable` means the code may have been perfectly good — rendering both as "code
not accepted" sends somebody to re-enrol a working authenticator. `docs/02-security-model.md`
says which of these is safe to reveal at which step, and why the login step's uniform message
does not carry over to a second factor whose account is already known.
