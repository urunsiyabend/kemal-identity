# 0010 — Rate limiting: consume before verifying, and key on two things

## Status

Accepted, 2026-08-25. Implemented in `src/kemal_identity/rate_limiter.cr` and
`src/kemal_identity/passwords/authenticator.cr`.

## The shape of the contract: `consume` and `reset`

`docs/05-testing.md` gives two rules that look like they describe different methods — "the
login path consumes before verifying the password, not after" and "a failure penalises and a
success resets" — and the obvious contract from them is `check` plus `penalise`.

That contract is wrong, and the reason is the first rule. Bcrypt verification is tens of
milliseconds of CPU **by design**; Crystal's own bcrypt documentation says to rate-limit the
endpoints that verify hashes because they are an easy denial-of-service target. A limiter that
penalised only *failures* would have already paid for the hashing before deciding to penalise.
The attacker never needs to succeed, so the lever survives.

So the contract is:

- `consume(key) : Verdict` — counts the attempt **and** judges it, ahead of any lookup or
  hashing.
- `reset(key)` — clears the count once someone has proved they are the account holder.

A failure penalises by simply not being reset. Both documented rules hold, and the expensive
work is behind the gate rather than in front of it.

`spec/security/rate_limiting_spec.cr` asserts this three ways: a denial performs no
verification (counting hasher), no account lookup (counting repository), and — with real
bcrypt — costs less than a fifth of a real attempt.

## Two keys, not one

`Passwords::Authenticator` consumes against both a login-derived key and a source-address key,
and denies if either does.

Either alone is close to useless. Credential stuffing is distributed by nature, so an
address-keyed limit barely touches it — that is what the login key is for, and it is why
`docs/05-testing.md` requires that "an account-keyed denial applies across source addresses".
Password spraying is the mirror image: one host, many logins, no single login tried twice —
which the login key never sees and the address key catches.

Both keys are consumed even when the first denies. Short-circuiting would let an attacker
spend somebody else's quota while preserving their own, and would make the order of the checks
observable.

The login key is `SHA-256(tenant_id + NUL + normalized_login)`. Hashed, so a limiter's storage
can answer "is this login under attack" without retaining the address somebody typed — the
claim made in `blueprints/0007-audit-events-omit-the-login.md`, now enforced by a spec that
asserts the key contains no part of the login. Tenant-scoped, because the same login in two
tenants is two accounts. Normalised, so `ADA@EXAMPLE.COM` and `  ada@example.com ` share a
counter rather than granting an attacker a fresh allowance per spelling.

## The correct password is throttled too

Once the limit is reached, every attempt is denied — including the right one.

Letting the correct password through would make the throttle an oracle: an attacker watching
which attempt is *not* refused learns they guessed correctly. It would also not be a throttle.

## `NullRateLimiter` is the default, and that is a real gap

`docs/06-roadmap.md` asks for the contract and a null implementation in v0.1, and
`docs/02-security-model.md` lists "Rate limiting on the password verification path" as a
release blocker. Those pull in opposite directions: shipping only a no-op means the blocker is
satisfied by a seam rather than by any actual limiting.

The shard cannot pick a limit on an application's behalf — a public consumer site and an
internal tool with nine users want wildly different numbers — and a default that silently did
or did not share state across processes would be worse than none.

So: `NullRateLimiter` remains the default, **and** `FixedWindowRateLimiter` ships alongside it
as a usable single-process option. That also makes the contract testable: a shared contract
spec with only a no-op implementation to run against asserts nothing.

`NullRateLimiter` deliberately does not satisfy the limiting contract spec, and has its own
spec asserting it allows everything. **The README says plainly that rate limiting is off
unless an application turns it on**, rather than leaving that to be discovered.

## `FixedWindowRateLimiter`, and what it does not do

Two honest limitations, both documented on the class and both with specs:

- **Per process.** Two processes have two counters, so the effective limit is
  `limit × processes`. Behind a load balancer that is usually not what was intended; a shared
  store behind the same contract is the answer.

  What that store does when it is *unreachable* was not settled here, and could not be: `Verdict`
  had no way to say it. `blueprints/0023-rate-limiter-store-failure.md` adds the third state and
  the fail-closed default.
- **Fixed window, anchored to the first attempt.** Up to `2 × limit` attempts can land within
  seconds by filling a window about to elapse and then filling the next as it opens. There is a
  spec demonstrating the burst, so the paragraph does not have to be taken on trust.

It also caps the number of tracked keys. Without that, an attacker mints one key per login
guessed until the process runs out of memory — turning the defence into the vulnerability.
When the cap is reached, elapsed windows are dropped first and the oldest live ones after:
forgetting a live counter grants a few extra attempts, whereas refusing to record new ones
would let an attacker pin the table and disable the limiter for everybody else.

## A spec of mine was wrong here too

The first version of the boundary spec advanced the clock 59 seconds *before* the first
attempt, then expected a burst. It failed — because the window opens on the first attempt, not
on a calendar boundary, so the window had simply started late. The implementation was right and
the class documentation was imprecise; both the spec and the comment were corrected to describe
what actually happens.
