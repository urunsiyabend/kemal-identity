# 0025 — Maturity validation results

**Status:** in progress
**Revision validated:** `4377672` (v0.8 unreleased)
**Validator:** Claude Opus 5, driven by Siyabend Urun
**Date:** 2026-08-29

## How this was run

`blueprints/maturity-validation-scenarios.md` deliberately carries no result for this library,
and it asks for evidence rather than opinion: *"Record evidence — code, compiler errors, queries
and test output — instead of recording only an opinion."*

So every scenario below was **attempted from a separate consumer project**, outside this
repository, depending on the shard the way an application does:

```yaml
name: consumer_app
dependencies:
  kemal_identity:
    path: ../kemal_identity
  sqlite3:
    github: crystal-lang/crystal-sqlite3
```

`shards install` resolved cleanly and the consumer had to declare `sqlite3` itself, which is
OPS-07 behaving as v0.7 intended.

Results are recorded here rather than in the catalogue so that the catalogue stays what it says
it is — a document with no result for any particular library — and so this one can be re-run
against a later revision without rewriting it.

**All seven very-high scenarios are done.**
Nothing below is an assessment made by reading the source; each row cites what was run.

## Summary

| ID | Frequency | Target | Result | Gap to target |
|---|---|---|---|---|
| TOK-01 | Very high | M4 | **M3** | Ships and works; no packaged contract test or worked example for a consumer |
| AUT-03 | Very high | M4 | **M3** | As TOK-01 — same machinery, same gap |
| HTTP-01 | Very high | M4 | **M3** | `WWW-Authenticate` is not sent, and cannot be sent *correctly* by a consumer |
| DEV-02 | Very high | M4 | **M2** | Contract suite and doubles reachable only through the shard's private `spec/` tree |
| OPS-02 | Very high | M4 | **M2** | No typed sink; two undocumented failure modes when the sink throws |
| OPS-01 | Very high | M4 | **M3** | The shared contract's concurrency example passes for an adapter that over-allows across processes |
| IDP-03 | Very high | M4 | **M3** | The shared `AccountRepository` contract cannot be run by a single-tenant adapter |

---

## TOK-01 — Per-token scopes or abilities

**Result: M3.** Applicable.

Two personal access tokens were issued for one account against SQLite, one scoped
`["reports.read"]` and one `["reports.read", "releases.write"]`, and both were authenticated
through `ApiTokens::Service#authenticate`.

**Consumer code required:** about 60 lines, all of it wiring — repositories, a role catalogue,
two permissions declared at `ApiToken` assurance. Issuing a scoped token is one argument:
`api.issue(account, "reporting", scopes: ["reports.read"])`.

**Core files reopened or copied:** none.

**Public contracts used:** `SQLite::AccountRepository`, `SQLite::ApiTokenRepository`,
`SQLite::AuthzRepository`, `ApiTokens::Service`, `Authz::RBAC`, `Authz::RoleCatalog`,
`Authz::PermissionRegistry`, `Principal#credential`.

**Hot-path cost:** measured, not argued. `ApiTokens::Repository` was wrapped in a counting
decorator — itself written from the consumer project with no friction, which is evidence for
OPS-04 — and `#find_by_digest` was called exactly **once** per authentication. That single
lookup produced the identity, the token id and the scopes together, which is the pass condition
*"No second token lookup is required merely to rediscover the token ID."*

**Failure behaviour:** the reporting token was refused `releases.write` with
`DenialReason::OutOfScope` while the account itself holds the permission. A token attenuated to
`[] of String` was refused everything, so the fail-closed edge of the `nil`-versus-empty
distinction holds from outside.

**Observed friction, and it is the one thing that would have stopped a real reader:**
`Permission#minimum_assurance` defaults to `Password`, and `AssuranceLevel::ApiToken` is below
it, so a permission left at the default is unreachable by *any* token however wide its scopes.
Until both permissions were declared at `ApiToken` assurance, every scoped request was denied
with `InsufficientAssurance` and the scopes looked broken. This is documented in the README as
of v0.8 — because this validation is what made it obvious that it had to be.

**Smallest change that would reach M4:** a packaged contract test a consumer can run against
their own token store's scope handling (which is DEV-02), and a worked example. The behaviour
itself is complete.

---

## AUT-03 — Token permissions attenuate account permissions

**Result: M3.** Applicable. Validated by the same run as TOK-01, since it is the same mechanism
seen from the authorization side.

**Pass conditions checked:**

- *"Effective permission is an intersection, never a union"* — the reporting token was refused
  `releases.write` that its owner holds (intersection narrowing), and a token naming a
  permission its owner was **not** granted received `NotPermitted` rather than access, so a
  scope cannot widen. Both directions asserted.
- *"a session without token scopes is not accidentally denied"* — a browser-session principal
  carries `credential.scopes == nil`, which reads as unattenuated and denies nothing.
- *"a token with `*` does not grant permissions added in a future release"* — there is no
  wildcard. `["*"]` is a scope named `*` and matches nothing; unrestricted is `nil`.

**Gap to M4:** as TOK-01.

---

## HTTP-01 — Standards-compliant API-only 401/403 responses

**Result: M3.** Applicable.

A real Kemal server was built in the consumer project, run, and probed with `curl` — not
simulated in-process, because the question is what a client actually receives.

**What was measured:**

| Request | Response |
|---|---|
| No credential, no `Accept` | `302 Found`, `Location: /login` |
| No credential, `Accept: application/json` | `401`, `{"error":"authentication required"}` |
| `Authorization: Bearer garbage` | `401`, same body |
| Valid bearer | `200` |
| Any of the above | **no `WWW-Authenticate` header** |

Two defects, and one of them turned out to be smaller than reading the source suggested.

**The redirect is fixable by the consumer, in one argument.**
`ErrorHandler.new(login_path: nil)` produces `401` with a JSON body regardless of `Accept`,
which satisfies *"API-only mode never redirects"*. The default is the browser-shaped one and
content negotiation is inferred from `Accept`, so a `curl` or a Go client with no `Accept`
header gets a redirect until the application says otherwise. That is a documentation and default
problem rather than a capability gap.

**The missing challenge is fixable too, but not *correctly*.** A consumer can replace
`ErrorHandler` entirely — the shard documents this — and emit RFC 6750 headers in about eighteen
lines by rescuing `NotAuthenticatedError`, `FreshAuthenticationRequiredError` and
`ForbiddenError`. Verified working: `WWW-Authenticate: Bearer realm="api", error="invalid_token"`
on the 401, valid tokens still served.

But the consumer's handler cannot emit the *right* `error=` code on a 403. `ForbiddenError`
carries no reason — deliberately, so that a denial cannot become an enumeration oracle — so the
handler has to answer `insufficient_scope` for every 403 including "not a member of this
tenant", which is not what RFC 6750 means by it. **Only the shard knows the reason, so only the
shard can emit an accurate challenge.** That is the strongest argument found for shipping this
rather than documenting the workaround.

**Smallest change that would reach M4:** send `WWW-Authenticate` from `ErrorHandler`, derived
from the denial reason it already has; and let a route subtree declare itself API-only rather
than inferring it from `Accept`.

---

## DEV-02 — Consumer-owned test doubles and shared contracts

**Result: M2.** Applicable.

Three attempts, in the order a consumer would make them.

**Attempt 1 — require the one contract you need.** Worked, for a contract with no dependencies:

```crystal
require "../lib/kemal_identity/spec/contract/clock_contract"
it_behaves_like_a_clock { FrozenClock.new(Time.utc) }
```

2 examples, 0 failures.

**Attempt 2 — the same, for the contract an adapter author actually wants.** Failed to compile:

```
In lib/kemal_identity/spec/contract/api_token_repository_contract.cr:7:9
Error: undefined constant KemalIdentity::SpecHelper::FIXED_NOW
```

The contract files carry no `require` of their own and depend on the shard's `spec_helper`
having loaded first.

**Attempt 3 — require the shard's `spec_helper`.** Worked. The full 32-example API-token
repository contract ran against `SQLite::ApiTokenRepository` from the consumer project: **32
examples, 0 failures**, including the three scope round-trip examples added in v0.8.

**Why this is M2 and not M3.** The working require is
`require "../lib/kemal_identity/spec/spec_helper"`, which is precisely what the pass condition
forbids: *"they do not depend on repository-private spec files"*. It also pulls in nineteen test
doubles and all thirteen contracts whether or not they are wanted, and it is documented nowhere.

**A second, sharper form of the same gap.** `KemalIdentity::Testing::MemoryAccountRepository`
and the other in-memory doubles are **not reachable** from a consumer that requires only
`kemal_identity`:

```
Error: undefined constant KemalIdentity::Testing::MemoryAccountRepository
```

They live under `spec/support`, not `src`. This was hit incidentally while validating OPS-02 —
which needed a fake account repository and could not have one without reaching into the private
tree.

**Observed friction:** the block signature is undocumented. `it_behaves_like_an_api_token_repository`
hands the block an array of accounts and expects a repository already wired to a store containing
them, including their `disabled_at`. Discovering that took a failing example
(*"the joined account status carries the account's disabled_at"*) and a read of the contract's
source.

**Smallest change that would reach M3:** move the contracts and the doubles under
`src/kemal_identity/testing/`, reachable as `require "kemal_identity/testing"`. M4 additionally
wants the block contracts documented.

---

## OPS-02 — Security event sink and audit correlation

**Result: M2.** Applicable.

**What works.** A consumer can subscribe to the shard's events with a Crystal `Log::Backend`
bound to `kemal_identity.*`, receive them, and read structured fields — a failed login arrived
with `reason: "InvalidCredential"`. The password submitted in the attempt did **not** appear
anywhere in the rendered entries, so *"raw credentials and sensitive claims are structurally
unavailable"* holds. The README documents the event catalogue with names and fields.

**What does not.** There is no typed sink to implement. The pass condition is *"A typed event
sink is injectable"*, and every event arrives as a `Log::Entry` whose `data` is a loosely-typed
bag. A SIEM adapter therefore matches on message strings and reads keys by name, so a renamed
field is a silent breakage rather than a compile error, and *"event names and required fields
are versioned"* has nothing to hang on.

**What is worse, and was not predicted.** The pass condition *"logging failure cannot bypass
security"* was tested with a backend that raises, which is what a SIEM does when its queue is
full or its socket is gone. Both dispatch modes were measured:

| Backend dispatch | What happens |
|---|---|
| `:direct` | The exception propagates out of `Passwords::Authenticator#authenticate`. Every login becomes a 500 |
| `:async` | `authenticate` returns normally, but the dispatcher fiber dies with `Unhandled exception in spawn` — and the audit trail goes quiet |

No bypass, in either case: nobody is authenticated by a broken sink, so the security property
holds. But for a security library the second row is the serious one — **the audit trail stops
and nothing says so.** Neither mode is documented, and the shard's only guidance is to plug a
backend into `Log`.

This is the same fail-open/fail-closed choice `blueprints/0023` gave the rate limiter, in a
place that has neither the policy knob nor the documentation.

**Smallest change that would reach M3:** document the two dispatch modes and their consequences.
M4 wants a typed `SecurityEvent` sink with declared failure semantics, versioned event names, and
correlation without global state.

---

## OPS-01 — Distributed rate limiting

**Result: M3.** Applicable.

A limiter over a store more than one process can see was written from the consumer project —
SQLite rather than Redis, so the test needs no server and the atomicity question stays concrete.
It implements the two-method contract and reopens nothing.

**The shard's own contract passes.** `it_behaves_like_a_rate_limiter` was required from the
consumer project and run against the adapter: **12 examples, 0 failures**, alongside six of this
validation's own.

**And that was not enough.** The catalogue asks for concurrent attempts through *different
processes*, so six processes were run against one store, twenty attempts each, global limit ten:

```
süreç 1: allowed=1     süreç 4: allowed=6
süreç 2: allowed=11    süreç 5: allowed=2
süreç 3: allowed=0     süreç 6: allowed=2
--- TOTAL allowed: 22 (limit 10, 120 attempts) ---
```

**Twenty-two allowed against a limit of ten**, and one process alone allowed eleven. The same
adapter had just passed the shard's contract, including its concurrency example — which runs
`limit * 2` **fibers in one process**, where crystal-db serialises through the pool and the
race never happens.

The cause was the adapter's, not the shard's: no `busy_timeout`, no `journal_mode=WAL`, and no
`BEGIN IMMEDIATE`, so contended writes failed with `SQLITE_BUSY`, were converted to
`Verdict.unavailable` by the adapter's own rescue, and the window reset behaviour did the rest.
With those three fixed:

```
süreç 1: allowed=10    (all others: 0)
--- TOTAL: 10 (limit 10) --- counter: 120
```

Exactly the limit, every attempt counted. **So the contract does permit a correct distributed
implementation** — which is what this scenario asks — and the pass conditions hold against the
corrected adapter: consume-and-decide atomic across processes, `retry_after` stable across
repeated denials, and the limiter never sees the login somebody typed (asserted against the
stored keys; the shard hashes it first).

**Store failure.** Two simulations were tried and rejected before one worked, and both are worth
recording. Pointing the adapter at a path that never existed raises `DB::ConnectionRefused` from
`DB.open` — construction, not `#consume` — so the adapter's rescue never runs. Closing the
database and querying again did **not** fail, because crystal-db's pool opens a fresh connection.
Dropping the table is a real store-level failure that reaches the query, and there the adapter
converts it: `Verdict.unavailable`, `allowed? == false`, no `retry_after`. A login against it
failed closed with `FailureReason::RateLimiterUnavailable`, and the same limiter wrapped in
`FailOpenRateLimiter` carried on — the per-endpoint choice `blueprints/0023` designed, exercised
from outside.

**The gap to M4 is specific and it is the shard's to close.** An adapter author who runs the
shared contract and sees twelve green examples has been told their limiter is correct across
processes, and it may not be. Either the contract needs a cross-process harness, or it needs to
say plainly that it does not test that — and the guidance a distributed adapter needs (take the
write lock up front; make a contended write wait rather than report the store unavailable)
belongs next to the contract rather than in a consumer's second attempt.

---

## IDP-03 — Existing users, UUIDs and custom account storage

**Result: M3.** Applicable.

An adapter was written over a consumer-owned `users` table: UUID primary keys, `email` plus a
lowercased `email_lower`, `deleted_at` for soft deletion, `auth_epoch` under the application's
own name, and a column of SHA-256 digests from whatever came before. **`auth_accounts` is never
created** — asserted against `sqlite_master`, which lists `users` and does not list it.

**Pass conditions, all four measured:**

- *"A repository adapter is sufficient"* — five methods, about seventy lines, no core class
  touched. A login against the application's own table returned an `Authenticated`.
- *"canonical subject conversion has one documented boundary"* — `Principal#subject` came back as
  the application's UUID, unconverted. Nothing casts it anywhere.
- *"soft-deleted/disabled users fail closed"* — `deleted_at` was mapped onto the shard's
  `disabled_at` in the adapter's row reader, and a soft-deleted user was then refused **with the
  correct password**, reason `DisabledAccount`, without the application writing a check.
- *"lazy digest migration is possible"* — `MigratingHasher` with bcrypt current and a
  consumer-written `Sha256Verifier`: a login against a `sha256$…` digest succeeded, and the row's
  scheme was `bcrypt` immediately afterwards. Nobody was sent through a password reset. The shard
  ships no legacy verifier implementations, deliberately, and writing one took nine lines.

Login normalisation also worked in the application's favour: `"  ADA@Example.COM "` resolved
against the existing lowercased column, because the shard normalises before the adapter is asked.

**Then the shard's own `AccountRepository` contract was run against it: 25 examples, 22 passed.**
The three failures are all in the tenancy group:

```
#find_by_login tenancy matches only the given tenant
#find_by_login tenancy matches only the null tenant when given nil
#find_by_login tenancy does not treat a nil tenant as a wildcard
```

**The contract requires multi-tenant behaviour, and this adapter is single-tenant.** Its table
has no tenant column, and `find_by_login` answers `nil` for any tenant-scoped question rather
than answering it from untenanted rows — which is the safe behaviour for the application it
belongs to.

That is the gap, and it lands on the scenario most likely to matter: IDP-03's persona is a mature
application with a `users` table, and most such applications are single-tenant. They can write the
adapter — that part works — but they cannot use the shared contract to check it without adding a
tenant column they do not want. DEV-02's whole value is unavailable to exactly the adapters most
likely to be written.

**Smallest change that would reach M4:** let the contract be told the adapter is single-tenant —
a `tenanted: false` argument, or the tenancy examples split into a separate opt-in group — plus a
worked example of the whole migration, which is what `blueprints/0019` describes and this
validation had to reconstruct.

---

## Not yet attempted

The remaining forty-three scenarios — twenty-eight high, twelve medium, one low, two
niche-critical — are unstarted. `blueprints/0020` decision 8 already records which of them are
additive and which were checked for freeze impact; that is a different question from this one and
does not substitute for it.

## What this exercise changed

Four things, which is the argument for running it before a release rather than after.

The `Permission#minimum_assurance` interaction in TOK-01 was found by attempting the scenario,
not by reading the code — a scoped token silently denied everything until two permissions were
re-declared, and nothing in the documentation said why. It is documented now.

And HTTP-01 came out **better** than the source reading in `blueprints/0020` predicted, because
`ErrorHandler.new(login_path: nil)` turns out to satisfy half the scenario. An assessment made
from `grep` had called that gap larger than it is. The catalogue's insistence on evidence over
opinion earned its keep in both directions.

The other two are about the shared contracts, and they point the same way. A rate limiter passed
all twelve of the shard's contract examples while allowing 2.2× its global limit across
processes, and an `AccountRepository` over a real application's `users` table could not run the
contract at all because three examples require a tenant column it has no reason to have. Both
say the same thing: **the contracts are the shard's main promise to adapter authors, and they are
currently narrower than they appear.** That is a stronger argument for DEV-02 than DEV-02's own
result was — a suite that is hard to reach is one problem, and a suite that is reachable but
silent on the property you needed is a worse one.

## Re-running this

`tools/validation/` holds every attempt. The multi-process rate-limit check is not a spec: build
`ops01_worker.cr` and `ops01_setup.cr`, then run several workers against one database file and sum
what they report. The numbers in the OPS-01 section came from six workers, twenty attempts each,
a global limit of ten.
