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

**Five of the seven very-high scenarios are done. OPS-01 and IDP-03 are not yet attempted.**
Nothing below is an assessment made by reading the source; each row cites what was run.

## Summary

| ID | Frequency | Target | Result | Gap to target |
|---|---|---|---|---|
| TOK-01 | Very high | M4 | **M3** | Ships and works; no packaged contract test or worked example for a consumer |
| AUT-03 | Very high | M4 | **M3** | As TOK-01 — same machinery, same gap |
| HTTP-01 | Very high | M4 | **M3** | `WWW-Authenticate` is not sent, and cannot be sent *correctly* by a consumer |
| DEV-02 | Very high | M4 | **M2** | Contract suite and doubles reachable only through the shard's private `spec/` tree |
| OPS-02 | Very high | M4 | **M2** | No typed sink; two undocumented failure modes when the sink throws |
| OPS-01 | Very high | M4 | *not yet run* | |
| IDP-03 | Very high | M4 | *not yet run* | |

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

## Not yet attempted

**OPS-01 — Distributed rate limiting.** Needs a limiter over a shared store, concurrent attempts
through more than one process, and the store-failure paths `blueprints/0023` introduced. The
contract side of it changed in v0.8, so this is the scenario most worth running next.

**IDP-03 — Existing users, UUIDs and custom account storage.** Needs an `AccountRepository`
implemented over a consumer-owned `users` table with UUID keys, soft deletion and a legacy digest
column, with no `auth_accounts` present at all.

The remaining forty-three scenarios — twenty-eight high, twelve medium, one low, two
niche-critical — are unstarted. `blueprints/0020` decision 8 already records which of them are
additive and which were checked for freeze impact; that is a different question from this one and
does not substitute for it.

## What this exercise changed

Two things, which is the argument for running it before a release rather than after.

The `Permission#minimum_assurance` interaction in TOK-01 was found by attempting the scenario,
not by reading the code — a scoped token silently denied everything until two permissions were
re-declared, and nothing in the documentation said why. It is documented now.

And HTTP-01 came out **better** than the source reading in `blueprints/0020` predicted, because
`ErrorHandler.new(login_path: nil)` turns out to satisfy half the scenario. An assessment made
from `grep` had called that gap larger than it is. The catalogue's insistence on evidence over
opinion earned its keep in both directions.
