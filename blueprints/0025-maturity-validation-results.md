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

**All seven very-high scenarios are done, twenty-six high-frequency ones, and two medium.**
Nothing below is an assessment made by reading the source; each row cites what was run.

## Summary

| ID | Frequency | Target | Result | Gap to target |
|---|---|---|---|---|
| TOK-01 | Very high | M4 | **M3** | Ships and works; no packaged contract test or worked example for a consumer |
| AUT-03 | Very high | M4 | **M3** | As TOK-01 — same machinery, same gap |
| HTTP-01 | Very high | M4 | **M3 → M4** | Fixed after measurement: the shard sends the challenge |
| DEV-02 | Very high | M4 | **M2 → M4** | Fixed after measurement: `require "kemal_identity/testing"` |
| OPS-02 | Very high | M4 | **M2 → M3** | Fixed after measurement: a typed sink, and a failure that is counted rather than fatal or silent |
| OPS-01 | Very high | M4 | **M3** | The shared contract's concurrency example passes for an adapter that over-allows across processes |
| IDP-03 | Very high | M4 | **M3 → M4** | Fixed after measurement: `it_behaves_like_an_account_repository(tenanted: false)` |
| TOK-03 | High | M3 | **M4** | — |
| AUT-01 | High | M3 | **M3** | The no-N+1 condition needs a cache that is off by default |
| OPS-04 | High | M3 | **M3** | One repository of eight validated; reaching the contract depends on DEV-02 |
| OPS-06 | High | M3 | **M3** | Shipped adapters hard-code their own table names |
| OPS-07 | High | M3 | **M3 → M4** | Fixed after measurement: CI resolves three consumers and checks what each gets |
| DEV-01 | High | M3 | **M3 → M4** | Fixed with HTTP-01: the shard emits the accurate challenge, so a replacement handler no longer has to guess |
| TOK-07 | High | High | **M3** | Workload identities work and deprovision promptly; a password reset used to mint a link for an account that had no password |
| TOK-02 | High | High | **M3** | Fine-grained restriction works and survives a global role; the shard supplies the credential id and the target, the selection table is the application's |
| TOK-05 | High | Medium | **M3** | Four families work, but a shape may have only one owner — the chain's built-in half is not reorderable |
| TOK-04 | High | M3 | **M2 → M3** | Fixed after measurement: `bearer_authenticators:` — the contract was implementable and had nowhere to go |
| HTTP-03 | High | M3 | **M2 → M3** | Fixed after measurement: `AuthenticationHandler.new(precedence: ...)`, and remember-me survives the reversal |
| JWT-01 | High | M3 | **M2 → M3** | Fixed after measurement: `JWT.unverified_issuer`, bounded and strict |
| JWT-02 | High | M3 | **M3** | — |
| JWT-03 | High | M3 | **M3** | — |
| JWT-04 | Medium | M2–M3 | **M3** | Works, but inherits JWT-01's hand-rolled routing to get per-issuer validators |
| HTTP-07 | High | M3 | **M3** | Works and was entirely undocumented, including the trust boundary |
| DEV-03 | Medium | M2–M3 | **M3** | The claim holds and links no Kemal; there is no worked example |
| IDP-01 | High | M3 | **M2 → M3** | Provider-specific parameters ship; `Pending` still does not bind the provider |
| IDP-02 | High | M3 | **M3** | — |
| IDP-04 | High | M3 | **M3** | — |
| AUT-06 | High | M3 | **M3** | Measured across two processes; the tenant a session copies had an unbounded window and no documented trigger |
| AUT-07 | High | M3 | **M3 → M3** | Fixed after measurement: `max_age` on the step-up challenge. Freshness is still not declarable per permission |
| HTTP-02 | High | M3 | **M3 → M4** | Fixed after measurement: `PathGuard.new(credentials:)` and `ErrorHandler.new(api_prefixes:)`, with a worked example |
| OPS-03 | High | M3 | **M3** | Every seam is a contract, so instrumentation is a decorator; a sink bound before `Log.setup` was silently unbound, and can now be asked |
| TOK-08 | High | M3 | **M2 → M3** | Fixed after measurement: `expire`, so an overlap window closes on the authentication path rather than when a job runs |
| TOK-09 | High | M3 | **M2 → M3** | Fixed after measurement: `api_token_lifetime:`, refused before storage, with the retro-fit spelled out |
| MFA-01 | High | M3 | **M2 → M3** | Fixed after measurement: `remove(factor_id, account_id)` and a last-factor guard; removing a factor by id alone would remove anybody's |
| MFA-04 | High | M3 | **M2 → M3** | Fixed after measurement: `AssuranceLevel::Recovery`, and the recovery-code alphabet, of which 46.8% were unredeemable |

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

### Fixed — re-measured at M4

The first half landed and this scenario was re-run against the same running server, with the
shard's own `ErrorHandler` rather than a consumer's replacement:

| Request | Before | After |
|---|---|---|
| no credential, `Accept: json` | 401, no header | 401, `Bearer realm="api"` |
| invalid bearer, no `Accept` | **302 → /login** | **401**, `error="invalid_token"` |
| no credential, no `Accept` (browser app) | 302 → /login | unchanged |

The redirect row was not in the plan. It came out of a failing spec: a client presenting a bearer
token and no `Accept` header was being redirected, because the redirect was decided purely by
content negotiation. Content negotiation guesses whether a browser is asking; an
`Authorization: Bearer` header is the client saying so. Five existing examples had asserted that
302 — none of their comments defended it, and all five were named for the refusal rather than the
status, so 401 is the more accurate expression of what they meant.

The accuracy problem this scenario identified — that only the shard knows the denial reason, so
only the shard can pick the right `error=` code — was solved without handing the reason to the
response layer. `ForbiddenError` carries a **projection**: `"insufficient_scope"` for
`DenialReason::OutOfScope`, `nil` for everything else. The handler cannot render a reason it was
never given, which is a boundary rather than a convention.
`blueprints/0026-bearer-challenges.md` records the RFC reading behind each row, including two
gates that came from the specifications rather than from the code: the challenge is announced only
where the application accepts bearer credentials, and `insufficient_user_authentication` only
where a bearer credential was actually presented — RFC 9470 defines it as a statement about the
authentication event behind an access token, and a browser session has none.

**M4 is claimed for the challenge, and the remaining half is named rather than closed.** API-only
behaviour is still app-wide: `ErrorHandler.new(login_path: nil)` turns the redirect off
everywhere, and there is no per-subtree switch — the same parameter HTTP-02 wants on `PathGuard`.
A monolith serving a browser UI and a REST API under one handler gets one answer for both. What
changed is that the common case no longer needs it: a bearer-presenting request is never
redirected regardless.

**DEV-01 moves with it.** Its one remaining gap was that a consumer's replacement handler could
not choose between `insufficient_scope` and anything else. It no longer has to: the shipped
handler is accurate, and a replacement that wants its own envelope still gets the three typed
exceptions plus `challenge_error` on the one that has it.

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

### Fixed — re-measured at M4

That change landed, and this scenario was re-run against it. From the consumer project, with no
path reaching into the shard's `spec/` tree:

```crystal
require "kemal_identity/testing"            # doubles, fixtures, assertions
require "kemal_identity/testing/contracts"  # the shared contract specs

it_behaves_like_an_api_token_repository { |accounts| MyAdapter.new(fresh_db(accounts)) }
```

**35 examples, 0 failures.** The doubles are reachable by published name — `Testing::MemoryAccountRepository`,
`Testing::TestClock`, `Testing::FIXED_NOW`, `Testing.account`, `Testing.principal`,
`Testing.should_authenticate` — and the contracts run against a consumer's own adapter.

`KemalIdentity::SpecHelper` was renamed to `KemalIdentity::Testing` in the same pass, 446
references across 50 files: a published API should not be called after this repository's spec
scaffolding, and the doubles were already in `Testing`.

The three attempts quoted above no longer run, because the fix deleted the paths they used. They
are kept in `tools/validation/before-dev02-fix/` rather than deleted, with a note saying so — a
quoted error message whose source has been removed is worth less than one a reader can go and
look at.

**And it costs a production consumer nothing**, which was the thing to check rather than assume.
The core-only project from OPS-07 was rebuilt and its symbols counted:

| Symbol | Count |
|---|---|
| `KemalIdentity` | 53 |
| `Spec::` | **0** |
| `KemalIdentity::Testing` | **0** |

`src/kemal_identity.cr` does not require the testing tree, and `spec/unit/source_hygiene_spec.cr`
now asserts that for all four production entry points — a compile-free check, so it holds without
needing a linked binary.

**One consequence worth recording, because it was the right kind of failure.** Moving the doubles
into `src/` immediately broke three examples in `source_hygiene_spec.cr`, which enforces
`src/CLAUDE.md`'s bans across `src/`: `Testing::TestClock` reads `Time.utc`,
`Testing::DeterministicRandom` calls `Random.new`, and the contracts use `or_fail`. All three are
what those files exist to be. The scan now excludes `src/kemal_identity/testing` specifically —
one directory, not a pattern, so a violation anywhere else is still caught — and a new example
asserts the exclusion is neither empty nor swallowing all of `src/`.

**One thing the move broke, caught by CI rather than by this validation.** `bench/hashing_latency.cr`
required four files by their old `spec/support` paths and stopped compiling. The suite, the lint,
the format check and the example build all stayed green; the benchmark is compiled by a CI step
that was not re-run locally after the move. Fixed, along with every stale `spec/support` and
`spec/contract` reference in the source comments, `docs/`, and four earlier blueprints — several
of which claimed the doubles "cannot become published API **because** they live under `spec/`",
a reason that stopped being true the moment they were published. The property still holds, for a
different reason: nothing in `kemal_identity` requires the tree.

**What DEV-02 still does not have**, and why M4 is claimed anyway: the block signatures are
documented in the contracts' own comments and now in the README, but there is no compile-time
statement of them. An adapter author still learns that `it_behaves_like_an_api_token_repository`
wants its accounts persisted *with* `disabled_at` from a failing example, as this validation did.
That is a documentation refinement rather than a reachability problem, which is what the level
turned on.

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

### Fixed — re-measured at M3

`SecurityEvent` and `SecurityEventSink` shipped, fed by an `EventBridge` that translates the
events the shard already emits. Re-run from the consumer project:

| Attempt | Result |
|---|---|
| implement the sink, read `event.subject` as a getter | works — typed, not a hash lookup |
| a dead SIEM during a login | the login is refused on the credential, `InvalidCredential`, not on the sink |
| a dead SIEM across two events | `bridge.failures == 2` |
| a healthy sink beside a broken one | keeps receiving |

Both measured failure modes are gone: an exception cannot leave `authenticate`, and a failing sink
is a rising counter rather than an absence. `Log` remains the fallback, so a broken sink loses the
SIEM copy and not the audit trail.

**Writing the bridge is what found something the first pass missed.** Reading all sixty-four
emissions to decide which keys were correlation fields showed they were not consistent:
`subject:` in twenty-eight places and `account:` in four, both the account id; and `session:`
where `authz.denied` already said `credential:`. Normalised at the source rather than aliased in
the bridge, so the `Log` output an operator greps is consistent too. Breaking for a log pipeline
keyed on the old names.

**M3 rather than M4, for one stated reason.** The pass condition asks that "event names and
required fields are versioned". They are catalogued and now partly compile-checked — a rename of
a correlation field breaks a consumer reading `SecurityEvent`'s getters — but the event names and
the `data` keys are still documented strings with no version attached. Inventing a versioning
scheme to close a checkbox would be worse than recording the gap. `blueprints/0027-security-event-sink.md`.

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

### Fixed — re-measured at M4

`it_behaves_like_an_account_repository(tenanted: false)` and the same adapter now passes the whole
contract: **22 examples, 0 failures**, against 25 with 3 failures before.

**It asserts rather than skips**, which is the part worth having. The unsafe way to be
single-tenant is to ignore the `tenant_id` argument and hand back the untenanted row — that passes
every other example in the contract, and it is a cross-tenant leak the day the application grows a
second tenant. So `tenanted: false` replaces the tenancy group with one example demanding a
tenant-scoped lookup answer `nil`.

Verified to fail when it should, by writing an adapter with exactly that bug:

```
#find_by_login a single-tenant adapter answers nil for a tenant-scoped lookup
rather than falling back to the untenanted row  — FAILED
```

Existing callers are untouched: `tenanted` defaults to `true`, and the suite's 1511 examples were
unchanged by the addition.

---

## TOK-03 — Access to current credential identity and metadata

**Result: M4.** Applicable.

All four pass conditions, from the consumer project.

*"Credential kind and stable ID are available separately from the identity"* — a resolved session
returned `credential.kind == Session` and `credential.id == issued.record.id`, next to a
`subject` that is neither.

*"session, opaque token and JWT credentials have an explicit representation"* — `Session`,
`ApiToken`, `Jwt`, and a JWT resolved with `credential.id == "jti-77"`. The opaque-token case was
already measured under TOK-01.

*"raw secret and digest remain inaccessible"* — `CredentialRef` responds to none of `secret`,
`digest`, `token` or `reveal`. There is nothing to redact because nothing secret reaches it.

*"custom authenticators can attach their own safe reference"* — a `GatewayAuthenticator` was
written from the consumer project, registered in an `AuthenticatorChain`, and returned
`kind: Custom, id: "abcdef123456", name: "corporate gateway"`. Twenty lines, no core class
touched.

Nothing was found to name as a gap: the behaviour is complete, the README documents it as of
v0.8, and there is no contract to run because a value type has none.

---

## AUT-01 — Object ownership and ABAC

**Result: M3.** Applicable.

An `Invoice` in the consumer project included `Authz::Authorizable`, and an `OwnershipAuthorizer`
wrapped the shipped `RBAC`: the grant first, the per-object rule second. The owner was permitted
and a non-owner refused with `code: "not_the_owner"` — same account, same permission, different
object.

**The N+1 condition was measured, and the answer has a condition attached.** A hundred invoices
were authorised through the same policy, with the authz store wrapped to count reads:

| Configuration | Policy evaluations | Store reads |
|---|---|---|
| `Authz::Cache` configured | 100 | **1** |
| Cache left at its default | 100 | **100** |

*"list endpoints can apply the same policy without an N+1 query per row"* therefore holds — but
only for an application that switches on a cache that is **off by default**, and whose TTL is
also the revocation delay (`blueprints/0018`). The shard documents that trade-off for revocation
and says nothing about it for list endpoints, where it is the difference between one read and a
hundred.

**A second finding, and this one is a hazard.** *"missing attributes deny"* does not hold
automatically. When the resource is not the type the rule expects, `context.resource.as?(Invoice)`
yields `nil`, and a rule written the obvious way — `return decision if invoice.nil?` — falls
through to the **permissive** branch. Measured: an `Authz::Resource` carrying only a type and an
id was permitted by a rule meant to require ownership.

The shard cannot make a consumer's downcast fail closed; only the consumer's rule can. But it can
say so, and the README's ownership example currently shows exactly the shape that fails open.

**Documented after measurement**, in `docs/02-security-model.md` under *Authorization rules an
application writes itself*: the fail-open downcast with the branch that fixes it, and the N+1 table
above with the TTL that buying your way out of it costs. It went to `docs/` rather than the README
because the README is being edited elsewhere — and because a security trade-off with a number
attached belongs in the security model, not in a getting-started file. **Still owed in the README:**
its ownership example still shows the `return decision if invoice.nil?` shape that fails open.

Still M3. The conditions were already met; what changed is that a reader can now find out on which
terms. M4 wants a worked example and operational guidance, and the worked example — the consumer
project's `OwnershipAuthorizer` — lives in `tools/validation/`, not in `examples/`.

---

## OPS-04 — Custom session/token stores such as Redis

**Result: M3.** Applicable, and validated for one repository of eight.

`SessionRepository` — the hot one, and the one with the join — was implemented over a key-value
store held to Redis-shaped rules: get, set, set-if-absent, an atomic read-modify-write, and no
scans on the read path. **The shard's own contract ran against it from the consumer project: 33
examples, 0 failures**, plus three of this validation's own.

*"Required atomic operations are expressible in the contract"* — yes. `create` needs
set-if-absent to refuse a duplicate digest loudly rather than overwrite; `revoke` and `touch`
need read-modify-write. Sixteen fibers revoking one session concurrently produced exactly one
report of having changed something.

*"TTL cleanup is an optimisation rather than the only expiry check"* — asserted directly: a
session was left in the store, the clock advanced past its deadline, no sweeper ran, and
`resolve` answered `Expired` with the row still present.

*"account disabled state remains promptly available"* — this is where the design shows. SQL joins
account status into `find_by_digest`; a key-value store cannot join, so the adapter has to read
the account separately. **Two reads on the hot path instead of one**, which is a real cost and
the honest one: caching the flag into the session value would make it stale, which is the
staleness the whole module exists to avoid. An account disabled after its session was minted was
refused on the next resolve.

**Why not M4.** Seven repositories were not attempted, and the scenario says "every repository
contract". Running the contract at all also depends on reaching it, which is DEV-02's M2.

---

## OPS-06 — Custom schema/table names and migration ownership

**Result: M3.** Applicable. Largely answered by IDP-03's run.

*"SQL migrations are reference implementations rather than hidden runtime requirements"* — proven
rather than asserted: IDP-03's application has a `users` table and no `auth_accounts`, verified
against `sqlite_master`, and authentication worked.

*"repository contracts fully describe required constraints and atomicity"* — the key-value session
adapter in OPS-04 was written from the contract's documentation alone and passed all 33 examples,
including the duplicate-digest and concurrency ones. That is the condition holding.

*"table names are not baked into core services"* — holds for the core. `Sessions::Service` and
`ApiTokens::Service` name no table; everything goes through a repository.

**The gap is one step out from the condition as written.** The *shipped adapters* do hard-code
their own table names: of eight SQLite adapters, only two take a name argument at all, and both
take `accounts_table` only, because they join to it. An application with a `myapp_` prefix cannot
use `SQLite::SessionRepository` against `myapp_sessions` — it writes its own adapter, which
IDP-03 showed costs about seventy lines. A capability gap it is not; a convenience gap it is.

**Friction worth recording.** Applying the shipped migrations from outside took a hand-rolled
parser: they are micrate-format, micrate cannot resolve on this stack (`blueprints/0002`), and
comments must be stripped *before* splitting on `;` or a semicolon inside a column comment cuts a
statement in half. The first attempt did exactly that and produced `incomplete input` from
SQLite — the same error the shard's own spec helper carries a comment about having hit.

---

## OPS-07 — Optional database drivers and minimal dependency graph

**Result: M3.** Applicable.

Three consumer projects were built, as the scenario asks, and each compiled and ran:

| Project | `lib/` after `shards install` |
|---|---|
| core only | `backtracer db exception_page kemal kemal_identity radix` |
| SQLite only | the above **+ `sqlite3`**, no `pg` |
| PostgreSQL only | the above **+ `pg`**, no `sqlite3` |

*"Each resolves and compiles with only its selected driver"* — yes, and the core-only project
resolves **neither**, which is the v0.7 packaging change doing its job. The core-only binary
hashed a password and built a `Principal` with no database present at all.

*"development/test dependencies do not leak into consumer resolution"* — `ameba` and `spec-kemal`
appear in none of the three.

Kemal itself is installed by all three, including core-only. That is documented as deliberate —
`docs/00-scope.md` says "One dependency: kemal" — so it is recorded rather than counted against
the result. Worth noting only because the same reasoning that moved the drivers out would apply
to a consumer that wants the hasher and nothing else, which is what the sibling
`kemal_identity_argon2` shard is.

**Why not M4: nothing protects this.** CI's "Core compiles without the Kemal adapter" step
compiles `src/kemal_identity.cr` *inside this repository*, where both drivers are installed as
development dependencies. It proves the core references no Kemal types. It does not prove that a
consumer resolving only the shard gets no drivers — so moving `pg` back into `dependencies` would
break the property with a green build. A CI step that resolves a throwaway consumer and asserts
`lib/` holds neither driver would close it.

### Fixed — re-measured at M4

CI now resolves all three projects from `tools/validation/ops07/` and checks what each one got:
a core-only consumer must resolve neither driver, each driver-specific one exactly its own, and
none of them a development dependency.

**Verified to fail when it should**, which is the half that makes a green run mean something. `pg`
was temporarily moved back into `dependencies` and the check caught it:

```
core resolves: backtracer db exception_page kemal kemal_identity pg radix
→ the step failed
```

Then reverted. A step that only ever passes is a step nobody has tested.

---

## DEV-01 — Custom error envelope and localisation

**Result: M3.** Applicable. Mostly answered by HTTP-01's run.

*"Security decisions and presentation are separate"* — `ErrorHandler` was replaced entirely by a
consumer-written handler, and authentication carried on unchanged.

*"the application can map errors without rescuing a broad base exception"* — the three guard
failures were rescued individually as `NotAuthenticatedError`,
`FreshAuthenticationRequiredError` and `ForbiddenError`. They do share a `KemalIdentity::Error`
base, and so do `InfrastructureError` and `ConfigurationError` — so an application that rescued
the base would swallow an infrastructure fault as an authentication failure. It is not forced to,
and the specific classes are the documented way.

*"internal failure reasons stay out of public messages"* — the exceptions carry no reason, which
is the same property from the other side.

*"401/403 and `WWW-Authenticate` semantics remain correct"* — this is where it stops at M3, and
for the reason HTTP-01 found: `ForbiddenError` carries no denial reason, so a consumer's handler
cannot choose between `insufficient_scope` and anything else and has to answer one code for every
403. Presentation is fully replaceable; *correct* presentation of an RFC 6750 challenge is not
available to the replacement.

Localisation was not attempted.

---

## HTTP-03 — Credential precedence when cookie and bearer coexist

**Result: M2.** Applicable.

A consumer app was built with two accounts — Alice with a browser session, Bob with a bearer token
— and every combination probed over HTTP:

| Request | Result |
|---|---|
| no credential | 401 |
| valid cookie (alice) | 200 — `alice via Session` |
| valid bearer (bob) | 200 — `bob via ApiToken` |
| **invalid cookie + valid bearer** | **401** |
| valid cookie + garbage bearer | 200 — `alice via Session` |
| valid cookie (alice) + valid bearer (bob) | 200 — `alice via Session` |

**Two pass conditions hold.** *"conflicting identities never merge"* — two valid credentials for
different people produced one principal, Alice's, with no blending. *"audit identifies which
credential won"* — `env.auth.credential.kind` named it on every request.

**The fourth row is a defect, now confirmed over HTTP rather than inferred from source.** A
session cookie that has expired, been revoked or been tampered with **masks a valid bearer token**:
`AuthenticationHandler` clears the bad cookie and stops, and only tries the bearer when no cookie
was presented at all. A same-origin SPA that keeps sending a stale cookie beside an
`Authorization` header gets 401s. Fail-closed, so not dangerous — but wrong, and surprising.

**The fifth row is the scenario's own persona**, and it is the one the catalogue names: "an SPA
accidentally sends both a valid session cookie and a revoked bearer token". The revoked bearer is
not rejected — it is never examined. The presented credential is silently ignored, which is the
same outcome the rule about silent fallback exists to prevent, arrived at from the other
direction.

**A consumer can change it, and that was proven rather than assumed.** A twenty-line
`BearerFirstHandler` using only public API — `@app.bearer`, `@app.sessions.resolve`,
`@app.cookie.extract`, `RequestContext.new` — was built, run, and probed:

| Request | With the consumer's handler |
|---|---|
| invalid cookie + valid bearer | 200 — `bob via ApiToken` |
| alice cookie + bob bearer | 200 — `bob via ApiToken` |

**Why it is M2 and not M3, in two measured parts.**

*The precedence was not documented anywhere a reader would find it.* `grep -i precedence` over
`README.md` and `docs/` returned nothing; the rule lived in a comment inside
`authentication_handler.cr`. The first pass condition is "Precedence is explicit **and
documented**". Fixed in the same commit as this document — the README now carries the table above,
the sharp edge, and the replacement handler.

*A replacement cannot keep remember-me.* Compiled, not guessed:

```
Error: protected method 'restore_remembered!' called for KemalIdentity::Kemal::RequestContext
```

`restore_remembered!` and `authenticate_bearer!` are `protected`, so a handler outside the shard
cannot call them. An application that uses remember-me and wants different precedence must
reimplement the restore — including the ordering `blueprints/0012` documents as subtle, since
restoring on a *failed* cookie widens the window in which parallel requests both present the
remember token and one of them reads as theft. That is duplicated I/O in the M2 sense, and it
lands on exactly the application HTTP-03 describes: a monolith serving browsers and APIs, which is
the kind most likely to have remember-me.

And precedence is app-wide either way. The pass condition asks for "unless **the route** explicitly
allows that policy"; one handler decides for every route.

**Smallest change that would reach M3:** make `authenticate_bearer!` and `restore_remembered!`
public, so a replacement handler can compose the pieces instead of reimplementing one. M4 wants
precedence declarable per route subtree, which is the same parameter HTTP-02 wants on `PathGuard`.

**A methodology note, recorded because it nearly produced a wrong result.** An earlier attempt
concluded `restore_remembered!` *was* reachable, because `crystal build --no-codegen` accepted a
file that defined a handler calling it. Crystal only analyses method bodies that are actually
reached, and nothing called that handler. The visibility error appeared only once the handler was
wired into a running app. **Compiling a file that merely defines a class proves nothing about its
method bodies** — a trap worth knowing about for the scenarios still unrun.

**Fixed after measurement — M2 → M3, and not by the change this section proposed.** The smallest
change named above was to make `authenticate_bearer!` and `restore_remembered!` public. That was
rejected on second look: it hands an application two methods whose *ordering* is the subtle part,
and `blueprints/0012-remember-me.md` is explicit that restoring on a failed cookie is the wrong
order. Publishing them would document the trap and then invite it.

What shipped instead is the policy as an argument:

```crystal
use KemalIdentity::Kemal::AuthenticationHandler.new(
  precedence: KemalIdentity::Kemal::AuthenticationHandler::Precedence::Bearer
)
```

`Precedence::Cookie` is the default and preserves every row of the first table above, byte for
byte. `Precedence::Bearer` resolves a presented bearer credential first and does **not** fall back
to the cookie when it fails — the mirror of the defect, and deliberate: a request that presented a
token is asking to be authenticated by it, and falling through would let a stale session paper
over a revoked token.

Both branches keep remember-me, which is the whole reason this is an argument rather than a
replaceable handler. Measured, in `spec/unit/authentication_handler_spec.cr` — eleven examples
driving the handler directly, because Kemal's chain is process-global and this is about two chains
differing in one constructor argument:

| Under `Precedence::Bearer` | Result |
|---|---|
| invalid cookie + valid bearer | the token's account, `kind: ApiToken` |
| valid cookie + valid bearer | the token's account |
| valid cookie + garbage bearer | not authenticated, and no fall-back |
| valid cookie, no bearer | the cookie's account, `kind: Session` |
| invalid cookie, no bearer | `failed?`, and the cookie is cleared |
| remember cookie only | restored, `assurance: Remembered`, both cookies written |
| remember cookie + valid bearer | the token's account; no remember cookie written |

**The specs have teeth, proven by breaking the code rather than by reading it.** Pointing
`Precedence::Bearer` at `resolve_cookie_first` — a one-line mutation — failed exactly the three
examples that assert the reversal, and none of the eight that assert the unchanged default or the
preserved remember-me path.

**One incidental finding, which cost two examples.** A handler driven directly with no successor
answers 404 through `HTTP::Server::Response#respond_with_status`, and that calls `reset` — which
clears the headers and the cookie jar, taking the `Set-Cookie` under assertion with it. Any spec
asserting on a cookie a handler wrote needs a no-op `handler.next`, or it measures the reset
instead of the handler.

**Documented in `docs/04-kemal-integration.md`**, under *When a request presents both a cookie and
a bearer token*: both tables, the sharp edge, the no-fall-back rule and the remember-me reasoning.
The section the earlier commit put in the README is gone from the current README, so `docs/` is
where this now lives.

**Still M3, not M4.** M4 wants precedence declarable per route subtree. Kemal's `use` registers one
chain for every route and this handler does not consult `only_match?`, so the setting is app-wide
— the same per-subtree parameter HTTP-02 wants on `PathGuard`, and the same reason both stop at
M3.

---

## JWT-01 — Multiple JWT issuers selected at runtime

**Result: M2.** Applicable.

Two validators were built for two issuers, each with its own HMAC key. Individually they work,
and each refuses the other's tokens — twice over, and the order matters:

| Presented to validator A | Refused on |
|---|---|
| a token from issuer B, signed with B's key | **the signature** — `InvalidCredential` |
| a token claiming issuer B, signed with A's key | **the claim** — `InvalidClaim` |

The first row was not what source reading predicted. The signature fails before `iss` is ever
compared, because each issuer signs with a key the other's ring does not hold. Correct, and it
shapes everything below.

**Chaining the two validators does not work, and cannot.** `AuthenticatorChain` is the mechanism
the shard ships for "one header, two credentials", and it routes on **shape**. Every JWT is three
base64url segments, so a token from issuer B is shape-identical to one from issuer A: validator A
recognises it, fails it on the signature, and the chain's own rule — stop at anything that was
recognised and then failed — ends the attempt. Validator B is never asked.

Measured in both orders, which is what makes this structural rather than a misconfiguration:

```
[A, B] -> issuer A's token authenticates, issuer B's is refused
[B, A] -> issuer B's token authenticates, issuer A's is refused
```

Whichever issuer is registered second loses. Half of a two-customer API is rejected either way.

**So a consumer must route on `iss` before validating, and there is no bounded way to do that.**
`Validator` exposes no issuer peek — asserted, not assumed — so the routing that works is the
consumer decoding the payload segment themselves:

```crystal
segments = credential.split('.')
payload = ::JSON.parse(Base64.decode_string(pad(segments[1])))
validator = validators[payload["iss"]?.try(&.as_s?)]?
validator.try(&.authenticate(credential))
```

Verified working: both issuers authenticate, and an unknown issuer is refused with no validator
consulted and no network touched.

**But the safety of it is now the consumer's.** The validator has a `max_bytesize` for exactly
this reason and applies it inside itself; the hand-rolled peek above has none, so it will happily
base64-decode and JSON-parse whatever arrives. The pass condition is *"Issuer selection happens
only after **bounded**, non-trusting parsing"* — achievable, and achieved by nobody who does not
know to write the bound. That is the difference between M2 and M3 here: it is not that the
scenario is impossible, it is that the safe version is not the obvious one and the shard offers
no help.

The other pass conditions hold once routing exists: each issuer keeps its own algorithm and
audience allow-list because each has its own `Validator`; cache keys include the issuer because
each has its own `KeySource`; and an unknown issuer triggers no network access in the version
above.

**Smallest change that would reach M3:** a bounded, non-trusting `JWT.unverified_issuer(credential) : String?`
— the same length check the validator already does, then one segment decoded, no signature
implied by the name. Additive, so it can land after 1.0.

### Fixed — re-measured at M3

`KemalIdentity::JWT.unverified_issuer` shipped, and the routing this scenario needs is now four
lines a consumer does not have to get right themselves:

```crystal
issuer = KemalIdentity::JWT.unverified_issuer(credential)
validator = issuer.try { |i| VALIDATORS[i]? }
outcome = validator.try(&.authenticate(credential)) ||
          KemalIdentity::Failed.new(KemalIdentity::FailureReason::InvalidClaim)
```

**Bounded, which was the whole reason M2 rather than M3.** `max_bytesize` defaults to what
`Validator` uses and is checked before anything is decoded, so a hostile header costs one integer
comparison. And it reuses the validator's own `decode_segment` rather than a second decoder — the
strict base64url of RFC 7515 §2, refusing `+`, `/` and `=`, because a decoder that agreed
*almost* with the validator is how one token comes to mean two things. Those helpers were lifted
to class level with no behaviour change; the suite was unchanged by the refactor.

**Nine examples, mostly about what it refuses:** nil, empty, not-three-segments, past the byte
limit, standard-base64 or padded segments, a payload that is not a JSON object, and a missing,
empty or non-string `iss`.

Two are the ones that matter. It reads the issuer out of a token **signed with a key nobody here
holds** — which is the point, since selection has to happen before verification can. And a token
whose claimed issuer *is* configured but whose signature is another issuer's is still refused, by
the validator: **selection proves nothing.**

The name carries the warning and the documentation states the two rules the return value is
subject to — never an identity, and never a URL. The second is the sharp one: fetching JWKS from
the issuer a token names is server-side request forgery with the attacker choosing the host, so
the lookup must be exact equality against a map configured at boot.

**Still M3 rather than M4:** `AuthenticatorChain` remains unable to route JWTs, so a consumer
writes the four lines rather than registering two validators and having it work. Whether the
chain should learn to route on a discriminator is a design question this does not settle.

**Fixed in this commit:** the README described shape-only routing accurately and left the
consequence for the reader to derive. It now says plainly that two JWT validators cannot be
chained, and points here for the routing.

---

## JWT-02 — Custom claim mapping without weakening validation

**Result: M3.** Applicable.

A token carrying `uid` and `tenant` alongside the registered claims was validated, and
`Validator#validate` returned a `Validated` whose `claims` held both. The mapping step is the
consumer's and runs on already-verified claims:

```crystal
claims = validator.validate(token).as(KemalIdentity::JWT::Validated).claims
Principal.new(subject: claims["uid"].as_s, tenant_id: claims["tenant"].as_s, ...)
```

*"Mapping cannot skip signature, issuer, audience, expiry or purpose checks"* — structurally so.
A validation failure returns `Failed`, which carries no claims, so there is nothing to map. That
was asserted directly: a wrong-issuer token yielded `Failed` and no claim access.

*"local identity linking uses issuer plus subject rather than email"* — `iss` and `sub` both come
back on the verified claims, so the pair is available without the consumer reaching for `email`.

Nothing named as a gap. Not M4 only because there is no packaged example of a mapping step and no
contract a consumer could run against their own mapper.

---

## JWT-03 — Audience/resource-specific validation

**Result: M3.** Applicable.

One process, two APIs, two validators differing only in audience. A token minted for `billing`
authenticated against the billing validator and was refused by the admin one with `InvalidClaim`.

*"route policy cannot accidentally use a global validator with a broader audience"* — there is no
global validator to pick up by accident. A `Validator` is a value a route holds; nothing is
registered ambiently, which is the same property that makes JWT off-by-default.

*"multi-audience tokens have explicit semantics"* — measured, because RFC 7519 permits `aud` to be
an array and what a verifier does with one it is only *one of* is the subtle part. A token with
`aud: ["billing", "admin"]` authenticated against **both** validators; a token with
`aud: ["billing"]` was refused by the admin validator. Membership, not equality, and it is the
right reading.

---

## JWT-04 — Revocation/introspection policy per issuer

**Result: M3.** Applicable.

Two validators, two policies: issuer A with a `RevocationStore`, issuer B with expiry only.
Revoking `jti-a` in A's store refused A's token on the next call with `Revoked`, and B's token
kept authenticating — B has no store to consult, so nothing about its policy changed.

*"The strategy is issuer-bound at boot"* — it is a constructor argument on the validator, so it
cannot drift at runtime.

**The cost it inherits.** Per-issuer revocation is only reachable if you have per-issuer
validators, and getting a token to the right one is JWT-01's hand-rolled routing. This scenario's
own mechanism is clean; the thing it sits on is M2.

Introspection-per-issuer — one partner offering RFC 7662 rather than a denylist — was not
attempted. It needs the HTTP-backed authenticator TOK-06 is about, which is unrun.

---

## DEV-03 — Framework adapter other than Kemal

**Result: M3.** Applicable.

A whole working server was built over raw `HTTP::Server`, requiring `kemal_identity` and
**never** `kemal_identity/kemal`. It resolves a bearer token or a session cookie, maps the three
outcomes to statuses, and emits the RFC 6750 challenge the shard does not:

| Request | Response |
|---|---|
| no credential | 401, `WWW-Authenticate: Bearer realm="raw"` |
| valid cookie | 200 — `u-1 via Session` |
| valid bearer | 200 — `u-1 via ApiToken` |
| invalid bearer | 401, `WWW-Authenticate: … error="invalid_token"` |

**The framework-independence claim was verified against the binary, not the source.**
`docs/01-architecture.md` says the layering "keeps the door open for an Amber or Lucky layer
without touching the core". Checked with `nm`:

| Binary | `KemalIdentity` symbols | `Kemal::` symbols |
|---|---|---|
| the raw `HTTP::Server` app | 189 | **0** |
| the Kemal app from HTTP-03 | — | 748 |

The first row alone would prove nothing — a stripped binary shows nothing either — which is why
the 189 and the 748 are there. Kemal is genuinely not linked.

*"framework-specific cookie/header/error handling stays in the adapter"* holds, and the seam is
at the standard library rather than at Kemal: `Sessions::CookieConfig#extract` takes
`HTTP::Cookies`, so the codec is reusable by anything that speaks stdlib HTTP.

*"the application object can be created without the Kemal shard being loaded"* — `KemalIdentity.configure`
was called and `KemalIdentity.app` built in a spec that requires neither `kemal` nor the adapter.

**Why not M4: there is no worked example, and finding the seams cost a compile error.** The codec
is `Sessions::CookieConfig` itself, not a `Sessions::Cookie` class — which is what the first
attempt reached for, with `Error: undefined constant KemalIdentity::Sessions::Cookie`. The
architecture doc asserts the door is open; nothing shows a reader through it.

---

## HTTP-07 — Authentication outside an HTTP request

**Result: M3.** Applicable.

A job's principal was constructed with no request, no cookie and no faked `HTTP::Server::Context`,
and authorised against the same `RBAC` a route uses. `Authz::RBAC`, `Sessions::Service`,
`ApiTokens::Service` and every repository are reachable with only `kemal_identity` required —
which DEV-03's symbol count independently confirms.

*"actor and source are auditable"* — a `CredentialRef` with `kind: Custom, id: "cron:nightly-sweep"`
names the launcher, so `authz.denied` distinguishes a job from a session rather than reporting
both as an account.

*"no fake HTTP request is necessary"* — none was built.

Freshness works with an injected clock: a principal fresh within five minutes went stale after
the `TestClock` advanced ten, with no request anywhere.

**The last pass condition is not enforced, and cannot be.** *"jobs cannot invent a stronger
assurance than their trusted launcher grants"* — `Principal.new` accepts any `AssuranceLevel`.
Measured both ways: a job claiming `ApiToken` was refused a permission demanding `MFA` with
`InsufficientAssurance`, and the same job claiming `MFA` was **permitted**.

There is no fix that keeps the scenario possible. Restricting the constructor would make
authentication outside HTTP impossible, which is the thing being validated. So the honest boundary
is that whatever builds a `Principal` is trusted code — and the hazard is that a reader might
assume otherwise.

**Which is the finding: none of this was documented.** `grep -i 'background job\|worker\|outside an
HTTP'` over `README.md` and `docs/` returned nothing. A capability the shard has, the scenario the
catalogue rates High, and no page telling anybody it exists or what it costs. Fixed in the same
commit: the README now has an `## Outside an HTTP request` section with the worked example, the
audit guidance, and the trust boundary stated as a warning.

---

## IDP-01 — Several OIDC providers with provider-specific options

**Result: M2.** Applicable. Two of five pass conditions do not hold.

Two providers were registered — a Google-shaped one and an Okta-shaped one — each with its own
issuer, client id, redirect URI and key source. **Concurrent flows stay apart**: two flows started
before either completed had distinct `state` and `nonce`, and both completed correctly in the
reverse order they were begun. **Key sources are isolated**, so one provider's JWKS cache cannot
answer for another.

**Then the one that fails: a callback can switch providers.**

Okta's client was handed *Google's* pending state together with a token Okta had minted, and it
completed successfully, returning a `Federation::Identity` for issuer Okta.

Every check passes from that client's point of view, which is why: `state` matches the pending it
was given, `nonce` matches the token, and `iss`/`aud` are compared against **Okta's** provider —
which did mint the token. `Pending` carries `state`, `nonce`, the PKCE verifier and `return_to`,
and **nothing naming the provider**; asserted directly, it has no `issuer`.

The pass condition is *"pending state binds provider, redirect URI, nonce and PKCE verifier"* and
*"callback cannot switch providers"*. Neither holds at the type level. What holds instead is
whatever the application's callback route does, and nothing told it that this was its job. No
exploit is claimed here — `PendingCodec` signs the pending, so an attacker cannot forge one, and
the realistic paths need a pending from the victim's own browser. But the provider boundary is
carried by application routing rather than by the flow state, which is not where the scenario
expects it.

**And the second: provider-specific authorisation parameters cannot be sent.** `authorize` takes
`return_to` and `prompt`. Measured — the generated URL has no `hd`, no `domain_hint`, no
`login_hint`, and `Provider` has no `extra_authorization_params`. Google's domain restriction,
Okta's login hint and Azure's domain hint are all unreachable through the shipped call.

**The workaround was attempted and works.** `authorize` returns the `Pending`, and everything the
URL needs is readable from it — `state`, `nonce`, `code_challenge` — so the consumer rebuilds the
query string with their own parameters and redirects to that instead of `flow.url`. Verified: the
rebuilt URL carries `hd` and `login_hint` alongside the shard's own state and challenge, and the
pending still completes through `client.complete` with every check intact. About twelve lines, and
none of them security logic — only query-string assembly.

That is what makes this M2 rather than M1: both gaps have consumer-side answers. It is M2 rather
than M3 because neither answer was written down anywhere, and one of them is a safety boundary.

**Fixed in this commit:** the README now has a `### More than one provider` section carrying the
callback-routing warning, the measured provider-switch behaviour, and the URL-rebuilding recipe.

### Half fixed — re-measured at M3

`Provider` gained `authorization_params`, so `hd`, `login_hint` and `domain_hint` are sent by the
shipped call and nobody rebuilds the URL:

```crystal
KemalIdentity::OIDC::Provider.new(
  # ...
  authorization_params: {"hd" => "example.com"},
)
```

**The guard rail is the feature.** The dangerous version of this lets an application overwrite
`state`, `nonce`, `code_challenge` or `code_challenge_method` — turning PKCE off by configuration
— or `redirect_uri`, sending the code somewhere else. `Provider::RESERVED` names all nine
parameters `authorize` builds, and a key matching one raises `ConfigurationError` **at
construction**: a boot failure rather than a silent drop or a silent win. A spec loops over all
nine and asserts each is refused.

`prompt` is reserved too, and is not a security value — `authorize(prompt:)` sets it, and two
`prompt` parameters in one query string is a request the provider interprets however it likes.

Values are escaped by `URI::Params`, asserted with a value that tries to add a `scope` of its
own: it arrives as data and the real `scope` is untouched.

**Still M3, and the reason is the other half.** `Pending` does not bind the provider, so a
callback can still be completed by the wrong provider's client and the boundary is carried by the
application's routing. Binding it means putting the issuer in the flow state and comparing it in
`complete` — a change to `Pending` and `PendingCodec`, both of which v1.0 freezes, so it is not a
patch-release change.

---

## IDP-02 — Safe account linking and conflict resolution

**Result: M3.** Applicable.

*"Email never auto-links identities"* — structurally, because there is nowhere to put one.
`Federation::Link` holds an id, an account, an issuer, a subject and timestamps; asserted, it does
not respond to `email`. The stored key cannot be an address even by mistake.

*"conflicts are typed outcomes"* — two providers asserting the same subject string for two
different people produced two independent links, resolving to two different accounts, with no
collision. And relinking an already-linked pair raises `InfrastructureError` — **including to the
same account**, which was checked separately, because silently accepting the second row is how one
provider identity ends up attached to two local accounts and whichever is found first decides who
signs in.

*"unlink cannot strand an account without a recovery path"* — the repository gives the application
what the guard needs (`for_account` returns the links) and does not enforce it: `unlink` on the
last remaining link succeeds and leaves the account with none. Recorded rather than counted
against the result, since deciding what counts as a recovery path — another provider, a password,
a recovery code — is not the repository's to know.

*"linking requires fresh proof of both sides"* is the application's, and `require_fresh!` is the
mechanism for its half.

---

## IDP-04 — Multi-tenant login discovery and tenant switching

**Result: M3.** Applicable.

One address, two tenants, two accounts: `find_by_login("ada@example.com", "acme")` and the same
call for `"globex"` returned different account ids.

*"authorization always receives the target tenant"*, from both ends. A lookup naming **no** tenant
did not match a tenanted row — `nil` is the single-tenant case, not a wildcard. And a principal
bound to `acme` asking about `globex` was refused with `TenantMismatch`, before membership was
consulted, even though it holds the role there.

*"tenant discovery does not enumerate accounts to an attacker"* — there is no discovery API to
abuse. `AccountRepository` answers one tenant at a time and has no "which tenants does this
address exist in" method; asserted against `responds_to?`.

*"session rotation occurs if assurance/security context increases"* was not exercised for a tenant
switch. `mfa_verified!` rotates on an assurance increase and has its own coverage in the shard's
suite; whether switching tenant should rotate is an application decision the shard does not make
either way.

---

## Not yet attempted

The remaining fifteen scenarios — two high, ten medium, one low, two niche-critical —
are unstarted.

A note on what "unstarted" means for the ones whose feature is absent — WebAuthn, magic links,
device flow, SCIM, token rotation. The catalogue is explicit that absence is not immaturity:
*"A feature may be absent and the library may still be mature if an application can add it
through a documented, safe contract."* So those are not quick entries. Each needs a real attempt
at adding it from outside, which is what DEV-03 and HTTP-07 above turned out to be, and what
TOK-01 was before the feature landed. `blueprints/0020` decision 8 already records which of them are
additive and which were checked for freeze impact; that is a different question from this one and
does not substitute for it.

## What this exercise changed

Five things, which is the argument for running it before a release rather than after.

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

The fifth is AUT-01's, and it is the one a reader of the README would walk into. The ownership
example in the documentation has the shape

```crystal
owner = context.resource.as?(KemalIdentity::Authz::Resource).try(&.["owner_id"])
return decision if owner.nil? || owner == principal.subject
```

and `owner.nil?` is reached both when the resource carries no owner *and* when it is not the type
the rule expected — where it permits. Measured: a resource with no owner attribute was permitted
by a rule meant to require ownership. The shard cannot make a consumer's downcast fail closed, but
the example it ships should not be the version that fails open.

**Fixed in the same commit as this document.** The README example now separates the two `nil`s —
"nobody asked an object question" passes, "the rule could not read what it needed" denies — and
says why, because the natural one-line version is the wrong one. `tools/validation/aut01_spec.cr`
asserts the denial, so the fix has a test rather than a paragraph.

## Re-running this

`tools/validation/` holds every attempt. The multi-process rate-limit check is not a spec: build
`ops01_worker.cr` and `ops01_setup.cr`, then run several workers against one database file and sum
what they report. The numbers in the OPS-01 section came from six workers, twenty attempts each,
a global limit of ten.

---

## TOK-04 — Custom bearer authenticator

**Result: M2 → M3.** Applicable. The first scenario of the second pass.

A `GatewayAuthenticator` was written in the consumer project against the published contract —
`gw.<subject>.<hmac>`, deliberately neither of the shard's own shapes, so that shape routing had
something real to route on. Every method body was *called*, not merely compiled: a file that
defines an authenticator compiles even when its bodies would not.

**Four of the five pass conditions held on the first attempt.**

| Condition | Result |
|---|---|
| ordering is deterministic | holds — `AuthenticatorChain` asks in list order |
| "not my credential" distinct from "my credential but invalid" | holds — `Failed(MalformedCredential)` is the only reason that falls through |
| a recognised rejection stops the chain | holds — a revoked gateway token was not offered to the JWT validator |
| the authenticator can attach credential metadata | holds — `CredentialKind::Custom`, an id, a name and scopes, all readable from `env.auth.credential` |
| **registration needs no custom HTTP handler** | **failed** |

**The fifth failed, and the compiler said so twice.**

```
Error: no parameter named 'bearer'
Error: undefined method 'bearer=' for KemalIdentity::Application
```

`Application#bearer` was assembled internally from `api_tokens:` and `jwt:` and from nothing else.
A consumer's authenticator had no way in.

**One accidental route existed, and it is worth recording as an accident.** With *both* built-ins
configured, `app.bearer` is an `AuthenticatorChain`, and `AuthenticatorChain#authenticators` is a
getter over a mutable array:

```crystal
KemalIdentity.app.bearer.as(KemalIdentity::AuthenticatorChain).authenticators.insert(1, GATEWAY)
```

Measured over HTTP, that worked completely: `200` with `kind: Custom`, the correct
`WWW-Authenticate: Bearer realm="api", error="invalid_token"` on a bad signature, CSRF exemption
honoured on a token-only `POST`, and the shard's own token still routed to the shard. But it is a
post-boot mutation of what `docs/01-architecture.md` calls a frozen configuration object, it races
with the fibers reading the chain, and it only exists when the application happens to have
configured two shipped authenticators — with one configured, `app.bearer` *is* that service and
there is no chain to reach into. Not an API.

**Without it, the failure cascades past authentication, and this is the actual finding.** The
persona's real shape is the gateway token being the *only* bearer credential. Then `app.bearer` is
`nil`, and a consumer resolving the credential in a handler of its own was measured over HTTP:

| Request | With a consumer's handler | Root cause |
|---|---|---|
| valid gateway token | 200, `kind: Custom` | — |
| bad signature | 401 **with no `WWW-Authenticate`** | `ErrorHandler#bearer_configured?` asks `app.bearer` |
| no credential | 401 **with no `WWW-Authenticate`** | same |
| `POST` with only the token | **403 `invalid CSRF token`** | `CSRFHandler#bearer_only?` asks `app.bearer` |

So an application whose bearer credential is its own silently lost HTTP-01's challenge — the thing
this shard reached M4 on — and had its API mutations rejected as forgeries, for a request no
browser can make.

**Fixed after measurement, additively: `bearer_authenticators:`** on `configure` and
`Application.new`. The application's authenticators join the same chain, after the shipped ones,
in the order given. Re-measured, same app, same probes, **no handler of the consumer's own**:

| Request | Before | After |
|---|---|---|
| valid gateway token | 200 (needed a handler) | 200, no handler |
| bad signature | 401, no header | 401, `Bearer realm="api", error="invalid_token"` |
| no credential | 401, no header | 401, `Bearer realm="api"` |
| `POST`, token only | **403 CSRF** | **200** |

**Why "after the shipped ones" rather than an interleaving API.** Measured, not assumed: the
consumer's authenticator was placed at all three positions of a three-authenticator chain and
every credential family — an issued opaque token, a gateway token, a JWT, garbage, nothing —
produced an identical answer at every position. What the fixed order buys is that a *loose* shape
check in a consumer's authenticator cannot shadow a credential this shard issued.

That measurement holds only because the four shapes were **disjoint**, which was not obvious at
the time and is not always true — TOK-05 below is the case where two authenticators claim one
shape, and there the order decides everything.

`spec/unit/custom_bearer_authenticator_spec.cr` holds nine examples, including the challenge and
the CSRF exemption driven through the real handlers. Teeth checked by mutation: dropping the
extras from the composition fails eight of the nine.

**Why M3 and not M4.** No worked example under `examples/`, and the README says nothing about
implementing the contract. The documentation is in `docs/01-architecture.md`.

**Recorded, not fixed: `AuthenticatorChain#authenticators` hands out its mutable array.** That is
what made the accidental route above possible, and it contradicts "configuration is boot-time and
immutable". Returning a copy would close it, and `AuthenticatorChain` is outside the freeze list —
but it changes the behaviour of a published getter, so it belongs in a minor release rather than
in the patch that adds a parameter.

---

## TOK-05 — More than two bearer credential families

**Result: M3.** Applicable. Reachable only because TOK-04's parameter now exists.

Four families in one application, as the persona describes: an opaque personal token, an internal
gateway JWT, a partner JWT with its own issuer and key, and a legacy credential kept alive during
a migration.

**Three of the four pass conditions hold, and one is measured rather than argued.**

*"Ambiguous shapes fail closed"* — a JWT from an issuer nobody knows is `MalformedCredential`, and
a partner-issuer JWT signed with the wrong key is `InvalidCredential` and **stops** the chain
rather than being offered to the next authenticator.

*"No authenticator performs I/O before determining that the shape could belong to it"* — counted,
not asserted. Five credentials that belong to nobody (empty, a plain string, an opaque token, a
too-short legacy token, a too-long one) produced **zero** I/O calls in either consumer-written
authenticator. A two-megabyte three-segment credential was refused in under fifty milliseconds
with no decode and no I/O.

*"Error behaviour does not reveal which backends exist"* — an unknown-issuer JWT and a plain
string produce the *same* `FailureReason`, and the reason names no backend. A probe cannot
enumerate the configured issuers.

**The first condition — "the chain is consumer-supplied rather than hard-coded to named
built-ins" — holds only halfway, and the failure is instructive.**

The first attempt configured `jwt:` *and* passed a JWT-shaped router of the application's own.
The partner token never reached the router:

```
chain: [shipped JWT validator, application's issuer router]
partner token → Failed(InvalidCredential), router io_calls: 0
```

`InvalidCredential` rather than `InvalidClaim`, because the signature fails before `iss` is
compared — JWT-01's first row again. Either way it is not `MalformedCredential`, so the chain
stops, exactly as it must: falling through would be a rejected token getting a second opinion.

**The same collision was then measured for the opaque family**, rather than assumed by analogy: an
application whose own credentials start with `ki_` and are 46 bytes long never sees them either,
because `ApiTokens::Service` claims that shape first.

**Both escapes work, and both were run.** Own the shape entirely — hold every issuer's validator
in your own authenticator and do not configure `jwt:` — and all four families resolve to the right
principal. Or move the shapes apart: with `api_token_prefix: "app_"`, the colliding `ki_`
credential reaches the application's authenticator and the shard's own tokens still resolve.

So the rule is **one owner per shape**, and it is a property of the stopping rule rather than of
this parameter. Documented in `docs/01-architecture.md`, which previously carried the
over-general claim that position never matters — true only for disjoint shapes, and TOK-04's
measurement happened to use four disjoint ones.

**Why M3 and not M4.** The built-in half of the chain is not reorderable and cannot be omitted
piecemeal: an application cannot say "my authenticator first, then the shipped one". Nothing in
this scenario needs that, because a shape has one owner either way — but the condition as written
asks for a consumer-supplied chain, and half of it is composed for you. The M4 step is an explicit
override (`bearer:` taking the whole chain), which is additive and can wait until something needs
it. `tools/validation/tok05_spec.cr` holds the eight examples.

---

## TOK-02 — Resource- or tenant-restricted personal token

**Result: M3.** Applicable.

Built the way GitHub's fine-grained tokens actually work, rather than the way the scenario's
wording suggests: the token carries *permissions*, and the *resources* it may touch are a
selection stored server-side against the token's identity. One human, member of `org-a` and
`org-b` with a `developer` role in each, and two tokens:

| Token | Scopes | Selected for |
|---|---|---|
| narrow | `repo.read` | `org-a`, repositories 17 and 24 |
| wide | `repo.read`, `repo.write` | all of `org-b` |

**Every pass condition holds.**

*"The authorization call receives both the current credential identity and the target
tenant/resource"* — `principal.credential.id` keys the selection table and `context.tenant_id` plus
`context.resource` name the target. Counted: one lookup per decision.

*"Scope cannot be inferred only from `Principal#tenant_id`"* — asserted directly, and the fixture
is built to make it impossible: this human belongs to two organisations, so `tenant_id` is **nil**
on both principals. Two tokens, one account, no account-level tenant, and the answers still
differ.

*"Global roles do not accidentally erase token attenuation"* — a global `operator` assignment
(`tenant_id: nil`, needing no membership, the sharpest thing in `Authz::Membership`) grants
`org.admin` everywhere. The narrow token still cannot reach `org-b`, and still cannot use
`org.admin` in `org-a` — its scopes do not name it. The same global role through the *browser
session* is unattenuated, which is the intersection behaving in both directions.

*"Denial is identical for unknown and unavailable resources"* — repository 31 (exists, wrong
organisation) and repository 9999 (does not exist) produce the same `reason`, the same `code` and
the same `step_up?`.

**Horizontal access attempted over HTTP**, which is what the scenario asks for — the same URL with
the organisation or the repository id changed:

| Request with the narrow token | Result |
|---|---|
| `GET /orgs/org-a/repos/17` | 200 |
| `GET /orgs/org-a/repos/24` | 200 |
| `GET /orgs/org-a/repos/31` — another org's repo id | 403 |
| `GET /orgs/org-a/repos/9999` — no such repo | 403 |
| `GET /orgs/org-b/repos/31` — organisation swapped | 403 |
| `GET /orgs/org-b` — organisation swapped, no repo | 403 |
| `PUT /orgs/org-a/repos/17` — outside the token's scopes | 403 |

And with the wide token: `GET`/`PUT` inside `org-b` succeed, `GET /orgs/org-a/repos/17` is 403.

**Both halves of the intersection have teeth, proven by breaking each.** Dropping the
application's organisation check fails three examples; dropping the shard's own credential
attenuation in `Authz::RBAC` fails two. Neither half is carrying the other.

**Why M3 and not M4.** The selection table, and the wrapper that reads it, are the application's
to write — about seventy lines here. That is the right split (`blueprints/0018`: a role grants a
permission everywhere or nowhere; per-object rules are an `Authorizer`), but there is no worked
example in the repository and no documentation of the pattern, which is what M4 asks for.

**A defect found by reading the app's own log output, and fixed.** The validation server printed:

```
api_token.issued -- subject: "ada", token: "IXDSymFfxYt9eOeZr6BafhRGZErzH6a78ySXLIoMaoI", ...
```

That value is the token's *id*, not the secret — but under a field named `token` it reads exactly
like the secret, in the one log line an incident responder would look at first. Measured through
the typed sink, the field name was worse than cosmetic:

| Event | `SecurityEvent#credential` | `data` |
|---|---|---|
| `api_token.issued` | **nil** | `{"token" => "...", "scopes" => "..."}` |
| `session.started` | **nil** | `{"session" => "...", "assurance" => "..."}` |
| `api_token.revoked` | **nil** | `{"token" => "..."}` |

So the three events that mint or kill a credential were the three that did not populate the typed
correlation field OPS-02 exists for. `blueprints/0027` renamed `session.revoked` and
`session.ended` to `credential:` and missed `session.started` and the whole `api_token.*` family —
and nothing tested the convention, which is why the whole suite stayed green through the rename.

Fixed: all three now emit `credential:`, and
`spec/security/event_sink_spec.cr` has an example that names the four events and the id each must
carry. Restoring any one of the old field names fails it.

**Breaking for a log reader**, exactly as `blueprints/0027`'s rename was, and for the same reason:
aliasing at the bridge would leave `grep` inconsistent.

---

## TOK-07 — Machine/service accounts

**Result: M3.** Applicable.

A `svc-deploy` account was created with `password_digest: nil`, `password_scheme: nil`,
`email_verified_at: nil` and a login that is not an address, alongside an ordinary human account
for comparison.

**Three of the four pass conditions hold.**

*"The account repository does not require human-only fields"* — holds. Every human-shaped field is
nilable, the login need not be an address, and `find_by_login("svc-deploy")` resolves, which is
what makes a provisioning script idempotent.

*"Destructive interactive actions are unavailable"* — password login fails closed for every input
tried, including the login as its own password and the empty string. `Passwords::Authenticator`
reaches a nil digest and refuses rather than treating "no credential" as "any credential".

*"Deprovisioning the service account revokes access promptly"* — measured across the boundary: a
token authenticates, the account is disabled, the *same* token then answers
`Failed(DisabledAccount)` on the next call. No sweeper, no TTL, no cache to expire.

*"Audit events distinguish human and workload identity"* — holds, but the distinction is the
application's. `Accounts::Account` has no field for it and should not: what counts as a workload
is a product question. The application keeps the set and tags at the sink, and the events carry
everything that needs — `subject` and, since TOK-02's fix, `credential`. Measured: two
`api_token.issued` events, one tagged `workload`, one `human`, each naming its token id with no
join.

**A defect found on the way, and this one is a privilege boundary.**

`request_password_reset` minted a reset token and delivered a link for `svc-deploy` — an account
with **no password credential at all**:

```
workload: 1 reset mail, 1 action tokens
human:    1 reset mail, 1 action tokens
```

And `reset_password` sets a digest unconditionally, so completing that link does not *reset* a
password, it **creates** one — turning a non-interactive identity into one that can be logged into
with a password. The proof of identity for that flow is reaching a mailbox, and a service
account's login is very often a team alias. The same applies to a human who has only ever signed
in through a federated provider and has no password by choice.

**Fixed:** `request_password_reset` now refuses when `password_digest` is nil, silently and
indistinguishably from the two refusals already there — unknown login, disabled account. The
token is minted before the branch either way, so the timing story does not change, and the
response an application builds cannot tell the three apart.

Django filters exactly this case out of its reset form, for exactly this reason
(`has_usable_password()`), which is the precedent this follows rather than an invention.

**What that deliberately does not remove.** Setting a *first* password is a profile action for
somebody already signed in, not a recovery one: an application offering it calls
`Accounts::Repository#update_password_digest` behind its own session guard. Recovery is for a
credential that exists.

**Two corrections to how this was measured, both worth keeping.**

*Disabling an account is not something the shard can do.* This validation called
`MemoryAccountRepository#disable`, which exists on the **double** and not in
`Accounts::Repository` — the contract has five methods and none of them writes `disabled_at`.
That is the right split, and deliberate: the application owns its accounts table, so turning an
account off is its `UPDATE`, and the shard only ever *reads* the flag, on every authentication.
The measured property is unaffected — `examples/service_account/app.cr` does the same thing
against SQLite with a plain `UPDATE` and gets the same `DisabledAccount` — but a reader of this
section should not conclude that a repository must implement `disable`.

*`revoke` was not account-scoped, which the example turned into a defect.* Writing
`DELETE /tokens/:id` for `examples/api_tokens` produced `ApiTokens::Service#revoke(token_id)` and
nothing else, so the obvious route ends whichever token the *caller* names. A token id is not
secret material: it appears in `api_token.issued` and `api_token.revoked` audit lines and in any
management listing built on `list`. Fixed additively with `revoke(token_id, account_id)`, which
answers `false` both for somebody else's token and for one that does not exist, so the caller
learns nothing from the difference. Two examples in `spec/security/api_token_spec.cr`.

**Now M3, with the example gap closed.** `examples/service_account/app.cr` is the worked example
this section said was missing: provisioning without human-only fields, a scoped credential, every
interactive path proven closed — including the reset that used to be sent — and both forms of
deprovisioning. What still keeps it from M4 is the human/workload tag, which stays the
application's with no `service_account?` flag anywhere in the shard: what counts as a workload is
a product question. `tools/validation/tok07_spec.cr` holds the six examples.

---

## AUT-06 — Immediate grant revocation and cache invalidation

**Result: M3.** Applicable. The first scenario of the third pass.

Revocation was performed **behind** `RBAC`, straight against the repository, everywhere in this
attempt. That is what "in another process" means to a process holding a cache: the write happened
somewhere that could not call `#invalidate` on this object. Going through `RBAC#revoke` would have
measured the local invalidation hook, which is a much weaker claim than the one the scenario
makes.

**The window was measured with two processes and a wall clock**, not with a test clock — one
process holding a warm cache over a shared SQLite file and asking the same authorized question
every 100ms, another removing the membership. `tools/validation/aut06_watcher.cr` prints the
instant its answer changes:

| Cache | Membership removed at | Answer changed at | Stale window |
|---|---|---|---|
| `ttl: 5.seconds` | +0.2s | +5.004s | 4.8s |
| `ttl: 5.seconds` | +2.0s | +5.004s | 3.0s |
| `ttl: 60.seconds` | +2.0s | still permitted at +10s | ≥8s, bounded at 60s |
| **no cache — the default** | +2.0s | +2.004s | one poll interval, ≤104ms |

So the window is the TTL measured from when the entry was *warmed*, not from the revocation, and
the honest worst case is the whole TTL. **All four pass conditions hold.**

*"The maximum stale-access window is explicit"* — `Cache::DEFAULT_TTL` is five seconds,
`Cache::MAX_TTL` is one minute, and a longer one is refused at construction: `ttl: 61.seconds`
raises `ConfigurationError` naming the ceiling. The cache is also **off by default**, which the
table above shows costs one store read per decision and buys a window of nothing.

*"Multi-process invalidation is possible"* — `RBAC#invalidate(account_id)` is public, and closing
the window early with it was measured: with a 60-second TTL, a decision after the call denies
immediately. It drops every tenant's entry for that account and no other account's.

*"Cache keys include tenant and relevant credential restrictions"* — the tenant is in the key,
length-prefixed so that `("ada:x", nil)` and `("ada", "x")` cannot collide; both were asked and
answered differently. Credential restrictions are **not** in the key, and that is correct rather
than a gap: what is cached is the account's `Grants`, and attenuation is applied *after* the
cache by `RBAC#decide`. Measured — a narrow token warms the entry, a wide token for the same
account reuses it with **no second store read** and is still permitted more, and a session that
warmed the entry with a write grant does not lend that answer to a read-only token.

*"Account-wide and tenant-only revocation cannot be confused"* — `remove_member` takes that
tenant's roles and leaves every other tenant's and every global one; `revoke` with no tenant
argument removes the global assignment only and answers `false` the second time, so a caller
learns that the row it meant to remove was not there; `remove_account` removed all three rows.

**A defect found on the way, and it is not in the cache.**

`Sessions::Service#start` copies `account.tenant_id` onto the session row, and `#resolve` rebuilds
the principal from that row. So the tenant binding is **the one authorization input this shard
copies into a session** — and `Authz::RBAC#decide` reads it, refusing a principal bound to one
tenant that asks about another before it consults membership at all.

Measured against SQLite, changing the column the way an application would:

```
UPDATE auth_accounts SET tenant_id = 'org-a' WHERE id = 'ada'
```

A session started *after* that is confined to `org-a`. The session that already existed still
reports `tenant_id: nil` — unconstrained — and was still permitted inside `org-b` eleven hours
later, kept active an hour at a time. It stops only when the session does, at the twelve-hour
absolute deadline.

The direction of the risk is the wrong one: confining an account has no effect on the sessions it
already has. Everything else in the authorization path is either read live or bounded to a minute;
this one was bounded by the session lifetime, and **nothing said so**. `docs/02-security-model.md`
lists the events that must revoke an account's sessions — password change, account disable, MFA
recovery — and a change to the account's tenant was not among them.

**Fixed, as documentation with a test rather than as a paragraph.** The tenant change is on that
list now, with the reasoning; `Sessions::Record#tenant_id`, `Principal#tenant_id` and
`Accounts::Repository#bump_auth_version` each say their half of it. Three examples in
`spec/security/session_revocation_spec.cr` pin the property: the window is the session's lifetime,
`bump_auth_version` closes it immediately, and `revoke_all` closes it immediately.

**Not fixed in code, deliberately.** `Sessions::Lookup` could carry the account's current tenant
and `#resolve` could fail a mismatch — but that struct is the shape every repository adapter
implements, its own documentation warns that widening it is how a hot path becomes a join across
half the schema, and it would add a column to every authenticated request for a value that
changes approximately never. The lever already exists and costs one row: `bump_auth_version`.

**Also corrected: `Principal#tenant_id` still said "Unused in v0.1".** It is read by `RBAC#decide`
on every tenant-scoped authorization. A comment that says an authorization input is unused is
worse than no comment.

**Why M3 and not M4.** Multi-process invalidation is *possible* and there is no worked example of
it — no pub/sub subscriber calling `invalidate`, which is the shape a replicated deployment needs
and the thing an M4 result would ship. `tools/validation/aut06_spec.cr` holds fourteen examples,
`aut06_tenant_spec.cr` four, and the two-process harness is `aut06_setup.cr`,
`aut06_watcher.cr` and `aut06_revoke.cr`.

---

## AUT-07 — Per-permission assurance/step-up

**Result: M3.** Applicable.

The scenario's three products, declared the way the shard offers them: `profile.read` at
`Remembered`, `data.export` at `Password`, `payout.update` at `MFA`, with `reports.read` at
`ApiToken` for the automated client. Then called through every credential the shard can produce —
a remembered session, a password session, an MFA session, and a personal access token **scoped to
all four permissions** — first in process and then over HTTP against a running server.

**Two of the three pass conditions hold outright.**

*"Strength and freshness are separate"* — they are two axes, measured independently.
`AssuranceLevel` is strength and `authenticated_at` is recency, and each fails while the other
holds: a second factor proved three hours ago is `at_least?(MFA)` and not `fresh?(5.minutes)`; a
password typed one second ago is fresh and not `at_least?(MFA)`. `RBAC#decide` reads strength
only, so a route that also wants recency asks separately.

*"An automated token cannot satisfy an interactive step-up by having a recent timestamp"* — holds,
and this is the condition the design earns its keep on. `AssuranceLevel::ApiToken` is 15,
below `Password` at 20, and `Principal#fresh?` returns false below `Password` **whatever the
timestamp says**: a token authenticated at this instant answers false for a window of one second
and for a window of a year. Over HTTP, the token scoped to all four permissions received 403 on
`/export`, `/payout` and `/email` — and its scopes were not what refused it. The assurance floor
is checked before the scope is consulted, so a token scoped to exactly `payout.update` is denied
`InsufficientAssurance` rather than `OutOfScope`.

Worth naming: the assurance gate runs **after** the grant check, so somebody with no role is told
"no" rather than "authenticate more strongly and try again". A step-up prompt is itself
information — it confirms the permission exists and that the caller would hold it.

**The third condition failed, and was fixed.** *"The denial can produce a suitable API challenge
without revealing unrelated policy."* Measured against the running server, three different
refusals produced one challenge:

| Request, bearer token | Why it refused | Challenge |
|---|---|---|
| `GET /export` | credential not strong enough | `Bearer realm="api", error="insufficient_user_authentication"` |
| `POST /payout` | credential not strong enough | the same |
| `POST /email` | authentication not recent enough | the same |

The shard holds that distinction internally — `minimum_assurance` is strength,
`require_fresh!(within:)` is recency — and discarded it at the response boundary, leaving the one
party that has to act on it unable to see it. "Type your password again" and "produce a second
factor" are different prompts.

**Fixed:** `FreshAuthenticationRequiredError` carries the window when recency is what failed, and
`ErrorHandler` emits RFC 9470 §3's `max_age` — "the allowable elapsed time in seconds since the
last active authentication event", which is precisely what `require_fresh!(within:)` means. Its
*absence* is the signal for the strength case, deliberately rather than `max_age="0"`, which would
tell a client to retry something that cannot succeed. Re-measured:

```
POST /email    Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication", max_age="300"
POST /payout   Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication"
POST /email    Cookie <session> 403   Bearer realm="api"
```

There is no `acr_values` beside it, and that is a decision rather than an omission: ACR values are
a deployment's own vocabulary, and this shard has an assurance *ordering* rather than a set of
strings it can honestly publish. `blueprints/0028-step-up-challenge-parameters.md` records the
whole argument, including the shape a future consumer with a real ACR vocabulary would get.

**Why M3 and not M4: freshness cannot be declared per permission.** The scenario asks to *"declare
minimum assurance and maximum authentication age per permission"*. Only the first is declarable.
`Permission` carries `minimum_assurance` and nothing about recency, so every route that needs a
recent credential says so itself — which is the exact hazard `Permission`'s own documentation
argues against for assurance:

> Assurance is part of the permission, not the call site … a rule written at each call site is a
> rule that is missing at the call site somebody forgot.

That argument does not stop being true for recency. A `payout.update` reachable from three routes
is three chances to omit `require_fresh!`, and the omission fails open. `PathGuard.new(prefix:,
within:)` covers a subtree, which is the mitigation and is not the same thing as declaring it once
with the action.

**Not closed in this pass**, because the shape is a real design question rather than a missing
argument: a `maximum_age` on `Permission` would have to be enforced somewhere that has both the
permission and the clock, and `RBAC#decide` deliberately does not raise. Two candidates —
`Decision` gaining a freshness denial, or `authorize!` checking it after the decision — and
choosing between them is worth a blueprint of its own rather than a line in this one.

`tools/validation/aut07_spec.cr` holds the seven in-process examples;
`tools/validation/aut07_app.cr` is the server the table above was measured against. The fix's own
regressions live in `spec/integration/kemal_spec.cr` under "step-up", including one that pins the
absence of `max_age` on a strength denial.

---

## HTTP-02 — Mixed browser session and bearer API in one monolith

**Result: M3 → M4.** Applicable.

One process, three audiences, three subtrees: `/app` for a browser, `/api` for token clients,
`/shared` for either. Sixteen requests through it — every subtree crossed with every credential,
and CSRF probed where a cookie can and cannot authenticate.

**All three pass conditions held on the first attempt**, and two of them held because the
application wrote the missing piece itself. That is what turned this into a fix rather than a
result — and one of the two gaps is one earlier scenarios had already pointed at. HTTP-01 and
HTTP-03 both stop at *"the same parameter HTTP-02 wants on `PathGuard`"*, three times between
them: HTTP-01 for the app-wide redirect, HTTP-03 for app-wide credential precedence. Two of the
three are closed here; the third — precedence per subtree — is not, and is noted below.

*"Each subtree can declare accepted credential classes"* — the shard had nothing for it.
`PathGuard` declared authentication, freshness and strength for a subtree, and not *which kind*
of credential it accepted. So the attempt wrote `CredentialClassGuard`, twenty-five lines over
`principal.credential.kind`, which works — the machinery has been public since
`blueprints/0021`.

*"JSON and redirect behaviour are independent"* — `ErrorHandler.new(login_path:)` is one setting
for the whole process, so the attempt registered the shard's handler **twice**, wrapped in a
path-scoping handler that reassigns `Kemal::Handler#next`. Also works, and it is the kind of
thing a consumer should not have to derive.

*"CSRF applies precisely where browser-attached credentials can authenticate"* — holds with no
help at all, and it is the sharp version of the rule rather than the convenient one:

| Request | Result |
|---|---|
| `POST /app/settings`, session cookie, no token | 403 `invalid CSRF token` |
| `POST /api/items`, bearer only | 200 |
| `POST /api/items`, bearer **and** session cookie | 403 `invalid CSRF token` |

The last row is the load-bearing one. A request carrying both is still protected, because the
cookie alone would authenticate it — so an attacker who can trigger the request cross-site does
not need the token.

**The measured gap, and it is the one an API client actually hits.** With `login_path:` set for
the browser half, an unauthenticated request to `/api/items` sending no `Accept` header received:

```
302 Found
Location: /login
```

The redirect decision is a *guess* about who is asking — JSON in `Accept`, an
`X-Requested-With`, or an `Authorization` header. HTTP-01 fixed the third of those in v0.8; what
is left is the client that sends none: `curl` with no flags, an HTTP library with no default
`Accept`, or anything probing for a 401 before it authenticates. It gets an HTML redirect for a
path that serves no HTML.

**Fixed, both halves, as configuration:**

```crystal
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login", api_prefixes: ["/api"])
use KemalIdentity::Kemal::PathGuard.new(prefix: "/app", credentials: [CredentialKind::Session])
use KemalIdentity::Kemal::PathGuard.new(prefix: "/api", credentials: [CredentialKind::ApiToken])
```

Re-measured: **all sixteen rows identical to the hand-written version**, with both hand-written
handlers deleted. `tools/validation/http02_app_before.cr` keeps the version that needed them, so
the two can be probed against each other.

Three details that are decisions rather than defaults:

- A wrong-class credential is **403**, not 401. It is valid; it is the wrong door, and 401 would
  tell a working client to authenticate again in a loop.
- The class check runs **after** `require!`, so an anonymous request is still a 401 and nobody
  learns which credential classes a subtree accepts without first holding one.
- An empty `credentials:` list is refused **at boot**. A subtree that accepts nothing is almost
  always a list built from configuration that came back empty, and the alternative is 403-ing
  every request in production.

`CredentialKind::Custom` covers every credential an application's own `RequestAuthenticator`
establishes, so two custom families are one kind to this parameter. That is stated in the API
documentation rather than worked around: `CredentialRef#name` is what tells those apart, and a
subtree selecting on it writes its own handler — which is now a smaller job, because
`PathPrefix.covers?` is public. The prefix rule was extracted rather than duplicated: `/api`
covers `/api/items` and not `/apiary`, and there is one implementation of that rather than two
that almost agree.

**What stays open, and it is HTTP-03's:** credential *precedence* is still app-wide.
`AuthenticationHandler.new(precedence:)` decides whether a cookie or a bearer header wins when
both arrive, once, for every route. A monolith can now say which classes each subtree accepts,
which is enough for the three subtrees above — the guard refuses the wrong class after
authentication either way — but a deployment that wants `/api` to resolve the bearer credential
*first* while `/app` resolves the cookie first cannot say so. That needs the handler to choose by
path, and choosing an order is a sharper decision than accepting a class, so it is left where
HTTP-03 left it rather than bundled in here.

**M4, not M3.** `examples/mixed_monolith/app.cr` is the whole arrangement with a `curl` line per
case, CI compiles it on every matrix entry, `docs/04-kemal-integration.md` has the wiring under
its own heading, and seven examples in `spec/integration/kemal_spec.cr` pin the behaviour —
including the lookalike-path rule and the boot refusal.

---

## OPS-03 — Metrics and tracing without secret leakage

**Result: M3.** Applicable.

The scenario's demand is precise: *"add instrumentation around public services and adapters
**without modifying their source**"*. So `tools/validation/ops03_metrics.cr` is a set of
decorators over published contracts — `Accounts::Repository`, `Sessions::Repository`,
`Authz::Repository`, `Passwords::Hasher`, `RateLimiter`, and the injected transports of
`JWT::JWKS` and `OIDC::Client` — and `ops03_spec.cr` runs a login, a session read, a bearer
authentication, ten authorization decisions and a rate-limit denial through them.

Nothing was reopened, nothing was subclassed from a concrete service, and no private method was
touched. **All four pass conditions hold.**

*"Hooks expose durations and low-cardinality outcome categories"* — durations come from the
decorators; the categories are the shard's own enums, which is what makes them bounded:
`FailureReason` has 10 members and `Authz::DenialReason` 7, every one a name rather than a value
read from a request. A metric labelled `reason=InvalidCredential` has a domain of ten
forever.

*"Subject, token, login and tenant are not metric labels by default"* — the shard publishes no
metrics at all, so the interesting question is whether a wrapper is *pushed* towards labelling
by identity, and it is not: every decorator sees the identifier and none of it has to be
recorded. Measured with a registry that **refuses** an unbounded label value, so a wrapper that
labelled by account id would fail the suite loudly rather than explode a time series quietly.
Asserted afterwards: no label value equals the account id, the login, a token id, a session id
or a raw secret.

*"Tracing never records raw headers or cookies"* — structurally, not by redaction. `SecurityEvent`
has six typed fields and a `Hash(String, String)`; there is no request object, no header map and
no cookie jar anywhere in it, so an event cannot carry an `Authorization` header even by
accident. Measured against a real run: a login, a failed login, a token issue, a token
authentication, a revoke and a session revoke produced events in which the raw session token,
the raw API token, the password and the login are all **absent**, while the session id and the
token id are present — which is the point of them.

*"Instrumentation can distinguish database, hashing and remote-provider latency"* — three layers,
separately timed, measured in one run: `["database", "hashing", "limiter", "remote"]`. The remote
one is only possible because both places this shard talks to somebody else's server take an
injected transport: `JWKS.new(fetcher:)` and `OIDC::Client.new(exchanger:)`. Without those two
seams this condition would fail outright.

**Cache hits are the one signal with no hook.** The persona's list includes them, and
`Authz::Cache` exposes `#size` and no counter. Measured: ten decisions over a warm cache produced
**one** repository read, so the hit rate is `decisions − reads` and both sides are already
counted by the application. Derivable, not exposed — now written down in
`docs/02-security-model.md` rather than left to be rediscovered.

**A defect found on the way, and it is the failure mode OPS-02 was built to prevent, reached
through a different door.**

`KemalIdentity.event_sink=` binds a `Log` backend. `::Log.setup` and `::Log.setup_from_env`
**replace the whole configuration**, binding included. So an application that wires its sink and
then configures its logging has no sink:

```crystal
KemalIdentity.event_sink = SiemSink.new
Log.setup_from_env                        # the sink is gone
```

Nothing raises, and `EventBridge#failures` stays at **zero** — because zero events reached the
bridge to fail. `blueprints/0027` decision 4 exists so that "a sink that is failing is never
silent"; a sink that was never *bound* is silent, and is invisible to the number built to watch
for silence.

The shape it was found in is the worst available. This attempt bound its sink at the top of a
spec file, as anybody would, and collected **nothing** — Crystal's spec runner configures `Log`
after the file loads. The same code in a plain program collected everything:

```
plain program:  after yields: 1 event
spec file:      events=0 failures=0
```

So the tests somebody writes to check their SIEM wiring are exactly the tests that cannot see it
working.

**Fixed:** `KemalIdentity.event_sink_delivering?` emits one named `sink.probe` event and answers
whether the bridge saw it. It is false for a binding a later `Log.setup` dropped, true again once
the sink is rebound, and — deliberately — **true** for a sink that raises on every event, because
that sink is bound and `#failures` is the number for it. Two questions, two answers.

The budget is a count of fiber yields rather than a duration: what is being waited for is a
handoff to the `:async` dispatcher, this shard reads time only through an injected `Clock` (its
own hygiene spec enforces that, and caught the first attempt at this), and a yield budget cannot
hang. Measured: nothing after ten yields, everything after fifty; the default is 1000.

Four examples in `spec/security/event_sink_spec.cr`, and one in the consumer suite that performs
the whole sequence — bind, verify, `Log.setup`, verify again, rebind, verify.

**Why M3 and not M4.** No worked example, and no packaged contract for an instrumentation
decorator — `docs/02-security-model.md` now has the rules and the two seams, which is
documentation rather than something a consumer can run. The decorators in
`tools/validation/ops03_metrics.cr` are the closest thing and they live outside the repository on
purpose, which is a reasonable place for them but not what M4 asks.

---

## TOK-08 — Token rotation with an overlap window

**Result: M2 → M3.** Applicable.

A `svc-deploy` account with a deploy key, rotated the way the scenario describes: a replacement
linked to the existing family, a bounded overlap during which both work, then the old one stops.

**Two pass conditions held on the first attempt.**

*"Both credentials are separately auditable"* — two token ids, two `api_token.issued` events each
naming its own credential, and both in one management listing. The operationally important half
is `Token#last_used_at`: it is what answers *"has the fleet picked up the new key yet"* without
asking the fleet, and it is per token.

*"Rotation never reveals an old raw token again"* — structurally. Only the digest is stored,
`Issued#token` is the only place a secret ever exists, and the record a management screen renders
carries `Bytes` that no client could present.

**The family is the application's, and that is the right split.** `ApiTokens::Token` has an id, an
account, a name and scopes, and nothing that groups two tokens; the attempt wrote a fifteen-line
family table, the same shape TOK-02's resource selection turned out to be.

**The condition that failed: the overlap had no upper bound that anything enforced.**

`expires_at` could only be chosen **at issuance**, and a rotation happens months later. "One hour
from whenever somebody rotates" was not expressible, so the only ways to close the window were:

- revoke the old token immediately — no overlap at all, which is the thing the scenario exists
  to avoid; or
- schedule a revoke — and then the window closes when a job runs. If the job does not run, the
  retired credential lives forever. The bound is the scheduler's, not the credential's, which is
  the wrong direction for a security deadline.

Measured as a compiler error, which is the honest form for a missing method:

```
Error: undefined method 'expire' for KemalIdentity::ApiTokens::Service
```

**Fixed: `Repository#expire(id, at)` and `Service#expire(token_id, account_id, at)`.** The
deadline lands on the row, so the authentication path enforces it — no sweeper, nothing that has
to have run. Three decisions inside it:

**It never lengthens.** `false` for a token that already expires at or before `at`, and the
comparison is *in the statement* rather than a read followed by a write, so two callers cannot
interleave into a later deadline than either asked for:

```sql
UPDATE auth_api_tokens SET expires_at = $1
 WHERE id = $2 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $1)
```

**It is account-scoped in the form a route may hand a client id to**, exactly as `revoke` became
in v0.9.0, and answers the same `false` for somebody else's token and for one that does not
exist.

**A past deadline is allowed** and closes the window immediately; the token then fails as
`Expired` rather than `Revoked`, which is the honest reason — nobody revoked it.

**This adds an abstract method to a repository contract**, so a third-party adapter must
implement it to compile. That is a breaking change for adapter authors, taken deliberately and
now rather than after the v1.0 freeze, and the shared contract gained seven examples so an
adapter learns the rule from a failing spec rather than from prose.

**A second defect, found while writing the contract examples, and this one is a fail-open in the
shipped test double.**

`MemoryApiTokenRepository#replace` rebuilt a token without its `scopes`. `touch` runs on the
**authentication path**, so the first authentication of a newly issued attenuated token rewrote
its row with no scopes, and every request after that was **unrestricted**:

```
after issue:     stored=nil          principal=["reports.read"]
after touch:     stored=nil          principal=nil
next request:    stored=nil          principal=nil
```

Production was never affected — both SQL adapters `UPDATE` one column — so the only thing this
could break is a consumer's *test*, in the direction of granting more than production would. That
is the exact hazard DEV-02 names: *"a fake cannot pass while violating production invariants."*
Fixed, and the contract now has four examples demanding that attenuation survive `touch`,
`revoke`, `expire` and a bulk revocation, so no adapter can lose it quietly either.

**What keeps this at M3.** Revoking a *family* atomically is still not expressible through the
shipped adapters: `revoke_all` is account-scoped, and two `revoke` calls are two statements, so a
process that dies between them leaves half the family live. An application that needs the pair to
fall together implements `ApiTokens::Repository` over its own table, where it owns the
transaction — which is a real answer and not a first-class one. `tools/validation/tok08_spec.cr`
holds the seven examples, and `docs/02-security-model.md` has the rotation under *Token
discipline*.

---

## TOK-09 — Organisation-wide token lifetime policy

**Result: M2 → M3.** Applicable.

Both deployments the scenario describes, in one attempt: an enterprise requiring every personal
token to expire within thirty days and forbidding unbounded ones, and the deployment next door
permitting a non-expiring deploy key.

**Before the fix there was no policy at all.** `issue(expires_at:)` refused a *past* expiry and
accepted everything else, including `nil`. An organisation-wide rule therefore had to live in
whatever wrapper the application put around issuance — which is a rule that is missing at the
call site somebody forgot, and this shard already rejects that shape for assurance
(`Permission#minimum_assurance`) and for passwords (`Passwords::Policy`).

**Fixed with the idiom that was already there:** `ApiTokens::LifetimePolicy`, injectable at boot
through `api_token_lifetime:`, absent by default. All four pass conditions now hold.

*"Policy is injectable and testable"* — a struct with `maximum` and an optional `default`, and
`#violation(expires_at, now)` takes the instant rather than reading a clock, so it is testable
with no service and no repository. A `default` larger than the `maximum` is refused at
construction.

*"Invalid issuance fails before storage"* — measured, not assumed: after a refusal
`list_for_account` is **empty**. The check runs before the secret is generated, so a rejected
issuance leaves no row, no digest and no credential that briefly existed. `PolicyError` carries
the violation and the limit, and both are safe to show — somebody creating a credential is not
somebody proving they hold one, so there is no account to enumerate. That is the same reasoning
`Passwords::PolicyViolation` already records.

*"The semantics of existing tokens after a policy change are explicit"* — they keep what they
were given, and the policy is **not** consulted on the authentication path. Both halves are
measured: a ninety-day token issued under the old rule still authenticates thirty-one days after
the limit drops to thirty. The alternative would be worse than surprising: a policy that could
refuse while authenticating turns a configuration change into an outage for every client holding
an older token.

And the retro-fit an organisation actually wants is now possible, because TOK-08 landed first:
walk the tokens that violate the new limit and `expire` each one. Measured in the same example —
after the sweep the ninety-day token fails as `Expired`, and nothing could have been lengthened
by accident because `expire` refuses to.

*"Management APIs can find tokens approaching expiry without exposing secrets"* — `list` carries
`expires_at` and `name` and a digest in `Bytes`, so "expiring within a week" is a filter over the
management listing. Deployment-wide rather than per-account is the application's query over its
own database, which is where it belongs.

**Why M3 and not M4.** No worked example — the policy is three lines in `configure`, and the
interesting part is the *pairing* with `expire` for a retro-fit, which lives in
`docs/02-security-model.md` as prose rather than as something a consumer can run.
`tools/validation/tok09_spec.cr` holds eleven examples and `spec/security/api_token_spec.cr`
another ten.

**A residual risk, stated rather than hidden.** The PostgreSQL `expire` statement is not verified
locally — this machine has no role for the test database, so `spec/integration/postgres_spec.cr`
is pending — and only CI runs it. The SQLite statement, the in-memory double and the shared
contract all pass; the PostgreSQL one differs by placeholder syntax alone.

---

## MFA-01 — Multiple factors per account

**Result: M2 → M3.** Applicable.

Three factors on one account — two authenticator apps and a "hardware credential" standing in as
a third TOTP factor, since WebAuthn is MFA-02's scenario and absent here — then one device lost.

**Two pass conditions held on the first attempt.**

*"Factor IDs are first-class"* — `Factor#id` is what `confirm`, `remove` and `MFA::Verified#factor`
all speak in, so "which device answered" is a fact the application receives rather than infers.
Measured: verifying with the tablet's code returns the tablet's id, and with the phone's returns
the phone's.

*"Audit identifies the factor without revealing its secret"* — `mfa.verified`,
`mfa.enrolment_started` and `mfa.factor_removed` all carry `factor:`, and `Factor#to_s` and
`#inspect` are overridden so the sealed secret cannot reach a log line through an accidental
interpolation. The provisioning URI — the only place the secret exists in the clear — is on
`PendingEnrolment` and never on the stored record.

**Replay across factors is not reachable, and the reason is worth stating.** A counter is
consumed per factor id, so spending the phone's code leaves the tablet's untouched — measured
both ways. And two factors cannot share a secret by an application's mistake, because `enrol`
takes no secret: the shard generates one. So the cross-factor replay this condition asks about
is closed by construction rather than by a check that could be forgotten.

**The condition that failed, and it is a privilege boundary.**

`MFA::Service#remove(factor_id)` took **only the factor id**. A route written the obvious way —
`DELETE /mfa/factors/:id` — removes whichever factor the caller names, including somebody
else's. This is precisely the defect TOK-07 found in `ApiTokens::Service#revoke` in v0.9.0, in a
second place, and a factor id is not secret material for the same reasons: it is in
`mfa.verified` and `mfa.factor_removed` audit lines and in every management listing.

The direction of the harm is worse than for a token. Removing somebody's second factor does not
end their access; it **weakens** their account, quietly, and the next password-only login
succeeds where it would have demanded a code.

**A second gap in the same call.** *"Replacing or removing the last strong factor requires fresh
policy"* — nothing distinguished removing one of two devices from removing the only one, which
is "turn MFA off" wearing the name of "unregister a device".

**Fixed:**

```crystal
mfa.remove(factor_id, account_id)                     # settings screen: refuses a last factor
mfa.remove(factor_id, account_id, allow_last: true)   # "turn MFA off", said out loud
mfa.remove(factor_id)                                 # administrative, unchanged
```

The account-scoped form answers `false` for somebody else's factor and for one that does not
exist — the same answer, so the difference cannot be used to discover whether an id is real —
and defaults `allow_last` to **false**, while the administrative form defaults it to true. The
asymmetry is the point: a settings screen should not be able to turn MFA off by accident, and an
administrator calling the id-only form has already said what they mean.

`confirm` gained the same optional scoping, though it is the cheaper guard: confirming somebody
else's pending enrolment also requires a code from their secret.

**A behaviour change came with it.** Removing the last confirmed factor now **voids the account's
recovery codes**, for the reason `#disable` already did: a list written down years ago that
survives into a later re-enrolment is a full bypass of the new factor. One existing example
asserted the old behaviour under the comment *"removing one of two devices is not MFA is off"* —
while removing the only device. It is now two examples, one for each case, which is what the
comment described all along.

**Why M3 and not M4.** No worked example: `examples/` has nothing for the MFA family, and "enrol
three factors, lose one, remove it safely" is the shape a consumer would copy.
`tools/validation/mfa_family_spec.cr` holds the attempt, and the new behaviour has eight examples
in `spec/security/mfa_spec.cr`.

---

## MFA-04 — Recovery and factor replacement policy

**Result: M2 → M3.** Applicable. And this is the scenario that found the worst defect of the
pass.

**Three of the four pass conditions held.**

*"Other sessions/tokens can be revoked according to policy"* — `redeem_recovery_code` calls
`Sessions::Service#revoke_all(account_id, except_id:)` itself. Measured: a session elsewhere
fails on its next read, and the session doing the recovery survives because `except_session_id`
spared it. The reasoning is already in the code and is right: "lost" and "taken" look identical
from the server.

*"Replacement requires a fresh trusted proof"* — the shard's half holds.
`AssuranceLevel::ApiToken` is below `Password` and `Principal#fresh?` answers false for it and
for `Remembered` whatever the timestamp says, so a route guarding recovery or enrolment with
`require_fresh!` refuses an automated credential outright. The chaining MFA-04 asks about — an
API token into recovery — cannot be built out of these pieces.

*"Every recovery event is auditable and rate-limited"* — `mfa.recovery_code_used` at **warning**
with the number of codes left, on the same per-account quota key as a second-factor check, and a
refusal when the limiter is unavailable rather than an unmetered guessing window on the last way
in. Measured, including the throttle.

**The condition that failed: recovery was not named separately, and the documentation said to
make it so.**

`redeem_recovery_code` returns `Verified(by_recovery_code: true)`, so the *result* distinguishes.
But `RequestContext#mfa_verified!` — whose own documentation said *"call it after
`MFA::Service#verify` **or** `#redeem_recovery_code` returns `Verified`"* — raises the session to
`AssuranceLevel::MFA`. A recovery code therefore produced a principal indistinguishable from one
that had proved a hardware key.

Which means the sharpest gate in the system was reachable through its weakest path. AUT-07's own
persona is *"changing payout details needs phishing-resistant MFA"*, expressed as
`minimum_assurance: MFA` — and a printed list of codes, held by whoever finds the piece of paper,
satisfied it.

**Fixed: `AssuranceLevel::Recovery = 25`**, between `Password` and `MFA`, plus
`env.auth.recovery_verified!` and a corrected comment on `mfa_verified!`. The enum's own
documentation asked for this — *"the gaps of ten exist so an intermediate level can be added
later"* — and appending is the one change it permits.

Measured over HTTP, in the integration application: after redeeming a code the session reaches
`/settings/factors` (guarded at `Recovery`, which is where a new factor gets enrolled) and is
**refused** at `/vault` (guarded at `MFA`). The session identifier rotates, as it does for every
assurance increase.

**And the defect that was found by accident, which is the most serious thing in this pass.**

Writing the "a spent code and an invented one answer alike" example produced a 401 where a 200
was expected — for a code the shard had generated seconds earlier. The reason:

```
FailureReason::MalformedCredential
```

`RandomSource#token` is base64url, whose alphabet includes `-`. `redeem_recovery_code` stripped
`-` before checking the length, because a recovery code is *typed* and applications display them
in groups. Those two decisions are individually sensible and together they were a defect: a code
containing a hyphen was shortened by one character, failed the length check, and could **never
be redeemed**.

Measured over two thousand freshly generated codes:

```
length=43; 935/2000 contain a hyphen (46.8%)
token_length(32)=43
raw=43  after stripping '-'=42
```

**Nearly half of every recovery list issued by v0.4 through v0.9 is dead on arrival** — on the
credential that exists for the day somebody has lost everything else. It survived because the
suite's recovery examples redeem *one* code, and one code passes half the time.

**Fixed in both directions:**

- **Generation no longer produces `-`.** A code is redrawn if it contains one, rather than
  substituted — replacing `-` with a fixed character would make that character twice as likely
  and quietly cost a bit of entropy. At one in sixty-four per character it takes about two
  draws, and the loop is bounded at thirty-two with an `InfrastructureError` rather than spinning
  on a random source that is not behaving like one.
- **Redemption accepts both readings.** Whitespace-stripped first, then whitespace-and-hyphen
  stripped: the first keeps every already-issued hyphenated code redeemable — which matters,
  because half the lists in existence hold one — and the second is the code an application
  displayed in groups and somebody typed with the separators. At most two digest comparisons,
  both length- and pattern-checked before anything is hashed, on a path that is rate limited and
  rarely reached.

The regression specs assert **every** code in a list of twenty-five, not the first one, since the
defect was a coin flip per code.

**Why M3 and not M4.** Same gap as MFA-01: no worked example of the recovery flow, and the
`Recovery` assurance level is new enough that no consumer's route has been written against it
yet. `tools/validation/mfa_family_spec.cr` holds eighteen examples across both scenarios,
`spec/security/mfa_spec.cr` sixty, and `spec/integration/kemal_spec.cr` four over HTTP.
