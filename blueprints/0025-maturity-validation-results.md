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

**All seven very-high scenarios are done, fourteen high-frequency ones, and two medium.**
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
| HTTP-03 | High | M3 | **M2** | An invalid cookie masks a valid bearer; precedence was undocumented and is not per-route |
| JWT-01 | High | M3 | **M2** | Two validators cannot be chained, and there is no bounded way to read `iss` first |
| JWT-02 | High | M3 | **M3** | — |
| JWT-03 | High | M3 | **M3** | — |
| JWT-04 | Medium | M2–M3 | **M3** | Works, but inherits JWT-01's hand-rolled routing to get per-issuer validators |
| HTTP-07 | High | M3 | **M3** | Works and was entirely undocumented, including the trust boundary |
| DEV-03 | Medium | M2–M3 | **M3** | The claim holds and links no Kemal; there is no worked example |
| IDP-01 | High | M3 | **M2** | `Pending` does not bind the provider, and provider-specific parameters cannot be sent |
| IDP-02 | High | M3 | **M3** | — |
| IDP-04 | High | M3 | **M3** | — |

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

The remaining twenty-seven scenarios — fourteen high, ten medium, one low, two niche-critical —
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
