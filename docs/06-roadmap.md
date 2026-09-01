# 06 — Roadmap

The dominant product risk is scope, not capability. A half-finished auth library is worse
than none, because people deploy it. Every milestone below is shippable on its own.

## v0.1 — Secure core

**Released as part of `v0.2.0` on 2026-08-25.** Every step below is done and every release
blocker in `docs/05-testing.md` has a named spec. The Crystal and Kemal floors were the last
outstanding item and are now measured rather than guessed — see `docs/00-scope.md`.

The whole of v0.1 is: password login, a revocable session, and a cookie.

| Order | Deliverable | Done when |
|---|---|---|
| 1 | `core`: `Principal`, `Outcome` union, `Clock`, `RandomSource`, errors | contract specs green, no DB |
| 2 | `Hasher` contract + `BcryptHasher` + length validation + `dummy_digest` | hasher contract spec green, over-length rejected |
| 3 | `AccountRepository` + `SessionRepository` contracts + in-memory adapters | contract specs green against the doubles |
| 4 | `SessionService`: create, resolve, rotate, revoke, revoke-all; cookie codec | full session lifecycle blocker list green |
| 5 | `PasswordAuthenticator` with timing equalisation and lazy rehash | credential blocker list green |
| 6 | `AuthenticationHandler`, `require!`, `require_fresh!`, `PathGuard`, `ErrorHandler` | Kemal integration blocker list green, including `HEAD` |
| 7 | `CSRFHandler`, login form included | CSRF blocker list green |
| 8 | `RateLimiter` contract, `NullRateLimiter`, login path wiring | rate limiting blocker list green |
| 9 | PostgreSQL adapters + migrations | **done** — same contract specs green against PostgreSQL. Migrations use micrate's *file format*; micrate itself cannot resolve on this stack, see `blueprints/0002-no-micrate-dependency.md` |
| 10 | Dedicated execution context for hashing | **done** — at 50 concurrent logins, p99 unrelated-request latency is 1.17 ms with `HashingExecutor` against 2,176 ms without |
| 11 | `examples/browser_session` + README + security documentation | **done** — the example compiles in CI; README carries the measured numbers |

**Not in v0.1:** remember-me, password reset, email confirmation. They are v0.2. The
`auth_action_tokens` schema and the token discipline ship now so that adding them is not a
migration.

Realistically this is several weeks of focused work, not a weekend. Steps 4 through 7 are
where nearly all the difficulty is.

## v0.2 — Account lifecycle

**Released as `v0.2.0` on 2026-08-25**, in the same tag as v0.1: the two milestones were
finished back to back and never had a release between them, so publishing a `v0.1.0`
containing v0.2 features would have misrepresented both.

Password reset, email confirmation, remember-me with rotating single-use tokens and family
revocation, `Notifier` events. Everything digest-only, single-use, atomically consumed.

| Deliverable | State |
|---|---|
| `ActionToken` + repository, atomically consumed | **done** — `blueprints/0011-action-token-atomicity.md` |
| `Notifier` contract and events | **done** |
| Password reset, with enumeration and flood protection | **done** |
| Email confirmation | **done** |
| Remember-me, rotating with family revocation | **done** — `blueprints/0012-remember-me.md` |
| Wired into `Application` and the Kemal handler chain | **done** — `env.auth.remember!`, restore on a session-less request, logout forgets the family |

Enumeration behaviour on the reset endpoint is the thing to get right: identical response
and identical timing whether or not the address exists, plus per-account rate limiting so
the endpoint cannot be used to flood someone's inbox.

## v0.3 — Adapters and hardening

SQLite adapter (which also makes CI cheaper), the sweeper, structured audit events,
`kemal_identity_argon2` as a separate shard, and the compatibility matrix.

| Deliverable | State |
|---|---|
| The sweeper | **done** — `KemalIdentity::Sweeper`, opt-in, across all four tables |
| Compatibility matrix | **done** — floors measured and CI-tested, `blueprints/0013` |
| Structured audit events | **done** — one named `Log` source, catalogue documented in the README, and `spec/security/audit_trail_spec.cr` asserts the events `docs/02-security-model.md` requires are actually emitted. Writing that spec is what found session rotation and bulk revocation missing entirely. |
| SQLite adapter | **done** — all four repositories, 111 contract examples, no server needed. `blueprints/0014-sqlite-adapter.md` |
| `kemal_identity_argon2` | **done** — separate shard, `urunsiyabend/kemal-identity-argon2`. Runs this project's own `Hasher` contract, required straight out of the dependency rather than copied. |
| Split the driver dependencies | **not started** — see below |

### Known issue: `pg` and `sqlite3` are hard dependencies

`shard.yml` declares `db`, `pg` and `sqlite3` under `dependencies`, so **every** consumer
installs both database drivers whether or not it uses either. Building
`kemal_identity_argon2` — a shard whose only job is to hash passwords — pulls in PostgreSQL and
SQLite, which is how this was noticed.

Nothing in `src/kemal_identity.cr` requires them. Only `kemal_identity/postgres.cr` and
`kemal_identity/sqlite.cr` do, and those are opt-in requires.

The fix is to move `pg` and `sqlite3` to `development_dependencies` and document that an
application using an adapter adds the matching driver to its own `shard.yml` — which it needs
anyway, since `DB.open("postgres://…")` resolves the driver in the application's own build.
`db` stays, because the adapters' types reference it.

Deferred rather than done: it changes what consumers resolve, so it belongs in a release where
that is the headline rather than a side effect.

## v0.4 — API authentication

**Released as `v0.4.0` on 2026-08-26.** Bearer tokens as a `RequestAuthenticator`, in the
order this section originally set out: opaque personal access tokens first, JWT second and
off by default. `blueprints/0015-bearer-credentials.md` records the decisions.

| Deliverable | State |
|---|---|
| `RequestAuthenticator` contract, `AssuranceLevel::ApiToken` | **done** — 15, between `Remembered` and `Password`, and never fresh, so `require_fresh!` refuses a token-bearing request outright |
| Opaque personal access tokens | **done** — `ApiTokens::Service`, digest-only storage, revocable on the next request, throttled `last_used_at`, `ki_` scanner prefix. PostgreSQL and SQLite adapters, both running the same 28-example contract |
| JWT validation | **done** — `JWT::Validator`, off unless an application passes one. HS256/384/512, algorithm allow-list, `none` unrepresentable, `kid` rotation, required `iss`/`aud`/`exp`/`purpose`, bounded skew, a lifetime ceiling |
| One header, two credentials | **done** — `AuthenticatorChain` routes on shape and stops at any credential that was recognised and then failed |
| CSRF exemption for bearer-only requests | **done** — keyed on the session cookie *as presented*, so an expired cookie cannot expire its way out of CSRF protection |
| The revocation trade-off, documented | **done** — `JWT::RevocationStore` |

Scopes are deliberately absent: a token authenticates, it does not authorize. That belongs
with the roles and permissions in v0.6, and `auth_api_tokens` has no scope column to
half-enforce in the meantime.

### The JWT revocation trade-off

Stated here as well as in the API docs, because it is the reason JWT is second and off.

**A stateless JWT cannot be revoked before its `exp`.** The signature is the entire proof, the
server keeps nothing, and there is therefore nothing to change when someone clicks "sign out
everywhere" or an employee leaves. There are exactly two honest answers:

1. **A very short lifetime.** Keep `exp` minutes away and accept that a stolen token works
   until then. `Validator#max_lifetime` enforces this and defaults to one hour. The property
   you get is bounded exposure, not revocation.
2. **A `jti` denylist.** `JWT::RevocationStore` records the id of every token that must stop
   working, and the validator checks it on every request. That is a read from shared storage
   on the hot path — precisely the thing a JWT was chosen to avoid. It buys real revocation
   and it costs the statelessness. Do not go on calling the result stateless.

If you are reaching for option 2, compare it against `ApiTokens::Service` first: that already
reads from storage on every request and gives revocation, an expiry you can extend, and a
`last_used_at` — for the same single lookup. A JWT plus a revocation store is usually the
worse half of both designs.

The optional `accounts:` argument is the same admission in miniature: without it, a disabled
account keeps authenticating until `exp`.

## v0.5 — Federated identity and MFA

OAuth2 / OIDC as a **client**, never an authorization server. Authorization Code + PKCE
only, `state` on every flow, `nonce` for OIDC, exact registered redirect URI matching,
issuer and audience validation, a cached JWKS with a timeout, and an open-redirect check on
the callback.

The persistent key for an external identity is `(issuer, subject)` — never email. Provider
emails change; `sub` is the stable identifier within an issuer. Provider access and refresh
tokens are not stored at all unless the application actually calls the provider's API, and
then only encrypted at rest in separate storage.

MFA: TOTP plus hashed recovery codes, reflected in `AssuranceLevel`. Disabling MFA,
replacing a factor and using a recovery code all require fresh authentication.

### Progress

| Deliverable | State |
|---|---|
| TOTP, RFC 6238 | **done** — `MFA::TOTP`, checked against the RFC's own SHA-1, SHA-256 and SHA-512 vectors, plus an RFC 4648 base32 codec because Crystal ships only base64 |
| Encrypted factor storage | **done** — `MFA::SecretBox`, AES-256-CBC with encrypt-then-MAC. The one secret here that is reversible by necessity, and `blueprints/0016-second-factors.md` says so rather than hiding it |
| `MFA::Service` | **done** — two-step enrolment, rate limiting before the code is checked, single-use counters, bounded drift, recovery codes |
| `MFA::Repository` + adapters | **done** — 34-example contract against the in-memory double, PostgreSQL and SQLite, including the two single-use operations run concurrently |
| `AssuranceLevel::MFA` and step-up | **done** — `env.auth.mfa_verified!` rotates the session up, as `docs/02-security-model.md` requires of any assurance increase |
| RS256 verification | **done** — `JWT::RSA`, binding the five libcrypto functions Crystal's stdlib omits. Every real provider signs ID tokens with it |
| Cached JWKS with a timeout | **done** — `JWT::JWKS`, with a TTL *and* a floor between refetches provoked by an unknown `kid`; a cache without both is either frozen at boot or a denial-of-service amplifier |
| OAuth2 / OIDC client | **done** — `OIDC::Client`, Authorization Code + PKCE only, `state`, `nonce`, exact redirect matching, `iss`/`aud`/`azp`, a flow TTL and an open-redirect check on `return_to` |
| `(issuer, subject)` identities | **done** — `auth_external_identities`, with no email column at all. `blueprints/0017-federated-identity.md` says why |
| Provider tokens discarded | **done** — the token response is read for `id_token` and the rest is dropped |

Fresh authentication for disabling MFA and replacing a factor is enforced at the route with
`require_fresh!`, not inside the service: `MFA::Service` takes an account id and has no request
to inspect.

Not done here, deliberately: a Kemal handler for the two OIDC routes. The flow is
framework-agnostic, `OIDC::PendingCodec` covers the sharp edge (the PKCE verifier has to survive
a round trip through the provider), and what is left is a redirect and a cookie — shown in the
README rather than wrapped.

## v0.6 — Authorization and tenancy

`Authorizer` contract, an RBAC extension, tenant membership. Deliberately last: it is a
different responsibility from authentication, and shipping it early would encourage baking
policy into the auth core.

Role and permission lists do not get copied into long-lived tokens or sessions. If
membership changes must take effect immediately, they are read from the authorization store
or a short-lived versioned cache.

### Progress

| Deliverable | State |
|---|---|
| `Authorizer` contract | **done** — `Authz::Authorizer`, plus `DenyAll`, because the only safe thing an unconfigured authorizer can do is permit nothing |
| Permissions and roles | **done** — `Authz::Permission` and `Authz::Role`, with roles defined in **code** and only assignments in the database. `blueprints/0018-authorization-and-tenancy.md` says why, and what it costs |
| No wildcards | **done** — `Permission::PATTERN` refuses `*` at construction. A wildcard is a grant of permissions that do not exist yet |
| Unknown permissions fail closed and loudly | **done** — `RoleCatalog` refuses at boot a role granting an undeclared permission; a typo at a call site denies with `DenialReason::UnknownPermission` rather than looking like a working check |
| Tenant membership | **done** — `auth_tenant_memberships`, separate from role assignment, and a tenant role is inert without one |
| Cross-tenant refusal | **done** — a principal bound to one tenant asking about another is refused before membership is read |
| Assurance-gated permissions | **done** — `Permission#minimum_assurance`; a denial for weak assurance asks for step-up rather than showing a dead end |
| `Authz::Repository` + adapters | **done** — a 30-example contract against the in-memory double, PostgreSQL and SQLite, plus sixteen-fiber concurrency examples that fail if the partial unique index on the global scope is dropped |
| Grants read, never carried | **done** — `Principal` still carries no roles; a revocation bites on the very next request with the same session, asserted over HTTP |
| Short-lived cache | **done** — `Authz::Cache`, off by default, five seconds by default, `MAX_TTL` one minute, bounded and self-clearing. The TTL *is* the revocation delay and is documented as such |

Not done here, deliberately: a path-prefix authorization guard along the lines of `PathGuard`.
Authorization is per-action, and a prefix-to-permission map encourages exactly the coarse check
that lets `/admin/billing` inherit whatever `/admin` required.

## v0.7 — Adoption

The migration path below, made real, plus the packaging change that had to happen before the
freeze rather than after it.

Nothing in v0.1 – v0.6 helps an application that already has users. Step 1 of the migration
path was always possible — `AccountRepository` is abstract — and step 4 shipped in v0.6 as its
own contract. Steps 2 and 3 were the gap: the lazy-rehash machinery existed and had no way to
verify the old digest in the first place, which made the whole path unreachable.

### Progress

| Deliverable | State |
|---|---|
| `Passwords::LegacyVerifier` | **done** — verify-only, by construction: no `hash_secret`, so the count of old digests can only go down |
| `Passwords::MigratingHasher` | **done** — routes a digest to exactly one legacy verifier by shape, and is a `Hasher` everywhere a hasher goes (it runs the same contract spec) |
| No shipped legacy implementations | **done**, deliberately — a published `Sha1Verifier` is a published working SHA-1 password check. The contract ships; yours is five lines |
| The migration-status timing oracle | **done** — a failed legacy verification pays for a throwaway current-hasher verification, so an attacker cannot tell which accounts are still on the cheap scheme |
| Over-length legacy passwords | **done** — refused rather than 500ing on the rehash, with a `Log.warn` naming the scheme and the byte count so an operator finds out those accounts exist |
| `Kemal::LegacySessionHandler` | **done** — the block returns a subject and nothing else; the adopted session is `Remembered`, so `require_fresh!` still forces a real login |
| Drivers out of `dependencies` | **done** — `pg` and `sqlite3` are development dependencies. **Breaking**, and pre-1.0 on purpose |

Counting what is left to migrate is a query against the application's own table, not a method on
`AccountRepository`: adding an abstract method would break every existing implementor for a
reporting convenience, weeks before the contracts freeze.

## v0.8 — The last breaking release

**Released as `v0.8.0` on 2026-08-29.**

Everything that has to change *before* the contracts freeze, and nothing that does not.

`blueprints/maturity-validation-scenarios.md` is the catalogue this project will be judged
against, and working through it in order turned out to be the wrong first move. Most of the
gaps it finds are closed by **adding** something — a header, a package path, an event sink —
and adding is not a breaking change. A minority are closed only by changing a signature that
v1.0 is about to freeze. Those are the ones with a deadline, and they are what this milestone
is. `blueprints/0020-api-freeze-blockers.md` records the scan that separated the two.

| Deliverable | State |
|---|---|
| `Principal` carries a reference to the credential that proved the request | **done** — `blueprints/0021-credential-reference.md`. `CredentialRef` on `Principal`, filled from the row already read at every producer, so no query was added. `session_id` survives as a derived reader |
| Per-token scopes, intersected with account permissions | **done** — the second half of 0021. A nullable `scopes` column, `issue(scopes:)`, and attenuation in `RBAC` after the account's own grant, so a scope only ever narrows. Reverses the v0.4 deferral, which was correct while there was no authorizer for a scope to intersect with |
| `Authorizer#decide` receives a resource and a context | **done** — `blueprints/0022-authorization-context-and-denials.md`. `Authz::Context` carries tenant, resource, environment attributes and credential; `Authorizable` is a two-method module frozen by the suite's compilation, since Crystal cannot store an `Object` in a struct at all |
| A denial names its own reason, and says whether re-authenticating would help | **done** — the second half of 0022. `DenialReason::Custom` plus a free-form `code`, and `step_up?` split off as the single authority for the control flow. Named constructors fix the flag, so `RBAC` cannot forget it |
| `RateLimiter` can report that its store is unavailable | **done** — `blueprints/0023-rate-limiter-store-failure.md`. `Verdict.unavailable`, fail-closed at all five call sites, and `FailOpenRateLimiter` for a path that would rather stay up — per endpoint, since each service takes its own limiter |
| `IdentityProvider` is written, or removed from the freeze list | **done** — removed, and the protocol-neutral half of federation moved out of the `OIDC` namespace instead. `blueprints/0024-federation-namespace.md`: a second protocol added after 1.0 is purely additive, so no interface had to be invented for one that does not exist yet |
| A typed security event sink | **done** — `blueprints/0027-security-event-sink.md`. `SecurityEventSink` fed by a bridge over the events already emitted, with a failing sink counted rather than fatal or silent. Also normalised two inconsistent field names in the audit trail |
| Refusals carry the RFC 6750 challenge | **done** — `blueprints/0026-bearer-challenges.md`. `WWW-Authenticate` on every refusal that reaches a status, with only an out-of-scope credential described; and a request presenting a bearer credential is no longer redirected. Not a freeze blocker either, but only the shard knows the denial reason, so only the shard can be accurate |
| The test doubles and shared contracts become published API | **done** — `require "kemal_identity/testing"`. Not a freeze blocker; brought forward because validation measured it as the root of three other findings, and because it makes the rest of the catalogue pass answerable by adapter authors rather than only from inside this repository |
| ~~`AuthenticatorChain` stops foreclosing a request-aware authenticator~~ | **withdrawn** — it was never a blocker. A defaulted overload carrying request attributes can be added to `RequestAuthenticator` after 1.0 without breaking any implementor, measured rather than assumed, so DPoP and trusted-proxy identity stay reachable. `blueprints/0020` decision 7 records what the reasoning got wrong |

Deliberately **not** in v0.8, because none of it requires a frozen signature to move: a declared
per-route API-only mode, credential-kind declarations on `PathGuard`,
token lifetime policy, an assurance level above `MFA` for phishing-resistant proof, and — once
it was measured rather than assumed — request attributes for DPoP and trusted-proxy identity.
All of those are real gaps against the catalogue's targets and all of them can land after 1.0
without breaking anybody. `blueprints/0020` lists them so that missing them stays a decision.

## v0.8.x — Additive, after the freeze list was settled

Nothing here moves a signature v1.0 freezes, so none of it needed to be in v0.8.0. All of it came
out of running the catalogue — `blueprints/0025-maturity-validation-results.md` names the scenario
each one closes.

| Deliverable | State |
|---|---|
| Credential precedence as a handler argument | **done** — HTTP-03 M2 → M3. `AuthenticationHandler.new(precedence: Precedence::Bearer)` instead of publishing `restore_remembered!`: the ordering is the subtle part, so handing it over would document the trap and then invite it |
| Provider-specific authorization parameters | **done** — IDP-01 M2 → M3. Allowlisted by exclusion: the nine parameters the flow builds are refused at construction, because the dangerous version of this feature turns PKCE off by configuration |
| `JWT.unverified_issuer`, so several issuers can be routed | **done** — JWT-01 M2 → M3. Bounded before decoding and reusing the validator's own strict base64url, because a second decoder that almost agrees is how one token means two things |
| The account contract can be told an adapter is single-tenant | **done** — IDP-03 M3 → M4. `tenanted: false` replaces the tenancy group with an example demanding that a tenant-scoped lookup answer `nil`, rather than skipping — ignoring the argument is the unsafe way to be single-tenant, and it passed everything else |
| CI resolves three consumers and checks what each gets | **done** — OPS-07 M3 → M4. The property v0.7.0 exists for had nothing keeping it true; verified to fail when `pg` is moved back into `dependencies` |

## v1.0 — API freeze

The criterion is contract stability, not feature count.

**Frozen.** The contracts an application implements or calls:

| | |
|---|---|
| Identity and credentials | `Principal`, `CredentialRef`, `CredentialKind`, `AssuranceLevel` |
| Authentication | `RequestAuthenticator`, `Outcome` and its three variants, `FailureReason` |
| Passwords | `Hasher`, `Secret` |
| Persistence | `AccountRepository`, `Accounts::Account`, `SessionRepository`, `Sessions::Record`, `Sessions::Lookup` |
| Authorization | `Authorizer`, `Authz::Decision` and its two variants, the denial-reason model |
| Supporting contracts | `RateLimiter` and `Verdict`, `Notifier`, `SecurityEventSink` and `SecurityEvent`, `Clock`, `RandomSource` |
| Federation | `Federation::Identity`, `Federation::Link`, `Federation::LinkRepository`, `OIDC::Provider`, `OIDC::Client`, `OIDC::Pending`, `OIDC::PendingCodec` |
| HTTP | `env.auth` |

A frozen method freezes its argument and return types with it, which is why the argument and
return types are named here rather than left implied. The original list in this section was
shorter and named `IdentityProvider`, which did not exist — see `blueprints/0020` decision 1. It
is gone: `blueprints/0024` establishes that a second federation protocol needs no interface above
the two clients, only a shared identity model outside either protocol's namespace.

**Not frozen, on purpose.** Provider lists, ORM and driver adapters, TOTP internals, the
shipped `RBAC` implementation, migration files, and everything under `KemalIdentity::Kemal`
apart from `env.auth` itself. These are where the shard is expected to keep moving.

The catalogue is validated against a v1.0 release candidate, after v0.8 has landed. Recording
maturity levels against contracts that are about to change would produce results that expire
the day they are written, and the results go in their own document so
`blueprints/maturity-validation-scenarios.md` stays what it says it is: a catalogue carrying no
result for this library.

That pass is under way in `blueprints/0025-maturity-validation-results.md`, run from a separate
consumer project rather than from inside this repository — several scenarios are about what an
application can reach from outside, which cannot be answered from in here. **All seven very-high
scenarios are done — five M3, two M2 — plus fourteen high-frequency and two medium. One reached
M4; five are M2.**
`tools/validation/` keeps the attempts so a later revision is measured against the same ones.

Two of the findings are about the shared contract specs rather than about any feature, and both
say the contracts are narrower than they look: a rate limiter passed all twelve limiter contract
examples while allowing 2.2× its global limit across processes, and an `AccountRepository` over a
real application's single-tenant `users` table cannot run the account contract at all. Closing
those is the same work as DEV-02.

The largest single gap found so far is JWT-01: two `JWT::Validator`s cannot be chained, because
`AuthenticatorChain` routes on shape and every JWT has the same one. A B2B API accepting two
customers' issuers has to route on `iss` itself, unbounded, before validating. A bounded
`JWT.unverified_issuer` would close it and is additive.

## Migration path for existing Kemal apps

Not a flag day. Four independent steps, each reversible.

Implemented in v0.7 — see `blueprints/0019-migrating-an-existing-application.md`.

**1. Adapter first, no schema change.** Implement `AccountRepository` against the existing
`users` table. `auth_accounts` need not exist. This is the step that makes the whole
approach adoptable, and it is why `AccountRepository` is abstract rather than a wrapper
around a shard-owned table.

**2. Passwords, lazily.** Keep the old verifier for verification only:

```
login
  ├─ current hasher verifies         → done
  └─ legacy verifier succeeds        → rehash with the current hasher, immediately
```

Nobody is forced through a reset. Old digests disappear as people log in. Track the
remaining count so the legacy verifier can eventually be removed —
`SELECT count(*) FROM users WHERE password_scheme <> 'bcrypt'`, against your own table.

`Passwords::MigratingHasher` is what makes this expressible: the current hasher plus one or
more `LegacyVerifier`s, which can verify and cannot write.

**3. Sessions, through a legacy authenticator.** `Kemal::LegacySessionHandler` takes a block
that reads the old cookie and extracts **only the subject**, then mints a new auth session and
issues the new cookie. The adopted session is `AssuranceLevel::Remembered`, so anything
sensitive still forces a real login. Secrets are never copied from one system to the other. After a grace
period the legacy authenticator is removed and any remaining old sessions become invalid.

**4. Authorization, separately.** Do not couple the authorization migration to the
authentication migration in one deployment. Read roles through an adapter from the existing
tables; copy them into auth-owned schema only if there is a concrete reason.

Two anti-patterns to name explicitly. Accepting long-lived legacy JWTs indefinitely is not
a migration — it is permanent security debt with a deprecation notice attached. And forcing
a global password reset to switch hashing algorithms is a support burden that lazy rehash
makes unnecessary.
