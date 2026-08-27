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
| Federated identity (OAuth2 / OIDC) | **not started** |

Fresh authentication for disabling MFA and replacing a factor is enforced at the route with
`require_fresh!`, not inside the service: `MFA::Service` takes an account id and has no request
to inspect.

## v0.6 — Authorization and tenancy

`Authorizer` contract, an RBAC extension, tenant membership. Deliberately last: it is a
different responsibility from authentication, and shipping it early would encourage baking
policy into the auth core.

Role and permission lists do not get copied into long-lived tokens or sessions. If
membership changes must take effect immediately, they are read from the authorization store
or a short-lived versioned cache.

## v1.0 — API freeze

The criterion is contract stability, not feature count. `Principal`,
`RequestAuthenticator`, `Hasher`, `SessionRepository`, `AccountRepository`,
`IdentityProvider`, `RateLimiter`, `Notifier`, `Clock`, `Authorizer` and `env.auth` are
frozen. Provider lists, ORM adapters and TOTP internals stay free to evolve behind them.

## Migration path for existing Kemal apps

Not a flag day. Four independent steps, each reversible.

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
remaining count so the legacy verifier can eventually be removed.

**3. Sessions, through a legacy authenticator.** A `LegacySessionAuthenticator` reads the
old `kemal-session` cookie, extracts **only the subject**, mints a new auth session and
issues the new cookie. Secrets are never copied from one system to the other. After a grace
period the legacy authenticator is removed and any remaining old sessions become invalid.

**4. Authorization, separately.** Do not couple the authorization migration to the
authentication migration in one deployment. Read roles through an adapter from the existing
tables; copy them into auth-owned schema only if there is a concrete reason.

Two anti-patterns to name explicitly. Accepting long-lived legacy JWTs indefinitely is not
a migration — it is permanent security debt with a deprecation notice attached. And forcing
a global password reset to switch hashing algorithms is a support burden that lazy rehash
makes unnecessary.
