# 06 — Roadmap

The dominant product risk is scope, not capability. A half-finished auth library is worse
than none, because people deploy it. Every milestone below is shippable on its own.

## v0.1 — Secure core

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

Password reset, email confirmation, remember-me with rotating single-use tokens and family
revocation, `Notifier` events. Everything digest-only, single-use, atomically consumed.

Enumeration behaviour on the reset endpoint is the thing to get right: identical response
and identical timing whether or not the address exists, plus per-account rate limiting so
the endpoint cannot be used to flood someone's inbox.

## v0.3 — Adapters and hardening

SQLite adapter (which also makes CI cheaper), the sweeper, structured audit events,
`kemal_identity_argon2` as a separate shard, and the compatibility matrix.

## v0.4 — API authentication

Bearer tokens as a `RequestAuthenticator`. Opaque personal access tokens first, since they
reuse the existing digest-and-revoke machinery and carry none of JWT's revocation problem.

JWT validation second, off by default, with a strict configuration: an algorithm
allow-list, `none` never accepted, required and verified `iss` and `aud`, mandatory `exp`,
bounded clock skew, key rotation via `kid`, and token-purpose separation.

The revocation trade-off gets documented rather than hidden. A stateless JWT cannot be
revoked before `exp` without server-side state; the two honest options are a very short TTL
or a `jti` revocation store, and the second one means it is not stateless any more. Say so
in the API docs.

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
