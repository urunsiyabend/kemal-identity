# Changelog

## v0.6.0 — 2026-08-29

Authorization and tenancy — `docs/06-roadmap.md`'s v0.6, and the last milestone before the v1.0
API freeze. Additive and **off by default**: an application that passes no `authorizer:` is
unchanged, and `Principal` still carries no roles.

### Authorization

- `Authz::Authorizer`, a contract, plus `Authz::RBAC` as the implementation this shard ships
  and `Authz::DenyAll` for anything half-configured — the only safe thing an unconfigured
  authorizer can do is permit nothing.
- **Roles are code; only assignments are data.** `Authz::RoleCatalog` is built at boot from
  literals in the application, and there is no `auth_roles` table. A role definition in a table
  is one UPDATE away from rewriting what everybody holding it can do, with nothing about the
  application having changed. The cost — roles cannot be administered at runtime — is stated in
  `blueprints/0018-authorization-and-tenancy.md` rather than hidden.
- A role granting a permission nobody declared raises at **boot**, so a rename that misses one
  definition fails on the machine of whoever made the change rather than denying an action in
  production for a month. A mistyped permission at a call site denies with
  `DenialReason::UnknownPermission`.
- **No wildcards.** `Permission::PATTERN` refuses `*` at construction: a wildcard is a grant of
  permissions that do not exist yet, and whoever holds `admin.*` silently acquires the next one
  somebody adds.
- `Permission#minimum_assurance` — assurance is a property of the action, declared once, not a
  rule repeated at every call site where somebody might forget it. A denial for weak assurance
  raises `FreshAuthenticationRequiredError` so the application can prompt for a second factor
  instead of showing a dead end.
- `env.auth.authorize!`, `#authorize` and `#can?`. New `ForbiddenError`, mapped to 403 by
  `ErrorHandler` with one body for every denial reason — `DenialReason` is for the audit log,
  and a response that varied with it would confirm that a guessed tenant exists.

### Tenancy

- New tables `auth_tenant_memberships` and `auth_role_assignments`, PostgreSQL and SQLite, both
  running the same 30-example contract.
- A role held inside a tenant is **inert without a membership**, so removing somebody from a
  tenant is a single call that revokes everything at once — `remove_member` deletes that
  tenant's assignments too, and re-inviting them does not restore the roles they used to hold.
- A principal bound to one tenant asking about another is refused before membership is read.
  That is the identifier-in-the-URL attack, and it must not depend on a database row being
  correct.
- A grant with no tenant is global: it applies everywhere, including inside every tenant, and is
  not gated by membership. `Assignment#granted_by` exists because that is the dangerous kind.
- The unique index on the global scope is **partial** (`WHERE tenant_id IS NULL`), because a
  plain unique index does not collide on NULL. Dropping it makes both the contract example and
  a sixteen-fiber concurrency example fail, which is how it was verified.

### Nothing is carried in a session

- A revocation bites on the very next request, with the same session, asserted over HTTP. That
  is the reason `Principal` carries no roles.
- `Authz::Cache` is off by default, five seconds when on, and refuses a TTL over one minute:
  the TTL *is* the revocation delay. It is bounded and clears itself at the limit rather than
  evicting one entry at a time — the key space is attacker-influenced, and the failure mode of
  a stampede should be "the cache stops helping", not "the process runs out of memory".
- `RBAC#grant`, `#revoke` and `#remove_member` invalidate it, which helps the process that made
  the change and no other. Documented as such rather than papered over with a pub/sub channel
  that would be one more thing to be silently broken.

Twenty mutations of the module, the adapters and the double: twenty killed, none surviving.

## v0.5.0 — 2026-08-28

Federated identity and MFA, the two halves of `docs/06-roadmap.md`'s v0.5. Additive; nothing
was removed or changed in behaviour.

### Second factors

- `MFA::TOTP` (RFC 6238), checked against the RFC's own SHA-1, SHA-256 and SHA-512 vectors,
  plus an RFC 4648 base32 codec because Crystal ships only base64.
- `MFA::Service`: two-step enrolment, a rate limit consumed **before** the code is checked,
  single-use counters, drift bounded at two steps, and ten recovery codes issued at the moment
  a first factor turns MFA on. What makes TOTP safe is these, not the arithmetic.
- `MFA::SecretBox` — AES-256-CBC with encrypt-then-MAC, verified before decrypting. The one
  secret in this shard that is encrypted rather than hashed, because the server has to read it
  back to compute a code. GCM would be the obvious choice and Crystal's `OpenSSL::Cipher` does
  not expose the authentication tag.
- `AssuranceLevel::MFA` and `env.auth.mfa_verified!`, which **rotates the session**: an id an
  attacker learned while it was worth `Password` must not silently become one worth `MFA`.
- Redeeming a recovery code signs the account's other sessions out, as
  `docs/02-security-model.md` requires.
- New tables `auth_mfa_factors` and `auth_mfa_recovery_codes`, PostgreSQL and SQLite, both
  running the same 34-example contract — including the two single-use operations run
  concurrently.

### Signing in with a provider

- `OIDC::Client`: Authorization Code with PKCE and nothing else. `state` compared in constant
  time before anything is exchanged, `nonce` compared inside the ID token, `S256` only, exact
  redirect matching, `iss`/`aud`/`azp`, a 15-minute flow TTL, and timeouts on every call out.
- `return_to` is restricted to a same-site path and validated **on the way in**, before it has
  round-tripped through the provider — including the `//evil.example.com` and `/\evil` forms a
  browser reads as absolute.
- `OIDC::LinkRepository` over `auth_external_identities`, keyed on `(issuer, subject)` with
  **no email column at all**. Addresses change and are claimed rather than proved; looking an
  account up by one is account takeover with extra steps.
- The provider's access and refresh tokens are discarded rather than stored. Keeping one your
  application never uses turns a breach here into a breach of every user's account there.
- `OIDC::PendingCodec` signs the flow state for a cookie, so applications do not hand-roll
  carrying the PKCE verifier through a redirect.

### JWT

- **RS256, RS384 and RS512.** `jwt/rsa.cr` reopens `lib LibCrypto` for the five functions
  Crystal's standard library omits, and builds the public key as a DER `SubjectPublicKeyInfo`
  for `d2i_PUBKEY` — the one route stable across OpenSSL 1.1.1 and 3.x. Verification only;
  signing is bound in `spec/support/` so it cannot become API by accident.
- A `JWT::Key` now holds a shared secret **or** a public key, and refuses to pair either with
  the wrong algorithm — the confusion attack written into configuration rather than a token.
- `JWT::JWKS`, a cached key source with a TTL *and* a floor between refetches provoked by an
  unknown `kid`. A failed refetch keeps serving the last good key set; a failed first fetch
  raises.
- `JWT::Validator` accepts a `KeySource` as well as a fixed `Keyring`, and gained `#validate`,
  which keeps the claim set an OIDC callback needs.

### Everything else

- `blueprints/0016-second-factors.md` and `blueprints/0017-federated-identity.md` record the
  decisions, including which defences are deliberately unobservable and why.

## v0.4.0 — 2026-08-26

API authentication: bearer tokens as a `RequestAuthenticator`, in the order
`docs/06-roadmap.md` set out — opaque personal access tokens first, JWT second and off by
default. Additive; nothing was removed or changed in behaviour.

### Personal access tokens

- `ApiTokens::Service`, with digest-only storage, revocation that takes effect on the very next
  request, an optional expiry (`nil` really does mean never, and the sweeper never touches
  one), and a `last_used_at` throttled to one write per five minutes.
- A fixed, searchable `ki_` prefix, configurable per application, so a secret scanner can
  recognise a leaked credential in a commit or a paste and say whose it is.
- `ApiTokens::Repository` with PostgreSQL and SQLite adapters and an in-memory double, all
  running the same 28-example contract. New table `auth_api_tokens` in both dialects.

### JWT validation

- `JWT::Validator`, off unless an application passes one. HS256/HS384/HS512, an algorithm
  allow-list, `kid` rotation, and required `iss`, `aud`, `exp` and `purpose`.
- `alg: none` is unrepresentable: no `Algorithm` can express it, the allow-list refuses the
  string at boot, and the header's `alg` is compared against the *key's* algorithm — which is
  also what defeats algorithm confusion, since the key names the algorithm and the token
  selects nothing.
- An unknown `kid` is rejected rather than retried against the ring, so a compromised key can
  actually be withdrawn. A token naming no `kid` resolves only when the ring holds one key.
- Clock skew is bounded at five minutes, and `max_lifetime` (one hour by default) rejects a
  token claiming to be valid for longer.
- **The revocation trade-off is documented rather than hidden.** A stateless JWT cannot be
  revoked before its `exp`; the two honest answers are a very short lifetime or a `jti`
  denylist that costs the statelessness. `JWT::RevocationStore` says so in full, and the
  optional `accounts:` argument is the same admission about disabled accounts.

### Everything else

- `AssuranceLevel::ApiToken = 15`, between `Remembered` and `Password`. Never fresh, so
  `require_fresh!` refuses a token-bearing request outright — an automated client cannot
  re-authenticate interactively. No persisted enum value was renumbered.
- `AuthenticatorChain` resolves one `Authorization: Bearer` header against several
  authenticators, routing on shape and stopping at any credential that was recognised and then
  failed on its merits.
- Neither bearer credential compares `auth_version`: a password change must not silently break
  a deploy key whose holder is a machine with no way to notice.
- The CSRF bearer exemption keys on the session cookie **as presented**, so a request carrying
  an expired or garbage cookie cannot expire its way out of CSRF protection.
- New `FailureReason::InvalidClaim`, for a token that verified cryptographically and then
  failed on a claim — a signal worth alerting on, and kept out of the response like every other
  reason.
- `Sweeper` now also drops expired API tokens and spent `jti` entries.
- `blueprints/0015-bearer-credentials.md` records the decisions, including why there are no
  scopes and which JWT defences are deliberately redundant.

## v0.3.0 — 2026-08-26

Compatibility release. No behaviour changes, no API removals.

- **The Crystal floor drops from 1.21.0 to 1.12.0.** `HashingExecutor` is now compiled
  conditionally: where `Fiber::ExecutionContext` is unavailable it refuses to be built rather
  than silently hashing on the request fiber, unless the application passes
  `allow_inline: true`. Crystal 1.21 is still recommended — the executor is the one thing worth
  upgrading for, holding unrelated-request p99 latency at 1.17 ms against 2,176 ms without it
  at 50 concurrent logins. See `blueprints/0013-execution-contexts-are-optional.md`.
- CI now runs Crystal 1.21.0, 1.14.0 and 1.12.0, plus the Kemal floor, so both floors are
  tested claims rather than comments. The example and the benchmarks are built on **every**
  matrix entry: the specs alone pass down to Crystal 1.4, but they never compile `Kemal.run`,
  which needs `Process.on_terminate` from 1.12 — a green suite is not a floor.
- Specs and benchmarks no longer use `WaitGroup` (Crystal 1.13+) or Kemal's `query` DSL
  (Kemal 1.13+) unconditionally. Both were test conveniences that had quietly set the
  supported floor for the whole library.

## v0.2.0 — 2026-08-25

First release. It contains both the v0.1 and v0.2 milestones of `docs/06-roadmap.md`: the two
were finished back to back with no release between them, and tagging a `v0.1.0` that already
held v0.2 features would have misrepresented both.

### Authentication

- Password login with bcrypt, timing equalisation against account enumeration, and lazy
  rehashing so a cost increase never forces a password reset.
- Server-side opaque sessions: digest-only storage, expiry evaluated on every read rather than
  by a sweeper, rotation on login, and revocation that takes effect on the next request.
- Cookie policy defaulting to `__Host-` prefixed, `Secure`, `HttpOnly`, `SameSite=Lax`, with
  incoherent combinations refused at boot rather than discarded by the browser in production.
- Password hashing on a dedicated execution context. At 50 concurrent logins this holds
  unrelated-request p99 latency at 1.17 ms against 2,176 ms without it.

### Kemal integration

- `env.auth`, `require!`, `require_fresh!`, `PathGuard` and `ErrorHandler`.
- Guards match on the path alone for every HTTP method, so they are unaffected by the four
  filter-dispatch defects in Kemal 1.10.0 – 1.12.0 and covered HTTP QUERY without a change
  when Kemal 1.13.0 added it.
- CSRF protection using a masked, session-bound HMAC — including the login form, which is the
  case most implementations miss.
- Rate limiting on the password verification path, consumed before any lookup or hashing.
  **Off by default**: `NullRateLimiter` allows everything until an application opts in.

### Account lifecycle

- Password reset and email confirmation over single-use, atomically consumed action tokens.
  The reset endpoint reveals nothing by response or by timing, and is rate limited per address
  so it cannot be used to flood an inbox.
- Remember-me with rotating single-use tokens and family revocation, so a stolen cookie is
  detected on the next visit by either party. A replay revokes the family, ends every session
  for the account, and notifies the account holder.
- A `Notifier` contract. No SMTP, no templates: the application delivers.

### Storage

- PostgreSQL adapters for accounts, sessions, action tokens and remember-me tokens, all
  running the same contract specs as the in-memory doubles.
- Migrations published as files to copy in, never run by the shard.

### Supported versions

Crystal **1.21.0** or later, Kemal **1.10.0** or later. Both floors measured by running the
suite downwards until it failed; CI runs the Kemal floor as its own job.

### Known limitations

- Rate limiting is off unless configured, and `FixedWindowRateLimiter` counts per process.
- Two requests presenting the same remember-me cookie simultaneously are indistinguishable
  from a theft. See `blueprints/0012-remember-me.md`.
- No SQLite adapter, no session sweeper, no API tokens. Those are v0.3 and v0.4.
- The API is not frozen until v1.0.
