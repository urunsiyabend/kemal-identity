# Changelog

## Unreleased — v0.8.0

The last breaking release before the v1.0 API freeze. `blueprints/0020-api-freeze-blockers.md`
records the scan that decided what belongs here: the contracts that cannot reach their targets
once frozen, and nothing else.

### ⚠ Breaking: `Principal` names the credential that proved the request

`Principal.new`'s `session_id:` argument is replaced by `credential : CredentialRef?`.
`#session_id` remains as a reader, derived from it, so `logout!`, `mfa_verified!`, CSRF
anchoring and `redeem_recovery_code(except_session_id:)` are unaffected. Code that *constructed*
a `Principal` with `session_id:` — a custom `RequestAuthenticator`, a test double — passes a
`CredentialRef` instead.

Two personal access tokens issued to one account used to produce indistinguishable principals.
`ApiTokens::Service` had the token id in hand when it authenticated and dropped it, so an
application could not tell which token was asking, and a token created for reading reports could
perform a write its owner happened to be permitted. Closing that from outside the shard meant
either a second digest-and-query on every authenticated request or a copy of the whole
validation path.

```crystal
credential = env.auth.credential
credential.try(&.kind)   # Session | ApiToken | Jwt | Custom
credential.try(&.id)     # the session id, the token id, or the JWT's jti
```

`CredentialRef` carries `kind`, `id`, `name`, `expires_at` and `scopes`, and never the token,
the digest or a signature — so it is safe in a log line, and `authz.denied` now records which
credential was refused rather than only whose account.

`scopes` is `nil` everywhere for now, and `nil` means **unrestricted**, not *permits nothing*: a
session has no scopes either, and reading their absence as an empty set would deny every
signed-in browser. Per-token scopes and their intersection with account permissions are the
second half of `blueprints/0021-credential-reference.md` and land in this same release.

No new query anywhere. Every value comes from a row that was already read to authenticate the
request.

### ⚠ Breaking: `Authorizer#decide` takes a context, and a denial is built by name

`Authorizer#decide`'s abstract form is now
`decide(principal, permission, context : Authz::Context)`. The tenant-only form remains as a
concrete overload, so every existing **call site** is unchanged; an existing **implementation**
overrides the new signature and reads `context.tenant_id`.

`Authz::Context` carries the tenant, the object being acted on, environment attributes and the
credential. A context object rather than more parameters because this method freezes at v1.0:
the last time it needed something new — a resource — there was nowhere to put it, so a route
with per-object rules had to bypass `env.auth` and re-implement the audit line, the step-up
mapping and the uniform 403 for itself.

```crystal
env.auth.authorize!(
  "invoices.edit",
  resource: KemalIdentity::Authz::Resource.new("invoice", invoice.id, {"owner_id" => invoice.owner_id}),
)
```

A resource is anything answering `authz_type` and `authz_id` — include `Authz::Authorizable` in
your own model, or use the shipped `Authz::Resource`. The module is frozen at those two methods:
a third would stop every implementor compiling, and a concrete addition would silently shadow a
name in every including class. Growth happens on `Authz::Context`, which injects nothing into
anybody's types.

**`Forbidden` is now built by named constructor**, not `new`:

```crystal
Forbidden.not_permitted(permission, tenant_id)
Forbidden.insufficient_assurance(permission, tenant_id)   # step_up: true
Forbidden.out_of_scope(permission, tenant_id)
Forbidden.policy(permission, code: "change_window_closed", step_up: false)
```

`DenialReason` gains `OutOfScope` and `Custom`, and `Forbidden` gains `code` — an application
authorizer's own reason, for the audit trail only. It never reaches the client; every denial
still renders one identical 403, because a denial that explains itself confirms which tenants
exist and who is in them.

`Forbidden#step_up?` now decides the control flow: `authorize!` raises
`FreshAuthenticationRequiredError` on it rather than on `reason.insufficient_assurance?`. Two
axes, one authority. The flag is not a parameter of the general constructor — `initialize` is
private — so `RBAC` cannot build an assurance denial and forget it and leave step-up silently
broken. The one place it is chosen is `.policy`, where this shard cannot know the answer.

## v0.7.0 — 2026-08-29

Adoption. The migration path `docs/06-roadmap.md` has described since v0.1, made real, plus one
packaging change that had to happen before the v1.0 freeze rather than after it.

### ⚠ Breaking: the database drivers are yours to declare

`pg` and `sqlite3` moved from `dependencies` to `development_dependencies`. An application that
requires `kemal_identity/postgres` or `kemal_identity/sqlite` must now list that driver in its
own `shard.yml` — which it already had to, for its own queries.

Nothing in `kemal_identity` itself requires either driver. Listing them made every consumer
compile and link both, including one using neither because it implements the repository
contracts over its own storage, which `docs/03-data-model.md` treats as the normal arrangement.
Deferred since v0.3; done now because a breaking packaging change belongs before an API freeze.

### Passwords, lazily

- `Passwords::LegacyVerifier` — verify-only by construction. No `hash_secret`, so a migration
  cannot keep creating rows in the old format and the count of old digests can only go down.
- `Passwords::MigratingHasher` — the current hasher plus one or more legacy verifiers. A correct
  password against a legacy digest logs in and is rehashed immediately; nobody is forced through
  a reset. It is a `Hasher` wherever a hasher goes and runs the same contract spec.
- Digests are routed to exactly **one** verifier by shape (`handles?`, which never sees the
  secret). Trying every verifier in turn would make a login cost the sum of every legacy scheme.
- **This shard ships no legacy verifier implementations**, deliberately: a published
  `Sha1Verifier` is a published working SHA-1 password check. Yours is five lines.
- A failed legacy verification pays for a throwaway verification against the current hasher's
  dummy digest. Legacy schemes are fast and bcrypt is slow, so without it the response time says
  which accounts are still on the cheap scheme — precisely the ones worth attacking if the
  database leaks. Distinct from the enumeration oracle `dummy_digest` already closes.
- A legacy password longer than the current hasher can represent is **refused** rather than
  verified-then-500ing on the rehash, with a `Log.warn` naming the scheme and the byte count so
  an operator learns those accounts exist. Truncating was never an option.

### Sessions, adopted once

- `Kemal::LegacySessionHandler` takes a block that returns **a subject and nothing else** — not a
  principal, not a timestamp, and above all not a token. Whatever signed the old session stays in
  the old system and dies with it.
- The adopted session is `AssuranceLevel::Remembered`, so `require_fresh!` still forces a real
  login before anything sensitive. An old cookie proves somebody authenticated at some point, to
  a system this one cannot inspect.
- It runs only when the session cookie, a bearer token and remember-me have all found nothing, so
  a live session is never replaced — and only on `Anonymous`, never on a rejected cookie, for the
  reason `blueprints/0012-remember-me.md` gives.
- Registered as its own handler because it is meant to be deleted. The day the `use` line goes is
  the day the old sessions stop working.
- `RequestContext#adopt_legacy_session!` returns nil rather than raising for an unknown or
  disabled account.

Thirteen mutations of the two new pieces: eleven killed outright, and the two survivors were both
real spec weaknesses — an example that named an account the legacy path would have refused
anyway, and an explicit argument shadowing the value it duplicated. Both fixed, both now killed.

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
