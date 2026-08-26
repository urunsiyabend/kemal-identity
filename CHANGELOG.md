# Changelog

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
