# Changelog

## v0.3.1 — 2026-08-26

Corrects the supported Crystal range announced in v0.3.0.

**v0.3.0 claimed Crystal 1.4.0 and was wrong.** The measurement behind it ran `crystal spec`
only, and the spec suite never compiles `Kemal.run` — it drives Kemal's handler chain in memory.
A real application does compile it, and `Kemal.run` calls `Process.on_terminate`, which arrived
in Crystal 1.12. On 1.4 through 1.11 the suite is green while no application builds.

The floor is **1.12.0**. CI now builds the example and the benchmarks on every matrix entry, so
a floor cannot be established from a green test suite alone.

If you installed v0.3.0 on Crystal 1.11 or below, it will have compiled and passed its tests and
then failed the moment you tried to start a server. Upgrade to Crystal 1.12 or later.

## v0.3.0 — 2026-08-26

Compatibility release. No behaviour changes, no API removals.

- **The Crystal floor drops from 1.21.0 to 1.4.0.** (Corrected to 1.12.0 in v0.3.1 — see above.) `HashingExecutor` is now compiled
  conditionally: where `Fiber::ExecutionContext` is unavailable it refuses to be built rather
  than silently hashing on the request fiber, unless the application passes `allow_inline:
  true`. Crystal 1.21 is still recommended — the executor is the one thing worth upgrading
  for. See `blueprints/0013-execution-contexts-are-optional.md`.
- CI now runs Crystal 1.21.0, 1.14.0 and 1.4.0 (1.12.0 from v0.3.1), plus the Kemal floor, so both floors are
  tested claims rather than comments.
- Specs no longer use `WaitGroup` (Crystal 1.13+) or Kemal's `query` DSL (Kemal 1.13+)
  unconditionally. Both were test conveniences that had quietly set the supported floor for
  the whole library.

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
