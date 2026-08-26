# Kemal Identity

Authentication for Crystal web applications — Kemal integration included.

Server-side opaque sessions, password credentials, and revocation that actually revokes.
It answers *who is making this request*, gives the application a typed answer, and stops
there.

> **Released: `v0.3.0`.** Password login, revocable server-side sessions, cookie policy, Kemal
> guards, CSRF including the login form, rate limiting, PostgreSQL adapters, a dedicated
> execution context for hashing, password reset, email confirmation, and remember-me with
> theft detection. Every release blocker in `docs/05-testing.md` has a named spec.
>
> `v0.2.0` covered both the v0.1 and v0.2 milestones of `docs/06-roadmap.md`, which were
> finished back to back with no release between them; `v0.3.0` widens compatibility down to
> Crystal 1.12. Not yet: a SQLite adapter and the session
> sweeper (v0.3), API tokens (v0.4). **The API is not frozen until v1.0.**

## What it is not

Not an authorization system, not an OAuth2 server, not an ORM integration, not a user
management system, not a password policy engine, not a JWT library. Each of those has a
reason recorded in `docs/00-scope.md`; if you are about to propose one, it is probably
already answered there.

## Install

```yaml
dependencies:
  kemal_identity:
    github: urunsiyabend/kemal-identity
    version: ~> 0.3.0
```

Requires **Crystal 1.12.0** or later and **Kemal 1.10.0** or later. Both floors are measured
rather than guessed — the suite is run downwards until it fails — and CI runs both floors as
their own jobs.

**Crystal 1.21 is recommended, and it is the one thing worth upgrading for.**
`HashingExecutor` needs `Fiber::ExecutionContext`, which arrived as the default in 1.21.
Everything else works on 1.12 onwards; below 1.21 the executor refuses to be built unless you
pass `allow_inline: true`, which hashes on the request fiber and accepts that a burst of logins
will slow unrelated requests. It refuses rather than degrading quietly, because a security
property that disappears silently on an older compiler is worse than one that is absent
loudly.

Kemal 1.13.0 is recommended; see warning 2.

## Three warnings you have to read before using this

### 1. The `__Host-` cookie prefix scopes the session to exactly one host

The default cookie name is `__Host-kemal_identity`. The prefix forbids a `Domain`
attribute, which means `app.example.com` and `api.example.com` **cannot share a session.**

This is the right default — it stops a compromised sibling subdomain from setting a session
cookie for the parent — but it is a wall people hit without understanding why. If your app
genuinely spans subdomains, configure a non-prefixed cookie name together with an explicit
`domain`. Configuring a `__Host-` name *and* a domain is an incoherent middle ground that
the browser would silently discard, so it fails at boot instead.

### 2. Kemal 1.10.0 – 1.12.0 has four defects that make authentication filters silently not run

**Fixed in Kemal 1.13.0 (2026-08-24). Upgrade if you can.** They matter anyway, because the
supported floor is 1.10.0: **this shard does not build authentication on `only`, `exclude`,
`before_get`, or router-scoped filters**, and neither should your application if you are
below 1.13.0.

- `HEAD` served by a `GET` route did not run `before_get` filters (GHSA-jf9q-62h3-924j).
  `HEAD /admin/users` skipped the auth filter, ran the protected handler, and left no audit
  record. This is Kemal's own documented auth pattern.
- `only ["/admin/*"]` defaults to `GET` and did not match `HEAD`, with the same result.
- `Kemal::Router` filters with a path ending in `/*` were registered nowhere at all, for
  any method.
- Router filters ran once per route rather than once per path, double-counting rate limits
  on a path carrying both `GET` and `POST`.

`AuthenticationHandler` is therefore registered globally, and every path-scoped guard does
its own prefix matching on `env.request.path` for every method. That design is kept on
1.13.0 too: it costs nothing, and it is what made the new `QUERY` method (RFC 10008, added
in 1.13.0) safe by default rather than a gap. Guard specs assert `GET`, `HEAD`, `POST`,
`DELETE` and `QUERY`.

Related, same set: uploaded temp files were only cleaned up if the request reached the route
handler, so on 1.10.0 – 1.12.0 **a guard that rejects a multipart upload leaks its temp
files permanently** — an unauthenticated client can fill the disk one *rejected* upload at a
time. Reject before anything touches `env.params` where you can. 1.13.0 moves cleanup into
`Kemal::InitHandler`; that also means **never register `AuthenticationHandler` at position
`0`**, since a handler ahead of `InitHandler` takes over that cleanup itself.

### 3. `Principal#subject` is a `String`, and you will convert it

Not a generic parameter. `RequestAuthenticator(T)` would propagate `T` through every
handler, service and repository in the type graph, and the first application wanting a UUID
in one place and an `Int64` in another would have no way out.

The cost is real: you will write `principal.subject.to_i64` at the application boundary.
That is one conversion in your code instead of a viral type parameter in library code.

## Performance

Measured with `bench/hashing_latency.cr` on Crystal 1.21.0, 20 CPUs. **Numbers from a
development machine — recalibrate on your deployment target.** Crystal's own bcrypt
documentation makes the same point.

### Hashing must not run on the request fiber

Bcrypt is tens of milliseconds of pure CPU by design, and Crystal's scheduler is cooperative —
a verification never yields. Run on request fibers, enough concurrent logins occupy every
scheduler thread and *everything else* queues behind them.

`HashingExecutor` dispatches to a small dedicated context. The measurement is what happens to
an **unrelated** request — a 1 ms wake-up — while N logins are in flight at cost 9:

| Concurrent logins | p99 on the request context | p99 on a hashing context |
|---|---|---|
| 1 | 52 ms | 1.21 ms |
| 10 | 449 ms | 1.22 ms |
| 50 | 2,176 ms | 1.17 ms |
| 100 | 4,602 ms | 1.18 ms |

Without it, 100 logins make an unrelated page take four and a half seconds. With it, a login
burst degrades *login* latency — the thing that should degrade — and nothing else moves.

```crystal
hasher: KemalIdentity::Passwords::HashingExecutor.new(
  KemalIdentity::Passwords::BcryptHasher.new(cost: 12), size: 2
)
```

The pool is small on purpose: it is a ceiling on how much of the machine logins may take, not
a throughput target.

### bcrypt cost

One verification, median of five:

| Cost | 8 | 9 | 10 | 11 | 12 |
|---|---|---|---|---|---|
| | 23 ms | 40 ms | 92 ms | 180 ms | 363 ms |

Pick the highest cost that keeps p95 login latency inside your budget, on your hardware.

### Session resolution, and the write it avoids

Resolving a session cookie — shape check, SHA-256, one indexed lookup — costs **2.6 µs** over
an anonymous request against the in-memory store, so what you pay in production is essentially
your database's lookup latency. A malformed cookie is rejected in **1 ns**, before any lookup.

Idle expiry naively means an `UPDATE` on every authenticated request. `touch_interval` throttles
it — over 600 requests, one per second:

| `touch_interval` | Writes | Share of requests |
|---|---|---|
| 60 s (default) | 9 | 1.5% |
| none | 600 | 100% |

The cost is that idle expiry is accurate only to within one `touch_interval`. That is part of
the contract, not an implementation accident.

## Handler order

Order matters and is not obvious:

```crystal
# Kemal::InitHandler, LogHandler, ExceptionHandler
# [kemal-session handler, if you use it — before authentication]
use KemalIdentity::Kemal::ErrorHandler.new            # outermost: catches what guards raise
use KemalIdentity::Kemal::AuthenticationHandler.new   # populates env.auth; never rejects
use KemalIdentity::Kemal::CSRFHandler.new             # needs the principal, so it comes after
# [your middleware]
use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")   # rejects
# Kemal::RouteHandler
```

**Never `use ... , 0`.** Position 0 puts a handler ahead of `Kemal::InitHandler`, which since
Kemal 1.13.0 makes it responsible for cleaning up temporary upload files. An authentication
handler has no business owning that.

`AuthenticationHandler` resolves but never rejects. Rejection is a guard's job. That is what
lets a public page render differently for a signed-in user, and what stops every stale
cookie from producing a 401 on the homepage.

## Guarding routes

```crystal
get "/dashboard" do |env|
  principal = env.auth.require!
  render_dashboard(principal)
end

post "/account/email" do |env|
  env.auth.require_fresh!(within: 5.minutes)   # the window is the caller's choice
  update_email(env)
end
```

`require!` raises `NotAuthenticatedError` → 401. `require_fresh!` raises
`FreshAuthenticationRequiredError` → 403.

A session restored from a remember-me cookie sits at `AssuranceLevel::Remembered` and is
**never** fresh, however recently it was restored — it proves possession of a stored token,
not the presence of the account holder.

## Logging in

The shard exposes services; the mountable router is optional.

```crystal
post "/login" do |env|
  result = KemalIdentity.app.passwords.authenticate(
    login: env.params.body["email"],
    password: env.params.body["password"],
    tenant_id: nil,
    ip: env.request.remote_address.to_s
  )

  case result
  in KemalIdentity::Authenticated
    # Mints the session, sets the cookie, and revokes whatever session the client presented
    # while logging in — the session fixation defence.
    env.auth.start!(result.principal)
    env.redirect "/dashboard"
  in KemalIdentity::Failed, KemalIdentity::Anonymous
    # One message for every failure reason. Never branch the response on `reason` —
    # `DisabledAccount` and `InvalidCredential` reading differently is an enumeration
    # oracle. `reason` is for the audit log.
    render_login_form(error: "Invalid email or password")
  end
end
```

No `not_nil!`: the union makes the principal reachable only in the branch where it exists.

## Rate limiting is off by default

`NullRateLimiter` is the default and it allows everything. **Nothing throttles your login
endpoint until you say so.** The shard will not pick a limit for you — a public consumer site
and an internal tool with nine users want different numbers, and a default that silently did or
did not share state across processes would be worse than none.

```crystal
KemalIdentity.configure(
  accounts: MyAccountRepository.new,
  sessions: session_repository,
  rate_limiter: KemalIdentity::FixedWindowRateLimiter.new(limit: 10, window: 5.minutes),
)
```

`FixedWindowRateLimiter` is in-memory and **per process**, so behind a load balancer the
effective limit is `limit × processes`. For anything larger, implement `RateLimiter` over a
shared store — the contract is two methods.

The login path consumes quota **before** looking anything up and before hashing. That ordering
is the point: bcrypt is tens of milliseconds of CPU by design, so an endpoint that verifies a
hash before deciding whether it should have is a denial-of-service lever. Attempts are counted
against two keys — the login (hashed, tenant-scoped) and the source address — because
credential stuffing rotates addresses and password spraying rotates logins.

Once the limit is reached the *correct* password is refused too. Letting it through would tell
an attacker they had guessed right.

## CSRF

Every unsafe request needs a token — including the login form, which is the case most
implementations miss. Without it an attacker can log a victim into the **attacker's** account
and then watch whatever the victim does under it.

```crystal
KemalIdentity.configure(
  accounts: MyAccountRepository.new,
  sessions: session_repository,
  csrf: KemalIdentity::CSRFConfig.new(secret: ENV["CSRF_SECRET"]),  # >= 32 bytes, no default
)
```

Render the token into the form, and the anchor cookie is minted for you on first use:

```html
<input type="hidden" name="_csrf" value="<%= env.auth.csrf_token %>">
```

An XHR client can send `X-CSRF-Token` instead — and should, because the header is checked
first, so it never triggers request-body parsing.

Three things worth knowing:

- **Protected by default, safe by exception.** Everything except `GET`, `HEAD`, `OPTIONS`,
  `TRACE` and `QUERY` requires a token. A denylist would leave `PROPFIND` — and every method
  invented after this was written — unprotected.
- **`exempt_prefixes` is a promise**, not a convenience. Exempting a path asserts it accepts
  no session cookie. An endpoint that accepts one is subject to CSRF regardless of also
  accepting a bearer token, and regardless of being called an API. Content type is not a
  defence.
- **On Kemal below 1.13.0, a rejected multipart POST leaks its temp files.** Finding the token
  in a multipart form requires parsing the body, and on those versions cleanup only ran if the
  request reached the route handler. The header path avoids it; upgrading fixes it.

## PostgreSQL

```crystal
require "kemal_identity/postgres"

db = DB.open(ENV["DATABASE_URL"])

KemalIdentity.configure(
  accounts: KemalIdentity::Postgres::AccountRepository.new(db),
  sessions: KemalIdentity::Postgres::SessionRepository.new(db),
  csrf: KemalIdentity::CSRFConfig.new(secret: ENV["CSRF_SECRET"]),
)
```

`kemal_identity/postgres` is a separate require, so an application using its own storage never
links a driver it does not use.

`AccountRepository` is a **reference implementation over `auth_accounts`, not a requirement**.
If you already have `users.email` and `users.password_digest`, implement
`KemalIdentity::Accounts::Repository` over that table and never create `auth_accounts` at all —
you then need only `auth_sessions`. `SessionRepository` takes the account table's name for
exactly that case:

```crystal
KemalIdentity::Postgres::SessionRepository.new(db, accounts_table: "users")
```

Both classes run the same contract specs as the in-memory doubles. That is the only thing that
makes the doubles trustworthy.

## Sweeping

Expired rows are rejected on read, always — a sweeper that never runs costs you storage and
nothing else. Revocation and expiry are never deferred to it, which is the lesson of
kemal-session #116.

It does not start itself:

```crystal
sweeper = KemalIdentity::Sweeper.new(KemalIdentity.app)
sweeper.run_every(1.hour)
```

For anything beyond a single process, call `sweeper.sweep` from cron instead — four processes
behind a load balancer would otherwise run four sweepers against one database.

It sweeps sessions (expired, and revoked past a retention window), action tokens, and
remember-me tokens. It never removes a spent remember-me token before it expires: that row is
the evidence of a replay, and deleting it early would make a stolen cookie look unknown rather
than stolen.

## Migrations

Published as files you copy in, not run automatically. An auth library that mutates your
schema on boot is a library that will one day mutate it at the wrong moment.

```bash
shards build migrate
bin/migrate up        # also: down, status
```

The files carry micrate's `-- +micrate Up` / `-- +micrate Down` directives, so tooling that
already understands them applies these files unchanged. `bin/migrate` reads the same
directives — this repository depends on no migration tool, because neither published micrate
resolves against Crystal 1.21 and crystal-pg 0.30
(`blueprints/0002-no-micrate-dependency.md`).

`migrations/postgres/` holds `auth_sessions`, `auth_action_tokens`, and the optional
reference `auth_accounts`. If you already have a `users` table with a password digest, you
implement `AccountRepository` over it and never create `auth_accounts` at all — that is the
whole point of the contract being abstract.

## Development

```bash
shards install
shards build ameba migrate

crystal tool format --check
bin/ameba
crystal spec spec/unit spec/security     # must pass with no DATABASE_URL

export DATABASE_URL=postgres://kemal_identity:...@localhost/kemal_identity_test
bin/migrate up
crystal spec
```

`spec/unit` and `spec/security` run without a database on purpose: skipping a security
regression because a database is missing defeats the point of having it.

Design documents are in `docs/`. Feature blueprints and decision records are in
`blueprints/`. Executable tests are in `spec/`. Those three directories never mix.

## Example

`examples/browser_session/` is a complete first-party browser application — log in, stay
logged in, step up, log out — wired with every handler in the right order. CI compiles it on
every push, because an example that has drifted from the API is worse than no example.

```bash
createdb kemal_identity_example
export DATABASE_URL=postgres://localhost/kemal_identity_example
export CSRF_SECRET=$(head -c 32 /dev/urandom | base64)
bin/migrate up
crystal run examples/browser_session/app.cr
```

## Remember-me

Not a long-lived session. Every token is single-use and rotates on presentation, and every
token descended from one login shares a family.

That is what makes theft **detectable**: after a thief uses a stolen cookie the token is spent,
so the real user's next visit is a replay — and the reverse if the user gets there first.
Either way somebody presents a spent token, the whole family dies, every session for the
account ends, and the account holder is told.

A restored session sits at `AssuranceLevel::Remembered`, below `Password`, and is **never**
fresh however recently it was restored. Anything sensitive calls `require_fresh!` and gets a
real re-authentication — possession of a cookie is not the presence of the account holder.

**Known trade-off:** two requests presenting the same remember cookie at the same instant are
indistinguishable from a theft, so a parallel prefetch against a cold session can sign a user
out and email them a warning. Restore only when there is no live session, which narrows the
window to a cold start. See `blueprints/0012-remember-me.md` for why the strict behaviour was
kept and what a grace window would cost.

## Design decisions

`docs/` describes the intended design. `blueprints/` records the ten places the implementation
had to diverge from it, and why — each one written when the divergence was made, not
reconstructed afterwards:

| | |
|---|---|
| [0001](blueprints/0001-single-outcome-union.md) | One three-variant outcome union |
| [0002](blueprints/0002-no-micrate-dependency.md) | No micrate dependency — neither published version resolves on this stack |
| [0003](blueprints/0003-kemal-1.13.0-fixes-the-filter-defects.md) | Kemal 1.13.0 fixes the filter defects; the design does not change |
| [0004](blueprints/0004-hasher-over-length-behaviour.md) | An over-length secret raises when hashing, returns false when verifying |
| [0005](blueprints/0005-one-account-identifier.md) | One account identifier |
| [0006](blueprints/0006-session-cookie-and-expiry-boundaries.md) | Insecure-cookie opt-in, expiry boundary, what rotation restarts |
| [0007](blueprints/0007-audit-events-omit-the-login.md) | Audit events omit the login |
| [0008](blueprints/0008-kemal-layer-owns-the-http-seam.md) | `start!` lives on `env.auth`, not on the session service |
| [0009](blueprints/0009-csrf-token-scheme.md) | The CSRF token scheme |
| [0010](blueprints/0010-rate-limiting.md) | Rate limiting: consume before verifying, and key on two things |
| [0011](blueprints/0011-action-token-atomicity.md) | Action token atomicity, and a concurrency spec that did not test it |
| [0012](blueprints/0012-remember-me.md) | Remember-me: rotation, families, and what a replay costs |
| [0013](blueprints/0013-execution-contexts-are-optional.md) | Execution contexts are optional, and the Crystal floor is 1.12 |

## License

MIT.
