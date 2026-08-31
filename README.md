# Kemal Identity

Authentication for Crystal web applications — Kemal integration included.

Server-side opaque sessions, password credentials, and revocation that actually revokes.
It answers *who is making this request*, gives the application a typed answer, and stops
there. Authorization is a separate, opt-in contract that carries nothing into a session.

> **Released: `v0.7.0`.** Password login, revocable server-side sessions, cookie policy, Kemal
> guards, CSRF including the login form, rate limiting, PostgreSQL and SQLite adapters, a
> dedicated execution context for hashing, password reset, email confirmation, remember-me with
> theft detection, the session sweeper, opaque API tokens, a strict off-by-default JWT
> validator, TOTP second factors with recovery codes, OpenID Connect sign-in, role-based
> authorization with tenant membership, and a migration path for applications that already have
> users. Every release blocker in `docs/05-testing.md` has a named spec.
>
> **v0.7.0 is a breaking packaging change:** `pg` and `sqlite3` are no longer dependencies of
> this shard, so an application requiring `kemal_identity/postgres` or `kemal_identity/sqlite`
> declares that driver itself.
>
> **Next is v0.8, the last breaking release.** A scan of every contract v1.0 would freeze found
> a handful that cannot reach their targets in their current shape — most visibly `Principal`,
> which does not record *which* credential proved a request, so two personal access tokens for
> one account are indistinguishable and a read-only token can perform a write the account is
> permitted. Those signatures change in v0.8 and then v1.0 freezes them; see
> `blueprints/0020-api-freeze-blockers.md`. **The API is not frozen until v1.0.**

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

### When the store is gone

A limiter over Redis has a third thing to say, and `Verdict` can say it:

```crystal
def consume(key : String) : KemalIdentity::Verdict
  # ...
rescue Redis::Error
  KemalIdentity::Verdict.unavailable   # never raise; never guess
end
```

**The default is fail-closed.** All five of this shard's own call sites — login, password reset,
and three ways of proving a second factor — refuse rather than run unmetered, and log
`rate_limiter.unavailable` at error level. The cheapest way to disable rate limiting is to break
the thing that stores the counts, so an outage is not the moment to stop enforcing.

If you would rather stay up on a given path, wrap the limiter:

```crystal
KemalIdentity::FailOpenRateLimiter.new(shared_limiter)
```

Per endpoint, because each service takes its own limiter — so the login can stay fail-closed
while something less sensitive keeps serving. It converts only the unavailable case; a genuine
denial still denies.

- **`Verdict.unavailable` reads as `allowed? == false`**, so code that never learned about the
  third state refuses on an outage rather than waving everything through. Ask `unavailable?` to
  tell the two apart.
- **It carries no `retry_after`.** There is no honest number when the limiter does not know what
  has been spent.
- **`FailureReason::RateLimiterUnavailable` is not `RateLimited`.** One is the limiter working,
  the other is an incident, and only one of them deserves a page. Neither is visible in the
  response.
- **`consume` and `reset` must never raise.** An exception is neither policy, and it arrives as
  a 500 rather than as either answer.

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

## API authentication

Two bearer credentials, one `Authorization` header. Both are `RequestAuthenticator`s, so
`env.auth.require!`, `PathGuard` and `require_assurance!` work unchanged — the whole point of
the `Outcome` union is that the credential type stops mattering once it has been resolved.

Both authenticate at `AssuranceLevel::ApiToken`, which is **never fresh**. `require_fresh!`
therefore refuses a token-bearing request outright, at any age. That is the intended answer: an
automated client cannot re-authenticate interactively, so a destructive account action should
not be reachable with a token in the first place.

Neither compares `auth_version`, unlike a session. A password change must not silently break a
deploy key whose holder is a machine with no way to notice. Revoking is explicit.

### Personal access tokens

The credential this shard recommends. Digest-only storage, revocable on the very next request,
and no revocation problem to document.

```crystal
KemalIdentity.configure(
  accounts:   accounts,
  sessions:   sessions,
  api_tokens: KemalIdentity::Postgres::ApiTokenRepository.new(db),
  api_token_prefix: "acme_",   # your own, so a scanner can tell whose token it found
)

issued = KemalIdentity.app.api!.issue(account, "ci deploy key", expires_at: 90.days.from_now)
issued.token.reveal   # shown once, never again — only the SHA-256 digest is stored
```

```crystal
get "/api/me" do |env|
  env.auth.require!.subject
end
```

- The `acme_` prefix is not decoration. A fixed, searchable prefix is what lets a secret
  scanner recognise a leaked credential in a commit or a paste and say *whose* it is.
- `expires_at: nil` means it never expires — a real choice for a deploy key and a poor one for
  a laptop, so it is yours to make. The sweeper never touches one.
- `last_used_at` is throttled to one write per five minutes. Without that, every authenticated
  API request becomes a write.
- `revoke_all(account_id)` is what a "revoke all my tokens" button calls.

#### Scopes: a token narrower than its owner

An administrator holds `reports.export`. Their reporting token should not.

```crystal
KemalIdentity.app.api!.issue(account, "reporting", scopes: ["reports.read"])
```

The route is unchanged — `env.auth.authorize!("reports.export")` — and now answers 403 for that
token while still answering 200 for the same person's browser session.

- **Effective permission is the intersection, never the union.** The account's grant is checked
  first, so a scope can only ever *narrow*: naming a permission its owner was never given
  grants nothing.
- **`scopes: nil` means unrestricted**, which is what every token issued before v0.8 reads back
  as, and what a browser session carries. `[] of String` means *permits nothing* — a different
  answer, and never conflated with `nil`.
- **There is no wildcard.** `["*"]` is a scope named `*` and matches nothing; unrestricted is
  `nil`. Same reason `Permission` refuses `*`: a wildcard grants permissions that do not exist
  yet.
- **An out-of-scope denial is not a step-up.** Re-authenticating does not widen a token that was
  issued narrow; issuing a new one does. The response is a plain 403, not a freshness prompt.

⚠ **A permission left at the default assurance is unreachable by any token, however wide its
scopes.** `Permission#minimum_assurance` defaults to `Password`, and `AssuranceLevel::ApiToken`
sits below it. Declare the permissions automation is allowed to perform:

```crystal
KemalIdentity::Authz::Permission.new(
  "reports.read", minimum_assurance: KemalIdentity::AssuranceLevel::ApiToken
)
```

Two questions, both of which must say yes: the assurance answers *may a machine do this at
all*, the scope answers *may this particular token*.

⚠ **If you implement `ApiTokens::Repository` yourself, persist the new column.** `Token#scopes`
is a defaulted field, so an adapter written before v0.8 keeps compiling and silently drops it —
and a dropped scope reads back as `nil`, which means *unrestricted*. Run the shared contract
suite; it has three examples that fail on exactly this.

### When a request presents both a cookie and a bearer token

**The cookie is resolved first, and it wins.** A request carrying both a valid session cookie and
a valid `Authorization: Bearer` is authenticated as whoever the cookie names; the token is never
looked at. Identities never merge — `env.auth.credential.kind` says which one answered.

Two consequences, and the second is a sharp edge:

| Cookie | Bearer | Result |
|---|---|---|
| valid | valid | the cookie's account, `kind: Session` |
| valid | invalid or revoked | the cookie's account — the bearer is not examined |
| absent | valid | the token's account, `kind: ApiToken` |
| **present but invalid** | **valid** | **401** |

That last row is the one to know about. A session cookie that has idle-expired, been revoked, or
been tampered with **masks a perfectly good bearer token**: the handler clears the bad cookie and
stops, rather than falling through. It is fail-closed rather than dangerous, but a same-origin SPA
that keeps sending a stale cookie alongside an `Authorization` header will get 401s it did not
expect.

If your application wants bearer-first, replace the handler. It is about twenty lines of public
API:

```crystal
class BearerFirstHandler < Kemal::Handler
  def initialize(@app : KemalIdentity::Application)
  end

  def call(env)
    header = env.request.headers["Authorization"]?
    bearer = header.try { |h| h.starts_with?("Bearer ") ? h.lchop("Bearer ") : nil }

    outcome =
      if bearer && (service = @app.bearer)
        service.authenticate(bearer)
      else
        @app.sessions.resolve(@app.cookie.extract(env.request.cookies))
      end

    env.auth = KemalIdentity::Kemal::RequestContext.new(env, @app, outcome)
    call_next(env)
  end
end

use BearerFirstHandler.new(KemalIdentity.app)   # instead of AuthenticationHandler
```

⚠ **A replacement handler cannot keep remember-me.** `restore_remembered!` is `protected`, so a
handler outside the shard cannot call it — replacing `AuthenticationHandler` means an application
using remember-me has to reimplement the restore, including the ordering
`blueprints/0012-remember-me.md` explains. If you use remember-me, weigh that before replacing
the handler.

### Which credential proved the request

`env.auth.require!` answers *who*. `env.auth.credential` answers *what proved it*:

```crystal
delete "/api/tokens/current" do |env|
  env.auth.require!
  credential = env.auth.credential

  if credential && credential.kind.api_token? && (id = credential.id)
    KemalIdentity.app.api!.revoke(id)
  else
    env.status(400).text("This endpoint revokes the token it was called with")
  end
end
```

`CredentialRef` carries the credential's `kind`, its `id`, a display `name`, `expires_at` and
`scopes`. It never carries the token itself, the digest or a signature, so it is safe to put in
a log line or hand to a template.

- **Two tokens for one account are distinguishable.** Before v0.8 they were not: the token id
  was known at the moment the token authenticated and then discarded, so a token issued for
  reading reports could perform any write its owner was permitted. Per-token policy is now
  something an application can write.
- **`principal.session_id` still works** and is derived from this. A bearer credential answers
  `nil` there — there is no session to spare on "log out everywhere else" and none to anchor
  CSRF on — while still being named on `credential`.
- **`scopes` is `nil` until v0.8's second half lands**, and `nil` means *unrestricted*, not
  *permits nothing*. The distinction matters: a session has no scopes either, and reading their
  absence as an empty set would deny every signed-in browser.

### JWT

Off unless you pass a validator, and second on purpose: **a JWT cannot be revoked before its
`exp`**. Read `## The JWT you cannot take back` below before turning it on.

This validates tokens minted elsewhere — an identity provider, a gateway, another service. It
does not mint them.

```crystal
KemalIdentity.configure(
  accounts: accounts,
  sessions: sessions,
  jwt: KemalIdentity::JWT::Validator.new(
    keyring: KemalIdentity::JWT::Keyring.new([
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, current_secret, id: "2026-08"),
      KemalIdentity::JWT::Key.new(KemalIdentity::JWT::HS256, previous_secret, id: "2026-05"),
    ]),
    issuer:     "https://issuer.example.com",
    audience:   "https://api.example.com",
    algorithms: ["HS256"],
    clock:      KemalIdentity::SystemClock.new,
  ),
)
```

Every one of these is a documented, exploited JWT failure, and none of them is optional:

| Attack | What stops it |
|---|---|
| `alg: none` | no algorithm can express it; the allow-list refuses the string at boot; `alg` is compared against the key's |
| algorithm confusion (RS256 verified as HS256) | the **key** names its algorithm; the token's `alg` selects nothing |
| a retired key still accepted | an unknown `kid` is rejected, never retried against the ring |
| a token replayed at the wrong service | `iss` and `aud` are required and compared |
| a token that never expires | `exp` is required, and `max_lifetime` bounds how far away it may be |
| a reset-link token used as an access token | `purpose` is required and compared |
| clock skew widened into an expiry bypass | `leeway` is bounded at five minutes |
| a signature over re-encoded claims | verification runs over the received bytes |
| a multi-megabyte header | size and shape are checked before any parsing |

Only HMAC ships — `HS256`, `HS384`, `HS512` — because Crystal's OpenSSL bindings expose `HMAC`
and not the `EVP` interface RSA and ECDSA verification need. RS256 is a subclass of
`JWT::Algorithm` plus a C binding away; nothing else changes, since the keyring names the
algorithm rather than trusting the token to.

Two knobs turn off, and both want an explicit `nil` rather than a default:

```crystal
max_lifetime: nil,   # for an issuer trusted to bound its own tokens
purpose:      nil,   # for an issuer that emits no purpose claim
```

Understand the second one: without it, any validly signed token from that issuer authenticates
a request, including one minted to authorise a password reset.

`kid` selection is strict in both directions. An unknown `kid` is rejected outright rather than
retried against the other keys — otherwise a compromised key can never be withdrawn. A token
naming no `kid` resolves only when the ring holds exactly one key.

### The JWT you cannot take back

**A stateless JWT cannot be revoked before its `exp`.** The signature is the entire proof, the
server keeps nothing, and there is therefore nothing to change when someone clicks "sign out
everywhere" or an employee leaves. Two honest answers, neither free:

1. **A very short lifetime.** `max_lifetime` defaults to one hour and rejects any token
   claiming longer. Nothing is stored, and what you get is bounded exposure, not revocation.
2. **A `jti` denylist.** Implement `JWT::RevocationStore`, pass it as `revocations:`, and the
   validator checks it on every request. That is a read from shared storage on the hot path —
   precisely the thing a JWT was chosen to avoid. It buys real revocation and it costs the
   statelessness. Do not go on calling the result stateless.

If you are reaching for option 2, compare it against personal access tokens first: those
already read from storage on every request, and give revocation, an extendable expiry and a
`last_used_at` for the same single lookup.

The same applies to account status. By default the validator makes no account lookup, so a
**disabled account keeps authenticating until `exp`**. Passing `accounts:` fixes that and costs
the same lookup:

```crystal
revocations: MyRevocationStore.new(db),   # your own JWT::RevocationStore
accounts:    accounts,                    # a disabled account stops immediately
```

### One header, two credentials

Configure both and `AuthenticatorChain` asks each in turn, routing on **shape alone**: an
opaque token is a fixed prefix plus a fixed-length random part, a JWT is three base64url
segments, and neither can be mistaken for the other before any I/O.

It falls through on `Anonymous` and on `MalformedCredential` — "this is not a credential of
mine" — and stops at anything else. A credential that was recognised and then failed on its
merits does not get a second opinion from an authenticator that never issued it, which is how a
revoked credential ends up authenticating a request.

⚠ **Shape-only routing means two JWT validators cannot be chained.** Every JWT is three
base64url segments, so a token from issuer B looks exactly like one from issuer A: validator A
recognises the shape, fails it on the signature, and the chain stops. Validator B is never
asked, and that customer's tokens are refused. Reversing the order moves the problem to the
other issuer rather than solving it.

Accepting several issuers therefore needs routing on `iss` **before** validating, and there is
no helper for that yet — you decode the payload segment yourself, bound it yourself, and pick
the validator by issuer. See `blueprints/0025-maturity-validation-results.md` (JWT-01) for a
worked version and what it costs.

When a bearer token is presented and fails, a remember-me cookie is not tried afterwards: a
client that sent a token is asking to be authenticated by it. Precedence between a **session
cookie** and a bearer token is a separate question, and the cookie is resolved first — see
`## When a request presents both a cookie and a bearer token` above, including the case where an
invalid cookie masks a valid token.

## Second factors

TOTP, the kind an authenticator app produces, plus single-use recovery codes. Off unless you
configure it.

```crystal
KemalIdentity.configure(
  accounts:       accounts,
  sessions:       sessions,
  mfa_factors:    KemalIdentity::Postgres::MfaRepository.new(db),
  mfa_secret_key: KemalIdentity::Secret.new(ENV["MFA_SECRET_KEY"]),   # >= 32 bytes
  mfa_issuer:     "Acme",                                             # shown in the app
  rate_limiter:   limiter,                                            # read the warning below
)
```

All three `mfa_` arguments or none: a service with nowhere to store a factor, or no key to seal
it with, would accept an enrolment and lose it, so a partial configuration is refused at boot.

### Enrolling

Two steps, and the second one is not optional. A secret that was generated but never proved is
a secret nobody may actually hold — a mis-scanned QR code, a clock two minutes out, an app that
failed to save — and treating it as a factor immediately is how somebody locks themselves out
of their own account. An unconfirmed factor never authenticates and never counts as enrolled.

```crystal
post "/mfa/enrol" do |env|
  subject = env.auth.require_fresh!(within: 5.minutes).subject
  account = accounts.find_by_id(subject) || raise "account vanished mid-request"
  pending = KemalIdentity.app.mfa!.enrol(account, "iPhone")

  # Contains the secret. Render it as a QR code and let it go — never log it, never store it.
  render_qr(pending.provisioning_uri)
end

post "/mfa/confirm" do |env|
  confirmed = KemalIdentity.app.mfa!.confirm(env.params.body["factor"], env.params.body["code"])

  if confirmed
    # Non-empty only when this is what turned MFA on. Show them once; only digests are stored.
    show_recovery_codes(confirmed.recovery_codes)
  else
    env.status(401).text("Invalid code")
  end
end
```

### Proving a factor

```crystal
post "/mfa/verify" do |env|
  principal = env.auth.require!

  case KemalIdentity.app.mfa!.verify(principal.subject, env.params.body["code"])
  in KemalIdentity::MFA::Verified
    env.auth.mfa_verified!    # rotates the session up to AssuranceLevel::MFA
    redirect_to "/"
  in KemalIdentity::Failed
    # One message for every reason, as everywhere else in this shard.
    env.status(401).text("Invalid code")
  end
end

get "/vault" do |env|
  env.auth.require_assurance!(KemalIdentity::AssuranceLevel::MFA)
  # ...
end
```

`mfa_verified!` **rotates the session**, exactly as login does. A session id an attacker learned
while it was worth `Password` must not silently become one worth `MFA`.

### ⚠ Configure a rate limiter before you turn this on

A six-digit code is one of a million, and with the default drift it is valid for ninety seconds.
Without a limit, a million guesses is a few minutes of traffic. `NullRateLimiter` is the default
and it counts nothing — see [Rate limiting is off by default](#rate-limiting-is-off-by-default).

Two more things do the rest of the work, and neither is optional:

- **Single use.** A code that verified once is spent, atomically, so six digits read over
  somebody's shoulder are worthless by the time they are typed again. This is why
  `TOTP.match` returns the counter rather than a boolean — a boolean cannot say "correct, but
  already spent".
- **Bounded drift.** Each step of tolerance multiplies the codes valid at any moment, so it is
  an authentication bypass with a limit on it. One step either side by default; more than two
  is refused at boot.

### Recovery codes

Ten of them, issued at the moment a first factor turns MFA on. Adding a *second* device does not
reissue them, because that would silently void a list somebody already wrote down.

```crystal
post "/mfa/recover" do |env|
  principal = env.auth.require!

  case KemalIdentity.app.mfa!.redeem_recovery_code(
    principal.subject, env.params.body["code"], except_session_id: principal.session_id
  )
  in KemalIdentity::MFA::Verified then env.auth.mfa_verified!
  in KemalIdentity::Failed        then env.status(401).text("Invalid code")
  end
end
```

- **Redeeming one signs the account's other sessions out.** Somebody is using a recovery code
  because the device is gone, and "lost" and "taken" look identical from here. Pass
  `except_session_id`, or the way back in signs them out.
- They are full-entropy bearer secrets, stored as digests, and printed in groups —
  `redeem_recovery_code` strips the spacing a person types back.
- `regenerate_recovery_codes` voids the old list. That is the point: it is what somebody calls
  when they think it leaked.
- `mfa.recovery_code_used` is logged at **warning**. It is worth alerting on.

### The secret you have to keep

Unlike every other secret here, a TOTP secret is **encrypted rather than hashed** — the server
recomputes a code from it on every verification, so it has to read it back. `mfa_secret_key` is
what makes a stolen table useless, and it belongs in configuration or a secrets manager, never
in the database it protects.

Lose it and every enrolled factor stops working; recovery codes still do, since those are
digests. Rotating it means decrypting and re-sealing each row with `AesSecretBox#reseal` — an
offline job over a small table.

## Signing in with a provider

OpenID Connect as a **client** — Google, Okta, an internal provider. Never as an authorization
server; `docs/00-scope.md` puts that permanently outside this shard.

Authorization Code with PKCE, and nothing else is expressible here. No implicit flow (a token in
a URL fragment lands in browser history and in any `Referer` that leaks), no password grant
(which asks your application to handle somebody else's password, the thing federating avoids).

```crystal
provider = KemalIdentity::OIDC::Provider.new(
  issuer:                 "https://accounts.google.com",
  client_id:              ENV["OIDC_CLIENT_ID"],
  client_secret:          KemalIdentity::Secret.new(ENV["OIDC_CLIENT_SECRET"]),
  authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth",
  token_endpoint:         "https://oauth2.googleapis.com/token",
  redirect_uri:           "https://app.example.com/auth/callback",
  keys: KemalIdentity::JWT::JWKS.new(
    uri:   "https://www.googleapis.com/oauth2/v3/certs",
    clock: KemalIdentity::SystemClock.new,
  ),
)

oidc = KemalIdentity::OIDC::Client.new(
  provider: provider,
  clock:    KemalIdentity::SystemClock.new,
  random:   KemalIdentity::SecureRandomSource.new,
)
```

### The two routes

```crystal
CODEC = KemalIdentity::OIDC::PendingCodec.new(KemalIdentity::Secret.new(ENV["SIGNING_KEY"]))

get "/auth/start" do |env|
  request = oidc.authorize(return_to: env.params.query["return_to"]?)

  # Holds the PKCE verifier. HttpOnly, Secure, scoped to the callback, and short-lived.
  env.response.cookies << HTTP::Cookie.new(
    name: "__Host-oidc", value: CODEC.seal(request.pending),
    path: "/auth/callback", secure: true, http_only: true,
    samesite: HTTP::Cookie::SameSite::Lax, max_age: 15.minutes
  )

  env.redirect request.url
end

get "/auth/callback" do |env|
  pending = CODEC.open?(env.request.cookies["__Host-oidc"]?.try(&.value))
  next env.status(400).text("No sign-in is in progress") if pending.nil?

  result = oidc.complete(
    pending,
    state: env.params.query["state"]?,
    code:  env.params.query["code"]?,
    error: env.params.query["error"]?,
  )

  case result
  in KemalIdentity::Federation::Identity
    account = account_for(result)          # yours — see below
    env.auth.start!(
      KemalIdentity::Principal.new(
        subject: account.id,
        assurance: KemalIdentity::AssuranceLevel::Password,
        authenticated_at: Time.utc,
      )
    )
    env.redirect(pending.return_to || "/")
  in KemalIdentity::Failed
    env.status(401).text("Sign-in failed")
  end
end
```

### More than one provider

Each provider is a `Provider` value with its own issuer, client id, redirect URI and key source,
and each gets its own `Client`. Concurrent flows stay apart: `state`, `nonce` and the PKCE
verifier are minted per flow.

⚠ **`Pending` does not name the provider, so routing the callback is your job.** It carries
`state`, `nonce`, the PKCE verifier and `return_to` — nothing that says which provider started
the flow. Hand a Google flow's pending to the Okta client and the Okta client will complete it
happily: the state matches the pending it was given, the nonce matches the token, and `iss`/`aud`
are checked against *Okta*, which minted it. Measured, not hypothetical.

So the callback route must give the pending to the client that started the flow — key the
callback path or the stored state by provider, and look the client up by that:

```crystal
get "/auth/callback/:provider" do |env|
  client = CLIENTS[env.params.url["provider"]]?
  next env.status(404) if client.nil?
  # ...decode the pending, then client.complete(...)
end
```

**Provider-specific authorisation parameters are not sent for you.** `authorize` takes
`return_to` and `prompt`. Google's `hd`, Okta's `login_hint`, Azure's `domain_hint` and the rest
have nowhere to go — so build the URL yourself from the `Pending` you were handed:

```crystal
flow = client.authorize(return_to: "/dashboard")
pending = flow.pending          # store this as usual, via PendingCodec

params = URI::Params.build do |form|
  form.add("response_type", "code")
  form.add("client_id", client.provider.client_id)
  form.add("redirect_uri", client.provider.redirect_uri)
  form.add("scope", client.provider.scopes.join(' '))
  form.add("state", pending.state)
  form.add("nonce", pending.nonce)
  form.add("code_challenge", pending.code_challenge)
  form.add("code_challenge_method", "S256")
  form.add("hd", "example.com")            # whatever your provider wants
end

uri = client.provider.authorization_endpoint.dup
uri.query = params
env.redirect uri.to_s            # instead of flow.url
```

Nothing security-relevant is duplicated — the state, nonce and challenge all come from the
`Pending` the shard minted, and `complete` still does every check. Only the query string is
yours.

### `(issuer, subject)` is the identity. The email is not.

```crystal
def account_for(identity : KemalIdentity::Federation::Identity)
  link = LINKS.find(identity.issuer, identity.subject)
  return accounts.find_by_id(link.account_id) if link
  # ... otherwise: create an account, or ask the person to confirm a merge.
end
```

`auth_external_identities` has **no email column**, and that is not an oversight:

- **Addresses change.** People marry, change surname, leave a company and come back. A row keyed
  on an address becomes a different person's row, or a stranded orphan.
- **Addresses are claimed, not proved.** A provider that lets somebody set an unverified address
  and hands it to you has let them claim to be whoever owns that address at *your* service.
  Looking an account up by it is account takeover with extra steps.

Use `identity.email` to display, and to pre-fill a form somebody then confirms. Never to find an
account. `identity.email_verified?` is a claim about a claim: it means only that this provider
says so.

That predicate answers a `Bool` and treats "not verified" and "the issuer said nothing" alike,
which is the only safe reading for a decision. When you need to tell them apart —
*"only accept issuers that verify addresses"* — read the field instead:

| `identity.email_verified` | Meaning |
|---|---|
| `nil` | the issuer asserted nothing. Normal for a protocol with no such concept, and for a claim that arrived as something other than a boolean |
| `false` | the issuer said the address is **not** verified |
| `true` | the issuer says it verified it |

### `Federation::` versus `OIDC::`

Protocol mechanics live under `OIDC` — `Provider`, `Client`, `Pending`, `PendingCodec`. The
durable identity model lives under `Federation` — `Identity`, `Link`, `LinkRepository` — because
none of it is specific to OpenID Connect, and a second protocol added later has to share it.

Sharing `LinkRepository` in particular is not optional. `for_account` answers "which providers is
this account linked to", and the guard that stops somebody unlinking their last remaining way in
reads it. Against a second table it would answer from half the rows and could strand an account
with no login method at all. `blueprints/0024-federation-namespace.md`.

Linking a pair that is already linked raises, **including to the same account**. Silently
accepting a second link is how one provider account ends up attached to two local ones, and then
whichever row is found first decides who somebody signs in as.

### What the flow checks, and why each one is there

| Attack | What stops it |
|---|---|
| login CSRF — an attacker's code handed to your victim | `state`, compared in constant time *before* the code is exchanged |
| an ID token replayed from another flow | `nonce`, carried into the token and compared |
| authorization-code interception | PKCE `S256`; only the hash ever leaves this process |
| a token issued to another app at the same provider | `aud`, and `azp` when present |
| a token from an issuer you do not trust | `iss`, compared exactly |
| a forged token | RS256 against the provider's JWKS, refetched on rotation |
| an open redirect after login | `return_to` restricted to a same-site path, checked on the way *in* |
| a stale flow resumed from an old tab | a 15-minute flow TTL |
| a hung provider | connect and read timeouts on both the JWKS and the token endpoint |

### The provider's tokens are thrown away

The token response is read for `id_token` and the rest is discarded. An access token is a
credential *for somebody else's service*, and storing one your application never uses turns a
breach of your database into a breach of every user's account there.

If you genuinely call the provider's API, run that exchange yourself and keep the result in your
own encrypted storage, with its own lifecycle.

### RS256 and the JWKS

`JWT::JWKS` caches the provider's keys with a TTL, and refetches once when a token names a `kid`
it does not hold — which is what a rotation looks like from here. That refetch is rate-limited,
because otherwise a stream of tokens carrying invented `kid`s is a way to make your process
hammer somebody else's identity provider.

A failed refetch keeps serving the last good key set: a provider outage should not sign every
user out. A failed *first* fetch raises, because an empty key set that verifies nothing while
looking healthy is worse than an error.

The endpoint must be `https`. Anybody who can rewrite a key set can mint tokens that verify —
that is the whole game.

## Authorization

Off by default, and separate from everything above on purpose. Authentication answers "who is
this"; authorization answers "and may they". The two have different lifetimes — a session is
minted once and lives for days, a grant can be taken away in the middle of it — and that is why
`Principal` carries no roles and no permissions, and why nothing here writes any into a session
or a token. Every check reads the current answer.

### Roles are code, assignments are data

```crystal
PERMISSIONS = KemalIdentity::Authz::PermissionRegistry.new([
  KemalIdentity::Authz::Permission.new("invoices.read", "See invoices"),
  KemalIdentity::Authz::Permission.new(
    "invoices.refund", "Move money back to a customer",
    minimum_assurance: KemalIdentity::AssuranceLevel::MFA
  ),
  KemalIdentity::Authz::Permission.new("members.invite", "Add somebody to a tenant"),
])

CATALOG = KemalIdentity::Authz::RoleCatalog.new(PERMISSIONS, [
  KemalIdentity::Authz::Role.new("reader", ["invoices.read"]),
  KemalIdentity::Authz::Role.new("finance", ["invoices.read", "invoices.refund"]),
  KemalIdentity::Authz::Role.new("owner", ["invoices.read", "members.invite"]),
])

KemalIdentity.configure(
  accounts: KemalIdentity::Postgres::AccountRepository.new(db),
  sessions: KemalIdentity::Postgres::SessionRepository.new(db),
  authorizer: KemalIdentity::Authz::RBAC.new(
    catalog: CATALOG,
    store: KemalIdentity::Postgres::AuthzRepository.new(db),
  ),
)
```

There is no `auth_roles` table. The database holds only **who holds which role**; what a role
grants is a literal in your application. A role definition in a table is one UPDATE away from
rewriting what everybody holding it can do, through an injection or an over-permissive admin
screen or a restored backup, with nothing about the application having changed. In code the
same change is a diff somebody reviews.

The cost is that roles cannot be administered at runtime. If you need that, implement
`Authz::Authorizer` against your own tables — that is why it is a contract.

`RoleCatalog` refuses at **boot** a role granting a permission nobody declared, so a rename
that misses one definition fails on your machine rather than denying an action in production
for a month.

### There are no wildcards

`invoices.*` is refused at construction. A wildcard is a grant of permissions **that do not
exist yet**: whoever holds `admin.*` today silently acquires `admin.billing.export_everything`
the day somebody adds it, and no reviewer sees a privilege change. Enumerate them; the typing
is the point.

### Guarding a route

```crystal
post "/invoices/:id/refund" do |env|
  env.auth.authorize!("invoices.refund", tenant: env.params.url["tenant"])
  # ...
end
```

Three refusals, three meanings:

| Situation | Raises | Status |
|---|---|---|
| nobody signed in | `NotAuthenticatedError` | 401 — logging in would help |
| signed in, no grant | `ForbiddenError` | 403 — logging in again would not |
| signed in, grant, weak assurance | `FreshAuthenticationRequiredError` | 403 — prompt for a second factor |

`ErrorHandler` maps all three. The response body for a denial is identical whatever the reason:
`Authz::DenialReason` distinguishes "not a member of this tenant" from "a member with no role",
and a body that varied with it would confirm that a guessed tenant exists.

For a template, ask without raising:

```crystal
<% if env.auth.can?("invoices.refund", tenant: tenant) %>
  <button>Refund</button>
<% end %>
```

Use `can?` to decide what to *render* and `authorize!` to guard what happens when it is
clicked. A permission list handed to a template is a snapshot, and a snapshot used as a
decision is the stale-grant problem this whole module exists to avoid.

### Guarding a particular object

A role answers "may this account refund invoices". It does not answer "may they refund *this*
one". Pass the object:

```crystal
put "/invoices/:id" do |env|
  invoice = Invoice.find(env.params.url["id"])

  env.auth.authorize!(
    "invoices.edit",
    resource: KemalIdentity::Authz::Resource.new(
      "invoice", invoice.id, {"owner_id" => invoice.owner_id}
    ),
  )
end
```

`RBAC` ignores it — a role grants a permission everywhere or nowhere, which is what an RBAC
implementation should do. An application with per-object rules implements `Authorizer` and
wraps the shipped one:

```crystal
class OwnershipAuthorizer < KemalIdentity::Authz::Authorizer
  def initialize(@inner : KemalIdentity::Authz::Authorizer)
  end

  def decide(principal, permission, context : KemalIdentity::Authz::Context)
    decision = @inner.decide(principal, permission, context)   # the grant first
    return decision unless decision.permitted?

    resource = context.resource
    return decision if resource.nil?          # not an object question: the grant decided it

    # From here the rule has been asked about an object, so it has to answer. Anything it
    # cannot read the owner of is a denial, not a pass -- see the note below.
    owner = resource.as?(KemalIdentity::Authz::Resource).try(&.["owner_id"])
    return decision if owner == principal.subject

    KemalIdentity::Authz::Forbidden.policy(permission, code: "not_the_owner")
  end
end
```

⚠ **The two `nil`s mean different things and only one of them is a pass.** `context.resource`
being nil means nobody asked an object question, and the grant already answered. `owner` being
nil means the rule *was* asked and could not read what it needed — a resource of the wrong type,
or one carrying no `owner_id` — and that has to deny. Writing the two checks as one
`return decision if owner.nil? || owner == principal.subject` reads naturally and fails **open**:
a resource with no owner attribute is permitted by a rule whose whole job is to require one.
This was found by attempting AUT-01 against an earlier version of this example; see
`blueprints/0025-maturity-validation-results.md`.

- **The grant runs first, and the object rule can only narrow.** Owning something is not a
  substitute for being allowed to act on it.
- **Your own models can be the resource** instead of `Authz::Resource`: include
  `Authz::Authorizable` and answer `authz_type` and `authz_id`. An authorizer that wants the
  real object writes `context.resource.as?(Invoice)`, and a wrong guess is `nil` rather than an
  exception. The module is frozen at those two methods, so an `include` cannot break on an
  upgrade.
- **`attributes:` carries the environment** — a device posture, a region, a change window —
  without a type change: `env.auth.authorize!("reports.export", attributes: {"device" => posture})`.
- **`Forbidden.policy` names your reason** for the audit trail. It never reaches the client;
  every denial still renders one identical 403.
- **`step_up: true` asks for re-authentication** under your own reason, without borrowing
  `InsufficientAssurance`. Only set it when authenticating again could actually change the
  answer — joining a tenant or enrolling a device cannot, and prompting for a second factor
  there asks for something that will not help.

### Tenancy

Two rows say one thing, and the redundancy is deliberate:

```crystal
authorizer = KemalIdentity.app.authorizer!.as(KemalIdentity::Authz::RBAC)

authorizer.add_member("account-1", "acme")
authorizer.grant("account-1", "finance", tenant_id: "acme", granted_by: current.subject)
```

A role held inside a tenant grants **nothing** without a membership in that tenant. So
`remove_member` is a single call that revokes everything at once — it deletes that tenant's
assignments too — and it cannot be defeated by an assignment somebody missed in the cleanup.
Re-inviting them later does not silently restore the roles they used to hold.

A grant with **no** tenant is global: it applies everywhere, including inside every tenant, and
is not gated by membership. That is the dangerous kind. Have very few, and record
`granted_by` on each.

`Principal#tenant_id` binds a session to one tenant. A bound principal asking about another is
refused before membership is even read — that is the identifier-in-the-URL attack, and it must
not depend on a database row being correct. A principal with no tenant is unconstrained, which
is the single-tenant deployment.

**Pass the tenant.** A check that names no tenant is a question about *global* scope, not about
whichever tenant the route happens to be operating on, so a route that forgets it gets a denial
rather than a quiet upgrade.

### Assurance belongs to the permission

`minimum_assurance` is a property of the action — refunding money needs a second factor wherever
it is called from — so it is declared once, not repeated at every call site where somebody might
forget it. The floor defaults to `Password`: a session restored from a remember-me cookie proves
possession of a stored token, not the presence of the account holder.

### The cache, and what its TTL costs you

Off by default. Every check reads the store, which is one indexed query.

```crystal
KemalIdentity::Authz::RBAC.new(
  catalog: CATALOG,
  store: KemalIdentity::Postgres::AuthzRepository.new(db),
  cache: KemalIdentity::Authz::Cache.new(KemalIdentity::SystemClock.new, ttl: 5.seconds),
)
```

**The TTL is the revocation delay.** Whatever you set, that is how long somebody keeps access
after it is taken away, in every process that had cached them. `MAX_TTL` is one minute and the
constructor refuses more — not because a longer one would not be faster, but because a
ten-minute cache is a ten-minute window in which a compromised account keeps working after
somebody has already noticed.

`grant`, `revoke` and `remove_member` called on the `RBAC` object invalidate it. Behind several
processes that clears only the one that made the change; the others wait out the TTL. That is
the honest bound, which is why the TTL is capped rather than trusted to invalidation.

### Deleting an account

```crystal
authorizer.remove_account(account_id)
```

Authorization data must not outlive the account it describes — otherwise a reused identifier
inherits somebody else's grants.

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

## The audit trail

Every security event goes through one named `Log` source, so an application routes the whole
trail with a single binding:

```crystal
Log.setup do |c|
  c.bind "kemal_identity.*", :info, Log::IOBackend.new(File.new("audit.log", "a"))
end
```

| Event | Emitted when |
|---|---|
| `authentication.succeeded` | a password verified |
| `authentication.failed` | it did not — carries `reason`, including `RateLimited` and `RateLimiterUnavailable` |
| `password.rehashed` | a correct password was re-hashed at current parameters |
| `session.started` | a session was created |
| `session.rotated` | a login replaced the session a client already held — the fixation defence firing |
| `session.revoked` | one session ended |
| `session.revoked_all` | bulk revocation — carries `count` |
| `session.ended` | logout |
| `session.rejected` | a presented cookie did not resolve — carries `reason` |
| `remember.restored` | a remembered login was restored |
| `remember.replay_detected` | **warning** — a spent remember-me token came back |
| `api_token.issued` | a personal access token was minted — carries `expires_at` |
| `api_token.revoked` | one token ended |
| `api_token.revoked_all` | bulk revocation — carries `count` |
| `mfa.enrolment_started` | a factor was created, not yet proved |
| `mfa.enabled` | a factor was proved — MFA is now on for that account |
| `mfa.confirmation_failed` / `mfa.rejected` | a code did not verify — carries `reason` |
| `mfa.throttled` | **warning** — code submissions were rate limited |
| `rate_limiter.unavailable` | **error** — the limiter could not reach its store and the attempt was refused. Carries `endpoint`. Worth paging on: the cheapest way to disable rate limiting is to break what stores it |
| `rate_limiter.failing_open` | **warning** — the same outage, on a path wrapped in `FailOpenRateLimiter`. The attempt proceeded **unmetered** |
| `mfa.verified` | a second factor was proved |
| `mfa.recovery_codes_issued` | carries `count` |
| `mfa.recovery_code_used` | **warning** — carries `remaining`. Worth alerting on |
| `mfa.factor_removed` | one factor was removed |
| `mfa.disabled` | **warning** — MFA was turned off for an account |
| `mfa.secret_unreadable` | **error** — a factor's secret will not open under the current key |
| `oidc.authorization_started` | a federated sign-in began |
| `oidc.identity_asserted` | a provider's ID token verified — carries `issuer` and `subject`, never the email |
| `oidc.state_mismatch` | **warning** — a callback that did not come from a flow we started. Login CSRF, or a stale tab |
| `oidc.nonce_mismatch` | **warning** — a valid token from somebody else's flow |
| `oidc.declined` / `oidc.rejected` / `oidc.token_error` | the flow did not complete |
| `oidc.exchange_failed` | **warning** — the provider's token endpoint could not be reached |
| `jwks.fetched` | signing keys were loaded — carries `keys` |
| `jwks.refresh_failed` | **warning** — a refetch failed; the last good key set is still in use |
| `jwks.fetch_failed` | **error** — there is no key set at all |
| `csrf.rejected` | an unsafe request carried no valid token |
| `password_reset.requested` | carries `known`, which the HTTP response deliberately does not |
| `password_reset.throttled` | a reset request was rate limited |
| `password_reset.completed` | carries `revoked_sessions` |
| `email_confirmation.requested` / `.completed` | |
| `sweeper.swept` / `.failed` | |

Events identify an account by its **id**, never by the login that was typed: an address in a log
line outlives the request and is read by people who never authenticated to anything. Passwords,
tokens, cookies and digests never appear —
`spec/security/audit_log_spec.cr` asserts it, and fails if a capture is empty rather than
passing vacuously.

`remember.replay_detected` is the one worth alerting on. It reports a suspicion rather than an
action somebody took.

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

## SQLite

```crystal
require "kemal_identity/sqlite"

db = DB.open("sqlite3://./identity.db?journal_mode=wal&busy_timeout=5000")

KemalIdentity.configure(
  accounts: KemalIdentity::SQLite::AccountRepository.new(db),
  sessions: KemalIdentity::SQLite::SessionRepository.new(db),
)
```

All four repositories, running the same contract specs as PostgreSQL and the in-memory doubles.
Migrations live in `migrations/sqlite/` — a sibling of the PostgreSQL set, not a shared file:
`BYTEA` versus `BLOB` and `TIMESTAMPTZ` versus `TEXT` are real differences.

Use `journal_mode=wal` and a `busy_timeout`. SQLite serialises writers across the whole file,
and without those, ordinary contention surfaces as `database is locked` rather than queueing.

For a busy application behind several processes, use PostgreSQL. One writer at a time across an
entire file is the constraint SQLite cannot be configured out of.

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

### The database drivers are yours to declare

`pg` and `sqlite3` are **not** dependencies of this shard. Nothing in `kemal_identity` requires
either; only `kemal_identity/postgres` and `kemal_identity/sqlite` do. If you require one of
those, add that driver to your own `shard.yml` — which you already had to for your own queries:

```yaml
dependencies:
  kemal_identity:
    github: urunsiyabend/kemal-identity
  pg:
    github: will/crystal-pg
```

An application that implements the repository contracts over its own storage links neither,
which is the point.

`migrations/postgres/` holds `auth_sessions`, `auth_action_tokens`, `auth_remember_tokens`,
`auth_api_tokens`, `auth_mfa_factors`, `auth_mfa_recovery_codes`, `auth_external_identities`,
`auth_tenant_memberships`, `auth_role_assignments`, and the optional reference
`auth_accounts`. `migrations/sqlite/` holds the same ten in SQLite's dialect. If you already have a `users` table with a password digest, you
implement `AccountRepository` over it and never create `auth_accounts` at all — that is the
whole point of the contract being abstract.

## Outside an HTTP request

A background job, a maintenance task or a message consumer can act under a principal and run the
same authorization policy a route would. Nothing needs Kemal, and nothing needs a faked request:

```crystal
require "kemal_identity"   # not kemal_identity/kemal

actor = KemalIdentity::Principal.new(
  subject: "worker-1",
  assurance: KemalIdentity::AssuranceLevel::ApiToken,
  authenticated_at: Time.utc,
  credential: KemalIdentity::CredentialRef.new(
    kind: KemalIdentity::CredentialKind::Custom,
    id: "cron:nightly-sweep",         # what the audit trail will name
    name: "scheduler",
  ),
)

authorizer.decide(actor, "invoices.sweep").permitted?
```

The same services work: `Sessions::Service`, `ApiTokens::Service`, `Authz::RBAC` and the
repositories know nothing about HTTP. Only `env.auth` and the handlers do, and they live in
`kemal_identity/kemal`, which a job need not require. Measured: a binary that requires only
`kemal_identity` and serves requests from raw `HTTP::Server` links **no Kemal symbols at all**.

- **Give the job its own credential reference.** `kind: Custom` with an id naming the launcher is
  what makes `authz.denied` answerable later. A job with no credential is indistinguishable from
  a session in the trail.
- **`AssuranceLevel::ApiToken` is the honest level for automation.** It is below `Password`, and
  `Principal#fresh?` is false for it, so a job cannot satisfy `require_fresh!`-style policy.

⚠ **Whatever constructs a `Principal` is trusted, and the shard cannot check that.**
`Principal.new` accepts any assurance, so a job *can* claim `MFA` and reach a permission that
demands it. There is no way around this: restricting the constructor would make this whole
section impossible. What protects the boundary is that the code building the principal is your
own launcher — treat it as the security decision it is, and do not build one from data that came
from outside.

## Migrating an application that already has users

Not a flag day. Four independent steps, each reversible, and three of them are things this shard
does for you.

### 1. Your own table, no schema change

`AccountRepository` is abstract. Implement it over the `users` table you already have and create
no `auth_accounts` at all. This is the step that makes the whole thing adoptable, and it has been
possible since v0.1.

### 2. Passwords, lazily

Keep the old scheme for **verification only**:

```crystal
class DeviseVerifier < KemalIdentity::Passwords::LegacyVerifier
  def name : String
    "devise"
  end

  # Shape alone, never the secret. This is what routes a digest to one verifier instead of all
  # of them.
  def handles?(digest : String) : Bool
    digest.starts_with?("$2a$")
  end

  def verify(secret : KemalIdentity::Secret, digest : String) : Bool
    Crypto::Bcrypt::Password.new(digest).verify(secret.reveal + PEPPER)
  rescue Crypto::Bcrypt::Error
    false
  end
end

KemalIdentity.configure(
  accounts: accounts,
  sessions: sessions,
  hasher: KemalIdentity::Passwords::MigratingHasher.new(
    KemalIdentity::Passwords::BcryptHasher.new,
    [DeviseVerifier.new.as(KemalIdentity::Passwords::LegacyVerifier)]
  ),
)
```

A correct password against a legacy digest logs in and is **rehashed immediately** with the
current hasher. Nobody is forced through a reset, and old digests disappear as people sign in.

`MigratingHasher` can verify the old scheme and can never write it: `hash_secret` and `scheme`
are always the current hasher's, so the count only goes down. Watch it go down with a query
against your own table:

```sql
SELECT count(*) FROM users WHERE password_scheme <> 'bcrypt';
```

When it reaches zero, delete the verifier and the `MigratingHasher` wrapper. That is the whole
lifecycle.

**This shard ships no legacy verifiers.** A ready-made `Sha1Verifier` would be this project
publishing a working SHA-1 password check, and the first thing anyone does with a class that
exists is use it for something new. Yours is the five lines above.

#### ⚠ Some of your users may have a password bcrypt cannot hold

Old schemes are usually unsalted digests with no input limit, so a table can contain passwords
longer than bcrypt's 71 bytes. Verifying one would succeed and the rehash would then raise,
because this shard refuses to truncate a secret — if bcrypt cuts at 71 bytes, then 71 A's and
71 A's followed by anything at all open the same account.

So those logins are **refused**, indistinguishable from a wrong password, and a `Log.warn` with
`password.legacy_secret_too_long` tells you the accounts exist. Those people have to reset their
password. Count them before you deploy:

```sql
SELECT count(*) FROM users WHERE length(password_digest) > 0 AND password_scheme = 'legacy';
```

— then check the ones that matter, or send that group a reset link in advance.

### 3. Sessions, adopted once

```crystal
# Built first and then passed to `use`. Kemal's `use` is a macro, so a block written after
# `use Handler.new(...)` attaches to `use` and the constructor complains it got none.
LEGACY = KemalIdentity::Kemal::LegacySessionHandler.new(clear_cookie: "kemal_sessid") do |env|
  Kemal::Session.get(env).try(&.string?("user_id"))
end

use KemalIdentity::Kemal::ErrorHandler.new
use KemalIdentity::Kemal::AuthenticationHandler.new
use LEGACY
use KemalIdentity::Kemal::CSRFHandler.new
```

Nobody is signed out by the deployment that introduces this shard, and nobody logs in twice.

The block returns **a subject and nothing else** — not a principal, not a timestamp, and above
all not a token. Whatever signed or keyed the old session stays in the old system and dies with
it. Reading the old cookie is your job because only you know what wrote it.

The adopted session is `AssuranceLevel::Remembered`: the old cookie proves somebody
authenticated at *some* point, to a system this one cannot inspect. So `require_fresh!` still
forces a real login before anything sensitive, which is what you want from a credential you are
retiring.

It runs only when the session cookie, a bearer token and remember-me have all found nothing, so
a live session is never replaced. Delete the `use` line when the grace period is over; that is
the moment the old sessions stop working.

### 4. Authorization, separately

Do not couple the two migrations in one deployment. See [Authorization](#authorization) — it is
its own contract, and it reads roles from wherever you point it.

### Two things that are not migrations

**Accepting long-lived legacy JWTs indefinitely** is permanent security debt with a deprecation
notice attached. **Forcing a global password reset** to change hashing algorithms is a support
burden that lazy rehash exists to make unnecessary.

## Testing an adapter you wrote

If you implement any of this shard's contracts — a Redis session store, a repository over your
existing `users` table, a rate limiter over a shared store — the doubles and the shared contract
specs are published for you:

```crystal
require "kemal_identity/testing"            # the in-memory doubles, fixtures, assertions
require "kemal_identity/testing/contracts"  # the shared contract specs

it_behaves_like_a_session_repository do |accounts|
  MyRedisSessionRepository.new(redis, KemalIdentity::Testing::MemoryAccountRepository.new(accounts))
end
```

Everything is `KemalIdentity::Testing`: an in-memory implementation of every repository contract,
`TestClock` (moves only when you move it), `DeterministicRandom`, a fast hasher for specs that do
not test hashing, and the assertion helpers this shard's own suite uses.

**Requiring `kemal_identity` does not compile any of it.** Verified against a built binary: a
production consumer has zero `Spec::` and zero `KemalIdentity::Testing` symbols.

Two limits are worth knowing before trusting a green contract run:

- **Concurrency is exercised with fibers in one process.** A store shared between *processes* can
  pass every example and still lose updates — measured, and recorded under OPS-01 in
  `blueprints/0025-maturity-validation-results.md`, where a limiter passed all twelve examples
  while allowing 2.2× its global limit across six processes. Test that separately.
- **`it_behaves_like_an_account_repository` requires multi-tenant behaviour.** Three of its
  examples cover tenant scoping, so a single-tenant adapter over an existing `users` table with no
  tenant column cannot pass them. The rest of the contract still applies.

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

The test doubles and shared contracts live in `src/kemal_identity/testing`, not in `spec/`,
because they are published API — see `## Testing an adapter you wrote` above.

### Releasing

A git tag and a GitHub release are different objects, and pushing the first does not create
the second. `.github/workflows/release.yml` closes that gap: pushing a `v*` tag publishes the
release with notes taken from `CHANGELOG.md`.

```bash
# 1. Bump both, in the same commit as the changelog entry.
#    shard.yml            version: 0.6.0
#    src/kemal_identity/version.cr   VERSION = "0.6.0"
# 2. Add the `## v0.6.0 — YYYY-MM-DD` section to CHANGELOG.md.
git commit -am "Release v0.6.0 with ..."
git push origin main

git tag -a v0.6.0 -m "v0.6.0 — ..."
git push origin v0.6.0     # this is what publishes the release
```

The workflow refuses to publish if the tag disagrees with `shard.yml` or `VERSION`, or if the
changelog has no section for it. A tag saying `v0.6.0` on a tree whose `shard.yml` still says
`0.5.0` is a release nobody can resolve correctly, and it is an easy mistake to make when the
bump and the tag are two separate commands.

## Example

`examples/browser_session/` is a complete first-party browser application — log in, be
remembered, step up, reset a forgotten password, confirm an address, log out — wired with every
handler in the right order. CI compiles it on every matrix entry, because an example that has
drifted from the API is worse than no example.

It uses SQLite and creates its own schema, so it runs with no setup at all:

```bash
crystal run examples/browser_session/app.cr
# seeded ada@example.com / correct horse battery
# listening on http://localhost:3000 — emails are printed here
```

The `Notifier` prints reset and confirmation links to stdout instead of sending them, which is
the whole of what a notifier does: the shard decides *what* to say, the application decides
*how*. Swapping the four repositories to PostgreSQL is a marked block near the top and changes
nothing else — that is what the shared contract specs are for.

## License

MIT.
