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

The same rule applies one level up: a request that presents a bearer token is never resolved
from a session cookie afterwards, even when the token is rejected. A client that sent a token
is asking to be authenticated by it.

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
  in KemalIdentity::OIDC::Identity
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

### `(issuer, subject)` is the identity. The email is not.

```crystal
def account_for(identity : KemalIdentity::OIDC::Identity)
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
| `authentication.failed` | it did not — carries `reason`, including `RateLimited` |
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

`migrations/postgres/` holds `auth_sessions`, `auth_action_tokens`, `auth_remember_tokens`,
`auth_api_tokens`, `auth_mfa_factors`, `auth_mfa_recovery_codes`, `auth_external_identities`,
and the optional reference `auth_accounts`. `migrations/sqlite/` holds the same eight in
SQLite's dialect. If you already have a `users` table with a password digest, you
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
