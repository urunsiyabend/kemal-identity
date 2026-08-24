# 04 — Kemal integration

## The constraint that shapes this whole document

Kemal's own changelog documents four defects that each cause an authentication guard to
silently not run. **They are fixed in Kemal 1.13.0 (released 2026-08-24). They are live in
1.10.0 through 1.12.0, and 1.10.0 is the supported floor** — so this section describes the
behaviour a consumer may still be running on, and the reason for the design, not the newest
release. See `blueprints/0003-kemal-1.13.0-fixes-the-filter-defects.md`.

1. `HEAD` served by a `GET` route did not run `before_get` filters
   (GHSA-jf9q-62h3-924j). `HEAD /admin/users` skipped the authentication filter while
   still executing the protected handler and returning its headers, leaving no audit
   record. This is Kemal's own documented auth pattern.
2. The same defect in the sibling API: `only ["/admin/*"]` — the `GET` default — did not
   match `HEAD`, so middleware scoped that way never ran on `HEAD` requests.
3. `Kemal::Router` filters whose path ends in `/*` were registered nowhere at all. A
   router-scoped `before_get "/admin/*"` used for authentication never ran, for any method.
4. Router filters were registered once per route rather than once per path, so a filter on
   a path carrying both `GET` and `POST` ran twice per request — double-counting rate
   limits.

Since **1.10.0** is the floor, **this shard must not build authentication on `only`,
`exclude`, `before_get`, or router-scoped filters.** A library whose security depends on the
consumer having upgraded has a silent failure mode. Two rules follow:

- `AuthenticationHandler` is registered globally with no `only`/`exclude` scoping, and
  populates `env.auth` for every request regardless of method.
- Any path-scoped guard performs its own prefix matching inside `call`, dispatching on the
  request path only, never on the method.

A fifth defect in the same set: uploaded temp files were only cleaned up if the request
reached the route handler, so a `before` filter that `halt`s — again, the documented auth
pattern — leaked them permanently. On 1.10.0 – 1.12.0, a guard that rejects a multipart
upload leaks its temp files. 1.13.0 moves cleanup into `Kemal::InitHandler`, which heads the
chain, so it runs however the request ends. The README says so, and the guard should reject
before anything touches `env.params` where it can.

That last fix carries a placement rule: a handler registered ahead of `InitHandler` with
`use handler, 0` owns temp-file cleanup for uploads it parses itself, because position 0
opts out of everything `InitHandler` does. **`AuthenticationHandler` is therefore never
registered at position 0.** It has no business owning that.

The next Kemal release landed, and the constraint did relax — for consumers who upgrade.
The "guard does its own method-agnostic matching" design stays: it is safe either way, it
costs nothing, and it is what makes new methods safe by default. 1.13.0 also adds the HTTP
QUERY method (RFC 10008), which did not exist when these rules were written — a guard
dispatching on an allowlist of methods would have silently not covered it.

## Handler chain

Order matters and is not obvious, so it gets its own section in the README.

```
Kemal::InitHandler
  ↓
Kemal::LogHandler / ExceptionHandler
  ↓
[kemal-session handler]                       ← if the app uses it, before authn
  ↓
KemalIdentity::AuthenticationHandler             ← populates env.auth; never rejects
  ↓
KemalIdentity::CSRFHandler                       ← needs the principal, so it comes after
  ↓
[application middleware]
  ↓
KemalIdentity::PathGuard (optional, path-scoped) ← rejects
  ↓
Kemal::RouteHandler
```

```crystal
use KemalIdentity::Kemal::ErrorHandler.new           # outermost: catches what guards raise
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
```

`ErrorHandler` has to sit outside anything that raises, which means outside `PathGuard` and
outside `Kemal::RouteHandler` — a route calling `env.auth.require!` raises from inside the
route handler. Registering it immediately before `AuthenticationHandler` satisfies that.

**Never register an authentication handler at position `0`.** `use handler, 0` places it ahead
of `Kemal::InitHandler`, and since Kemal 1.13.0 that position takes over temporary-file
cleanup for uploads the handler parses itself.

`AuthenticationHandler` resolving but never rejecting is deliberate. Rejection is the
guard's job. This is what lets a public page render differently for a signed-in user, and
what stops every stale cookie from producing a 401 on the homepage.

`AuthenticationHandler` should also skip work entirely for requests carrying no
credential — the common case for static assets — so the cost on an anonymous request is one
cookie-map lookup and nothing else.

## Guarding routes

Route-level, which is the recommended form and immune to all four defects above:

```crystal
get "/dashboard" do |env|
  principal = env.auth.require!
  render_dashboard(principal)
end

post "/account/email" do |env|
  env.auth.require_fresh!(within: 5.minutes)
  update_email(env)
end
```

Path-scoped, when a whole subtree needs the same rule:

```crystal
use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
```

`PathGuard` matches on `env.request.path` for **every** method. It does not use `only`.

`require!` raises `NotAuthenticatedError`; `require_fresh!` raises
`FreshAuthenticationRequiredError`. `KemalIdentity::Kemal::ErrorHandler` maps them to 401 and
403 respectively, content-negotiating between a redirect to the login page and a JSON body.
Applications can register their own `error` handlers for these classes instead.

## Routes: services first, router optional

The shard exposes services. It also ships a mountable `Kemal::Router` for applications that
want the default flows, which they can choose not to mount.

```crystal
auth = KemalIdentity::Kemal.routes   # returns a Kemal::Router
mount "/auth", auth
```

Applications that want their own URLs, templates or response shapes call the services
directly:

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
    # `env.auth`, not `sessions`: a core service taking an HTTP::Server::Context would put
    # HTTP into the layer that must not know HTTP exists. This also revokes whatever session
    # the client presented, which is the fixation defence. See
    # `blueprints/0008-kemal-layer-owns-the-http-seam.md`.
    env.auth.start!(result.principal)
    env.redirect "/dashboard"
  in KemalIdentity::Failed
    # One message for every failure reason. Never branch the response on `reason`.
    render_login_form(error: "Invalid email or password")
  in KemalIdentity::Anonymous
    render_login_form(error: "Invalid email or password")
  end
end
```

Two things this example is showing on purpose. There is no `not_nil!` — the union makes the
principal available only in the branch where it exists. And the response does not vary with
`reason`, because `DisabledAccount` and `InvalidCredential` producing different messages is
an enumeration oracle. `reason` is for the audit log.

## Interop with kemal-session

The two are complementary and the boundary must stay sharp:

- **kemal-session** — flash messages, wizard state, CSRF token storage. Application state.
- **kemal_identity** — its own opaque token, digest, expiry, revocation, security metadata.

Consequences:

1. Never serialize a `User` into `env.session`. Never copy roles, email, or tenant
   membership into a long-lived cookie or session — mutable authorization state in a
   long-lived container means revocation does not take effect.
2. The auth session's lifetime is independent of the application session's.
3. `KemalIdentity::Kemal::CSRFHandler` can delegate token storage to kemal-session when it is
   present, or use its own double-submit implementation when it is not.

An optional `KemalSessionAdapter` can read a legacy `kemal-session` login for migration
purposes. It is a `RequestAuthenticator` that extracts a subject and nothing else — see
`docs/06-roadmap.md` for the migration path.

## Concurrency

Crystal 1.21 makes execution contexts the default concurrency model, which changes what
"CPU-bound work in a request fiber" costs.

Bcrypt verification at cost 12 is tens of milliseconds of pure CPU. Run in the request
fiber, it occupies a scheduler thread for that whole time; enough concurrent logins and
unrelated requests queue behind them. The naive implementation is therefore a latency
problem for the entire application, not just for logins.

Run password hashing and verification in a dedicated execution context sized independently
of the main one. This is one of the few places where the shard can be meaningfully better
on Crystal than a direct port of a Ruby or Node design would be, and it should be treated
as a v0.1 concern rather than a later optimisation — retrofitting it changes the `Hasher`
call path.

The benchmark that gates release measures application-wide p95/p99 under 1, 10, 50 and 100
concurrent logins, not `hashes/sec` in isolation. The stdlib's own bcrypt documentation
makes the same two points: benchmark the cost on the production machine rather than a
laptop, and rate-limit the endpoints that verify hashes, because they are an easy DoS
target.

## Testing Kemal integration

`spec-kemal` for HTTP-level specs. Every guard gets a spec that issues the request with
`GET`, `HEAD`, `POST`, `DELETE` and `QUERY`, asserting the guard runs for all of them.

Given defects 1 and 2 above, `HEAD` is not an edge case here — it is the regression, and it
stays in the set now that upstream has fixed it, because the floor has not. `QUERY` is in
the set because it is new in 1.13.0, reaches routes, and carries a body: exactly the kind of
addition a method-allowlisting guard misses. QUERY is safe and idempotent per RFC 10008, so
it is *not* in the CSRF-protected set — a spec asserts that its body does not get it
mistaken for a mutation.
