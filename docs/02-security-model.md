# 02 — Security model

Every rule here has a corresponding spec in `spec/security/`. If a rule has no spec, it is
not enforced and should be treated as aspirational until one exists.

## Threat model

What this shard defends against, and what it explicitly does not.

**In scope.** Credential stuffing and password spraying (rate limiting, generic responses).
Session hijacking via XSS (`HttpOnly`). Session fixation (rotation on login). Session
theft via a leaked database backup (digest-only storage). CSRF on cookie-authenticated
mutations. Account enumeration through responses *and* through timing. Replay of a consumed
reset or remember token. Privilege escalation through a stale session after a password
change or account disable.

**Out of scope, stated so nobody assumes otherwise.** XSS in the host application — the
shard cannot fix it, only limit the blast radius. Network-level attacks; HTTPS is assumed
and is the operator's responsibility. Malicious first-party code. Physical access to the
session store. Offline cracking of a modern password digest, beyond choosing a sound
algorithm and cost.

## Session model

The browser receives a high-entropy random secret and nothing else. Everything meaningful
lives server-side.

```
Cookie: __Host-kemal_identity=<32 bytes, base64url, from Random::Secure>
   │
   ▼  fixed-length + charset validation, before any I/O
   ▼  SHA-256
   ▼
SessionRepository#find_by_digest   ← single query, returns account status too
   │
   ├─ revoked_at present?             → Failed(Revoked)
   ├─ now >= absolute_expires_at?     → Failed(Expired)
   ├─ now >= idle_expires_at?         → Failed(Expired)
   ├─ account_disabled_at present?    → Failed(DisabledAccount)
   ├─ auth_version mismatch?          → Failed(StaleAuthVersion)
   └─ ok
        ├─ maybe touch (throttled)
        └─ Authenticated(Principal)
```

Validate the cookie's shape **before** hashing or querying. A caller who sends a 2 MB
cookie value should be rejected by a length check, not by the database.

Expiry is `>=`, not `>`: a session is expired *at* its deadline. That makes this agree with
`delete_expired`, which removes rows at or before the instant it is given — if they
disagreed, the sweeper could delete a session this check still called live, which would make
the sweeper a correctness dependency.

Expiry is evaluated here, on every read. This is a direct lesson from kemal-session
issue #116, where `timeout` only marked a session for deletion at the next GC pass, so a
session past its timeout stayed valid until the sweeper happened to run — and a read could
refresh the access time before any expiry check, reviving it. The issue is now fixed
upstream, but the design rule stands: correctness on read, sweeping for disk only.

### `last_seen_at` and the write-per-request problem

Idle expiry requires moving `idle_expires_at` forward as the user stays active, which
naively means an `UPDATE` on every authenticated request. That turns a read-only hot path
into a write-heavy one and is the single biggest performance trap in this design.

Throttle it: only write when `now - last_seen_at > config.session.touch_interval`
(default 60 s). The cost is that idle expiry is accurate only to within one
`touch_interval`, which must be documented as part of the contract rather than left as an
implementation accident.

### Rotation and revocation

Rotate the session — new secret, new row, old row revoked — on:

- successful login (session fixation defence)
- assurance level increase (`Remembered` → `Password`, `Password` → `MFA`)
- password change

Revoke *all* of an account's sessions on: password change (except optionally the current
one), account disable, MFA recovery, and **a change to the account's tenant**.
`bump_auth_version` provides the same effect without enumerating rows and is the belt to
revocation's braces.

The tenant belongs on that list because it is the one authorization input a session copies.
Roles and memberships are read on every decision, and an `Authz::Cache` bounds its own
staleness to at most a minute; the tenant is stamped onto the session row at login and
`Sessions::Service#resolve` rebuilds the principal from that row. So confining an account to a
tenant — or moving it to another one — has no effect on a session that already exists, for as
long as that session lives, and `Authz::RBAC` will keep answering the *old* binding's
questions. Measured: `blueprints/0025`, AUT-06.

That is a deliberate trade — `Sessions::Lookup` does not carry the account's tenant, so the
hot path does not read a second column for a value that changes approximately never — and it
is only safe if the application knows to revoke. Whichever code path writes the new tenant
calls `bump_auth_version` or `revoke_all` beside it.

## Cookie policy

| Attribute | Default | Note |
|---|---|---|
| Name | `__Host-kemal_identity` | see caveat below |
| `Secure` | `true` | boot fails if false, unless `allow_insecure: true` is passed explicitly — the shard does not guess at what "production" means; see `blueprints/0006-session-cookie-and-expiry-boundaries.md` |
| `HttpOnly` | `true` | |
| `SameSite` | `Lax` | `Strict` breaks return-from-OAuth navigation; `None` requires an explicit justification and `Secure` |
| `Path` | `/` | required by `__Host-` |
| `Domain` | unset | required by `__Host-` |
| Value | 32 bytes from `Random::Secure`, base64url | |

**The `__Host-` caveat, which must be in the README and not just here.** The prefix forbids
a `Domain` attribute. That means the cookie is scoped to exactly one host, so
`app.example.com` and `api.example.com` cannot share a session. This is the right default —
it prevents a compromised sibling subdomain from setting a session cookie for the parent —
but for an app that spans subdomains it is a wall people hit without understanding why. The
config must offer a documented, explicit way out (a non-prefixed name plus an explicit
`domain`), and the validator must refuse the incoherent middle ground of a `__Host-` name
with a domain set.

Crystal's `HTTP::Cookie` validates security prefixes, so an incoherent configuration can be
made to fail at boot rather than silently produce a cookie the browser discards.

## Timing and enumeration

Both matter, and the shard gets the second one wrong by default unless it is explicit.

Generic responses are the easy half: identical status, body and headers for unknown login
and wrong password, on login and on password reset request alike.

Timing is the half that is usually missed. If no account matches, the naive implementation
returns before doing any bcrypt work, and the response comes back a hundred-odd
milliseconds early — a reliable oracle regardless of how generic the body is. Therefore:

```crystal
account = accounts.find_by_login(normalized, tenant_id)
digest  = account.try(&.password_digest) || hasher.dummy_digest
ok      = hasher.verify(submitted, digest)
return Failed.new(FailureReason::InvalidCredential) if account.nil? || !ok
```

`dummy_digest` is a digest of a fixed string at the hasher's current parameters, computed
once at boot. The spec for this asserts that the two paths are within a tolerance of each
other, not that they are identical.

The same discipline applies to password reset: the response and its timing must not differ
between a known and an unknown address.

## Login normalization

`normalized_login` is `login.strip.downcase` under Unicode case folding, stored at write
time. Store it; do not compute it in the `WHERE` clause, or the index goes unused and the
uniqueness constraint stops agreeing with the lookup.

Unicode is a real hazard here: two visually identical logins can normalize differently, and
the reverse. v0.1 uses simple case folding and documents the limitation. It does not attempt
confusable detection.

## CSRF

Required for every state-changing request. Implemented **inverted** from that list:
everything is protected except `GET`, `HEAD`, `OPTIONS`, `TRACE` and `QUERY`. A denylist of
`POST`/`PUT`/`PATCH`/`DELETE` leaves every method nobody thought of unprotected — `PROPFIND`
mutates in WebDAV, and HTTP QUERY did not exist when this was written. `QUERY` is on the safe
list because RFC 10008 defines it as safe and idempotent, however much its request body looks
like a mutation.

Protection does not depend on the request being authenticated, because the login form is not.
See `blueprints/0009-csrf-token-scheme.md` for the token scheme: an HMAC over the session id
(or, for an anonymous request, over a `__Host-` anchor cookie), masked per issue so a constant
token cannot be extracted by a compression oracle. Plain double-submit is *not* used — it
cannot satisfy "a token from another session is rejected", since anyone able to set the cookie
can set the field to match.

`SameSite=Lax` is defence in depth, not a replacement for a token — it is a browser-side
control with inconsistent behaviour across clients and does nothing for a request the
browser considers same-site.

**Login CSRF is in scope**, and is the case most implementations miss. Without a token on
the login form, an attacker can log a victim into the *attacker's* account and then observe
whatever the victim does under it. The login route is protected like any other mutation.

An endpoint that accepts a session cookie is subject to CSRF regardless of whether it also
accepts a bearer token, and regardless of it being labelled an "API". Content type is not a
defence. When bearer-token authentication lands in v0.4, the exemption applies only to
endpoints that accept *nothing but* an `Authorization` header.

## Password policy

Separate from hashing, and separate from the `Hasher` contract.

Ship: a minimum length (12 by default), a maximum length that rejects rather than truncates
(bcrypt's is 71 **bytes**, not characters — accepting a longer one and silently cutting it
means two different passwords open the same account), and a hook for a breached-password
check that does nothing by default.

The minimum counts characters and the maximum counts bytes, because they measure different
things: what a person chose to type, versus what the algorithm can represent. See
`blueprints/0007-audit-events-omit-the-login.md`.

Do not ship: composition rules. "One uppercase, one lowercase, one digit, one symbol" is
not supported by current guidance, and hard-coding it into a library forces it on every
consumer. Compare `aloli-crystal/kemal-auth`, which documents exactly such a 12-character
composition rule as a feature — that is a policy decision an application should own, not
inherit from its auth library.

Mandatory periodic rotation is likewise not implemented and not encouraged.

## Token discipline

Every non-session token — remember-me, password reset, confirmation, invitation — follows
the same rules:

1. Generated from `Random::Secure`, at least 32 bytes.
2. Stored as a SHA-256 digest. Never stored raw, never logged, never included in an error
   message, never put in a URL that ends up in a Referer header if avoidable.
3. Short-lived, with an explicit `expires_at` checked on read.
4. Single-use, consumed **atomically**. Two concurrent requests must not both succeed. In
   SQL this means `UPDATE ... SET used_at = $now WHERE id = $id AND used_at IS NULL` and
   checking the affected row count — not a read-then-write.
5. Consumed on use even when the surrounding operation then fails.

### Remember-me

Not "an ordinary session with a 30-day expiry". That is a bearer secret sitting in a browser
for a month with no detection if it is stolen.

```
remember cookie
   │
   ▼ digest lookup + atomic consume
   │
   ├── already consumed → replay → revoke the whole token family, notify
   │
   └── valid
        ├── issue a fresh session at assurance = Remembered
        └── rotate: issue a new remember token, same family
```

The family revocation on replay is what makes theft detectable: either the thief or the
legitimate user will present the already-consumed token, and both sessions die.

A session restored this way sits at `AssuranceLevel::Remembered`, below `Password`. Any
sensitive operation calls `require_fresh!` and forces a real re-authentication.

### Rotating a personal access token

A deploy key has to be replaced without breaking a fleet in the seconds — or hours — between
distributing the new secret and retiring the old one. Issue the replacement, then give the old
credential a deadline:

```crystal
replacement = KemalIdentity.app.api!.issue(account, "deploy-key (rotated)", scopes: old.scopes)
KemalIdentity.app.api!.expire(old.id, account.id, at: Time.utc + 15.minutes)
```

Both work until the deadline; after it the old one fails as `Expired` **on the authentication
path**, so the window closes whether or not a sweeper has run. `expire` never lengthens a
token's life — a rotation that could extend the credential it replaces is not a rotation, and a
management screen that could push a deadline out is a way to keep a compromised credential
alive.

Each half is separately auditable: two ids in the trail, and `last_used_at` per token, which is
what answers "has the fleet picked up the new key" without asking the fleet.

There is deliberately no token *family*. `revoke_all` is account-scoped and atomic; retiring an
arbitrary set of tokens as one operation is not expressible through the shipped adapters, and an
application that needs it implements `ApiTokens::Repository` over its own table, where it owns
the transaction. Measured in `blueprints/0025`, TOK-08.

### Token lifetime policy

An enterprise requires every personal token to expire within thirty days and forbids unbounded
ones. The deployment next door permits a non-expiring deploy key. Both are correct, so the rule
is injectable and **absent by default**:

```crystal
KemalIdentity.configure(
  # ...
  api_token_lifetime: KemalIdentity::ApiTokens::LifetimePolicy.new(
    maximum: 30.days, default: 7.days
  ),
)
```

Issuance then raises `ApiTokens::PolicyError` — before the secret is generated and before
anything is written — for an unbounded token and for one that would outlive the maximum. The
error carries the violation and the limit, and both are safe to show: somebody creating a
credential is not somebody proving they hold one, so there is no account to enumerate.

**A policy is a rule about creation, and tightening it does not shorten the tokens that already
exist.** It is not consulted on the authentication path either — a policy that could refuse
while authenticating would turn a configuration change into an outage for every client holding
an older token. An organisation that must apply a new limit retroactively walks its tokens and
calls `expire` on each, which is the pairing above and cannot lengthen anything by accident.

## Step-up

```crystal
env.auth.require_fresh!(within: 5.minutes)
```

The window is the caller's choice (decision D5). Operations that must call it: changing
email, changing password, disabling MFA, generating or revoking API credentials, and any
destructive account action.

Strength and recency are separate axes and both are asked for separately: `require_fresh!` is
recency, `require_assurance!` and `Permission#minimum_assurance` are strength. An API token is
**never** fresh however recent its authentication is — it sits below `Password`, and an
automated client cannot re-authenticate interactively, so a destructive account action should
not be reachable with one in the first place.

A bearer-credentialled request that is refused for either reason gets RFC 9470's
`insufficient_user_authentication`, plus `max_age` when it was recency that failed — so a client
can tell "type your password again" from "produce a second factor". `blueprints/0028`.

### Recovery is not a second factor

A recovery code is a printed or stored list. Spending one proves possession of a piece of paper,
not of a device, so it lands at `AssuranceLevel::Recovery` — above `Password`, below `MFA`:

```crystal
case KemalIdentity.app.mfa!.redeem_recovery_code(subject, code, except_session_id: current)
in KemalIdentity::MFA::Verified then env.auth.recovery_verified!   # not mfa_verified!
in KemalIdentity::Failed        then render_the_same_error_for_every_reason
end
```

A permission declared `minimum_assurance: MFA` therefore stays shut after a recovery, which is
the point: recovery restores access, it does not unlock the sharpest action in the application.
Prompt for re-enrolment immediately — a session sitting at `Recovery` is a half-finished
recovery rather than a normal signed-in state.

Redeeming a code also revokes the account's other sessions (`except_session_id` spares the one
doing the recovery), because "lost" and "taken" look identical from the server. Recovery is
rate-limited on the same per-account key as a second-factor check, and audited at **warning**
level with the number of codes left.

Removing the account's **last** confirmed factor voids its recovery codes, for the reason
`MFA::Service#disable` already did: a list that survives into a later re-enrolment is a full
bypass of the new factor. `MFA::Service#remove(factor_id, account_id)` refuses to remove a last
factor unless the caller passes `allow_last: true`, so "remove this device" cannot silently mean
"turn MFA off". Measured in `blueprints/0025`, MFA-01 and MFA-04.

## Authorization rules an application writes itself

`Authz::Authorizer` is a seam: the shipped `Authz::RBAC` answers *does this account hold the
permission*, and an application that also has per-object rules wraps it. Two things about that
wrapper are measured in `blueprints/0025-maturity-validation-results.md` (AUT-01) and neither is
obvious.

### A rule that cannot read its resource must deny

`Authz::Context#resource` is an `Authorizable`, so a rule reaching for its own type downcasts:

```crystal
invoice = context.resource.as?(Invoice)
```

`as?` yields `nil` for anything that is not an `Invoice` — including an `Authz::Resource` carrying
only a type and an id, which is what a route that did not load the row passes. Written the obvious
way, the rule then **fails open**:

```crystal
return decision if invoice.nil?      # WRONG: falls through to the permissive branch
```

Measured: a resource with no owner attribute was permitted by a rule whose entire purpose was to
require ownership. The shard cannot make a consumer's downcast fail closed — only the consumer's
rule can — so write the other branch:

```crystal
# The rule needs an Invoice to have an opinion. Anything else is a route that did not load one,
# and "I could not check" is not "yes".
return Authz::Forbidden.policy(permission, code: "no_invoice_in_context") if invoice.nil?
```

The same holds for attributes: `context["device"]` is nilable, and a missing value is a question
nobody answered.

### The N+1 on a list endpoint, and what removing it costs

A route applying one policy per row queries the authz store per row. Measured over a hundred
invoices, with the store wrapped to count reads:

| Configuration | Policy evaluations | Store reads |
|---|---|---|
| `Authz::Cache` configured | 100 | **1** |
| Cache left at its default | 100 | **100** |

`Authz::Cache` is **off by default**, and that is deliberate: its TTL *is* the revocation delay
(`blueprints/0018`). A grant removed from the store keeps deciding requests until the entry
expires — five seconds by default, one minute at `MAX_TTL`.

So the choice on a list endpoint is explicit rather than tuned away: either a hundred reads per
page, or revocation that lags by the TTL. Pick the TTL against how fast a removed grant must stop
working, not against the page size. A page that authorises a hundred rows is also worth a second
look on its own terms — one `authorize!` for *reading the list* plus per-row filtering the
application already does in SQL is often the same answer with one query.

## Logging

Never log: passwords, raw tokens of any kind, session cookies, `Authorization` headers,
password digests, or `Set-Cookie` values.

Do log, as structured events: login success and failure with reason, logout, session
rotation, bulk revocation, rate-limit denials, and replay detection. Events identify the
account by its id and deliberately **never carry the login that was typed** — an address in a
log line outlives the request and is read by people who never authenticated to anything, and
a failed attempt against an unknown login would be recording an address belonging to somebody
with no account at all. See `blueprints/0007-audit-events-omit-the-login.md`. These are the audit
trail; a spec asserts that a login attempt produces an event containing no secret material.

## Metrics and tracing

Every seam this shard has is a contract, so instrumentation is a **decorator** rather than a
patch: wrap a repository to time the database, wrap `Passwords::Hasher` to time hashing, wrap
`RateLimiter` to count denials, and pass a `fetcher:` to `JWT::JWKS` or an `exchanger:` to
`OIDC::Client` to time the identity provider. Nothing needs reopening and no private method is
involved. Measured end to end in `blueprints/0025`, OPS-03.

Two rules about what those wrappers may record.

**The label is the outcome, never the identity.** `FailureReason` and `Authz::DenialReason` are
small enums and make excellent metric labels; `subject`, the login, a token id, a tenant id and a
rate-limit key are unbounded and must not be. A metric labelled by account id is a time series
per account, which is both an operational problem and a way to enumerate your users from a
dashboard. Correlation belongs in the event trail, where it is already, and the identity is what
joins the two.

**A duration is not a security decision.** Time wrappers with the wall clock — the injected
`Clock` is for expiry and freshness, and a test clock reports every operation as instantaneous.

Cache hits have no hook: `Authz::Cache` exposes `#size` and nothing else, so a hit rate is
`decisions − repository reads`, both of which the application already counts. That is deliberate
rather than missing — a counter on the cache would be a second thing to keep correct — but it
does mean the subtraction is yours to do.

**Check that the event sink is connected**, after your `Log` setup rather than before it:

```crystal
Log.setup_from_env
KemalIdentity.event_sink = SiemSink.new

abort "security events are not reaching the sink" unless KemalIdentity.event_sink_delivering?
```

`::Log.setup` replaces every binding, so wiring the sink first leaves no sink, with nothing
raised and `EventBridge#failures` at zero — an empty trail rather than a failing one.
`blueprints/0027` decision 6.

## Release blocking checks

| Check | Level |
|---|---|
| Secrets redacted from logs and errors | required |
| `Secure` + `HttpOnly` + `SameSite` on the session cookie | required |
| Session rotation on login | required |
| Idle and absolute expiry evaluated on read, not by a sweeper | required |
| Digest-only storage for every token | required |
| Single-use tokens consumed atomically | required |
| Generic responses on login and reset | required |
| Constant-ish timing for unknown login vs wrong password | required |
| CSRF on cookie-authenticated mutations, including login | required |
| Rate limiting on the password verification path | required — the contract and a usable `FixedWindowRateLimiter` ship, but `NullRateLimiter` is the **default**, so an application must opt in. Quota is consumed before the lookup and before hashing. See `blueprints/0010-rate-limiting.md`. |
| Session revocation on account disable and password change | required |
| Explicit rejection of over-length passwords, never truncation | required |
| `__Host-` prefix and its subdomain consequence documented | required |
| Boot-time validation of the cookie configuration | required |
| Security events reach a structured audit log | recommended |
