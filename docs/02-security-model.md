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
one), account disable, and MFA recovery. `bump_auth_version` provides the same effect
without enumerating rows and is the belt to revocation's braces.

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

## Step-up

```crystal
env.auth.require_fresh!(within: 5.minutes)
```

The window is the caller's choice (decision D5). Operations that must call it: changing
email, changing password, disabling MFA, generating or revoking API credentials, and any
destructive account action.

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
