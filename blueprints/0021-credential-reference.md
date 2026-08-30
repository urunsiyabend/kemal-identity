# 0021 — The credential that proved the request

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

Ali holds two personal access tokens. One is for reading reports, one is for publishing
releases. He calls `POST /releases` with the reporting token, and the request succeeds.

It succeeds because the token's identity is discarded at the moment it is established.
`ApiTokens::Service#authenticate` finds the row, checks its shape, its revocation, its expiry
and the account's status, and then builds this:

```crystal
record = lookup.token          # record.id == "tok_reporting", right here

Authenticated.new(
  Principal.new(
    subject: record.account_id,
    assurance: AssuranceLevel::ApiToken,
    authenticated_at: now,
    session_id: nil,
  )
)
```

`record.id` is never read. Both of Ali's tokens therefore produce a `Principal` that is
byte-for-byte the same, and the only question `env.auth.authorize!("releases:write")` can ask
is whether *Ali* may publish releases. He may. The reporting token publishes a release.

An application cannot fix this from outside. It can re-read the `Authorization` header and
query the token repository a second time on every authenticated request; it can copy the whole
validation path into an authenticator of its own and risk omitting one of the four checks; or
it can smuggle the token into `Principal#tenant_id`. `blueprints/maturity-validation-scenarios.md`
names all three as failure signals, and the scenarios that depend on this — TOK-01 and AUT-03,
both very high — are targeted at M4 before the freeze.

### `Principal` already does this, for exactly one credential

```crystal
# The session this principal was resolved from, when there is one. Present so that
# "log out everywhere else" can spare the current session.
getter session_id : String?
```

That is a credential reference. It is present for the same reason this document exists: some
decisions need to know *which* credential proved the request, not only who it belongs to. The
field simply stops at sessions, so `logout!` and `csrf_anchor` work and per-token policy does
not.

### What other libraries do

Four mature implementations, and they agree on more than they disagree on.

- **Django REST Framework** returns a two-tuple from `authenticate()`. `request.user` is the
  identity, `request.auth` is "any additional authentication information" — for
  `TokenAuthentication` it is the `Token` model instance itself.
- **Spring Security** puts the identity inside an `Authentication` container alongside
  `getAuthorities()` and `getDetails()`. For a bearer JWT the principal *is* the decoded token,
  scopes become `SCOPE_`-prefixed authorities, and the credential kind is recorded as an
  authority of its own.
- **Laravel Sanctum** hangs it off the identity: `$user->currentAccessToken()` and
  `$user->tokenCan('server:update')`.
- **ASP.NET Core** records the authenticating scheme on the identity as
  `ClaimsIdentity.AuthenticationType`.

Three points of consensus, all of which this design adopts:

1. **The credential reference reaches the application.** None of the four makes the consumer
   re-read the header or re-query the store.
2. **Effective permission is an intersection.** Sanctum's documentation gives the shape
   directly: `$request->user()->id === $server->user_id && $request->user()->tokenCan('server:update')`.
   The token never grants what the account lacks, and the account never escapes what the token
   restricts.
3. **A session is not denied for having no scopes.** Sanctum returns `true` from `tokenCan`
   for first-party session-authenticated requests, and says so deliberately: it is convenient
   to always be able to ask. Absence of scopes means *unrestricted*, not *nothing permitted*.

The one thing they do not agree on is where it hangs — a separate slot (DRF) or on the object
that flows through the application (Sanctum, ASP.NET, and in effect Spring).

## Decisions

### 1. `Principal` carries `credential : CredentialRef?`

```crystal
enum CredentialKind
  Session
  ApiToken
  Jwt
  Custom
end

# A safe reference to the credential that proved this request.
#
# Never the secret, never the digest, never a signature. This is what an audit line, a
# per-token policy and a "used by token X" screen need, and it is all they need.
struct CredentialRef
  getter kind : CredentialKind
  getter id : String?
  getter name : String?
  getter expires_at : Time?
  getter scopes : Array(String)?
end
```

On `Principal` rather than on `Authenticated`, for two reasons.

**`session_id` is already there.** Putting the token id somewhere else would keep one idea in
two homes, and the next reader would have to learn both.

**`Authorizer#decide` receives a `Principal` and nothing else.** Consensus point 2 — the
intersection — is the authorizer's job, so the authorizer has to see the credential. Placing it
on `Authenticated` would make TOK-01 and AUT-03 wait for the `Authorizer` signature change in
`blueprints/0020` decision 3. They are separate problems and they stay separable. It also keeps
the reference available wherever a `Principal` travels without an HTTP request — a background
job, a message consumer, the HTTP-07 case.

The cost is that `Principal` is a struct passed by value and now carries an embedded one. The
copy grows. This project measures rather than assumes, so the change ships with a number
against the authenticated-request path.

### 2. `session_id` becomes a derived reader

```crystal
def session_id : String?
  c = @credential
  c && c.kind.session? ? c.id : nil
end
```

Every existing caller — `logout!`, `start!`'s session-fixation defence, `csrf_anchor`,
`revoke_after_credential_change` — keeps working untouched. A `Remembered` credential does not
answer this, which is correct: a restored remember-me login mints a session and reports
`Session` from that point on.

### 3. `scopes` has three states and two of them must never be confused

| Value | Meaning |
|---|---|
| `nil` | no attenuation — a browser session, a remembered login, a token issued without scopes |
| `["reports:read"]` | attenuated to this set |
| `[] of String` | attenuated to nothing; valid, and denies everything |

`nil` and `[]` are the fail-open and fail-closed edges of the same field. Reading `nil` as
"empty set" locks out every session user; reading `[]` as "unset" hands an intentionally
powerless token the run of the application. The type keeps them apart and the contract spec
asserts both.

### 4. No wildcard scope

`*` is not a scope. Unrestricted is `nil`.

This follows `blueprints/0018` decision 2, where `Permission::PATTERN` refuses `*` at
construction because a wildcard grants permissions that do not exist yet. A wildcard *scope*
is the same hazard aimed at tokens: `["*"]` issued today silently covers every permission added
afterwards, and the catalogue names it as a TOK-01 failure signal. Sanctum offers `['*']`; this
shard does not, and the absence is deliberate rather than incomplete.

### 5. Nothing secret enters `CredentialRef`

No raw token, no digest, no signature, no JWT beyond its `jti`. `name` exists for display and
nothing reads it for a decision. `ApiTokens::Token` already redacts itself in `inspect`; this
struct has nothing to redact because it never holds the material in the first place.

### 6. The authorizer applies the account grant first, then the attenuation

```crystal
def decide(principal, permission, tenant_id = nil) : Decision
  # unchanged: unknown permission, cross-tenant, grants, assurance

  if cred = principal.credential
    if scopes = cred.scopes           # nil means unattenuated; skip
      unless scopes.includes?(permission)
        return Forbidden.new(permission, DenialReason::OutOfScope, tenant_id)
      end
    end
  end

  Permitted.new(permission, via, tenant_id)
end
```

The order is the security property. A token cannot introduce a permission the account does not
hold, because the grant check runs first and denies. An account cannot escape its token's
restriction, because the attenuation runs last and can only remove. Intersection, never union —
and the same code path serves a session, where `scopes` is `nil` and the second step is a no-op.

### 7. Both phases ship in v0.8

The change divides cleanly and both halves land together:

**The reference.** `CredentialRef` exists, the five `Principal.new` sites fill it, `env.auth`
exposes it, and audit lines carry it. No schema change. This alone closes TOK-03 and gives
OPS-02 its credential correlation.

**The scopes.** A scope column on `auth_api_tokens`, a scope argument on
`ApiTokens::Service#issue`, and decision 6's attenuation in `RBAC`. This closes TOK-01 and
AUT-03.

Only the first is strictly forced by the freeze — once `CredentialRef#scopes` exists, filling
it later is additive. They ship together anyway, because a scope field that nothing populates
is a contract nobody has exercised, and freezing an unexercised contract is how a field ends up
meaning something slightly different from what it says.

This reverses the v0.4 position that "scopes are deliberately absent: a token authenticates, it
does not authorize". That position was right for v0.4, where there was no authorizer for a
scope to intersect with. v0.6 shipped one. The reason for the deferral has expired.

### 8. Where each producer gets its values

All five construction sites already hold what they need. No new query is introduced anywhere.

| Site | Fills |
|---|---|
| `sessions/service.cr` | `Session`, `id` from the resolved record, `expires_at` from its absolute deadline |
| `api_tokens/service.cr` | `ApiToken`, `id`, `name` and `expires_at` from the row already read |
| `jwt/validator.cr` | `Jwt`, `id` from `jti` when the issuer states one |
| `passwords/authenticator.cr` | `nil` — login proves a credential, it does not present one |

An authenticator written by an application reports `Custom`, or `nil` if it fills nothing, which
reads as unattenuated and preserves today's behaviour for it.

**Amended during implementation: there is no `Remembered` kind and no `Legacy` kind.** Both were
in the first draft of this document and both were wrong. A restored remember-me login and an
adopted legacy session each *mint a real session row* and are presented as a session cookie from
the next request onward, so the kind would read `Remembered` once and `Session` forever after —
a value that changes for the same credential between two requests is worse than one that was
never offered. What actually differs is the assurance, and `AssuranceLevel::Remembered` already
carries that on the session row, durably, where every later request reads it.

`Custom` took their place, because a closed set of kinds would repeat against application
authenticators the mistake `blueprints/0020` decision 6 records against `DenialReason`: a
credential family this shard did not ship would have nothing truthful to report.

## Consequences

**A route does not change.** `env.auth.authorize!("releases:write")` is the same line before
and after; it simply stops ignoring which credential is asking.

**The hot path does not grow a query.** Every value comes from a row that was already read to
authenticate the request. The catalogue's rule 8 — no repeated parsing, hashing or primary
lookup — holds.

**`Authorizer` keeps its signature here.** Resource and environment context is a different
problem, tracked as decision 3 of `blueprints/0020`. This change deliberately does not depend
on it.

**Two questions were left open here. One has since been answered.**

**The denial reason for an out-of-scope credential — settled by `blueprints/0022-authorization-context-and-denials.md`.** Scope attenuation
is this shard's own behaviour rather than an application's policy, so it gets a built-in member
and a named constructor rather than the free-form `code` that 0022 adds for application
authorizers:

```crystal
Forbidden.out_of_scope(permission, tenant_id)   # step_up: false
```

`step_up: false` is worth stating rather than assuming. Re-authenticating does not widen a
token's scope: the attenuation was fixed when the token was issued, and no amount of proving
who you are changes what the credential is allowed to carry. Prompting for a second factor here
would ask the user for something that cannot help. Issuing a new token can help, and that is a
remediation rather than a step-up — the distinction 0022 decision 6 draws.

**A JWT with no `jti` — still open.** It produces `id: nil`. Whether a credential with no stable identity may carry
scopes at all — or whether that combination should be refused at validation, since a token that
cannot be named also cannot be revoked — needs an answer before `Jwt` credentials are allowed
to attenuate anything.
