# 0031 — The password is its own evidence

**Status:** accepted
**Date:** 2026-09-03
**Milestone:** v0.12

## Context

The second item on the consumer's list from `blueprints/0030`: nothing in the shard answers
*"did this person actually type their password in the last ten minutes?"*

Two fields look as though they should, and neither does.

`Principal#authenticated_at` is "when the credential behind `assurance` was last verified", and
it is **restamped by every assurance increase** — `#start!` is what `#elevate!` calls. So:

```
10:00  password typed          authenticated_at = 10:00
10:09  second factor proved    authenticated_at = 10:09   ← the password did not move
10:10  require_fresh!(within: 10.minutes)  → passes
```

The window meant "type your password again". A TOTP satisfied it. Worse, the person who
proved the second factor need not know the password at all — the session was already open.

`assurance` cannot stand in either. `AssuranceLevel::Password` means *one* factor was proved,
not which one, and a federated login reaches exactly that level. So "confirm your password
before linking another identity to this account" — the consumer's actual use case, and the one
where getting it wrong hands an account to whoever controls a provider login — was
unenforceable.

## What everything else does, and the split between two kinds of system

Measured before designing, as in `blueprints/0030`, and the reading divided cleanly in two.

### Identity providers store the evidence and ship no guard

| System | Shape |
|---|---|
| **Supabase** | `auth.mfa_amr_claims`, one row per authentication method per session. The JWT carries `"amr": [{"method": "password", "timestamp": 1640991600}]`, with methods including `password`, `oauth`, `totp`, **`recovery`**, `magiclink`, `sso/saml`. `aal` is *derived* from those rows rather than stored |
| **Keycloak** | A `loa-map` in the user session note: level → the time that level was reached, plus a per-level max age. Step-up compares against it |
| **Auth0** | `event.authentication.methods`, an array of `{name, timestamp}` readable in a post-login Action |

All three publish the raw evidence and stop there. None ships a guard, because the sensitive
operation lives in the relying application, not in the IdP — the party holding the data is not
the party making the decision. Supabase's own documentation says nothing about what to do with
the timestamp.

Two asides worth recording. Supabase had to invent its own method vocabulary (`recovery` is one
of its values) because the IANA `amr` registry has no value for a recovery code — see
`blueprints/0030`. And OIDC itself models none of this: `auth_time` is a **single** value and
`max_age` compares against it, so the protocol can express "authenticated recently" and cannot
express "authenticated recently *by this method*".

### Application frameworks ship the guard, with one dedicated slot

| System | Shape |
|---|---|
| **Laravel** (core, since 6.2) | `password.confirm` middleware over `Illuminate\Auth\Middleware\RequirePassword`. Session key `auth.password_confirmed_at`, separate from the login time; window from `auth.password_timeout`, three hours by default. Jetstream gates enabling and disabling 2FA with it |
| **django-sudo** (Sentry's, the de facto Django answer) | `@sudo_required`. The elevation lives in its **own cookie with its own TTL**, deliberately shorter than the session, so a long session carries a short elevation. Logging in elevates automatically |
| **Phoenix 1.8** (core generator) | `require_sudo_mode` plug and `sudo_mode?/2` over an `authenticated_at` field, with the window in minutes. Method-**agnostic**: recency only |

So the two mainstream app-side implementations do not build a general method→timestamp map at
all. They add **one** timestamp — the password's — keep it separate from the login time, and
give it its own window. Only Phoenix generalises, and it generalises in the other direction, to
plain recency.

That is the design this decision takes, and it is a quarter of the size of the general evidence
model the consumer's notes proposed.

## Decisions

### 1. One column: `auth_sessions.password_verified_at`

Not a general `AuthenticationMethod` enum with a timestamp per member. In practice the only
method a policy names is the password: everything else is answered by `#require_fresh!`
(recency) and `#require_assurance!` (strength), which already exist.

A JSON map was considered, as Keycloak keeps. Rejected: it puts a parse on the session-resolve
path, which is the one query on every authenticated request, and it introduces an encoding two
adapters can disagree about — the argument `Sessions::Record#token_digest` already makes about
`Bytes` over hex. A nullable timestamp column is what an adapter cannot get subtly wrong, and
adding a second one later is the most boring migration there is.

`Principal#password_verified_at` carries it, and `#password_verified?(within:, now:)` answers.

### 2. The producer stamps it

`Passwords::Authenticator` sets `password_verified_at` on the principal it returns, exactly as
it sets `assurance`. `#start!` carries the principal's value into the session row, so an
ordinary login records it with no change to the login route.

This is the `CredentialRef` pattern from `blueprints/0021`: filled where the fact is known,
because nothing downstream can reconstruct it. No later code can tell a password login from a
federated one — both are `Password` — so if it is not stamped here it is not recoverable.

The consequence is that a federated login stamps **nothing**, which is the correct answer and
the whole point of the field.

### 3. `nil` means no, never "unknown, allow it"

`#password_verified?` is false for a principal no password produced: a remembered browser, a
bearer token, a federated login, an account with no password at all, and every session that
already existed when the column was added.

So an application that adopts the guard without adopting the flow gets a route nobody can
reach, rather than a route everybody can reach. An OIDC-only or passkey-only deployment cannot
satisfy this guard at all — and should be asking `#require_fresh!`, or re-authenticating
through the provider, rather than reaching for a password its people do not have.

### 4. Rotation carries the evidence; `#password_verified!` only ever raises the level

`Sessions::Service#rotate` and `RequestContext#start!` both carry the previous value forward.
A session that forgot its evidence on rotation would answer false the instant a second factor
was proved, which is the bug this decision exists to fix, arriving by another road.

`#password_verified!` records a re-confirmation on an existing session. It takes the level from
the session rather than from the fresh authentication, and raises it monotonically, for the
same reason `#elevate!` does: the obvious `start!(result.principal)` would drop an `MFA`
session back to `Password`, spending the second factor to confirm a password.

### 5. The refusal is the existing one

`FreshAuthenticationRequiredError`, with the window, so it is the same 403 and the same RFC
9470 `max_age` as any other recency refusal. A client still cannot read off it *which*
credential would satisfy the route. That is a structured step-up requirement, it is the next
item on the consumer's list, and it is deliberately not smuggled in here.

## Consequences

- One nullable column, in both adapters, added by a migration that backfills nothing.
- The shared `SessionRepository` contract now asserts the round-trip, because an adapter that
  drops the column produces a guard nobody can satisfy — silent, and visible only on the
  sensitive route it protects.
- `Sessions::Record` and `Principal` gain a field. Both are on the v1.0 freeze list, which is
  why this lands now: after the freeze, a third-party adapter that does not persist the column
  could not be asked to.
- Laravel's window is a global three hours; here it stays the caller's argument, as
  `#require_fresh!` already does. "Recent enough" for linking an identity is not "recent
  enough" for deleting an account.
- Deliberately **not** done: a general evidence map, `authentication_methods` in the shape of
  `amr`, or per-method windows for anything but the password. Nothing in the survey supports
  building them on the application side, and the IANA registry cannot even name half of what
  this shard would have to put in them.
