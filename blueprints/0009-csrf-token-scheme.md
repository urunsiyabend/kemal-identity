# 0009 — The CSRF token scheme

## Status

Accepted, 2026-08-25. Implemented in `src/kemal_identity/csrf.cr` and
`src/kemal_identity/kemal/csrf_handler.cr`.

## Context

`docs/04-kemal-integration.md` says `CSRFHandler` "can delegate token storage to
kemal-session when it is present, or use its own double-submit implementation when it is
not". `docs/05-testing.md` requires four things: a cookie-authenticated `POST` without a
token is rejected; with a valid token it is accepted; **a token from another session is
rejected**; and the login form itself is protected.

Plain double-submit — compare a cookie against a form field — cannot satisfy the third. Its
only claim is that the two values agree, and anyone able to set the cookie can set the field
to match. It proves nothing about *which* session the token belongs to.

## Decision

A signed, session-bound, masked token. No server-side token store, and no dependency on
kemal-session.

```
raw    = HMAC-SHA256(secret, anchor)
pad    = 32 random bytes
token  = base64url(pad ++ (raw XOR pad))
```

**`anchor`** is the session id when the request is authenticated, and the value of a
dedicated `__Host-` prefixed cookie when it is not. An attacker cannot compute `raw` without
the application secret and cannot read the victim's anchor, so a token minted for their own
session does not verify against the victim's.

**The mask** exists because `raw` is constant for the life of a session, and a value repeated
in every response is what BREACH-style compression oracles extract. The pad changes per
issue, so the rendered token differs every time and still verifies. `spec/unit/csrf_spec.cr`
asserts twenty issues produce twenty distinct strings, all valid.

**The anonymous anchor** is what makes login CSRF protection possible: the login form has no
session to bind to. It is minted lazily, the first time `env.auth.csrf_token` is called, so a
request for a static asset never pays for one. The `__Host-` prefix is load-bearing rather
than decorative here — it forbids a `Domain` attribute, so a compromised sibling subdomain
cannot plant an anchor value the attacker knows.

### Safe-by-name, protected otherwise

`docs/02-security-model.md` lists the protected methods as `POST`, `PUT`, `PATCH`, `DELETE`.
That is implemented **inverted**: everything is protected except `GET`, `HEAD`, `OPTIONS`,
`TRACE` and `QUERY`.

A denylist leaves every method nobody thought of unprotected. `PROPFIND` mutates in WebDAV,
and HTTP QUERY did not exist when these documents were written — the same reasoning that
keeps `PathGuard` from dispatching on an allowlist of methods. `QUERY` is on the safe list
because RFC 10008 defines it as safe and idempotent; its request body makes it look like a
mutation, and a spec asserts it is not treated as one.

### Protection does not depend on being authenticated

Every unsafe request is checked, signed in or not. Restricting the check to
cookie-authenticated requests would leave the login form — the case
`docs/02-security-model.md` calls "the case most implementations miss" — unprotected.

An application with a genuine non-cookie endpoint declares an `exempt_prefixes` entry.
Exempting a path is a promise that it accepts no session cookie: an endpoint that accepts one
is subject to CSRF regardless of also accepting a bearer token, and regardless of being
labelled an API. Content type is not a defence.

### A new error class

`CSRFError` joins the taxonomy in `src/CLAUDE.md`, mapped to 403. A CSRF rejection is neither
"not authenticated" (the caller may well be) nor "not fresh enough" (their authentication is
fine); collapsing it into either would make both mean less. It never redirects — bouncing a
rejected `POST` to a login page would suggest the session had ended when it had not.

### The secret is required, with no default

`CSRFConfig` takes a signing key of at least 32 bytes and refuses anything shorter at boot.
There is deliberately no default: a default key would be shared by every deployment that
forgot to set one, which is the same as having no protection while appearing to have some.
`Application#csrf` is therefore nilable, and `CSRFHandler` raises at construction when it is
missing.

The key is wrapped in `Secret` immediately, so a configuration dump in a crash report cannot
leak it.

## A layering bug this caught

`CSRFConfig` was first written inside `KemalIdentity::Kemal`, and `Application` — core code —
gained a `getter csrf : Kemal::CSRFConfig?`. The whole shard still compiled, because
requiring the Kemal adapter defines both. Building the core alone did not:

```
Error: undefined constant Kemal::CSRFConfig
```

That is exactly the design error `docs/01-architecture.md` names, and it would have broken
the property that makes `spec/unit` runnable without a server. The token maths and the
configuration touch no `HTTP::Server::Context`, so they moved to
`src/kemal_identity/csrf.cr`; only `CSRFHandler` stayed in the adapter.

CI now builds `src/kemal_identity.cr` on its own as a separate step, so a reference from the
core into the Kemal layer fails the build rather than waiting to be noticed.

## Not done here

Delegating token storage to kemal-session, as `docs/04-kemal-integration.md` offers as an
alternative. The scheme above needs no storage at all, so the delegation would add a
dependency and a second code path to test in exchange for nothing. If a concrete need appears
it can be added behind the same `CSRFConfig`.
