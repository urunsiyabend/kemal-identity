# 0008 — `start!` lives on `env.auth`, not on the session service

## Status

Accepted, 2026-08-24. Implemented in `src/kemal_identity/kemal/request_context.cr`.

## Context

`docs/04-kemal-integration.md`'s login example writes the session-minting step as:

```crystal
KemalIdentity.app.sessions.start!(env, result.principal)
```

`KemalIdentity.app.sessions` is a `Sessions::Service`, which lives in `src/kemal_identity/sessions/`
— the framework-agnostic core. Giving it a method that takes an `HTTP::Server::Context`
contradicts the layering rule in `docs/01-architecture.md`:

> The only layer that knows `HTTP::Server::Context` exists.
> […] A core file that needs `HTTP::Server::Context` is a design error: extract the two or
> three values it actually reads (a cookie string, a request method, a path) and pass those.

That rule is not decoration. It is what makes `spec/unit` runnable without a server, what lets
`spec/contract` run against every adapter, and what leaves the door open to an Amber or Lucky
adapter without touching the core. One `env` parameter in the session service would end all
three.

There is also a signature problem underneath the layering one. `start!` needs the account's
`auth_version` to stamp onto the new session, and `Principal` deliberately does not carry it —
`Principal` is the minimum security context, and `auth_version` is storage bookkeeping. So a
`start!` taking only a principal has to read the account anyway.

## Decision

The method lives on `env.auth`:

```crystal
env.auth.start!(result.principal)
```

`RequestContext` already holds the `env`, the `Application`, and the current outcome, so it is
the natural owner: it reads the account by `principal.subject`, calls
`Sessions::Service#start`, revokes whatever session the client presented, writes the
`Set-Cookie`, and updates its own outcome so a `require!` later in the same request sees the
new principal.

`env.auth.logout!` is the symmetric operation, for the same reasons.

## The fixation defence, stated precisely

`start!` revokes **the session the client presented on this request**, and nothing else.

That is the session fixation defence: an attacker plants a session identifier in the victim's
browser, the victim authenticates while presenting it, and the identifier must not survive
into the authenticated session. It does not.

It is deliberately *not* "one session per account". Logging in from a second device must not
end the first device's session — `docs/02-security-model.md` supports several live sessions
per account, which is what "list my devices" and `revoke_all_for_account` exist for. The two
behaviours are one line apart in the implementation and a world apart for a user, so
`spec/integration/kemal_spec.cr` asserts both halves as separate examples.

A first draft of that spec conflated them, asserting that a second login killed the first
session. It failed, correctly, and the fix was to the spec.

## Consequences

- `docs/04-kemal-integration.md`'s example is updated.
- The core session service still knows nothing about HTTP: it takes an `Accounts::Account` and
  an `AssuranceLevel` and returns an `Issued`.
- `start!` raises `InfrastructureError` when the account cannot be found. A credential was
  just verified against that account, so its disappearance is not an authentication failure —
  something underneath is wrong, and it should say so rather than returning "not signed in".
