# 0034 — Checking the chain at boot

**Status:** accepted
**Date:** 2026-09-03
**Milestone:** v0.12

## Context

Last item on the consumer's list. The handler chain's order is a security property:

```crystal
use KemalIdentity::Kemal::ErrorHandler.new(login_path: "/login")
use KemalIdentity::Kemal::AuthenticationHandler.new
use KemalIdentity::Kemal::CSRFHandler.new
use KemalIdentity::Kemal::PathGuard.new(prefix: "/admin")
```

Every wrong arrangement of those four lines compiles, and most of them start. What arrives later
is a 500 where a 401 belonged (the error handler inside the thing that raises), a CSRF token
anchored on nothing (CSRF before authentication), or a guard refusing on a principal nobody
resolved. `docs/04-kemal-integration.md` spells the order out precisely because it is not
obvious — but a document is not a check.

## What everything else does

**Django** has the strongest answer: the **system check framework**. `admin.E408` is literally
"`django.contrib.auth.middleware.AuthenticationMiddleware` must be in `MIDDLEWARE` in order to
use the admin application", and its siblings check the rest. Checks run at startup, report
*every* problem rather than the first, carry stable identifiers, and can be turned off through
`SILENCED_SYSTEM_CHECKS`.

**ASP.NET Core** catches the same class of mistake twice: `ASP0001` is a **compile-time
analyzer** — "Authorization middleware is incorrectly configured" — and the runtime throws
"Endpoint contains authorization metadata, but a middleware was not found that supports
authorization" when `UseAuthorization` is missing or misplaced. The message names the fix.

**Laravel** does not check at all; it **sorts**. `$middlewarePriority` declares the order the
framework wants, and the pipeline reorders whatever the application registered.

**Rails** raises when `insert_before` names a middleware that is not in the stack, and ships
`rails middleware` to print the chain, but validates no ordering.

So: two frameworks check and name the fix, one silently repairs, one prints. The one thing
nobody does is leave it to a document.

## Decisions

### 1. A validator, not an installer

The consumer proposed either `KemalIdentity::Kemal.install!(...)` — one call that registers the
whole chain — or a validator. Laravel's priority sort is the same idea as `install!`: take the
ordering away from the application.

Rejected, because `blueprints/0008` is the reason this shard has an explicit `use` list at all:
the Kemal layer owns the HTTP seam and the application owns its own chain, which is what lets
application middleware sit between CSRF and the guards, lets one deployment register four
`PathGuard`s and another none. The shipped examples use three different chains between them and
one of them registers no handlers at all, so `install!` would freeze a shape most of them do not
have.

`validate_middleware_order!` leaves the chain to the application and tells it when it is wrong.

### 2. It reads `Kemal::Config::CUSTOM_HANDLERS`, and this is the only thing that works

`use` appends to `CUSTOM_HANDLERS`. `Kemal.config.handlers` — the array that actually runs — is
**empty until `Kemal.run` calls `setup`**, so a boot-time check reading it sees nothing.

Two alternatives were tried and rejected:

- **Call `Kemal.config.setup` from the validator**, then read the real chain. It works, and it
  poisons the thing it validates: `setup` is guarded by `@default_handlers_setup`, so a `use`
  written *after* the validator is silently dropped. A check that can break the configuration
  it is checking is worse than no check.
- **Validate on the first request.** That is where the problem already shows up, and the
  consumer's own criterion was that it should fail at startup instead.

`spec/integration/kemal_spec.cr` calls the validator against its real registration list, so the
suite fails if that reading ever stops finding what `use` put there.

### 3. Explicit positions are refused rather than interpreted

`use handler, 0` puts a handler ahead of `Kemal::InitHandler`, which since Kemal 1.13.0 owns
temporary-file cleanup for uploads — `docs/04-kemal-integration.md` already calls that out. More
generally, an explicit position makes registration order stop being the final order, which is
the assumption this check runs on. So any position on one of this shard's handlers is itself a
finding.

### 4. Every problem, not the first

Django's checks report the whole list, and a chain with two things wrong should take one round
trip to fix rather than two.

### 5. Matched with `===`, so a subclass counts

Django had to fix its own middleware check for exactly this (ticket #30237). An application that
subclasses `AuthenticationHandler` to add a log line has not stopped using it.

### 6. What is deliberately not checked

- **`CSRFHandler` versus `PathGuard`.** Both run after authentication, both refuse, neither
  reads the other. The documented chain puts application middleware between them, which this
  check cannot see anyway, so an application that guards earlier has made a choice.
- **Anything about handlers this shard did not write.** It reads the chain to find its own.
- **Silencing.** Django needs `SILENCED_SYSTEM_CHECKS` because its checks run whether you asked
  or not. This one is a function an application calls; not calling it is the escape hatch.

### 7. The legacy adapter goes *after* authentication

Worth recording because writing this check got it wrong first. `LegacySessionHandler` is not the
third-party session middleware in the chain diagram: it adopts an old cookie **only when the
session cookie, the bearer token and remember-me all found nothing**, so it runs after
`AuthenticationHandler` and before `CSRFHandler`. Before authentication, an adopted session
would replace a live one; after CSRF, the token would anchor on a session that did not exist
when it was minted.

## Consequences

- Additive, opt-in, and outside the v1.0 freeze — everything under `KemalIdentity::Kemal` except
  `env.auth` is explicitly not frozen.
- Nothing enforces that an application calls it. That is the residual risk, and it is the same
  one Django accepts for a check somebody silences.
- The rules encode `docs/04-kemal-integration.md`. If that document changes, this changes with
  it, and the integration suite is what notices.
