# 0032 — What a refusal asks for

**Status:** accepted
**Date:** 2026-09-03
**Milestone:** v0.12

## Context

Third item on the consumer's list, and the one this milestone made worse before it made better.

A step-up refusal carried one piece of information: whether
`FreshAuthenticationRequiredError#max_age` was present. `blueprints/0028` decided that
deliberately — a window means recency, its absence means strength, and a client branches on one
bit. So an application inferred:

```crystal
error.max_age ? "fresh" : "mfa"
```

Two things have broken that inference since.

**v0.10 added `AssuranceLevel::Recovery`.** `blueprints/0028` reasoned about the ordering
`Remembered < ApiToken < Password < MFA`, where "not a recency problem" left one plausible
answer. With `Recovery` between `Password` and `MFA` the absent window covers three, and "mfa"
is a guess.

**This milestone added `require_recent_password!`** (`blueprints/0031`). It refuses with a
window, exactly like `require_fresh!`, and means a different prompt: *type your password* rather
than *re-authenticate*, and a second factor proved a minute ago satisfies one and not the other.
So the two guards that an application most needs to tell apart became the two that look
identical. `blueprints/0031` decision 5 recorded that as owed work rather than shipping a
half-answer with it.

## What everything else does

Unanimous, and in the same shape.

**ASP.NET Core** puts the failed requirement *objects* in
`AuthorizationFailure.FailedRequirements`, and an `IAuthorizationMiddlewareResultHandler` reads
them back by type. Duende — who write IdentityServer — publish exactly this for step-up:

```csharp
var maxAgeReq = authResult.AuthorizationFailure!.FailedRequirements
    .OfType<MaxAgeRequirement>().FirstOrDefault();
```

with a `ClaimsAuthorizationRequirement` on `amr=mfa` alongside it, projected into
`401` + `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age=…,
acr_values=mfa`.

**Spring Security 7** (October 2025) ships `FactorAuthorizationDecision`, whose whole content is
`List<RequiredFactorError>` — the denial names which factors were missing, and the framework
redirects to where each one is obtained.

**Laravel** answers the password case with a different **status code**: `423 Locked` plus
"Password confirmation required." for a JSON request, so a client interceptor separates it from
every other refusal without reading a parameter.

**RFC 9470** carries `max_age` and `acr_values`, and the distinction between them is worth
recording: `max_age` is *enforceable* and `acr_values` is *advisory* — OIDC says the
authorization server MAY try to satisfy the acr values but MUST attempt re-authentication when
max_age is exceeded.

The pattern in the first three: **the requirement travels inside the refusal, decided where the
security decision was made, and the response layer projects it.** That is the same principle
`blueprints/0026` used for `ForbiddenError#challenge_error`; it was simply never applied to the
step-up half.

## Decisions

### 1. `StepUpRequirement`, carried by the error

```crystal
struct StepUpRequirement
  getter minimum_assurance : AssuranceLevel?
  getter max_age : Time::Span?
  getter method : AuthenticationMethod?
end
```

`FreshAuthenticationRequiredError#requirement` carries it. `#max_age` stays, as a delegating
reader, so nothing that already reads it breaks — including `ErrorHandler`.

Four raise sites, four shapes:

| Guard | Requirement |
|---|---|
| `require_fresh!(within:)` | `max_age` |
| `require_recent_password!(within:)` | `max_age` **and** `method: Password` |
| `require_assurance!(level)` | `minimum_assurance` |
| `authorize!` where `step_up?` | `minimum_assurance`, when the denial knows it |

### 2. A single requirement, not a list

ASP.NET and Spring both carry collections, because both evaluate a policy made of many
requirements and report every one that failed. Here a guard refuses for one reason and returns,
so a list would always hold one element, and `authorize!` reaches this path only for a denial
that is already a single reason.

### 3. `AuthenticationMethod` is born with one member

`Password`, and nothing else — because a password is the only proof whose own recency this
shard records (`blueprints/0031`). An enum member with no evidence behind it compiles into a
guard that can never be satisfied, which is precisely the trap `require_recent_password!` avoids
by naming only what exists. Members arrive with their evidence.

This is not `amr`: the IANA registry has 22 values and none of them means "recovery code"
(`blueprints/0030`), so it is not a vocabulary this shard can adopt even if it wanted to.

### 4. The denial carries the level it wanted

`Authz::Forbidden#minimum_assurance`, filled by `RBAC` from `Permission#minimum_assurance` at
the moment it refuses. It was known there and discarded, and nothing downstream could recover
it: the response layer sees a `Forbidden` and a route sees an exception, and neither can read a
permission's declaration.

`nil` for every other reason, including an application authorizer's own `step_up: true` denial.
That authorizer knows its policy and this shard does not, so an empty requirement is the honest
answer rather than a guessed level. `StepUpRequirement#empty?` names that case.

### 5. The wire is unchanged, and that is a separate decision

`ErrorHandler` still emits `403` with `max_age` and nothing else. Two things could change and
neither belongs here:

- **`acr_values`.** `blueprints/0028` declined to publish it because the values are a
  deployment's own authentication context class references. That reasoning holds, but it is
  weaker than it was: Duende publishes `acr_values=mfa` and Okta `urn:okta:loa:2fa:any`, so the
  ecosystem has converged on something. Reopening it means choosing a vocabulary and asking
  consumers to adopt it, which is a decision with its own consequences.
- **A distinct status for the password case**, as Laravel's `423`. That reopens
  `blueprints/0026`'s status mapping.

Keeping the wire fixed is what makes this milestone purely additive: no response an existing
client parses changes, and the application-side ambiguity — the one the consumer actually hit —
is closed today.

## Consequences

- Additive. One new struct, one new enum, one new getter on `Forbidden`, and a delegating
  `#max_age`. No migration, no behaviour change, nothing on the wire.
- An application can finally render the right prompt. The integration suite asserts the three
  distinguishable cases through a route that does exactly that.
- `Authz::Forbidden` is on the v1.0 freeze list, so a getter added now is a getter that can
  still be added.
- An application that renders `#minimum_assurance` to its own user is telling them which proof
  to produce, which is the point. Putting it in an API response for an unauthenticated caller
  would be telling everybody what guards what — the same discipline `DenialReason` already
  carries, and the reason none of this reaches the wire by default.
