# 0028 — Telling an API client what would satisfy a step-up

**Status:** accepted
**Date:** 2026-09-02
**Milestone:** v0.9

## Context

`blueprints/0026` added `error="insufficient_user_authentication"` to the challenge sent when a
bearer-credentialled request is authenticated but not good enough. AUT-07 in
`blueprints/0025-maturity-validation-results.md` then drove the scenario the code was written for
— three products at three assurance levels, called through every credential the shard can produce
— and measured what a client actually receives.

The pass condition it failed is the third one: *"the denial can produce a suitable API challenge
without revealing unrelated policy."* Measured against a running server, three different
refusals produced the same challenge:

```
GET  /export   Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication"
POST /payout   Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication"
POST /email    Bearer <token>   403   Bearer realm="api", error="insufficient_user_authentication"
```

Those are not the same problem. `/export` and `/payout` refused because the credential is not
*strong* enough — an API token is below `Password`, and no amount of re-presenting it helps.
`/email` refused because the authentication behind it is not *recent* enough, and re-typing a
password fixes it in five minutes.

The shard holds that distinction internally and always has: `Permission#minimum_assurance` is
strength, `require_fresh!(within:)` is recency, and `Principal` measures them on separate axes.
It threw the distinction away at the response boundary, so the client — which is the one party
that has to *do* something about it — was the only party that could not see it. "Type your
password again" and "produce a second factor" are different prompts, and a 403 saying only
"insufficient" leaves an API client guessing which.

RFC 9470 §3 defines exactly the vocabulary for this, alongside the error code the shard already
sends:

> `acr_values`: A space-separated string listing the authentication context class reference
> values in order of preference.
>
> `max_age`: Indicates the allowable elapsed time in seconds since the last active
> authentication event.

## Decisions

### 1. `max_age` is emitted, because the shard already knows the number

`require_fresh!(within: 5.minutes)` *is* an allowable elapsed time since the last active
authentication event. The window is a caller argument, in hand at the moment of refusal, and
nothing has to be invented to publish it: the challenge becomes

```
Bearer realm="api", error="insufficient_user_authentication", max_age="300"
```

`FreshAuthenticationRequiredError` carries the window so that the handler can read it. That is
the same shape as `ForbiddenError#challenge_error` from `blueprints/0026` — one piece of protocol
classification travelling with the refusal, decided where the security decision was made rather
than reconstructed in the response layer.

### 2. Its **absence** is the signal for the other case

`require_assurance!`, and an authorization denial that `step_up?` says a stronger credential
would fix, raise with no window. So a strength refusal is the same challenge without the
parameter, and a client can branch on one bit.

Deliberately not `max_age="0"`. Zero would read as "re-authenticate right now and retry", which
for an API token that can never reach `MFA` is an instruction to loop.

### 3. There is no `acr_values`, and this is not an oversight

`acr_values` are a deployment's own authentication context class references — the strings its
identity provider mints and its clients recognise. This shard has an assurance *ordering*
(`Remembered` < `ApiToken` < `Password` < `MFA`), which is a different thing: publishing
`acr_values="mfa"` would be inventing a vocabulary and asking every consumer to adopt it, and
publishing the enum member name would leak the shard's internals into a protocol field that is
supposed to be about the deployment.

An application that has an ACR vocabulary — because it federates, and its provider already
defines one — can add the parameter in its own error handler: `ErrorHandler` is one class an
application does not register when it wants its own behaviour (`blueprints/0026`, DEV-01).

**Revisit if** a consumer arrives with a real ACR vocabulary and a client that needs it. The
shape would be a mapping supplied at configuration, `assurance_acr: {MFA => "mfa"}`, so the
strings stay the deployment's.

### 4. The parameter is gated exactly like the error code it accompanies

`max_age` is sent only when `error="insufficient_user_authentication"` is, which means only when
a bearer credential was actually presented. A browser session gets neither: RFC 9470 defines
both as statements about *the access token presented with the request*, and a session has no
access token to say them about. `blueprints/0026` decided that for the error code; the parameter
follows it rather than being gated on its own.

A 401 for a missing credential never carries it either. The parameter answers "what would be
good enough"; a request that presented nothing has not asked that question yet.

### 5. Whole seconds, rounded down

`max_age.total_seconds.to_i`. A client that re-authenticates within the number it was handed must
land *inside* the window: 299 seconds is inside a 299.5-second window and 300 is not, so rounding
up would hand out a value that fails on the retry.

## Consequences

**Measured against a running server**, one route per case, one account, three credentials:

| Request | Guard | Before | After |
|---|---|---|---|
| `GET /export`, bearer | `authorize!("data.export")`, `Password` | `error="insufficient_user_authentication"` | unchanged |
| `POST /payout`, bearer | `authorize!("payout.update")`, `MFA` | `error="insufficient_user_authentication"` | unchanged |
| `POST /email`, bearer | `require_fresh!(within: 5.minutes)` | `error="insufficient_user_authentication"` | `…, max_age="300"` |
| `POST /email`, session | same | `Bearer realm="api"` | unchanged |

**Additive.** `FreshAuthenticationRequiredError.new("message")` still compiles; the window is an
optional second argument. No signature moved, so `blueprints/0020`'s freeze list is untouched.

**A client that was parsing the challenge strictly** now sees one more parameter on the recency
case. RFC 6750's `auth-param` list is extensible and RFC 9470 registers this name, so a
conforming client ignores what it does not know.

**What this does not do.** It does not name the permission, the tenant, or the reason — `scope`
stays omitted for the reason `blueprints/0026` gives. The client learns how *stale* its
authentication is allowed to be, which is a property of the endpoint it already chose to call,
and nothing about who exists or what anybody else holds.

**Freshness is still not declarable per permission.** `Permission` carries `minimum_assurance` and
no maximum age, so recency remains a call-site decision while strength is a declared one — which
is the asymmetry AUT-07 recorded and this decision does not close. Both halves of the challenge
now work; only one of them can be declared in the catalogue. See AUT-07 in `blueprints/0025` for
the argument that this is the remaining gap.
