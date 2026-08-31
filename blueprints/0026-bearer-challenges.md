# 0026 — What a refusal tells the client, and what it keeps back

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

`WWW-Authenticate` appeared nowhere in `src/`. RFC 6750 §3 is explicit:

> If the protected resource request does not include authentication credentials or does not
> contain an access token that enables access to the protected resource, the resource server
> MUST include the HTTP "WWW-Authenticate" response header field.

`blueprints/0025-maturity-validation-results.md` measured the consequence against a running
server (HTTP-01, very high, targeted at M4): every 401 and 403 arrived without it.

A consumer *can* replace `ErrorHandler` and emit the header themselves — eighteen lines, verified
working during that validation. But they cannot emit the **right** one. `ForbiddenError` carries
no reason, deliberately, so their handler has to answer `insufficient_scope` for every 403
including "not a member of this tenant" — which is not what RFC 6750 means by it. Only the shard
knows the reason, so only the shard can be accurate.

Which is the whole difficulty: the reason is exactly what must not reach the client.

## Decisions

### 1. The response layer receives a projection, not the reason

`ForbiddenError` gains `challenge_error : String?`, and `authorize!` sets it:

```crystal
raise ForbiddenError.new(
  "not permitted",
  challenge_error: decision.reason.out_of_scope? ? "insufficient_scope" : nil,
)
```

**Not `DenialReason` itself.** Handing the enum to the handler would put `NotAMember` and
`TenantMismatch` one `to_s` away from a header, and the property that keeps a denial from
confirming a guessed tenant would become a convention that a future maintainer has to know
about. The projection makes the leak unrepresentable: the handler cannot render a reason it was
never given.

Same shape as the rest of this release. `Verdict.unavailable` reads as `allowed? == false` so
that forgetting the third state fails closed; `Forbidden`'s named constructors fix `step_up` so
`RBAC` cannot forget it; here the response layer is handed only what it is allowed to say.

### 2. Only `OutOfScope` maps, and that is not a leak

RFC 6750 registers three codes — `invalid_request`, `invalid_token`, `insufficient_scope` — and
none of them means "the account does not hold this permission". So of six denial reasons, one
maps and five collapse to the same output: the challenge with no `error` parameter.

That is the distinction worth preserving. `NotAMember` versus `NotPermitted` — *does the tenant I
guessed exist, and am I inside it* — produce byte-identical responses, asserted directly in
`spec/integration/kemal_spec.cr`.

`insufficient_scope` is safe to say for a reason better than "the client chose its own scopes",
which is not always true — an access token can be opaque to the client it was issued to, and
requested scope is not always granted scope. The stronger reason is that RFC 6750 §3.1 defines
this code as information the resource server tells the client **on purpose**: it is the protocol's
own way of saying "your credential is narrower than this action".

**`scope` is omitted.** RFC 6750 makes the attribute OPTIONAL, and naming the permission a caller
lacks is the part of a denial this shard keeps for the audit log. A spec asserts the challenge
contains neither `scope=` nor a permission name.

### 3. The challenge is only sent where a bearer credential means something

Two gates, and both were found by reading the RFCs rather than by reading the code.

**The scheme is announced only when the application configured bearer credentials.** A
browser-only deployment accepts no bearer token, and advertising `Bearer` would be pointing at a
door that is not there.

**`error="insufficient_user_authentication"` is only sent when a bearer credential was actually
presented.** RFC 9470 defines it as:

> The authentication event associated with the access token presented with the request does not
> meet the authentication requirements of the protected resource.

`FreshAuthenticationRequiredError` is raised by `require_fresh!` and `require_assurance!`, which
guard **session** requests too. Emitting that code for a browser session would be making a claim
about an access token that does not exist. A session that needs re-authentication gets the
challenge and no error code.

The same gate applies to `invalid_token`: RFC 6750 says a request lacking any authentication
information **SHOULD NOT** carry an error code, so "nothing was presented" and "what was presented
did not hold" are told apart by whether an `Authorization: Bearer` header arrived.

### 4. A request that presented a bearer credential is never redirected

Found by a failing spec rather than by design. Before this, a `curl` sending a valid-shaped bearer
token and no `Accept` header received `302 Location: /login`, because the redirect decision was
made purely by content negotiation.

Content negotiation is a *guess* about whether a browser is asking. An `Authorization: Bearer`
header is the client saying so outright. Answering it with an HTML login page answers an API call
with something it cannot use.

Five existing examples asserted the 302. None of their comments defended it — they were named
"rejects a revoked token", "turns away a forged signature" — so the status was incidental to the
behaviour they meant to pin, and 401 is the more accurate expression of it.

### 5. The status codes do not change

`NotAuthenticatedError` stays 401. Everything else stays 403.

RFC 6750 recommends 401 for `invalid_token` and **403 for `insufficient_scope`**, so the
authorization side is already what the specification asks for.

RFC 9470's step-up examples answer 401, but — checked against the document — it states no
normative requirement about the status code. So 403 with
`error="insufficient_user_authentication"` is compliant, if not the shape a generic OAuth client
is most likely to recognise. Some clients run their challenge-handling path only on a 401.

**Deferred, deliberately: whether `FreshAuthenticationRequiredError` should become 401.** That is
a compatibility decision about existing consumers, not a compliance one, and it would abandon a
documented rationale — sending somebody to a login page when they are already logged in is
confusing, which is why the 403 was chosen. Worth revisiting with evidence about real clients; not
worth bundling into a patch whose purpose is to add a missing header.

## Consequences

**Measured against a running server, before and after:**

| Request | Before | After |
|---|---|---|
| no credential, `Accept: json` | 401, no header | 401, `Bearer realm="api"` |
| invalid bearer, no `Accept` | **302 → /login** | **401**, `error="invalid_token"` |
| out-of-scope token | 403, no header | 403, `error="insufficient_scope"` |
| any other denial | 403, no header | 403, `Bearer realm="api"` |
| no credential, no `Accept`, browser app | 302 → /login | unchanged |

**Breaking for a client that relied on the 302.** An API client presenting a rejected bearer
token now receives 401 rather than a redirect. That is the point, and it is called out in the
changelog.

**What HTTP-01 still does not have.** API-only behaviour is app-wide: `ErrorHandler.new(login_path: nil)`
turns off the redirect everywhere, and there is no per-subtree switch. A monolith serving both a
browser UI and a REST API under one `ErrorHandler` gets one answer for both — the same parameter
HTTP-02 wants on `PathGuard`, and left with it.
