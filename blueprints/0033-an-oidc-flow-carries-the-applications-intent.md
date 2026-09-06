# 0033 — An OIDC flow carries the application's intent

**Status:** accepted
**Date:** 2026-09-03
**Milestone:** v0.12

## Context

Fourth item on the consumer's list. `OIDC::Pending` carries `state`, `nonce`, `code_verifier`
and `return_to` — everything the *protocol* needs — and nothing the application needs. So an
account-linking callback cannot answer:

- was this a login or a linking flow?
- which account started it?
- from which session?

The application therefore builds a second place to keep that: its own table keyed by `state`, or
its own signed cookie beside the one this shard is already signing. The second one is the
problem — the shard has a signing key, a codec, domain separation and a size cap, and an
application reaching for `to_json` and a plain cookie has none of them. The dangerous version of
this feature is the one an application writes for itself.

## What everything else does

**ASP.NET Core Identity.** `ConfigureExternalAuthenticationProperties(provider, redirectUrl,
userId)` — the third argument is the linking intent, and the documentation says it is there "to
provide CSRF protection". It travels in `AuthenticationProperties.Items`, which the OAuth
handler puts inside the `state` parameter **encrypted** with data protection. When that grows
too large for a URL, `ISecureDataFormat<AuthenticationProperties>` moves it server-side.

**Spring Security.** `OAuth2AuthorizationRequest.attributes` is a free-form map, persisted by an
`AuthorizationRequestRepository` whose default is `HttpSessionOAuth2AuthorizationRequestRepository`
— server-side. A cookie-backed repository is the well-known alternative for stateless or
multi-instance deployments, where a callback may land on a different instance than the one that
issued the session.

**django-allauth.** The `state` parameter is a **random pointer**; the real state — a dict
including `process: "connect" | "login"` and `next` — lives in the session.

**Keycloak.** Client-initiated account linking binds the intent to the session
cryptographically: `hash = SHA-256(nonce + session_id + client_id + provider_alias)`, validated
against the browser's current SSO session. Deprecated since 26.3 in favour of Application
Initiated Actions, which move the whole flow server-side.

Two things fall out. Everyone carries application context through the flow — this is not an
exotic requirement. And they differ on exactly two axes: **where it lives** (session, encrypted
state, cookie) and **whether the intent is bound to the session that started it**.

## Decisions

### 1. `Pending#context`, a `Hash(String, String)` the shard does not interpret

```crystal
client.authorize(
  return_to: "/settings/security",
  context: {
    "flow"       => "link",
    "account_id" => principal.subject,
    "session_id" => principal.session_id.to_s,
  },
)
```

Spring's `attributes` in shape, this shard's already-signed cookie as the carrier. The keys mean
nothing here; the *integrity* of them is what nothing else in the flow can provide.

Nested under its own JSON key (`"x"`), so an application key can never collide with one of the
codec's — the same discipline `Provider` applies when it refuses reserved authorization
parameters.

### 2. Signed, not sealed — so it is not secret, and the docs say so loudly

The payload is HMAC-signed and readable by the browser, exactly like the PKCE verifier beside
it. ASP.NET can put an account id in its equivalent because it encrypts; this one only proves
nobody changed it.

Encrypting was considered and rejected for this milestone: it is a second key, a second
construction and a second thing to get wrong, for a payload whose only current occupants are an
account id and a session id that the browser's own session already establishes. What is not
acceptable is silence about it, so `Pending#context` states the limit and names the alternative
— a server-side table keyed by `state` — for state that genuinely must stay hidden.

### 3. The comparison is the application's, deliberately

Carrying `session_id` does nothing on its own; somebody has to check it against the session
presenting the callback. Keycloak does that comparison itself, and this shard will not, because
which account a federated identity may be attached to is on the short list of decisions
`docs/02-security-model.md` says must never be made on an application's behalf. Guessing that a
context key called `account_id` means "link to this account" would be exactly that guess.

### 4. A context that cannot be read refuses the whole flow

`decode` returns nil when the `"x"` field is present but is not an object of strings — rather
than dropping it and returning a flow with no context.

Dropping would be the quiet disaster. An application comparing `context["session_id"]` against
the current session would find an empty context, skip the comparison, and complete a linking
flow with no intent check at all. Absent and unreadable mean opposite things here, so they get
opposite answers.

### 5. Bounded, and enforced where the developer is

`MAX_CONTEXT_ENTRIES = 8`, keys to 64 bytes, values to 512, raising `ArgumentError` at
construction; and `PendingCodec#seal` now refuses to produce a value over `MAX_BYTES`.

That second half is a defect this feature exposed rather than created. `MAX_BYTES` was checked
only in `open?`, so an oversized flow sealed happily, was written to the browser, and came back
as `nil` — presenting as a login that silently never completes, with no error anywhere and the
evidence in the user's cookie jar. Now it raises when the flow starts, in front of whoever wrote
the call.

### 6. No `PendingRepository` yet

Server-side storage — Spring's default, allauth's design, and where Keycloak has moved — is what
single-use intents and server-side invalidation need, and the cookie codec cannot do either. It
is a new port, three adapters, a contract and a sweeper, and nothing measured needs it yet: the
flow already expires (`Pending#expired?`), and the callback deletes the cookie, which is
single-use per browser in practice. Left out until something asks for it.

## Consequences

- Additive. One optional argument on `#authorize`, one optional field on `Pending`, one new
  JSON key that older payloads simply do not carry.
- `OIDC::Pending` and `PendingCodec` are on the v1.0 freeze list, which is why this lands now
  rather than later.
- An application still has to write the comparison. The blueprint says so, `Pending#context`
  says so, and the shard cannot enforce it — this is the residual risk, and it is the same one
  Spring and ASP.NET carry.
- `#seal` can now raise where it previously could not. It raises only for a flow an application
  built too large, and the alternative was failing later and silently.
