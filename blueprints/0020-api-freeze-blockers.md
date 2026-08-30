# 0020 — What has to change before the contracts freeze

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

`docs/06-roadmap.md` describes v1.0 as an API freeze: "The criterion is contract stability,
not feature count." `blueprints/maturity-validation-scenarios.md` is the catalogue against
which that stability gets judged — 52 scenarios, each with a maturity target, and a rule that
very-high-frequency scenarios should reach M4 before the freeze.

The obvious way to use the catalogue is to work through it in order and record a result for
each scenario. That order is wrong, and this document exists because of it. Most of the gaps
the catalogue finds are raised by **adding** something — a header, a package path, an event
sink — and adding is not a breaking change. A minority are raised only by **changing a
signature that v1.0 is about to freeze**. Those are the ones with a deadline, and they are
invisible until you ask a different question:

> If this contract freezes exactly as it is today, is the scenario's target still reachable?

This document is the answer to that question, run across the frozen contracts rather than
across the scenarios. It records no maturity levels — that is the catalogue's job, and it
happens after the changes below have landed.

## Decisions

### 1. The freeze list names the wrong set of types

The roadmap freezes `Principal`, `RequestAuthenticator`, `Hasher`, `SessionRepository`,
`AccountRepository`, `IdentityProvider`, `RateLimiter`, `Notifier`, `Clock`, `Authorizer` and
`env.auth`. That list is both too short and, in one place, fictional.

**Too short**, because a frozen method freezes its argument and return types too. These are
not on the list and are frozen in practice:

| Type | Why it is frozen |
|---|---|
| `Outcome`, `Anonymous`, `Authenticated`, `Failed` | `RequestAuthenticator#authenticate` returns it |
| `Accounts::Account` | `AccountRepository#find_by_id` returns it |
| `Sessions::Record`, `Sessions::Lookup` | `SessionRepository` takes and returns them |
| `AssuranceLevel` | on `Principal`, and on `env.auth.require_assurance!` |
| `FailureReason` | on `Failed` |
| `Authz::Decision`, `Permitted`, `Forbidden`, `DenialReason` | `Authorizer#decide` returns it |
| `Verdict` | `RateLimiter#consume` returns it |
| `Passwords::Secret` | argument to `Hasher#verify` |

**Fictional**, because `IdentityProvider` does not exist. There is `OIDC::Provider`, a struct
with a fixed constructor, and `OIDC::Client`, a concrete class with no abstract ancestor. A
list that freezes a type nobody can implement is not a promise, it is an oversight.

`docs/06-roadmap.md` now enumerates the frozen types rather than a subset of them, and names
what is deliberately *not* frozen alongside them. `IdentityProvider` stays in the list with the
condition attached — see decision 4 — and the condition is discharged in v0.8, one way or the
other.

### 2. `Principal` must carry a reference to the credential that proved it

The blocker: after `ApiTokens::Service#authenticate` finds a token, `record.id` is in hand and
is dropped. Two tokens for one account therefore produce two indistinguishable `Principal`s,
and `authorize!` cannot tell a read-only reporting token from a deployment token.

This blocks TOK-01 and AUT-03 (both very high, both targeted at M4), TOK-02, TOK-03 and
OPS-02. The application cannot close it from outside without either a second lookup on every
authenticated request or a copy of the whole token-validation path — the catalogue names both
as failure signals.

Decided, with the design recorded separately in `blueprints/0021-credential-reference.md`:
`Principal` gains `credential : CredentialRef?`, and `session_id` becomes a derived reader
over it. This lands in v0.8.

`Principal` is where it goes rather than `Authenticated`, and the short reason is that
`Principal#session_id` is already a credential reference — generalising an existing field
beats introducing a second home for the same idea.

### 3. `Authorizer#decide` must be able to receive a resource and a context

`decide(principal, permission, tenant_id)` has nowhere to put the object being acted on. An
application implementing ownership or attribute rules subclasses `Authorizer`, adds its own
resource-aware method, and then discovers that `env.auth.authorize!` only ever calls the
three-argument one. The route has to bypass `env.auth` entirely, and in doing so loses the
`authz.denied` audit line, the `InsufficientAssurance` to step-up mapping and the single
uniform 403 body that keeps denial reasons away from clients.

This blocks AUT-01 (high), AUT-03, TOK-02, AUT-02, AUT-04 and AUT-05.

The fix is a context object rather than more positional parameters, so that later additions do
not repeat this problem:

```crystal
abstract def decide(principal : Principal, permission : String, context : AuthzContext) : Decision
```

with `AuthzContext` carrying `tenant_id`, an application-supplied resource, free attributes and
the credential, and the existing three-argument form kept as a concrete overload that builds
one. Designed in `blueprints/0022-authorization-context-and-denials.md`; the decision here is
only that the abstract method has to move before the freeze, because afterwards it cannot.

### 4. `IdentityProvider` is either written or removed from the freeze list

`OIDC::Provider` cannot express a provider-specific authorisation parameter — Google's `hd`,
Okta's `prompt`, Azure's `domain_hint` — which IDP-01 requires, and nothing abstract exists for
a non-OIDC issuer such as SAML, LDAP or a legacy corporate SSO.

Both resolutions are legitimate. Declaring the contract makes federation extensible and then
genuinely frozen. Removing it from the list says federated identity stays free to evolve after
1.0, which is consistent with `docs/00-scope.md` already placing the authorization-server role
permanently out of scope. What is not acceptable is shipping 1.0 with the current mismatch.

### 5. `RateLimiter` must be able to say that its store is unavailable

`consume(key) : Verdict` has two outcomes: allowed, or denied with a `retry_after`. A limiter
backed by shared storage has a third state and no way to report it. Its options today are to
return `allow` and let rate limiting disappear under exactly the conditions an attacker can
provoke, to return `deny` and take the login endpoint down for everyone, or to raise — which
`Passwords::Authenticator` does not rescue and `ErrorHandler` does not catch, so it surfaces as
a 500.

OPS-01 is very high and requires the fail-open or fail-closed choice to be made **per
endpoint**. Today it is baked into the adapter. Adding a state to `Verdict` after the freeze
would break every exhaustive `case` over it, so the state is added now.

### 6. `DenialReason` must be extensible

The enum has five members. An `Authorizer` that denies for a reason of its own — an unmanaged
device, a closed change window, an incident lockdown — has to report `NotPermitted` and the
audit trail loses what happened.

Worse, `env.auth.authorize!` decides whether to raise `FreshAuthenticationRequiredError` by
asking `decision.reason.insufficient_assurance?`. A custom authorizer that wants to say "a
stronger credential would fix this" has to borrow that member and distort its meaning.

`Forbidden` is reachable from a frozen method's return type, so the reason model is settled
before the freeze rather than after. Settled in
`blueprints/0022-authorization-context-and-denials.md`: `DenialReason::Custom` plus a free-form
`code` for the audit trail, and "would authenticating again help" split off as its own axis so
that control flow has one authority instead of two.

### 7. ~~`AuthenticatorChain` must not foreclose a request-aware authenticator~~ — withdrawn

**This was wrong, and measuring it before implementing is what found that out.** It is left in
place rather than deleted because the reasoning that produced it is the kind worth being able
to recognise again.

The problem it names is real. `RequestAuthenticator#authenticate(credential : String?)` sees a
string and nothing else, so DPoP (TOK-11) cannot check the method, URI and access-token hash its
proof covers, and a trusted-proxy or mTLS authenticator (HTTP-06) cannot see the peer address or
TLS state. The catalogue supplies the escape — TOK-11 asks for it "through a deliberate
HTTP-facing adapter without infecting framework-independent credential contracts".

The mistake was the mechanism. This assumed the escape had to be a **sibling** contract, which
`Array(RequestAuthenticator)` could not hold, and concluded that the element type had to widen
before the freeze. Both halves fall apart on contact:

- Nothing requires a sibling. A request-aware contract can subclass `RequestAuthenticator`, or
  `RequestAuthenticator` can simply gain the overload — and either way the array's element type
  never changes. You also cannot widen an `Array` to admit a type that does not exist yet, so
  the prescribed fix was not expressible in the first place.
- What is actually missing is a way for request attributes to *reach* an authenticator, and that
  road stays open. Adding a **defaulted concrete overload** to the frozen abstract class after
  1.0 is additive:

```crystal
abstract class RequestAuthenticator
  abstract def authenticate(credential : String?) : Outcome

  # Addable after 1.0 without breaking anybody.
  def authenticate(credential : String?, request : RequestAttributes?) : Outcome
    authenticate(credential)
  end
end
```

Measured, not assumed. An implementor written against the 1.0 shape keeps compiling and routes
through its own one-argument method; one-argument call sites still resolve; and even a consumer
that had defined its own two-argument `authenticate` with a different second type resolves both
overloads correctly rather than colliding.

The abstract one-argument form also survives, which turns out to be worth having: a request-aware
authenticator is forced to implement it too, so it must answer *"what if no request attributes
were supplied"* explicitly. For DPoP that answer is a rejection, and being unable to leave it
implicit is the right kind of friction.

`AuthenticatorChain`, `AuthenticationHandler` and `Application` are all outside the freeze list,
so the plumbing that would carry the attributes can change whenever the contract does.

**Residual risk, stated rather than dismissed.** If the eventual contract genuinely cannot be a
`RequestAuthenticator` — because it needs to return something other than an `Outcome`, say —
then it would be a sibling after all and the chain would need widening. Nothing in TOK-11 or
HTTP-06 suggests that: both answer the same question ("who is making this request?") with the
same three outcomes, and only need more input to answer it.

Nothing ships for this in v0.8. `RequestAttributes` is deliberately not written now: designing
and freezing the input type of a contract with no implementation is the same mistake
`blueprints/0021` decision 7 refused when it declined to ship a scope field nothing populated.

What does ship is a guard for the one thing that *would* close the road: a second `abstract def`
on `RequestAuthenticator`, which would freeze at 1.0 and force every consumer's authenticator to
implement it. `spec/unit/authenticator_chain_spec.cr` holds a fixture implementing exactly the
one method, so adding a second does not fail an example — it stops the suite compiling. Verified
by adding one, which halts the build at `AuthenticatorChain` (this shard's own subclass guards it
before the fixture is reached) with `abstract def
KemalIdentity::RequestAuthenticator#kind() must be implemented by
KemalIdentity::AuthenticatorChain`.

### 8. Everything else the catalogue wants is additive, and waits

These miss their targets today and are named here so that missing them is a decision rather
than an accident. None of them requires a frozen signature to change, so none of them has the
v0.8 deadline:

| Gap | Scenario | Why it can wait |
|---|---|---|
| No `WWW-Authenticate` header anywhere in `src/` | HTTP-01, very high | Sending a header is additive. RFC 6750 requires it on a 401 from a bearer-accepting resource server, and `insufficient_scope` on the 403 |
| API-only mode is inferred from `Accept`, not declared | HTTP-01 | A client that sends no `Accept` currently gets a 302 to the login page. A per-subtree switch is a new parameter |
| Contract specs live under `spec/` and require the repository's own `spec_helper` ordering | DEV-02, very high | Republishing them under `src/kemal_identity/testing/` is additive |
| No injectable typed security-event sink; only `Log` | OPS-02, very high | A new contract plus an `Application` parameter |
| `PathGuard` cannot declare which credential kinds a subtree accepts | HTTP-02 | A new parameter |
| `ApiTokens::Service#issue` takes no lifetime policy | TOK-09 | `ApiTokens` is not on the freeze list |
| No assurance level above `MFA` for phishing-resistant proof | MFA-02 | `AssuranceLevel` is documented append-only with gaps of ten, precisely for this |

### 9. Three scenarios are out of scope for 1.0, and say so

- **TOK-12** (delegation and impersonation, low): `Principal` carries one subject. Separating
  actor from subject is a second identity on every request and is not worth its weight here.
- **OPS-05** (KMS/HSM-held keys, niche-critical): `JWT::KeySource` may already permit it;
  unverified, and not a 1.0 commitment.
- **TOK-11** (DPoP, niche-critical): deferred to the sibling contract that decision 7 keeps
  possible.

Out of scope means documented with its security boundary, not silently absent.

## Consequences

**v0.8 is a breaking release, and it is the last one.** Decisions 2 through 7 all change a
type that v1.0 freezes. Doing them together in one pre-1.0 release is the point; doing them
piecemeal would mean several breaking releases in a row and would undermine the freeze it is
supposed to make possible.

**The catalogue is validated after v0.8, not before.** Recording M-levels against contracts
that are about to change would produce a document that expires on the day it is written. The
worksheet pass belongs to a release candidate, and its results go in their own document so
`blueprints/maturity-validation-scenarios.md` stays what it says it is: a catalogue with no
result for this library.

**One behavioural defect surfaced during the scan and is not a freeze blocker.**
`Kemal::AuthenticationHandler` resolves the session cookie first and, when that cookie is
present but fails, clears it and never attempts the bearer credential. An expired session
cookie therefore masks a valid `Authorization` header, and a same-origin SPA sending both gets
a 401. The rule the catalogue cares about — that a rejected credential must not silently fall
back to a weaker one — is satisfied; the reverse is not. HTTP-02 and HTTP-03 both want the
precedence to be a route-level policy rather than a fixed order. Additive, and tracked with
decision 8.
