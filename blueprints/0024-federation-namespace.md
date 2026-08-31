# 0024 — Where a federated identity lives, so a second protocol needs no breaking change

**Status:** accepted
**Date:** 2026-08-29
**Milestone:** v0.8

## Context

`docs/06-roadmap.md` listed `IdentityProvider` among the types v1.0 freezes, and no such type
exists. `docs/01-architecture.md` names it too, with an imagined signature —
`authorization_uri(...)` / `exchange_callback(...)` — as one of the three concepts the design
keeps apart. When federation was actually built in v0.5 the honest shape turned out to be data
plus one client: `OIDC::Provider`, `OIDC::Client`. The name stayed in the list; nothing was
written under it.

The question is not whether to invent the missing interface. It is narrower and better:
**adding a second federation protocol after 1.0 must not require a breaking change.**

## What was measured

Every point a hypothetical `SAML::Client` would touch, checked against what v1.0 freezes:

| Touch point | Forces a break? |
|---|---|
| A new `SAML::Client` class | No — a new class is always additive |
| `Application` / `KemalIdentity.configure` wiring | No — **OIDC is not wired into `Application` at all.** The application constructs the client and calls it from its own routes, deliberately (`docs/06-roadmap.md`, v0.5) |
| `auth_external_identities` | No — already protocol-neutral: `issuer` and `subject` are `TEXT`, the unique index is `(issuer, subject)`, and the table is not named `auth_oidc_*`. The schema got this right from the start |
| `Outcome`, `FailureReason`, `AssuranceLevel` | No — the shapes fit and the enums are append-only |
| `OIDC::Pending`, `OIDC::PendingCodec` | No — genuinely OIDC-specific. A nonce and a PKCE verifier are not concepts every protocol has, and a SAML flow brings its own state |
| **`OIDC::Identity`** | **Yes** |
| **`OIDC::Link`, `OIDC::LinkRepository`** | **Yes** |

The last two are protocol-neutral concepts trapped inside a protocol's namespace, and
`LinkRepository` is implemented by consumers as well as by this shard's two adapters. Renaming
them after 1.0 is a breaking change; renaming them now is not.

## Decisions

### 1. What is shared moves to `KemalIdentity::Federation`

```
KemalIdentity::Federation::Identity        (was OIDC::Identity)
KemalIdentity::Federation::Link            (was OIDC::Link)
KemalIdentity::Federation::LinkRepository  (was OIDC::LinkRepository)

KemalIdentity::OIDC::Provider              unchanged
KemalIdentity::OIDC::Client                unchanged, now returns Federation::Identity | Failed
KemalIdentity::OIDC::Pending               unchanged
KemalIdentity::OIDC::PendingCodec          unchanged
```

The seam this puts in the right place: **protocol mechanics under `OIDC`, the durable external
identity model under `Federation`.** `Federation` rather than a new word because the project
already uses it — `blueprints/0017-federated-identity.md`, and v0.5 is "Federated identity and
MFA".

No aliases are kept. v0.8 is already a breaking release and its changelog carries the rename;
two names for one type is the thing this document exists to avoid.

### 2. `LinkRepository` is shared because of `#for_account`, not because of the unique index

This was worth getting right, because the first version of the argument was wrong.

The unique index on `(issuer, subject)` does **not** merge a person's Google identity with their
corporate SAML one, and was never going to: two protocols produce different issuers, so those are
two rows, and both may legitimately point at the same `account_id`. What the index guarantees is
narrower and still important — that one external identity cannot be attached to two local
accounts. Splitting protocols across two tables would not violate it, because it would hold
inside each.

The reason a second protocol must write *here* is the two methods that ask about an **account**
rather than about a link:

- `#for_account(account_id)` is "which providers is this account linked to". Answered from half
  the rows, it is a management screen that lies.
- `#unlink` is guarded by the application against removing somebody's last remaining way in, and
  that guard reads `#for_account`. Against a split store it can strand an account with no login
  method at all — the one outcome unlinking must never produce, and what IDP-02 means by "unlink
  cannot strand an account without a recovery path".

Both failures are silent and both lose access.

### 3. `Identity#email_verified` becomes `Bool?`

It was a non-nilable `Bool` defaulting to `false`, and `OIDC::Client` wrote
`claims["email_verified"]?.try(&.as_bool?) || false`. So "the issuer said the address is not
verified" and "the issuer said nothing at all" arrived as the same value.

The fail-closed *behaviour* was right — both mean the address proves nothing — but the
distinction is not recoverable, and a protocol with no equivalent concept says nothing by
definition. A policy of *"only accept issuers that verify addresses"* cannot be written against a
field that cannot tell an issuer's silence from its denial. This shard has made exactly that
distinction load-bearing three times already: `CredentialRef#scopes` (`nil` versus `[]`),
`Verdict.unavailable` versus a denial, and `DenialReason::Custom` versus `NotPermitted`.

| Value | Meaning |
|---|---|
| `nil` | the issuer asserted nothing |
| `false` | the issuer said the address is not verified |
| `true` | the issuer says it verified it, and that is all it means |

`|| false` is gone from the client. A claim present but not a boolean — some issuers send the
string `"true"` — also reads as nothing said, which is the safe direction.

### 4. `#email_verified?` is written out, and returns `Bool`

```crystal
def email_verified? : Bool
  @email_verified == true
end
```

Not `getter?`. Measured: over a `Bool?`, `getter?` generates a method whose return type is
`Bool?` and which answers `nil`. That is falsy in a conditional, so the behaviour would happen to
be right, but the *type* is not a boolean — and a security predicate whose answer can be `nil` is
one refactor away from somebody reading the third state as something other than "no". The
security answer is a `Bool` and only ever a `Bool`.

Two APIs, deliberately: `#email_verified` for code that wants to observe all three states, and
`#email_verified?` for the decision.

### 5. Whether `(issuer, subject)` is one namespace across protocols is left open — on purpose

OIDC's `(iss, sub)` and SAML's `(EntityID, NameID)` are independent identifier spaces whose
values can coincide as strings; at least one mainstream identity provider serves both protocols
from the same realm URL. This shard does **not** claim to know what such a coincidence means.

Two remedies suggest themselves and only one can be right:

- Declare the values a single canonical namespace, and require each protocol adapter to encode
  into it.
- Give the key a discriminator — `(protocol, issuer, subject)`.

**The second is not obviously the safe choice, which is the point.** If the same provider
legitimately hands the same subject identifier to the same person over both protocols, a
discriminator splits one external identity into two accounts — a duplicate-account bug
introduced while preventing a collision bug. Which failure is real depends on how the second
protocol's adapter derives its subject, and that cannot be known before there is one.

So this document records the question rather than answering it by omission, and the mapping
"EntityID → issuer, NameID → subject" is written here as the *expected* shape, not as settled
semantics. Whoever implements the second protocol settles it.

### 6. The freeze list follows from the contracts, not from a wish

`IdentityProvider` leaves the list. What replaces it is derived rather than chosen, by the rule
`blueprints/0020` decision 1 states — a frozen method freezes its argument and return types:

```
Federation::LinkRepository frozen        (consumers implement it)
        ↓  link(record : Link), find(…) : Link?, for_account(…) : Array(Link)
Federation::Link frozen

OIDC::Client frozen                      (consumers call it)
        ↓  complete(…) : Federation::Identity | Failed
Federation::Identity frozen
```

`OIDC::Provider` is frozen as `Client`'s constructor argument. `OIDC::Pending` and
`PendingCodec` are frozen as `authorize`'s output and `complete`'s input.

## Consequences

**No new abstraction was invented.** An `IdentityProvider` contract over one implementation would
have had to abstract `Pending` (nonce, PKCE) and `complete`'s parameters (`state`, `code`,
`error`) — all OAuth-shaped — which means designing SAML's interface without SAML to validate it
against. This session found three separate instances of that mistake already
(`Authz::Context#credential`, the empty `StepUp` shell, `blueprints/0020` decision 7), and
`docs/00-scope.md` says the order out loud: "Split later, if and when a contract has stabilized".

**A second protocol is now purely additive**, and can be written whenever there is a reason:
its own client class, its own flow state, returning `Federation::Identity` and writing through
`Federation::LinkRepository`. If a shared contract turns out to be worth extracting at that
point, `Federation` is where it goes.

**Test doubles stay awkward and this does not fix it.** Faking `OIDC::Client` works — it is a
concrete class and both methods override — but a double that ignores everything still has to be
handed a valid `Provider`, a `KeySource` over a `Keyring` holding a real `Key`, a `Clock` and a
`RandomSource`. Measured, about eight lines of ceremony. That is an ergonomics problem and not a
freeze problem, so it belongs with DEV-02 rather than here.
