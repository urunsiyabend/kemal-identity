# 0001 — One three-variant outcome union

## Status

Accepted, 2026-08-24. Implemented in `src/kemal_identity/core/outcome.cr`.

## Context

The design documents describe the authentication result twice, and not identically.

- `docs/01-architecture.md`, module map: `AuthenticationResult   Authenticated | Failed`,
  and the table of the central split gives both `RequestAuthenticator#authenticate` and
  `CredentialAuthenticator#authenticate` the return type `AuthenticationResult`.
- `src/CLAUDE.md`: `alias Outcome = Anonymous | Authenticated | Failed`.
- `docs/04-kemal-integration.md`, the login route example: an exhaustive
  `case result ... in Anonymous` branch over the result of
  `KemalIdentity.app.passwords.authenticate`.

Reconciling the first bullet with the third is not possible: if the credential path
returns a two-variant union, the documented login example does not compile. Crystal
rejects an `in Anonymous` branch on a union that cannot hold one.

The substantive question underneath the naming is whether "no credential was presented"
is a distinct outcome from "a credential was rejected". It is, and the distinction is
load-bearing: a request with no cookie needs no response action, whereas a request whose
cookie did not resolve needs that cookie cleared. `docs/02-security-model.md` states this
requirement directly — "Returns `Anonymous` when no cookie is present, and `Failed` when a
cookie is present but invalid, so the caller can distinguish 'not signed in' from 'clear
this cookie'."

## Decision

One union, three variants, used at every authentication boundary:

```crystal
alias Outcome = Anonymous | Authenticated | Failed
alias AuthenticationResult = Outcome
```

`AuthenticationResult` is retained as an alias so that the name used throughout
`docs/01-architecture.md` resolves, and so contract signatures can be written with
whichever name reads better at that boundary.

The credential path never *returns* `Anonymous` in practice — a login attempt with an
empty form field is `Failed(MalformedCredential)`, not `Anonymous`. The variant is
reachable in the type only. That is the price of a single union, and it is the cheaper
side of the trade: two unions would mean two exhaustive-case shapes to keep in step, and a
conversion at the point where the credential path hands off to the session path.

## Consequences

- Every consumer writes one `case ... in` shape, whatever it is authenticating.
- The `docs/04-kemal-integration.md` login example compiles as written.
- Callers of the credential path carry one branch that cannot fire. Where that reads badly,
  handle `Anonymous` and `Failed` identically — which is what the example does, and what
  the enumeration rules require anyway, since the response must not vary with the reason.
- `docs/01-architecture.md`'s module map is now one line out of date. Left as-is rather
  than edited: the module map is a sketch, and this record is the authority.
