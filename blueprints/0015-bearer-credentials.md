# 0015 — Bearer credentials: opaque tokens first, JWT second and off

**Status:** accepted
**Date:** 2026-08-26
**Milestone:** v0.4

## Context

`docs/06-roadmap.md` asks for bearer tokens as a `RequestAuthenticator`, in a stated order:
opaque personal access tokens first, "since they reuse the existing digest-and-revoke
machinery and carry none of JWT's revocation problem", then JWT validation "second, off by
default, with a strict configuration".

Both arrive through one header. `Authorization: Bearer <value>` says nothing about which kind
of credential the value is, so the decisions below are as much about routing between them as
about either one.

## Decisions

### 1. `ApiToken` sits between `Remembered` and `Password`, and is never fresh

`AssuranceLevel::ApiToken = 15`. Above `Remembered` because the holder deliberately created
this credential and can revoke it; below `Password` because no person typed anything.

The consequence is deliberate: `Principal#fresh?` is false for it at any age, so
`require_fresh!` refuses a token-bearing request outright. An automated client cannot
re-authenticate interactively, so a destructive account action should not be reachable with a
token in the first place. The gaps of ten in the enum existed for exactly this kind of
insertion, so no persisted value was renumbered.

### 2. Neither bearer credential compares `auth_version`

A session is invalidated by a password change, through `auth_version`. A bearer token is not.

The holder of a deploy key is a machine with no way to notice it stopped working, and a
password change is not a statement about the CI job's key. Revoking tokens is explicit —
`revoke_all_for_account` exists for the case where the account really is compromised, and it
is what a "revoke all my tokens" button calls.

This is a divergence from sessions, so it is stated in the doc comment of both authenticators
rather than left to be discovered.

### 3. Opaque tokens carry a searchable prefix

`ki_` by default, and an application is expected to change it to something identifying itself.

Not decoration. A fixed, searchable prefix is what lets a secret scanner — GitHub's, a
pre-commit hook, a log scrubber — recognise a leaked credential in a commit or a paste and say
*whose* it is. A bare base64 blob is indistinguishable from any other base64 blob.

It also makes the shape check exact rather than a bound, which is what lets the chain in
decision 6 route on shape for the cost of a comparison.

### 4. No scopes in v0.4

A token authenticates; it does not authorize. Scopes are an authorization concern, they belong
with the roles and permissions that `docs/06-roadmap.md` puts in v0.6, and adding a
half-enforced `scope` column now would invite applications to rely on a check this shard does
not make. `auth_api_tokens` gains no scope column, so adding one later is a migration rather
than a redesign of the token.

### 5. JWT is validated, never minted

The shard verifies tokens issued elsewhere — an identity provider, a gateway, another service.
There is no signing path, so there is no signing key to be careless with, and only
`Algorithm#verify` is abstract.

Only HMAC ships (`HS256`/`HS384`/`HS512`), because Crystal's OpenSSL bindings expose `HMAC`
and not the `EVP` interface that RSA and ECDSA verification need. RS256 is a subclass plus a C
binding away rather than a redesign: the keyring names the algorithm, so nothing else changes.

### 6. One header, two credentials, routed on shape alone

`AuthenticatorChain` asks each authenticator in turn and falls through on exactly two answers:

* `Anonymous` — nothing was presented.
* `Failed(MalformedCredential)` — "this is not a credential of mine".

Anything else stops the chain. A credential that was *recognised* and then failed on its
merits — expired, revoked, a bad signature — must not get a second opinion from an
authenticator that never issued it, which is how a revoked credential ends up authenticating a
request. This is the same rule the request layer already applies between a bearer token and a
cookie, one level down.

It works only because every authenticator here checks shape before any I/O, which they do for
independent reasons.

### 7. The CSRF bearer exemption keys on the credential *as presented*

`docs/02-security-model.md`: the exemption applies only to endpoints that accept **nothing but**
an `Authorization` header. The handler therefore looks at whether a session cookie was
presented, not at whether one resolved. A request carrying an expired or garbage session cookie
still carries a cookie, and exempting it would let a client expire its way out of CSRF
protection.

### 8. JWT strictness is not configurable downward

Each of these is a documented, exploited failure, and none is optional:

| Attack | What stops it |
|---|---|
| `alg: none` | no `Algorithm` can express it; the allow-list refuses the string at boot; `alg` is compared against the key's |
| algorithm confusion | the *key* names its algorithm; the token's `alg` selects nothing |
| a retired key still accepted | an unknown `kid` is rejected, never retried against the ring |
| a token replayed at the wrong service | `iss` and `aud` are required and compared |
| a token that never expires | `exp` is required, and `max_lifetime` bounds how far away it may be |
| a reset token used as an access token | `purpose` is required and compared |
| skew widened into an expiry bypass | `leeway` is bounded at five minutes |
| a signature over re-encoded claims | verification runs over the received bytes |

Two knobs can be turned off, and both take an explicit `nil` at the call site rather than
being defaults: `max_lifetime`, for an issuer trusted to bound its own tokens, and `purpose`,
for an issuer that emits no such claim. A keyring holding an algorithm the allow-list forbids
is a `ConfigurationError` at boot, so a typo in an algorithm name surfaces then rather than on
the day rotation needs it.

Two of the three defences against a lying `alg` are unreachable one at a time, by
construction: the boot check forces the keyring's algorithms to be a subset of the allow-list,
so an `alg` the allow-list refuses can never match the selected key either. They are kept as
independent gates — one misconfigured keyring should not be enough — and the reachable half of
each is asserted at boot. Mutation testing reports both as survivors for that reason, and
`spec/security/jwt_spec.cr` says so at the point where a reader would otherwise wonder.

`kid` selection is strict in both directions: an unknown `kid` is rejected outright, and a
token naming no `kid` resolves only when the ring holds exactly one key. Guessing between keys
is how a retired one gets used again.

### 9. The revocation trade-off is stated, not hidden

A stateless JWT cannot be revoked before its `exp`. `JWT::RevocationStore`'s doc comment says
so in full, names the only two honest answers — a very short lifetime, or a `jti` denylist that
costs the statelessness — and points the reader at `ApiTokens::Service`, which already reads
from storage on every request and gives revocation, an extendable expiry and a `last_used_at`
for the same single lookup.

The optional `accounts:` argument is the same admission in a smaller form: without it, a
disabled account keeps authenticating until `exp`.

## Consequences

* An application accepting both credentials gets one `Authorization` header and no
  disambiguating parameter, at the cost of both authenticators having to reject the other's
  shape cheaply. They already did.
* `require_fresh!` is unreachable for API clients. An application that needs a machine client
  to perform a destructive action must model that as something other than step-up.
* JWT support adds no dependency: `OpenSSL::HMAC`, `Base64` and `JSON` are stdlib.
* Every defence above has an example in `spec/security/jwt_spec.cr` named for the attack, and
  each was mutation-tested: thirty-two mutations of the validator, the keyring and the chain,
  thirty killed and the two documented above surviving by construction. Three of the thirty
  only started failing once the specs stopped asserting a bare `Failed` — a size cap, a
  base64url alphabet and the key-versus-header algorithm check are each masked by a second
  check that rejects the same token for a different reason, so each now asserts against a
  token that would otherwise authenticate.
