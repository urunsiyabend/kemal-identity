# 0017 — Federated identity: a client, and only a client

**Status:** accepted
**Date:** 2026-08-28
**Milestone:** v0.5

## Context

`docs/06-roadmap.md`: "OAuth2 / OIDC as a **client**, never an authorization server.
Authorization Code + PKCE only, `state` on every flow, `nonce` for OIDC, exact registered
redirect URI matching, issuer and audience validation, a cached JWKS with a timeout, and an
open-redirect check on the callback."

Almost every OAuth vulnerability with a name comes from omitting one of those. The decisions
below are about which are optional (none of them) and where each check lives.

## Decisions

### 1. Authorization Code with PKCE, and nothing else is expressible

No implicit flow, no hybrid, no resource-owner password grant. The implicit flow puts a token in
a URL fragment, where it lands in browser history and in any `Referer` that leaks. The password
grant asks your application to handle somebody else's password, which is the thing federating
was supposed to avoid. Neither has a code path here.

PKCE is not optional either, including for a confidential client with a secret. It costs a hash
and closes authorization-code interception, which a client secret does not: the secret proves
the *client*, PKCE proves the request came from where the code was issued to. `S256` only —
a `plain` challenge *is* the verifier and protects against nothing.

### 2. RS256 required binding libcrypto

Every real provider signs ID tokens with RS256, and Crystal's OpenSSL bindings stop at
`OpenSSL::HMAC`: no `EVP_PKEY`, no `d2i_PUBKEY`, no `EVP_DigestVerify`. So `jwt/rsa.cr`
reopens `lib LibCrypto` and adds five functions.

The key is assembled as a DER `SubjectPublicKeyInfo` from the JWKS `n` and `e` and handed to
`d2i_PUBKEY`, rather than built with `RSA_new` / `RSA_set0_key`. The low-level route is
deprecated in OpenSSL 3.0, and `EVP_PKEY_fromdata` is 3.0-only, which would make the shard
refuse to build against 1.1.1. `d2i_PUBKEY` is stable in both. About forty lines of ASN.1 write
the structure; OpenSSL parses and validates it.

**Verification only.** Signing is bound in the test-only tree, where it cannot become part of the
published API by accident — a shard that can sign is a shard someone will use to issue tokens,
and issuing is out of scope.

### 3. A `Key` holds either a secret or a public key, and dispatches on itself

`Key` refuses to pair an RSA algorithm with a shared secret, or an HMAC algorithm with a public
key, at construction. That is the algorithm-confusion attack written into the *configuration*
rather than into a token, and it is worth refusing in both places.

The result is that confusion is now blocked three times over: the key names its algorithm, the
key dispatches on its own material, and the header's `alg` is compared against the key's. The
third is redundant given the first two and is kept anyway — it is the one a reader looks for.

### 4. The JWKS cache has two bounds, and both are the point

A cache with no expiry is a key set that cannot rotate. A cache that refetches on every unknown
`kid` is a denial-of-service amplifier: anybody who can send a token can make this process
hammer somebody else's identity provider.

So: a TTL (ten minutes), *and* a floor between refetches provoked by an unknown `kid` (one
minute). The `Cache-Control` the provider publishes on that endpoint is deliberately ignored —
a header from the thing being verified is not a good input to how long you trust it.

A failed refetch keeps serving the last good ring. A provider outage should not sign every user
out, and a key that verified a minute ago has not become dangerous because a fetch failed. A
failed *first* fetch raises, because there is nothing to fall back to and an empty ring that
verifies nothing while looking healthy is worse than an error.

### 5. `(issuer, subject)`, and there is no email column

`auth_external_identities` has no email column at all — not an unused one. Two reasons:

1. **Addresses change.** People marry, change surname, leave a company and come back. A row
   keyed on an address becomes a different person's row, or a stranded orphan.
2. **Addresses are claimed, not proved.** A provider that lets somebody set an unverified
   address and hands it to you has let them claim to be whoever owns that address at *your*
   service. Matching on it is account takeover with extra steps.

Both halves are the key because `subject` is stable within an issuer and meaningless outside it:
two providers can hand out the same `sub` and mean two different people.

The unique index on `(issuer, subject)` is doing the security work. Linking a pair that is
already linked raises — **including to the same account** — because silently accepting a second
link is how one provider account ends up attached to two local ones, and then whichever row is
found first decides who somebody logs in as.

Two things about this key were sharpened in v0.8, and `blueprints/0024-federation-namespace.md`
carries both. The index prevents one external identity reaching two accounts; it does *not* merge
one person's identities across providers, and was never going to — different issuers are
different rows, both of which may point at the same account, which is what a person linked to
Google and to a corporate IdP looks like. And whether `(issuer, subject)` is a single namespace
*across protocols* is deliberately left open: OIDC's `(iss, sub)` and SAML's `(EntityID, NameID)`
are independent identifier spaces whose values can coincide, and neither remedy — one canonical
namespace, or a protocol discriminator — is safe to pick before there is a second protocol to
pick it against.

### 6. The provider's access and refresh tokens are dropped

The roadmap: "not stored at all unless the application actually calls the provider's API, and
then only encrypted at rest in separate storage."

This flow answers "who is this person?", and the ID token answers it. An access token is a
credential *for somebody else's service*; storing one the application never uses turns a breach
of this database into a breach of every user's Google account. The token response is read for
`id_token` and the rest is discarded — not stored and not returned.

### 7. `return_to` is validated on the way *in*

By the callback, the value has round-tripped through the provider and back through the browser,
so anything checked only then is checked on attacker-influenced input. Checked at `#authorize`
and carried in signed state, it cannot be substituted — and `PendingCodec` re-validates on the
way back anyway, because a signature proves who wrote a value and not that the value was ever
any good.

The rejected cases are the ones people miss: `//evil.example.com` is protocol-relative and a
browser reads it as absolute; `/\evil.example.com` normalises to the same thing in some
browsers; a newline is a second header if the value ever reaches a `Location` unescaped.

### 8. `PendingCodec` exists so applications do not hand-roll it

A flow's state has to survive a round trip, and it holds the PKCE verifier. An application
reaching for `to_json` and a plain cookie has put a secret somewhere anybody can rewrite —
and rewriting `state` or `nonce` is exactly the attack.

Signed, not encrypted. The browser may read the verifier it is carrying; that is how PKCE works
in a browser flow, since the browser *is* the party the verifier proves. What matters is that
nobody can change it.

## Consequences

* The shard now links against libcrypto for more than hashing. The five bound functions are all
  stable across OpenSSL 1.1.1 and 3.x.
* `JWT::Validator` grew `#validate`, which keeps the claim set. `Principal` still carries only a
  subject — an OIDC callback needs the rest, and re-parsing a token this shard already verified
  would be the wrong way to get it.
* Twenty-six mutations of the client, the provider and the link repository: twenty-five killed.
  The survivor is genuinely equivalent — returning `""` instead of `nil` for a missing
  `id_token` produces the same rejection one line later, and differs only in a log message.
* Not done here: a Kemal handler for the two OIDC routes. The flow is framework-agnostic, the
  codec covers the sharp edge, and the remaining glue is a redirect and a cookie the application
  writes itself.

## Amendment, v0.8.0

Two paths named above moved. The test-only RSA signing helper is now
`src/kemal_identity/testing/rsa_key.cr`, published behind `require "kemal_identity/testing"`
rather than hidden under `spec/` — so the reason it cannot reach a production build changed with
it. It is not the location any more; it is that nothing in `kemal_identity` requires that tree,
which was measured rather than asserted: a consumer binary carries zero `KemalIdentity::Testing`
symbols (`blueprints/0025`, DEV-02 and OPS-07).

The decision itself is unchanged: this shard verifies signatures and does not mint them.
