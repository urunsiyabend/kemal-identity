# 0004 — An over-length secret raises when hashing and returns false when verifying

## Status

Accepted, 2026-08-24. Implemented in `src/kemal_identity/passwords/`.

## Context

`docs/05-testing.md` states the `Hasher` contract, including: "a password over the
algorithm's limit **raises** rather than being truncated". `docs/02-security-model.md` gives
the reason — bcrypt's limit is 71 bytes, and "accepting a longer one and silently cutting it
means two different passwords open the same account" — and lists "Explicit rejection of
over-length passwords, never truncation" as a release blocker.

The rule does not say which operation raises, and the two operations are not alike:

- `hash_secret` runs on registration and password change, behind a `Policy` that is supposed
  to have rejected an over-long secret already.
- `verify` runs on the request path, on whatever a client chose to post.

Raising from `verify` conflicts with two other rules. `src/CLAUDE.md`: expected failures are
values, and the only deliberate exceptions on the authentication path are `require!` and
`require_fresh!`. And the login snippet in `docs/02-security-model.md` calls
`hasher.verify(submitted, digest)` with no length check in front of it:

```crystal
account = accounts.find_by_login(normalized, tenant_id)
digest  = account.try(&.password_digest) || hasher.dummy_digest
ok      = hasher.verify(submitted, digest)
```

If `verify` raised on an over-length secret, that documented code turns a 10 KB password
field into an unhandled exception — a 500, an alarming log line, and a response that differs
from a normal failed login, which is its own oracle.

## Decision

Neither operation ever truncates. They differ in how they refuse:

| Operation | Over-length secret | Why |
|---|---|---|
| `hash_secret` | raises `ArgumentError` | The caller has a bug; `Policy` should have caught it. Silence would mean storing a digest of a secret the user did not choose. |
| `verify` | returns `false` | Request path, hostile input. Must be a `Failed`, not a 500. |

`verify` checks the length *before* handing anything to `Crypto::Bcrypt`, which raises
`Crypto::Bcrypt::Error` on an out-of-range password — so the check is not a rescue, it is a
guard that avoids the work entirely.

Two supporting decisions:

- **`max_secret_bytesize` is public on `Hasher`**, in bytes rather than characters, so
  `Policy` can reject an over-long secret with a useful message instead of letting
  `hash_secret` raise. Characters would be the wrong unit: 36 two-byte characters is 72
  bytes, one over bcrypt's limit while being half its length in characters — so a
  character-counted limit fails exactly for the users least likely to be testing it.
- **An empty secret is treated the same way**: `hash_secret` raises, `verify` returns false.
  A minimum length is `Policy`'s business, but a digest of an empty string is never
  something a caller wants, and an empty submitted password must be an ordinary failed
  login.

## Consequences

- `docs/05-testing.md`'s one-line rule has been split into the two rows above.
- The contract spec asserts both behaviours, plus the truncation property directly: a secret
  at the limit and that secret with a byte appended must not verify against the same digest.
- `spec/security/password_truncation_spec.cr` names the attack and covers the multi-byte
  case.

## Footnote: the method is `hash_secret`, not `hash`

`hash` collides with `Object#hash`. Declaring `hash(secret : Secret) : String` on a class
made the compiler resolve an internal call against `Reference#hash(hasher)` and fail with
`undefined method 'reference' for KemalIdentity::Secret`. Beyond the compile error, a class
whose `hash` means "digest this password" cannot safely be used as a hash key. The standard
library calls its equivalent `Crypto::Bcrypt.hash_secret`, so the name matches precedent.
