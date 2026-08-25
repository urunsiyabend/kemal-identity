# 0011 — Action token atomicity, and a concurrency spec that did not test it

## Status

Accepted, 2026-08-25. Implemented in `src/kemal_identity/accounts/action_token_repository.cr`
and its two adapters.

## The contract

`ActionTokenRepository#consume` spends a token and returns it, or returns `nil`. Everything
else on the contract is bookkeeping; this is the method that has to be right.

It must be **atomic**. A read followed by a write lets two concurrent requests both observe an
unused token and both proceed — for a password reset that means one link setting two
passwords, which is an account takeover with a race condition in front of it.
`docs/02-security-model.md` gives the required shape:

```sql
UPDATE auth_action_tokens
   SET used_at = $1
 WHERE token_digest = $2 AND used_at IS NULL AND expires_at > $1
```

`purpose` is part of that condition, not a label checked afterwards. A token issued to confirm
an email address must not be redeemable to reset a password, or anybody able to trigger a
confirmation message has a takeover. Expired, already used, wrong purpose and unknown all
update zero rows and are therefore **indistinguishable to the caller by design** — telling
them apart would let somebody probe which links had been issued.

## The part worth recording: the spec was vacuous against PostgreSQL

The first concurrency example spawned eight fibers at one token and asserted exactly one won.
It passed. Then a mutation test replaced the PostgreSQL adapter's conditional update with a
read followed by a write — the exact bug the contract exists to prevent — and **the whole
suite still passed**.

Against the in-memory double the example is sound: atomicity there is a mutex, so a broken one
fails every time. Against PostgreSQL it was not. A racy adapter loses only when two callers
complete their `SELECT` before either commits its `UPDATE`, and at eight fibers that happened
in roughly one run in ten.

Measured on the racy implementation, per round:

| Fibers | Rounds catching the race (out of 30) |
|---|---|
| 8 | 0–2 |
| 16 | 5–8 |
| 24 | 6–11 |

The example now runs **thirty rounds of twenty-four fibers**, each round against a fresh
token. At roughly a quarter of rounds catching a racy implementation, thirty rounds miss with
probability near 1e-4. Re-run against the mutation three times, it now fails all three.

### It is still a regression test, not a proof

Atomicity in SQL ultimately rests on `consume` being one statement, and no amount of racing
demonstrates that — it only samples for the absence of a symptom. The single-statement shape
has to be confirmed by reading the adapter. Both checks are worth having and neither is
sufficient alone, which is why this is written down rather than left as a number in a spec.

The wider lesson is the one that keeps recurring in this project: **a concurrency spec that has
never been run against a broken implementation is an assumption wearing a test's clothing.**
Every security-relevant assertion here has now been mutation-tested, and this is the second
that turned out not to test what it claimed — after the outcome matchers in
`blueprints/0006-session-cookie-and-expiry-boundaries.md`'s step, which reported regressions as
`TypeCastError` stack traces rather than as failures.

## Shared token discipline

`KemalIdentity::OpaqueToken` was extracted while writing this. Session cookies, remember-me
tokens, reset links and confirmation links are the same construct with different lifetimes:
32 bytes from a CSPRNG, base64url, stored only as a SHA-256 digest, shape-checked before any
I/O. `docs/02-security-model.md` states those rules once for all of them, so they now live in
one place instead of being restated per token type. `Sessions::Token` delegates to it and keeps
its own name.

The rules that only a repository can enforce — expiry on read, single use, atomic consumption —
stay with each repository, because only it can make them atomic.
