# 0012 — Remember-me: rotation, families, and what a replay costs

## Status

Accepted, 2026-08-25. Implemented in `src/kemal_identity/sessions/remember_*.cr` and both
adapters.

## The design

`docs/02-security-model.md` is explicit that remember-me is **not** "an ordinary session with
a 30-day expiry": that is a bearer secret sitting in a browser for a month with no way to
notice it has been copied.

Instead every token is single-use and rotates on presentation, and every token descended from
one login shares a `family_id`. After a thief uses a stolen cookie the token is spent, so when
the real user next presents their copy it is a **replay** — and the reverse if the user gets
there first. Either way somebody presents a spent token.

Nothing here prevents the theft. What it guarantees is that the next visit by either party
surfaces it, which is the difference between a month of silent access and one request.

A session restored this way sits at `AssuranceLevel::Remembered`, below `Password`, and
`Principal#fresh?` is false for it however recently it was restored. Possession of a cookie is
not the presence of the account holder.

## `#consume` answers three questions, and the order is the argument

An action token's consume is yes or no. This one distinguishes **live**, **replayed** and
**unknown**, because replayed is not a failure — it is a detection that the caller must act on.

A single conditional `UPDATE` cannot express that: it changes zero rows both for a spent token
and for one that never existed. So the PostgreSQL adapter runs the conditional update **first**
and only consults the table when nothing was spent:

```sql
UPDATE auth_remember_tokens SET used_at = $1
 WHERE token_digest = $2 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $1
RETURNING ...
-- only if that returned nothing:
SELECT ... WHERE token_digest = $1
```

Looking first would be the read-then-write race that lets two callers both spend one token —
which here means a stolen cookie working silently instead of being caught. Mutation-tested:
reordering these two statements fails the contract.

Expired and revoked tokens return **unknown**, not replayed. Neither is evidence of theft: an
expired token is somebody returning after a month, and a revoked family has already raised its
alarm — reporting it again would send a second warning for one incident.

## Divergence: a replay revokes sessions too

`docs/02-security-model.md` says "revoke the whole token family, notify". This implementation
also revokes **every session for the account**.

Killing only the family leaves any session the thief already minted with the stolen cookie
alive for its full lifetime. The detection would fire, the notification would go out, and the
intruder would stay signed in — which makes the detection nearly worthless at the moment it
matters most.

A replay is a strong signal that the account is compromised. Everything ends, the real user
signs in again with a password, and the thief cannot. The cost is that a legitimate user hit by
a false positive is signed out everywhere, which is the right way round for this trade.

Note what is *not* revoked: the account's **other remember-me families**. A cookie stolen from
a laptop says nothing about the phone, and signing every device out of remembered state would
punish the user for the thief.

## The hazard: parallel requests look like theft

This is the design's real cost, and it is not hypothetical.

Tokens are single-use, so **two requests presenting the same remember cookie simultaneously
are indistinguishable from a theft**. A browser opening two tabs against a cold session, a
prefetch, a page with parallel sub-resource requests that each carry cookies — any of these can
present one token twice before the first response writes the replacement. The family dies, the
user is signed out, and they get an email saying their cookie may have been stolen.

The contract makes this explicit rather than hiding it: the concurrency example asserts that
one caller is accepted and *the rest see a replay*, because that is genuinely what happens.

Mitigations exist and none is free:

- **Restore only when there is no session**, which the handler layer should do — the window is
  then a cold start rather than every request. This narrows it a great deal but does not close
  it.
- **A grace window**, where re-presenting a token spent seconds ago returns the same successor
  rather than a detection. This is what most production implementations do. It requires storing
  the replacement against the spent row, and it weakens detection by exactly the width of the
  window.

v0.1 does neither beyond the first. The strict behaviour is what `docs/02-security-model.md`
describes, it is the safe direction to err in, and a grace window is a refinement that should
be added deliberately with its own decision record rather than assumed. **It is written down
here so that the first person to see a spurious sign-out knows it is a known trade and not a
bug.**

## Sweeping must not be eager

`delete_expired` removes rows past their expiry and nothing sooner. A spent token's row *is*
the evidence of replay: delete it early and a stolen token coming back looks unknown rather
than replayed, and nobody is told. There is a contract example asserting a spent token survives
until it expires.

## `remember` is only called after a real authentication

Chaining remembrance off a restored session would make the thirty days a rolling window that
never closes, so the method takes an `Account` and the caller is expected to have just verified
a password. A disabled account raises rather than being remembered.
