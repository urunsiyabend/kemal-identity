# 0006 — Insecure-cookie opt-in, expiry boundary, and what rotation restarts

## Status

Accepted, 2026-08-24. Implemented in `src/kemal_identity/sessions/`.

Three small decisions from step 4 that each depart from a literal reading of the design
documents. None changes the security properties; each makes one of them enforceable.

---

## 1. `secure: false` needs an explicit opt-in, not an environment guess

`docs/05-testing.md` lists the blocker as "`secure = false` in production fails at boot".

Implementing that literally requires the shard to decide what "production" means. The
available options are all bad: read `KEMAL_ENV` (the core is not allowed to know Kemal
exists), read `ENV["APP_ENV"]` (a name the shard does not own), or accept an `environment`
string and compare it to `"production"` (a magic value, and wrong for anyone whose staging
environment is also internet-facing).

**Decision.** `secure: false` fails at boot *always*, unless the application passes
`allow_insecure: true`. There is no environment sniffing.

This is stricter than the documented rule, not weaker: under the original wording a
misconfigured `KEMAL_ENV` yields an insecure cookie silently, whereas here an insecure cookie
requires a parameter that is conspicuous in code review and cannot be set by an environment
variable. The parameter is named for what it does rather than for where it is meant to be
used, so `allow_insecure: true` in a production branch reads as the mistake it is.

---

## 2. A session is expired *at* its deadline

`docs/02-security-model.md` writes the check as `now > absolute_expires_at`. The repository
contract, meanwhile, has `delete_expired(before)` remove rows at or before `before` — a `<=`.

Those two disagree at exactly one instant. With `>` for validity and `<=` for deletion, a
session whose `absolute_expires_at` equals the current instant is simultaneously *valid* to
`resolve` and *deletable* by the sweeper. The sweeper could then delete a live session, which
would make the sweeper a correctness dependency — the precise thing
`docs/02-security-model.md` forbids ("correctness never depends on it having run").

**Decision.** `>=`. A session is expired at its deadline, not one instant after, and the two
sides agree. `expires_at` also reads more naturally as the first invalid instant than as the
last valid one.

The window involved is one clock tick, so this is not a security difference. It is a
consistency one, and `spec/security/session_lifecycle_spec.cr` pins it: at exactly the
deadline, `resolve` fails *and* `delete_expired` removes the row.

---

## 3. Rotation restarts both windows; activity restarts neither

`docs/02-security-model.md` requires rotation on login, on an assurance increase, and on
password change, and separately requires that "absolute expiry fires regardless of activity".
It does not say what the rotated session's deadlines are.

**Decision.** `rotate` issues a genuinely new session: new secret, new row, new
`authenticated_at`, and both windows restarting from now.

The distinction that matters is **re-authentication is not activity**. Activity moves
`idle_expires_at` and can never postpone the absolute deadline — that is what stops a session
living forever through mere use, and it has its own spec. Verifying a credential again is a
different event, and refusing to extend the session after it would mean a user who
re-authenticates at hour eleven of a twelve-hour window gets logged out an hour later having
just proved who they are.

`rotate` also revokes the old row **after** creating the new one. The other order leaves a
window in which a crash logs the user out rather than leaving them where they were.

---

## Consequences

- `docs/02-security-model.md`'s cookie table and expiry pseudo-code are updated to match.
- `CookieConfig` refuses the incoherent combinations at construction, so an application
  cannot ship a `__Host-` cookie with a domain and discover it in production.
- The insecure escape hatch is one grep away: `allow_insecure`.
