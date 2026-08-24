# 0007 — Audit events omit the login, and where `Policy` ended up

## Status

Accepted, 2026-08-24. Implemented in `src/kemal_identity/log.cr`,
`src/kemal_identity/passwords/authenticator.cr` and `src/kemal_identity/passwords/policy.cr`.

---

## 1. The attempted login is not written to the audit log

`docs/02-security-model.md` requires login success and failure with reason to reach a
structured log, and forbids passwords, raw tokens, session cookies, `Authorization` headers,
digests and `Set-Cookie` values from doing so. The login itself is on neither list.

Most auth libraries log it. It is the obvious field, and it is what an operator reaches for
when investigating a credential-stuffing run.

**Decision.** Events carry `subject` — the account id — and never the login.

An email address in a log line outlives the request that produced it. It is copied into
aggregators, replicated to whoever operates them, retained under a policy nobody checked, and
read by people who never authenticated to anything. A failed login against an unknown address
is the worst case: the shard would be writing down an address belonging to somebody who has
no account and no relationship with the application at all, purely because an attacker typed
it.

The account id identifies the account for anyone who can already query the database, which is
the audience an audit trail has.

**What this costs.** A failed attempt against an unknown login records no identifier, so the
log alone cannot say *which* addresses were sprayed. That is a real loss, and it is the
reason this is a recorded decision rather than a detail. Detecting the spray is the rate
limiter's job (v0.1 step 8), which keys on the login without writing it down — a counter
under a hashed key answers "is this login under attack" without retaining the login.

An application that needs login-level audit adds its own event at the call site, where its
own retention policy applies. That is the right place for a decision about somebody else's
personal data.

---

## 2. `Policy` shipped in step 5, though the roadmap gives it no step

`docs/02-security-model.md` says to ship a minimum length, a maximum that rejects rather than
truncates, and an inert breached-password hook. `docs/06-roadmap.md` does not list `Policy` in
any v0.1 step: step 5 is "`PasswordAuthenticator` with timing equalisation and lazy rehash".

It is implemented here anyway, because it belongs to this module, it is small, and its
ceiling has to come from `Hasher#max_secret_bytesize` — which step 2 exposed *for it*. Leaving
it out would have left that method with no caller and the documented deliverable with no home.

It has no call site in v0.1: there is no registration and no password-change flow to run it.
That is expected. It exists so that the flows in v0.2 have a contract to call rather than a
reason to invent composition rules.

### The two units are not an oversight

`LengthPolicy` counts its **minimum in characters** and its **maximum in bytes**. They measure
different things: how much a person chose to type, versus what the algorithm can represent.
Counting a two-byte character as two would punish a passphrase in Greek for being in Greek;
counting the ceiling in characters would let 36 two-byte characters — 72 bytes — past a
71-byte limit and into silent truncation.

The clearest demonstration is that a password can violate both at once: six four-byte
characters is simultaneously too few characters and too many bytes. A single-unit policy
could not produce that pair, and there is a spec for it.

`docs/02-security-model.md` describes bcrypt's limit as "71 characters"; it is 71 bytes, and
the document has been corrected.
