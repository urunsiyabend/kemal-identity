require "log"

module KemalIdentity
  # The audit trail.
  #
  # `docs/02-security-model.md` lists what must reach a structured log — login success and
  # failure with reason, logout, session rotation, bulk revocation, rate-limit denials,
  # replay detection — and, more importantly, what must never: passwords, raw tokens of any
  # kind, session cookies, `Authorization` headers, password digests, `Set-Cookie` values.
  #
  # Emitting through a named source rather than `puts` is what lets an application route
  # these somewhere durable, filter them by severity, or ship them to a SIEM without parsing
  # prose. `src/CLAUDE.md` bans `puts` for exactly this reason.
  #
  # ### The login is deliberately absent
  #
  # Events carry `subject` — the account id — and never the login that was typed. An email
  # address in a log file is a disclosure that outlives the request, gets copied into
  # aggregators, and is read by people who never authenticated to anything. The account id
  # identifies the account for anyone who can already query the database, which is the
  # audience an audit trail is for.
  #
  # The cost is that a failed attempt against an *unknown* login records no identifier at
  # all, since there is no account to name. Detecting credential stuffing is the rate
  # limiter's job (`RateLimiter`, v0.1 step 8), which keys on the login without writing it
  # down.
  Log = ::Log.for("kemal_identity")
end
