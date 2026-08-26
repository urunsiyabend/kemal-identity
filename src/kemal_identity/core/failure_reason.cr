module KemalIdentity
  # Why an authentication attempt did not produce a principal.
  #
  # **This is for the audit log, not for the response.** Branching a user-facing response
  # on the reason is an enumeration oracle: `DisabledAccount` and `InvalidCredential`
  # producing different messages tells an attacker which logins exist. Every credential
  # failure renders one identical response — see `docs/02-security-model.md`.
  enum FailureReason
    # The identifier is unknown, or the secret does not verify. One reason for both cases,
    # so that the two cannot be told apart even by accident downstream.
    InvalidCredential

    # The presented credential was rejected on its shape alone, before any I/O: wrong
    # length, illegal characters, an oversized cookie value.
    MalformedCredential

    # Past `idle_expires_at` or `absolute_expires_at`. Evaluated on read, never deferred
    # to the sweeper.
    Expired

    # `revoked_at` is set: logout, password change, or bulk revocation.
    Revoked

    # The account exists and the credential was valid, but the account is disabled.
    DisabledAccount

    # The session was minted before the account's `auth_version` was bumped. The belt to
    # revocation's braces — invalidates every session for an account without enumerating
    # rows.
    StaleAuthVersion

    # The rate limiter denied the attempt before the password was verified. `Failed`
    # carries a `retry_after` in this case.
    RateLimited

    # A single-use token was presented twice. For a remember-me token this also revokes
    # the whole token family, because either the thief or the legitimate holder is
    # replaying it.
    ReplayedToken

    # A token verified cryptographically, and then a claim inside it did not hold: the
    # wrong `iss`, an `aud` naming somebody else, a missing `exp`, a purpose that belongs
    # to a different flow.
    #
    # Kept apart from `InvalidCredential` because the two mean opposite things to whoever
    # reads the audit log. `InvalidCredential` is noise — a stale token, a typo, a scanner.
    # This one says a *validly signed* token was presented to the wrong verifier, which is
    # either a misconfigured client or a genuine attempt to replay a token across a trust
    # boundary. Both are worth an alert; neither is visible in the response, which is
    # identical for every reason.
    InvalidClaim
  end
end
