module KemalIdentity::Accounts
  # Where single-use grants live.
  #
  # ### The whole contract is `#consume`
  #
  # Everything else here is bookkeeping. `#consume` is the method that has to be right, and it
  # is right only if it is **atomic**: a read followed by a write lets two concurrent requests
  # both see an unused token and both proceed, which for a password reset means the link works
  # twice. `docs/02-security-model.md` spells out the shape it must have in SQL —
  #
  # ```sql
  # UPDATE auth_action_tokens
  #    SET used_at = $1
  #  WHERE token_digest = $2 AND used_at IS NULL AND expires_at > $1
  # ```
  #
  # — and then check the affected row count. A count of zero means expired, already used, or
  # unknown, and **the three are indistinguishable to the caller by design**: telling them
  # apart would let somebody probe which reset links had been issued.
  #
  # ### Concurrency
  #
  # Implementations must be safe for concurrent use from multiple fibers on multiple threads.
  # For PostgreSQL the guarantee comes from the conditional update; for the in-memory double,
  # from a mutex. Both run the same contract spec, which spawns fibers at one token and
  # asserts exactly one wins.
  abstract class ActionTokenRepository
    # Stores a newly issued token.
    #
    # Raises `KemalIdentity::InfrastructureError` if the digest is already present. As with
    # sessions, the unique index exists so that a collision is a loud error rather than two
    # grants sharing a secret.
    abstract def create(token : ActionToken) : Nil

    # Spends the token with this digest, for this purpose, and returns it — or `nil`.
    #
    # Atomic: exactly one of any number of concurrent callers gets the token back.
    #
    # `purpose` is part of the condition, not a label checked afterwards. A token issued to
    # confirm an email address must not be redeemable to reset a password, or anybody able to
    # trigger a confirmation message gets an account takeover.
    #
    # Returns `nil` for expired, already used, wrong purpose, and unknown alike.
    abstract def consume(digest : Bytes, purpose : ActionPurpose, at : Time) : ActionToken?

    # Marks every outstanding token of this purpose for this account as used, returning how
    # many it spent.
    #
    # Issuing a new reset link invalidates the previous ones, so a link sitting in an old
    # email — or in an inbox somebody else now controls — stops working. Also the right
    # response to a completed password change.
    abstract def revoke_all_for_account(account_id : String, purpose : ActionPurpose, at : Time) : Int32

    # Deletes rows past their expiry, returning the count.
    #
    # Disk reclamation only. Correctness never depends on it: expiry is evaluated inside
    # `#consume`.
    abstract def delete_expired(before : Time) : Int32
  end
end
