module KemalIdentity::ApiTokens
  # The result of resolving an API token: token state **and** account status, together.
  #
  # The same shape, and the same reason, as `Sessions::Lookup`. Fetching the token and then
  # fetching the account is two round trips on every authenticated API request, which is the
  # busiest path an API has. One indexed lookup with a join.
  struct Lookup
    getter token : Token
    getter account_auth_version : Int32
    getter account_disabled_at : Time?

    def initialize(@token : Token, @account_auth_version : Int32, @account_disabled_at : Time? = nil)
    end

    def account_disabled? : Bool
      !@account_disabled_at.nil?
    end
  end

  # Where personal access tokens live.
  #
  # ### `auth_version` is read but not compared here
  #
  # Sessions store the `auth_version` they were minted under and fail when it moves. Tokens do
  # not: a password change should not silently break a deploy key, because the token was created
  # deliberately and separately and its holder may be a machine with no way to notice.
  #
  # The account's current version is still returned, so an application that *does* want tokens
  # to die with a password change can compare it and act. That is a policy decision, and the
  # repository's job is to make it possible rather than to make it.
  #
  # ### Concurrency
  #
  # Implementations must be safe for concurrent use from multiple fibers on multiple threads.
  abstract class Repository
    # Stores a newly issued token.
    #
    # Raises `KemalIdentity::InfrastructureError` on a duplicate digest — the unique index makes
    # a collision a loud error rather than two accounts sharing a credential.
    abstract def create(token : Token) : Nil

    # Resolves a token by the digest of its secret, with account status.
    #
    # Returns `nil` — never raises — when nothing matches, and when the token's account does not
    # exist: the reference SQL is an inner join, so a token pointing at a deleted account
    # resolves to nothing and the failure mode is closed.
    #
    # Expiry and revocation are **not** evaluated here. This reports facts; the service decides
    # what they mean, which is what lets a management screen list revoked tokens through the
    # same repository.
    abstract def find_by_digest(digest : Bytes) : Lookup?

    # Moves `last_used_at` forward. Called only when the service's throttle allows it, never on
    # every request.
    abstract def touch(id : String, last_used_at : Time) : Bool

    # Marks one token revoked, returning false if it does not exist or was already revoked.
    abstract def revoke(id : String, at : Time) : Bool

    # Brings a token's expiry **forward** to `at`, returning false if it does not exist, is
    # already revoked, or already expires at or before `at`.
    #
    # This is what a rotation with an overlap window needs: the replacement is issued, the old
    # credential is given a deadline instead of being killed outright, and the fleet has until
    # then to pick the new one up. Because the deadline lands on the row, `expiry` is enforced
    # by the authentication path on every request — no sweeper, no scheduled revoke, nothing
    # that has to have run for the window to close (`blueprints/0025`, TOK-08).
    #
    # **It must never lengthen a token's life.** "Expire" is not "renew": a rotation that could
    # extend the credential it replaces is not a rotation, and a management screen that could
    # push a deadline out is a way to keep a compromised credential alive. The comparison
    # belongs in the statement rather than in a read followed by a write, so that two callers
    # cannot interleave into a later deadline than either asked for:
    #
    # ```sql
    # UPDATE auth_api_tokens SET expires_at = $2
    #  WHERE id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)
    # ```
    #
    # A time in the past is allowed and closes the window immediately. The token then fails as
    # `Expired` rather than `Revoked`, which is the honest reason: nobody revoked it.
    abstract def expire(id : String, at : Time) : Bool

    # Revokes every live token for an account, returning how many it revoked. What "revoke all
    # my API tokens" calls, and the right response to a compromised account.
    abstract def revoke_all_for_account(account_id : String, at : Time) : Int32

    # Every token for an account, newest first, revoked ones included.
    #
    # This is the management screen. It returns revoked tokens too, because "when did I revoke
    # that?" is exactly the question such a screen exists to answer.
    abstract def list_for_account(account_id : String) : Array(Token)

    # Deletes rows past their expiry, returning the count. Disk reclamation only — correctness
    # never depends on it, because expiry is evaluated on read.
    abstract def delete_expired(before : Time) : Int32
  end
end
