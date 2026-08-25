module KemalIdentity::Sessions
  # Where remember-me tokens live.
  #
  # ### `#consume` has to answer three questions, not two
  #
  # An action token's consume is a yes or a no. This one distinguishes **live**, **replayed**
  # and **unknown**, because replayed is not a failure — it is a detection, and the caller has
  # to act on it by killing the family and telling the account holder.
  #
  # A single conditional `UPDATE` cannot express that: it updates zero rows both for a token
  # that was already spent and for one that never existed. So an implementation consumes
  # first and, only when that changes nothing, looks to see whether the digest is known. The
  # order matters — looking first would reintroduce the read-then-write race that lets two
  # callers both spend one token.
  #
  # ### Concurrency
  #
  # Implementations must be safe for concurrent use from multiple fibers on multiple threads,
  # and exactly one of any number of simultaneous callers may consume a given token. The
  # others see a replay, which is the correct reading: two parties presenting one single-use
  # token is precisely what this design exists to notice.
  abstract class RememberRepository
    # Stores a newly minted token.
    #
    # Raises `KemalIdentity::InfrastructureError` on a duplicate digest.
    abstract def create(token : RememberToken) : Nil

    # Spends the token with this digest, or reports why it could not.
    #
    # Returns `RememberAccepted` exactly once per token. Every later presentation of the same
    # digest returns `RememberReplayed`, until the row is swept.
    #
    # An expired or revoked token returns `RememberUnknown` rather than a replay: neither is
    # evidence of theft. An expired token is somebody returning after a month, and a revoked
    # one is a family already killed — reporting that as a fresh detection would send a second
    # alarm for the same incident.
    abstract def consume(digest : Bytes, at : Time) : RememberLookup

    # Kills every token in a family, returning how many it killed.
    #
    # The response to a replay. It ends that browser's remembered state — including the
    # thief's — and leaves the account's other devices signed in, because a stolen cookie on
    # one machine says nothing about the others.
    abstract def revoke_family(family_id : String, at : Time) : Int32

    # Kills the family that this token belongs to, **without spending the token**, and returns
    # how many it killed.
    #
    # This is what logging out calls. Consuming the token instead would mark it used, and the
    # browser's next visit with the same cookie would then look like a replay — the user would
    # be told their cookie may have been stolen because they pressed "log out".
    #
    # Returns zero when the digest is unknown.
    abstract def revoke_family_by_digest(digest : Bytes, at : Time) : Int32

    # Kills every token for an account, across all families. "Forget me everywhere", and the
    # right response to a password change.
    abstract def revoke_all_for_account(account_id : String, at : Time) : Int32

    # Deletes rows past their expiry, returning the count.
    #
    # Disk reclamation, with one caveat that matters: a spent token must survive **at least**
    # as long as its expiry, or replay detection stops working. Delete it early and a stolen
    # token that comes back looks unknown rather than replayed, and nobody is told.
    abstract def delete_expired(before : Time) : Int32
  end
end
