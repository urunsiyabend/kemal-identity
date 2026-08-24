module KemalIdentity::Sessions
  # Where sessions live.
  #
  # The hot path is `#find_by_digest`, and it is the one method whose cost shows up on every
  # authenticated request. Everything else runs at login, at logout, or in a background
  # sweep.
  #
  # ### Concurrency
  #
  # Implementations must be safe for concurrent use from multiple fibers on multiple threads
  # (`docs/01-architecture.md`). Two simultaneous logins for one account must produce two
  # distinct sessions, and `#create` must refuse a duplicate digest rather than overwrite —
  # see below.
  abstract class Repository
    # Stores a new session.
    #
    # Raises `KemalIdentity::InfrastructureError` if `record.token_digest` is already present.
    # This is not defensive noise: `auth_sessions.token_digest` carries a unique index
    # precisely so that a digest collision is a loud database error rather than a silent
    # security failure in which two accounts share a session
    # (`docs/03-data-model.md`). An implementation that upserted here would convert that
    # error into exactly the failure the index exists to prevent.
    abstract def create(record : Record) : Nil

    # Resolves a session by the digest of its token, returning session state and account
    # status together.
    #
    # Returns `nil` — never raises — when nothing matches. "Unknown digest" is the ordinary
    # case for an expired cookie, a tampered one, or one from a previous deployment.
    #
    # Also returns `nil` when the session's account does not exist. The reference SQL is an
    # inner join, so a session pointing at a deleted account resolves to nothing: the
    # failure mode is closed, not open.
    #
    # Revocation, expiry and account status are **not** evaluated here. This method reports
    # facts; `SessionService` decides what they mean. That split is what lets the same
    # repository serve a "list my devices" screen that wants to see revoked rows.
    abstract def find_by_digest(digest : Bytes) : Lookup?

    # Moves `last_seen_at` and `idle_expires_at` forward for one session.
    #
    # Called only when the throttle in `SessionService` allows it, never on every request.
    # Returns false if no such session exists.
    abstract def touch(id : String, last_seen_at : Time, idle_expires_at : Time) : Bool

    # Marks one session revoked, returning false if it does not exist or was already revoked.
    #
    # Already-revoked returns false rather than raising: logging out twice is not an error,
    # and the caller learns whether it changed anything.
    abstract def revoke(id : String, at : Time) : Bool

    # Revokes every live session for an account, optionally sparing one, and returns how many
    # it revoked.
    #
    # `except_id` is what makes "log out everywhere else" and "change password without
    # logging myself out" possible. Already-revoked sessions are not counted and not
    # re-stamped, so the count is the number of sessions actually ended.
    abstract def revoke_all_for_account(account_id : String, at : Time, except_id : String? = nil) : Int32

    # Deletes rows whose `absolute_expires_at` is at or before `before`, returning the count.
    #
    # Disk reclamation only. **Correctness never depends on this having run**: expiry is
    # evaluated on every read, which is the direct lesson of kemal-session issue #116, where
    # a timeout only marked a session for deletion at the next GC pass and a read could
    # refresh its access time before any expiry check, reviving it
    # (`docs/02-security-model.md`).
    abstract def delete_expired(before : Time) : Int32
  end
end
