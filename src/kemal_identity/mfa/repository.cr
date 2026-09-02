module KemalIdentity::MFA
  # Storage for enrolled factors and recovery codes.
  #
  # ### Two operations here have to be atomic, and they are the ones that matter
  #
  # `#consume_counter` and `#consume_recovery_code` are single-use operations, and
  # `blueprints/0011-action-token-atomicity.md` already established what that means in this
  # shard: **one statement that both checks and marks**, never a read followed by a write.
  #
  # The read-then-write version passes every spec written against one fiber and fails against
  # two. Two requests arrive with the same intercepted TOTP code, both read
  # `last_used_counter`, both find it lower, both accept, and the replay defence was never
  # there. The same is true of a recovery code spent twice. An implementation must express
  # these as one `UPDATE ... WHERE ... RETURNING`, and the contract spec runs them
  # concurrently against a real database rather than trusting the comment.
  #
  # The rest is ordinary CRUD.
  abstract class Repository
    # Stores a newly enrolled, unconfirmed factor.
    #
    # Raises `InfrastructureError` if the id already exists, rather than overwriting: a
    # collision means the id source is broken, and silently replacing an enrolled factor is
    # how somebody loses access to their account.
    abstract def create_factor(factor : Factor) : Nil

    abstract def find_factor(id : String) : Factor?

    # Every factor for an account, confirmed or not, oldest first. Unconfirmed ones are
    # included because the enrolment screen has to show what is half-finished.
    abstract def factors_for_account(account_id : String) : Array(Factor)

    # Marks enrolment finished, recording the counter that proved it.
    #
    # Returns `false` if the factor does not exist or was already confirmed. Confirming twice
    # is not an error — a double-submitted form is a normal thing — but the caller still
    # learns nothing changed, and the first timestamp is the one an audit trail wants.
    abstract def confirm_factor(id : String, counter : Int64, at : Time) : Bool

    # Records that `counter` has now been used, **if and only if** it is strictly greater than
    # whatever this factor was last used at.
    #
    # Returns `false` when the counter has already been spent, which the caller must treat as
    # a failed verification even though the code itself was arithmetically correct. This is
    # the replay defence, and it must be one statement — see the note above.
    abstract def consume_counter(id : String, counter : Int64, at : Time) : Bool

    # Records that a code offered for this factor was wrong, returning the new consecutive
    # failure count — or `nil` if the factor does not exist.
    #
    # One statement (`UPDATE ... SET consecutive_failures = consecutive_failures + 1 ...
    # RETURNING consecutive_failures`, or the dialect's equivalent), because the count is what
    # a lifetime bound is enforced against and two parallel wrong guesses must count as two.
    # A read followed by a write loses one of them, which is the direction that favours the
    # guesser.
    abstract def record_failure(id : String, at : Time) : Int32?

    # Zeroes the consecutive failure count. What a successful verification calls.
    #
    # Returns `false` if the factor does not exist. Idempotent: a factor already at zero is
    # not an error, since every success calls this and most successes follow a success.
    abstract def clear_failures(id : String) : Bool

    # Marks a factor disabled, returning `false` if it does not exist or was already disabled.
    #
    # `at` is stamped rather than defaulted so the caller's clock is the one on the row. A
    # disabled factor must stop authenticating — see `Factor#usable?` — while remaining
    # visible to a management listing, so this is a flag and not a delete.
    abstract def disable_factor(id : String, at : Time) : Bool

    # Removes one factor. Returns `false` if it was not there.
    abstract def delete_factor(id : String) : Bool

    # Removes every factor for an account, returning how many. What "disable MFA" calls.
    abstract def delete_factors_for_account(account_id : String) : Int32

    # Replaces an account's recovery codes with `codes`, atomically.
    #
    # Atomic because the two halves are a security hole apart: an account left briefly with no
    # codes cannot recover, and one left briefly with both sets has old codes that were
    # supposed to be void. Regenerating is exactly the operation somebody performs when they
    # think the old codes leaked.
    abstract def replace_recovery_codes(account_id : String, codes : Array(RecoveryCode)) : Nil

    # Spends the code with this digest, if it exists for this account and is unused.
    #
    # Returns `false` for an unknown or already-spent code. One statement, for the same reason
    # as `#consume_counter`: two requests carrying the same code must not both succeed.
    abstract def consume_recovery_code(account_id : String, digest : Bytes, at : Time) : Bool

    # How many unused recovery codes an account has left, so a screen can say "2 remaining"
    # before somebody discovers it is zero at the worst moment.
    abstract def unused_recovery_codes(account_id : String) : Int32
  end
end
