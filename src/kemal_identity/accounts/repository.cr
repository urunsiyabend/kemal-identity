module KemalIdentity::Accounts
  # Where accounts are read from, and the two places the authentication path writes to one.
  #
  # Fully abstract, and that is the single most important thing about it. The shipped
  # `auth_accounts` table is a **reference implementation, not a requirement**: an
  # application that already has `users.email` and `users.password_digest` implements this
  # over that table and creates no new account table at all. That distinction is the
  # difference between "adoptable incrementally" and "rewrite your user model first"
  # (`docs/03-data-model.md`).
  #
  # ### What is deliberately absent
  #
  # There is no `create`. v0.1 ships password login, a revocable session and a cookie — no
  # registration flow — and an adapter over somebody's existing `users` table has no
  # business being asked to insert rows into it. Account creation belongs to the
  # application. The reference PostgreSQL adapter offers it as an extra, outside this
  # contract.
  #
  # ### Concurrency
  #
  # Implementations must be safe for concurrent use from multiple fibers on multiple
  # threads. Since Crystal 1.21 made execution contexts the default concurrency model, that
  # may genuinely mean multiple threads (`docs/01-architecture.md`).
  abstract class Repository
    # The account with this id, or `nil`.
    abstract def find_by_id(id : String) : Account?

    # The account whose stored `normalized_login` equals `normalized_login`, within
    # `tenant_id`.
    #
    # **The caller normalises.** `KemalIdentity::Accounts::Login.normalize` is applied on the
    # way in; this method compares by equality against the stored column so the index is
    # used and the uniqueness constraint agrees with the lookup
    # (`docs/02-security-model.md`).
    #
    # A `nil` `tenant_id` means the single-tenant case and matches only rows whose
    # `tenant_id` is also null — not "any tenant". In PostgreSQL that needs an explicit
    # `IS NULL`, since `= NULL` matches nothing.
    abstract def find_by_login(normalized_login : String, tenant_id : String? = nil) : Account?

    # Replaces the stored digest and scheme, and moves `updated_at` to `at`.
    #
    # This is the lazy-rehash write: a successful login against a digest at an outdated cost
    # rehashes at the current one, so old digests disappear as people sign in and nobody is
    # forced through a password reset (`docs/06-roadmap.md`).
    #
    # Returns false if no such account exists. Does **not** revoke sessions — a rehash of
    # the same password is not a credential change, and revoking here would log everyone out
    # of the application that just upgraded its cost.
    abstract def update_password_digest(id : String, digest : String, scheme : String, at : Time) : Bool

    # Records that this account's address has been proved, and returns false if no such account
    # exists.
    #
    # Idempotent: confirming twice is not an error, and the second call moves the timestamp
    # forward rather than refusing. A user who clicks a link twice has not done anything wrong.
    abstract def mark_email_verified(id : String, at : Time) : Bool

    # Increments `auth_version` and returns the new value, or `nil` if no such account
    # exists.
    #
    # Invalidates every session for the account without enumerating rows: each session
    # stores the `auth_version` it was minted under, and a mismatch fails the session on its
    # next read. Used on password change and MFA recovery, alongside explicit revocation
    # rather than instead of it (`docs/02-security-model.md`).
    #
    # Also the answer for a change to the account's **tenant**, which is the one authorization
    # input a session copies: without a bump or an explicit revocation, sessions that already
    # exist keep the tenant they were minted with until they expire
    # (`Sessions::Record#tenant_id`).
    abstract def bump_auth_version(id : String) : Int32?
  end
end
