module KemalIdentity::Passwords
  # Turns a secret into a digest, and checks a secret against one.
  #
  # Hashing only. Whether a password is *acceptable* is a `Policy` the application supplies
  # (`docs/02-security-model.md`): no composition rules ship as a default, and the two
  # concerns are kept apart so an application can change one without touching the other.
  #
  # ### Over-length secrets
  #
  # Every algorithm has an input limit, and silently truncating at it is a real
  # vulnerability: if bcrypt cuts at 71 bytes, then 71 A's and 71 A's followed by anything
  # at all open the same account. The two operations therefore treat the limit differently,
  # and the difference is deliberate:
  #
  # * `#hash_secret` **raises**. Creating a digest from a secret the algorithm cannot represent is
  #   a bug in the caller — `Policy` is supposed to have rejected it already — and failing
  #   loudly is the only way the caller finds out.
  # * `#verify` returns **false**. It is on the request path, fed by whatever a client
  #   chose to post. Expected failures are values (`src/CLAUDE.md`), so a two-megabyte
  #   password field has to become a `Failed`, not a 500. The documented login snippet in
  #   `docs/02-security-model.md` calls `verify` with no length check in front of it, which
  #   settles it.
  #
  # Neither ever truncates. See `blueprints/0004-hasher-over-length-behaviour.md`.
  abstract class Hasher
    # Identifies the algorithm, and is stored alongside the digest in
    # `auth_accounts.password_scheme` so `#needs_rehash?` can tell a foreign digest from
    # one of ours.
    abstract def scheme : String

    # The largest secret this algorithm can represent, in **bytes** — not characters. A
    # multi-byte character costs more than one byte of the budget, so a limit measured in
    # characters would be wrong for exactly the users least likely to be testing it.
    #
    # `Policy` reads this to reject an over-long secret with a useful message before
    # `#hash_secret` raises on it.
    abstract def max_secret_bytesize : Int32

    # Digests `secret` at the current parameters.
    #
    # Raises `ArgumentError` if `secret` is empty or longer than `#max_secret_bytesize`.
    # The message carries the length and never the secret.
    abstract def hash_secret(secret : Secret) : String

    # Whether `secret` produced `digest`.
    #
    # Returns false — never raises, never truncates — for a secret the algorithm cannot
    # represent, and for a digest this hasher cannot parse.
    abstract def verify(secret : Secret, digest : String) : Bool

    # Whether `digest` was produced at parameters weaker than the current ones, or by
    # another scheme entirely.
    #
    # This is what makes lazy rehashing work: a successful login at an outdated cost
    # silently rehashes at the current one, so old digests disappear as people sign in and
    # nobody is forced through a password reset (`docs/06-roadmap.md`, migration step 2).
    # A digest this hasher cannot parse counts as needing a rehash — that is precisely the
    # legacy digest the migration is trying to retire.
    abstract def needs_rehash?(digest : String) : Bool

    # A digest that no input verifies against, costing what a real verification costs.
    #
    # This closes the enumeration-timing oracle. If an unknown login returns before doing
    # any hashing work, the response comes back a hundred milliseconds early and the
    # attacker has a reliable account oracle no matter how identical the response body is:
    #
    # ```
    # account = accounts.find_by_login(normalized, tenant_id)
    # digest = account.try(&.password_digest) || hasher.dummy_digest
    # ok = hasher.verify(submitted, digest)
    # return Failed.new(FailureReason::InvalidCredential) if account.nil? || !ok
    # ```
    #
    # Computed once, when the hasher is built, so it costs nothing per request.
    abstract def dummy_digest : String
  end
end
