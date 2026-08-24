module KemalIdentity
  # How strongly the current principal was authenticated.
  #
  # Deliberately not a boolean `logged_in?`: "typed a password just now", "typed a
  # password two hours ago" and "restored silently from a remember-me cookie" are three
  # different security situations that a boolean cannot tell apart. Combined with
  # `Principal#authenticated_at` (how recently) this is what makes
  # `require_fresh!(within: 5.minutes)` a caller decision rather than a configured global.
  #
  # The numeric value is persisted in `auth_sessions.assurance` as a `SMALLINT`.
  # **Append only. Never renumber an existing member** — a renumbering silently reclassifies
  # every session row already on disk. The gaps of ten exist so an intermediate level can
  # be added later without breaking the ordering that `Comparable` gives us.
  enum AssuranceLevel : Int16
    # Restored from a remember-me cookie. The account holder has not typed a password
    # recently and may not be present at all. Below `Password` on purpose.
    Remembered = 10

    # A password (or equivalent single factor) was verified in this session's lifetime.
    Password = 20

    # A second factor was verified in addition to the first.
    MFA = 30
  end
end
