module KemalIdentity::Sessions
  # The session secret: what the browser holds, and how it is checked before any work.
  #
  # The cookie carries a high-entropy random value and nothing else — no account id, no
  # signature, no encoded state. Everything meaningful lives server-side, which is what makes
  # revocation possible at all (`docs/02-security-model.md`).
  # The rules themselves live in `KemalIdentity::OpaqueToken`, which every bearer secret in the
  # shard shares — a session cookie and a password reset link differ in lifetime and in what
  # consuming them means, not in how they are generated or stored. This is the session-shaped
  # name for them.
  module Token
    # :ditto:
    PATTERN = OpaqueToken::PATTERN

    # Mints a new session secret.
    def self.generate(random : RandomSource) : Secret
      OpaqueToken.generate(random)
    end

    # Whether `raw` could possibly be one of our tokens.
    #
    # Checked **before** hashing and before any database call. A client that sends a
    # two-megabyte cookie value should be turned away by a length comparison, not by the
    # database — and since every token we mint is exactly one length, that comparison is
    # exact rather than a bound (`docs/02-security-model.md`).
    def self.valid_shape?(raw : String) : Bool
      OpaqueToken.valid_shape?(raw)
    end

    # SHA-256 of the raw token, as the raw bytes stored in `auth_sessions.token_digest`.
    #
    # Digest-only storage is what makes a leaked database backup useless for hijacking a
    # session: the rows contain no value a browser could present.
    def self.digest(raw : Secret) : Bytes
      OpaqueToken.digest(raw)
    end
  end
end
