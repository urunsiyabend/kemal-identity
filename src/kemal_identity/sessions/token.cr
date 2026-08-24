module KemalIdentity::Sessions
  # The session secret: what the browser holds, and how it is checked before any work.
  #
  # The cookie carries a high-entropy random value and nothing else — no account id, no
  # signature, no encoded state. Everything meaningful lives server-side, which is what makes
  # revocation possible at all (`docs/02-security-model.md`).
  module Token
    # Exactly the alphabet `RandomSource#token` emits: base64url, unpadded.
    PATTERN = /\A[A-Za-z0-9_-]+\z/

    # Mints a new session secret.
    def self.generate(random : RandomSource) : Secret
      Secret.new(random.token)
    end

    # Whether `raw` could possibly be one of our tokens.
    #
    # Checked **before** hashing and before any database call. A client that sends a
    # two-megabyte cookie value should be turned away by a length comparison, not by the
    # database — and since every token we mint is exactly one length, that comparison is
    # exact rather than a bound (`docs/02-security-model.md`).
    def self.valid_shape?(raw : String) : Bool
      raw.bytesize == RandomSource.token_length && raw.matches?(PATTERN)
    end

    # SHA-256 of the raw token, as the raw bytes stored in `auth_sessions.token_digest`.
    #
    # Digest-only storage is what makes a leaked database backup useless for hijacking a
    # session: the rows contain no value a browser could present.
    def self.digest(raw : Secret) : Bytes
      raw.digest
    end
  end
end
