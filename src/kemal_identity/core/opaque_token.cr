module KemalIdentity
  # The rules every bearer secret in this shard follows.
  #
  # Session cookies, remember-me tokens, password reset links and confirmation links are all
  # the same thing wearing different labels: a high-entropy random value the holder presents,
  # which the server recognises without being able to reconstruct. `docs/02-security-model.md`
  # states the discipline once, under "Token discipline", and it applies to all of them:
  #
  # 1. Generated from a CSPRNG, at least 32 bytes.
  # 2. Stored as a SHA-256 digest. Never stored raw, never logged, never put in an error
  #    message, and never in a URL that ends up in a `Referer` header if avoidable.
  # 3. Short-lived, with an explicit `expires_at` checked on read.
  # 4. Single-use, consumed atomically.
  # 5. Consumed on use even when the surrounding operation then fails.
  #
  # Rules 1 and 2 live here, because they are the ones that are easy to get subtly wrong in
  # each place separately. Rules 3 to 5 belong to whichever repository stores the token, since
  # only it can make consumption atomic.
  module OpaqueToken
    # The alphabet `RandomSource#token` emits: base64url, unpadded.
    PATTERN = /\A[A-Za-z0-9_-]+\z/

    # Mints a new secret.
    def self.generate(random : RandomSource) : Secret
      Secret.new(random.token)
    end

    # Whether `raw` could possibly be a token this shard minted.
    #
    # Checked **before** hashing and before any database call. A client that sends a
    # two-megabyte value should be turned away by a length comparison, not by the database —
    # and since every token is exactly one length, that comparison is exact rather than a
    # bound.
    def self.valid_shape?(raw : String) : Bool
      raw.bytesize == RandomSource.token_length && raw.matches?(PATTERN)
    end

    # SHA-256 of the raw token, as the bytes stored in a `BYTEA` column.
    #
    # Digest-only storage is what makes a leaked database backup useless: the rows contain no
    # value a client could present.
    def self.digest(raw : Secret) : Bytes
      raw.digest
    end
  end
end
