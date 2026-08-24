module KemalIdentity
  # The only source of randomness in the shard.
  #
  # Injected rather than called directly so that token generation is reproducible under
  # test. `src/CLAUDE.md` bans `Random::Secure` everywhere in `src/` except
  # `SecureRandomSource` below; `spec/unit/source_hygiene_spec.cr` enforces that ban.
  abstract class RandomSource
    # Minimum entropy for any secret this shard hands to a browser. Session tokens,
    # remember-me tokens and action tokens all use at least this many bytes
    # (`docs/02-security-model.md`, token discipline rule 1).
    TOKEN_BYTES = 32

    # `count` cryptographically random bytes.
    abstract def bytes(count : Int32) : Bytes

    # A URL-safe secret of `count` random bytes, base64url encoded without padding.
    #
    # Padding is stripped so the value carries no `=`, which keeps it safe in a cookie
    # value and in a URL without further escaping, and keeps its length fixed — the shape
    # check on the hot path is an exact length comparison, performed before any hashing or
    # I/O.
    def token(count : Int32 = TOKEN_BYTES) : String
      raise ArgumentError.new("token must be at least #{TOKEN_BYTES} bytes") if count < TOKEN_BYTES
      Base64.urlsafe_encode(bytes(count), padding: false)
    end

    # The exact length of `token(count)`'s output, for the pre-I/O shape check.
    def self.token_length(count : Int32 = TOKEN_BYTES) : Int32
      (count * 4 + 2) // 3
    end
  end

  # The production CSPRNG. This is the single permitted call site for `Random::Secure` in
  # `src/`.
  class SecureRandomSource < RandomSource
    def bytes(count : Int32) : Bytes
      raise ArgumentError.new("count must be positive") unless count > 0
      Random::Secure.random_bytes(count)
    end
  end
end
